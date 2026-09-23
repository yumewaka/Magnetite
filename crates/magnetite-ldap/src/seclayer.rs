//! The RFC 4752 GSS-API security layer for the LDAP GSS-SPNEGO SASL bind.
//!
//! After the Kerberos context is established (AP-REQ / AP-REP), the SASL GSSAPI
//! mechanism negotiates a per-message security layer, then protects every
//! subsequent LDAP PDU with it. Active Directory requires LDAP signing, so a real
//! domain-join client uses **integrity** or **confidentiality** — offering only
//! "no security layer" would be refused.
//!
//! Negotiation (RFC 4752 §3.1), both tokens integrity-`GSS_Wrap`ed (never sealed):
//!  1. Server → client: one octet of supported layer bits ‖ 3-octet max message
//!     size the server can receive.
//!  2. Client → server: the selected layer bit ‖ its max size (‖ optional authzid).
//!
//! After that, each LDAP PDU on the wire is `length(4) ‖ GSS_Wrap token`; the codec
//! ([`crate::codec`]) applies this once a layer is active.
//!
//! The server is the GSS **acceptor**: it protects outgoing PDUs with the acceptor
//! key usage and opens incoming ones with the initiator usage.

use magnetite_krb5::gss::{
    gss_seal_token, gss_unseal_token, gss_unwrap_integrity, gss_wrap_integrity,
    KG_USAGE_ACCEPTOR_SEAL, KG_USAGE_INITIATOR_SEAL,
};

/// RFC 4752 security-layer bits (the octet in the negotiation token).
pub(crate) const LAYER_NONE: u8 = 0x01;
pub(crate) const LAYER_INTEGRITY: u8 = 0x02;
pub(crate) const LAYER_CONFIDENTIALITY: u8 = 0x04;

/// The maximum wrapped message size the server advertises and accepts (1 MiB).
pub(crate) const MAX_WRAP_SIZE: u32 = 0x0010_0000;

/// The negotiation layers the server offers: signing (integrity), sealing
/// (confidentiality), or none — the client picks the one it prefers.
pub(crate) const OFFERED_LAYERS: u8 = LAYER_NONE | LAYER_INTEGRITY | LAYER_CONFIDENTIALITY;

/// The 4-octet SASL security-layer message: a layer bitmask followed by a 24-bit
/// big-endian maximum message size.
pub(crate) fn layer_message(layers: u8, max_size: u32) -> [u8; 4] {
    let m = max_size.to_be_bytes();
    [layers, m[1], m[2], m[3]]
}

/// Parse the client's 4-octet selection, returning the single selected layer bit.
pub(crate) fn selected_layer(message: &[u8]) -> Option<u8> {
    message.first().copied()
}

/// An established GSS per-message security layer over one LDAP connection. Seals
/// (confidentiality) or signs (integrity) each PDU with the acceptor subkey.
pub(crate) struct GssSecurityLayer {
    subkey: Vec<u8>,
    confidential: bool,
    /// The server's outgoing sequence number (acceptor direction).
    send_seq: u64,
}

impl GssSecurityLayer {
    /// A layer keyed on the GSS acceptor `subkey`. `confidential` selects sealing
    /// vs. signing; `first_seq` is the sequence the first protected PDU uses.
    pub(crate) fn new(subkey: Vec<u8>, confidential: bool, first_seq: u64) -> Self {
        Self {
            subkey,
            confidential,
            send_seq: first_seq,
        }
    }

    /// Protect an outgoing LDAP PDU, returning the GSS token (no length prefix).
    /// `None` if the crypto fails.
    pub(crate) fn seal(&mut self, pdu: &[u8]) -> Option<Vec<u8>> {
        let seq = self.send_seq;
        self.send_seq = self.send_seq.wrapping_add(1);
        if self.confidential {
            gss_seal_token(&self.subkey, KG_USAGE_ACCEPTOR_SEAL, seq, pdu).ok()
        } else {
            gss_wrap_integrity(&self.subkey, KG_USAGE_ACCEPTOR_SEAL, seq, pdu).ok()
        }
    }

    /// Open an incoming client GSS token, returning the inner LDAP PDU. `None` if
    /// the token is malformed or fails its integrity check.
    pub(crate) fn open(&self, token: &[u8]) -> Option<Vec<u8>> {
        if self.confidential {
            gss_unseal_token(&self.subkey, KG_USAGE_INITIATOR_SEAL, token).map(|(_, p)| p)
        } else {
            gss_unwrap_integrity(&self.subkey, KG_USAGE_INITIATOR_SEAL, token).map(|(_, p)| p)
        }
    }
}

/// An established NTLM SSP sign+seal security layer over one LDAP connection (the
/// layer a Windows domain-join client uses when it binds with NTLM rather than
/// Kerberos). Each PDU on the wire is `length(4) ‖ signature(16) ‖ sealed`; the
/// [`magnetite_rpc::ntlmssp::NtlmContext`] holds the per-direction RC4 handles and
/// sequence numbers, so both `seal` and `open` mutate it.
pub(crate) struct NtlmSecurityLayer {
    ctx: magnetite_rpc::ntlmssp::NtlmContext,
}

impl NtlmSecurityLayer {
    pub(crate) fn new(ctx: magnetite_rpc::ntlmssp::NtlmContext) -> Self {
        Self { ctx }
    }

    /// Seal an outgoing LDAP PDU, returning `signature(16) ‖ sealed` (no length
    /// prefix — the codec frames it).
    pub(crate) fn seal(&mut self, pdu: &[u8]) -> Vec<u8> {
        self.ctx.seal(pdu)
    }

    /// Open an incoming `signature(16) ‖ sealed` token, returning the inner LDAP
    /// PDU, or `None` if the signature does not verify.
    pub(crate) fn open(&mut self, token: &[u8]) -> Option<Vec<u8>> {
        self.ctx.unseal(token)
    }
}

/// The per-connection SASL security layer, whichever mechanism established it.
// One per authenticated connection, held for the connection's lifetime; boxing the
// larger NTLM layer to even the variants would only add an allocation for no benefit.
#[allow(clippy::large_enum_variant)]
pub(crate) enum SecurityLayer {
    Gss(GssSecurityLayer),
    Ntlm(NtlmSecurityLayer),
}

impl SecurityLayer {
    /// Protect an outgoing LDAP PDU (no length prefix). `None` only if GSS crypto
    /// fails; the NTLM path is infallible.
    pub(crate) fn seal(&mut self, pdu: &[u8]) -> Option<Vec<u8>> {
        match self {
            SecurityLayer::Gss(l) => l.seal(pdu),
            SecurityLayer::Ntlm(l) => Some(l.seal(pdu)),
        }
    }

    /// Open an incoming protected token into the inner LDAP PDU.
    pub(crate) fn open(&mut self, token: &[u8]) -> Option<Vec<u8>> {
        match self {
            SecurityLayer::Gss(l) => l.open(token),
            SecurityLayer::Ntlm(l) => l.open(token),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetite_krb5::gss::{gss_seal_token, gss_unseal_token, gss_unwrap_integrity};

    #[test]
    fn layer_message_encodes_bitmask_and_24bit_size() {
        assert_eq!(
            layer_message(OFFERED_LAYERS, MAX_WRAP_SIZE),
            [0x07, 0x10, 0x00, 0x00]
        );
        assert_eq!(
            selected_layer(&[LAYER_CONFIDENTIALITY, 0, 0x40, 0]),
            Some(0x04)
        );
    }

    #[test]
    fn confidentiality_layer_round_trips_both_directions() {
        let subkey: Vec<u8> = (0u8..32).collect();
        let mut server = GssSecurityLayer::new(subkey.clone(), true, 0);
        let pdu = b"\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"; // a bind-ish BER

        // Client → server: the client seals with the initiator usage; server opens.
        let client_token = gss_seal_token(&subkey, KG_USAGE_INITIATOR_SEAL, 0, pdu).unwrap();
        assert_eq!(server.open(&client_token).as_deref(), Some(&pdu[..]));

        // Server → client: the acceptor token opens under the acceptor usage.
        let server_token = server.seal(pdu).expect("seal");
        let opened =
            gss_unseal_token(&subkey, KG_USAGE_ACCEPTOR_SEAL, &server_token).map(|(_, p)| p);
        assert_eq!(opened.as_deref(), Some(&pdu[..]));
    }

    #[test]
    fn integrity_layer_signs_without_encrypting() {
        let subkey: Vec<u8> = (0u8..32).collect();
        let mut server = GssSecurityLayer::new(subkey.clone(), false, 0);
        let pdu = b"a plaintext LDAP search result";

        let token = server.seal(pdu).expect("sign");
        // Integrity only: the plaintext is visible in the token body.
        assert!(
            token.windows(pdu.len()).any(|w| w == pdu),
            "must not be encrypted"
        );
        let opened = gss_unwrap_integrity(&subkey, KG_USAGE_ACCEPTOR_SEAL, &token).map(|(_, p)| p);
        assert_eq!(opened.as_deref(), Some(&pdu[..]));

        // Client → server integrity: client signs with the initiator usage.
        let client_token = gss_wrap_integrity(&subkey, KG_USAGE_INITIATOR_SEAL, 0, pdu).unwrap();
        assert_eq!(server.open(&client_token).as_deref(), Some(&pdu[..]));
    }

    #[test]
    fn seal_advances_the_sequence_number() {
        let subkey: Vec<u8> = (0u8..32).collect();
        let mut layer = GssSecurityLayer::new(subkey, true, 0);
        let a = layer.seal(b"one").unwrap();
        let b = layer.seal(b"one").unwrap();
        assert_ne!(a, b, "same plaintext at a new sequence must differ");
    }
}
