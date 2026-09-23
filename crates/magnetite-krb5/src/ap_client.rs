//! Client-side Kerberos AP-REQ construction (Tier C C1 part 4b-2) — the inverse of
//! [`verify_ap_req`](crate::ap_req::verify_ap_req). A replication client
//! authenticating to a Kerberos-protected service (DRSUAPI) presents an AP-REQ: a
//! service ticket (encrypted under the *service* key) carrying a session key, plus
//! an authenticator (encrypted under that session key) proving it holds the key.
//!
//! A magnetite realm's service keys are deterministic, so the client mints the
//! service ticket directly instead of running a full AS→TGS exchange against a KDC.
//! Against a real foreign KDC (Samba) the ticket would instead come from a TGS-REQ;
//! the AP-REQ assembly is identical.

use crate::as_exchange::{
    asn1, encrypted_data, int, principal_name, realm_string, ticket_flags, to_generalized,
};
use crate::error::{KdcError, KdcResult};
use crate::keys::AES256_CTS_HMAC_SHA1_96;
use chrono::{Duration, Utc};
use picky_asn1::bit_string::BitString;
use picky_asn1::wrapper::{
    BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2,
    ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag7,
    OctetStringAsn1, Optional,
};
use picky_krb::constants::key_usages::{AP_REP_ENC, AP_REQ_AUTHENTICATOR, TICKET_REP};
use picky_krb::constants::types::{AP_REP_MSG_TYPE, AP_REQ_MSG_TYPE, NT_PRINCIPAL};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{
    Authenticator, AuthenticatorInner, EncApRepPart, EncApRepPartInner, EncTicketPart,
    EncTicketPartInner, EncryptionKey, Ticket, TicketInner, TransitedEncoding,
};
use picky_krb::messages::{ApRep, ApRepInner, ApReq, ApReqInner};
use rand::RngCore;

fn crypto(e: impl std::fmt::Display) -> KdcError {
    KdcError::Crypto(e.to_string())
}

/// An AES256 [`EncryptionKey`] carrying `key`.
fn enc_key(key: &[u8]) -> EncryptionKey {
    EncryptionKey {
        key_type: ExplicitContextTag0::from(int(i64::from(AES256_CTS_HMAC_SHA1_96))),
        key_value: ExplicitContextTag1::from(OctetStringAsn1::from(key.to_vec())),
    }
}

/// Build an AP-REQ for `service_spn` in `realm`, authenticating as `client`. The
/// service ticket is minted directly under `service_key` (valid for this realm's
/// deterministic keys). Returns the DER-encoded AP-REQ and the ticket **session
/// key** (which the client later uses to decrypt the mutual-auth AP-REP).
///
/// # Errors
/// [`KdcError::Crypto`] on encryption failure or [`KdcError::Asn1`] on encoding.
pub fn build_ap_req(
    service_key: &[u8],
    realm: &str,
    service_spn: &[&str],
    client: &[&str],
) -> KdcResult<(Vec<u8>, Vec<u8>)> {
    let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();
    let now = Utc::now();
    let end = now + Duration::hours(10);

    let mut session_key = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut session_key);

    let client_comp: Vec<String> = client.iter().map(|s| (*s).to_string()).collect();
    let service_comp: Vec<String> = service_spn.iter().map(|s| (*s).to_string()).collect();

    // --- Service ticket enc-part, sealed under the service key (usage 2) ---
    let enc_ticket_part = EncTicketPart::from(EncTicketPartInner {
        flags: ExplicitContextTag0::from(ticket_flags()),
        key: ExplicitContextTag1::from(enc_key(&session_key)),
        crealm: ExplicitContextTag2::from(realm_string(realm)?),
        cname: ExplicitContextTag3::from(principal_name(NT_PRINCIPAL, &client_comp)?),
        transited: ExplicitContextTag4::from(TransitedEncoding {
            tr_type: ExplicitContextTag0::from(int(0)),
            contents: ExplicitContextTag1::from(OctetStringAsn1::from(Vec::new())),
        }),
        auth_time: ExplicitContextTag5::from(to_generalized(now)),
        starttime: Optional::from(None),
        endtime: ExplicitContextTag7::from(to_generalized(end)),
        renew_till: Optional::from(None),
        caddr: Optional::from(None),
        authorization_data: Optional::from(None),
    });
    let enc_ticket_der = picky_asn1_der::to_vec(&enc_ticket_part).map_err(asn1)?;
    let ticket_cipher = cipher
        .encrypt(service_key, TICKET_REP, &enc_ticket_der)
        .map_err(crypto)?;
    let ticket = Ticket::from(TicketInner {
        tkt_vno: ExplicitContextTag0::from(int(5)),
        realm: ExplicitContextTag1::from(realm_string(realm)?),
        sname: ExplicitContextTag2::from(principal_name(NT_PRINCIPAL, &service_comp)?),
        enc_part: ExplicitContextTag3::from(encrypted_data(ticket_cipher)),
    });

    // --- Authenticator, sealed under the ticket session key (usage 11) ---
    let authenticator = Authenticator::from(AuthenticatorInner {
        authenticator_vno: ExplicitContextTag0::from(int(5)),
        crealm: ExplicitContextTag1::from(realm_string(realm)?),
        cname: ExplicitContextTag2::from(principal_name(NT_PRINCIPAL, &client_comp)?),
        cksum: Optional::from(None),
        cusec: ExplicitContextTag4::from(int(0)),
        ctime: ExplicitContextTag5::from(to_generalized(now)),
        subkey: Optional::from(None),
        seq_number: Optional::from(None),
        authorization_data: Optional::from(None),
    });
    let auth_der = picky_asn1_der::to_vec(&authenticator).map_err(asn1)?;
    let auth_cipher = cipher
        .encrypt(&session_key, AP_REQ_AUTHENTICATOR, &auth_der)
        .map_err(crypto)?;

    let ap_req = ApReq::from(ApReqInner {
        pvno: ExplicitContextTag0::from(int(5)),
        msg_type: ExplicitContextTag1::from(int(i64::from(AP_REQ_MSG_TYPE))),
        ap_options: ExplicitContextTag2::from(BitStringAsn1::from(BitString::with_len(32))),
        ticket: ExplicitContextTag3::from(ticket),
        authenticator: ExplicitContextTag4::from(encrypted_data(auth_cipher)),
    });
    let ap_req_der = picky_asn1_der::to_vec(&ap_req).map_err(asn1)?;
    Ok((ap_req_der, session_key))
}

/// Recover the **acceptor subkey** (the GSS-API session key) from a server's
/// mutual-auth AP-REP: decrypt its enc-part with the ticket `session_key` (usage 12)
/// and read the subkey. This is the client counterpart of
/// [`build_ap_rep`](crate::ap_req::build_ap_rep).
///
/// # Errors
/// [`KdcError::Crypto`] if decryption fails, [`KdcError::Asn1`] on a decode error,
/// or [`KdcError::Malformed`] if the AP-REP carries no subkey.
pub fn decrypt_ap_rep_subkey(session_key: &[u8], ap_rep_der: &[u8]) -> KdcResult<Vec<u8>> {
    let ap_rep: ApRep = picky_asn1_der::from_bytes(ap_rep_der).map_err(asn1)?;
    let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();
    let plain = cipher
        .decrypt(session_key, AP_REP_ENC, &ap_rep.0.enc_part.0.cipher.0 .0)
        .map_err(crypto)?;
    let enc: EncApRepPart = picky_asn1_der::from_bytes(&plain).map_err(asn1)?;
    enc.0
        .subkey
        .0
        .as_ref()
        .map(|k| k.0.key_value.0 .0.clone())
        .ok_or_else(|| KdcError::Malformed("AP-REP carries no acceptor subkey".into()))
}

/// Complete a **DCE-style** (three-leg) GSS mutual authentication: given the
/// server's mutual-auth AP-REP, recover the acceptor subkey *and* build the
/// client's final leg (AUTH3) AP-REP. Samba's DCE/RPC requests `GSS_C_DCE_STYLE`,
/// so the acceptor's context stays `CONTINUE_NEEDED` after the AP-REP until it
/// receives this reply; per-message ops fault (`RPC_S_SEC_PKG_ERROR`) otherwise.
///
/// The leg-3 AP-REP echoes the server AP-REP's `ctime`/`cusec`/`seq-number` and
/// carries **no** subkey, sealed under the ticket `session_key` (key usage 12) —
/// the exact shape a real Samba client sends. Returns `(acceptor_subkey, auth3_ap_rep)`.
///
/// # Errors
/// [`KdcError::Crypto`] on decrypt/encrypt failure, [`KdcError::Asn1`] on an ASN.1
/// error, or [`KdcError::Malformed`] if the server AP-REP carries no subkey.
pub fn dce_style_auth3(
    session_key: &[u8],
    server_ap_rep_der: &[u8],
) -> KdcResult<(Vec<u8>, Vec<u8>)> {
    let ap_rep: ApRep = picky_asn1_der::from_bytes(server_ap_rep_der).map_err(asn1)?;
    let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();
    let plain = cipher
        .decrypt(session_key, AP_REP_ENC, &ap_rep.0.enc_part.0.cipher.0 .0)
        .map_err(crypto)?;
    let enc: EncApRepPart = picky_asn1_der::from_bytes(&plain).map_err(asn1)?;
    let subkey = enc
        .0
        .subkey
        .0
        .as_ref()
        .map(|k| k.0.key_value.0 .0.clone())
        .ok_or_else(|| KdcError::Malformed("AP-REP carries no acceptor subkey".into()))?;

    // The leg-3 reply echoes ctime/cusec/seq-number with no subkey.
    let leg3 = EncApRepPart::from(EncApRepPartInner {
        ctime: enc.0.ctime.clone(),
        cusec: enc.0.cusec.clone(),
        subkey: Optional::from(None),
        seq_number: enc.0.seq_number.clone(),
    });
    let leg3_plain = picky_asn1_der::to_vec(&leg3).map_err(asn1)?;
    let sealed = cipher
        .encrypt(session_key, AP_REP_ENC, &leg3_plain)
        .map_err(crypto)?;
    let auth3 = ApRep::from(ApRepInner {
        pvno: ExplicitContextTag0::from(int(5)),
        msg_type: ExplicitContextTag1::from(int(i64::from(AP_REP_MSG_TYPE))),
        enc_part: ExplicitContextTag2::from(encrypted_data(sealed)),
    });
    let auth3_der = picky_asn1_der::to_vec(&auth3).map_err(asn1)?;
    Ok((subkey, auth3_der))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ap_req::{build_ap_rep, verify_ap_req};

    #[test]
    fn ap_req_round_trips_through_verify_and_the_ap_rep_subkey_agrees() {
        // The client's AP-REQ verifies with the same service key, and both sides
        // derive the SAME GSS acceptor subkey — the full mutual-auth handshake.
        let service_key = vec![0x11u8; 32];
        let realm = "EXAMPLE.COM";

        let (ap_req, client_session_key) =
            build_ap_req(&service_key, realm, &["host", "magnetite"], &["alice"]).unwrap();

        // The service verifies it and recovers the same session key + client id.
        let verified = verify_ap_req(&service_key, &ap_req).unwrap();
        assert_eq!(
            verified.session_key, client_session_key,
            "session key agrees"
        );
        assert_eq!(verified.client_name, vec!["alice".to_string()]);
        assert_eq!(verified.client_realm, realm);

        // The service mints the AP-REP; the client recovers the acceptor subkey from
        // it and both sides now hold the same GSS session key.
        let (ap_rep, server_subkey) =
            build_ap_rep(&verified.session_key, verified.ctime, verified.cusec, 1).unwrap();
        let client_subkey = decrypt_ap_rep_subkey(&client_session_key, &ap_rep).unwrap();
        assert_eq!(client_subkey, server_subkey, "GSS acceptor subkey agrees");
        assert_eq!(client_subkey.len(), 32, "AES256 subkey");
    }

    #[test]
    fn a_wrong_service_key_fails_verification() {
        let (ap_req, _) = build_ap_req(
            &[0x11u8; 32],
            "EXAMPLE.COM",
            &["host", "magnetite"],
            &["alice"],
        )
        .unwrap();
        assert!(verify_ap_req(&[0x22u8; 32], &ap_req).is_err());
    }
}
