//! RPC secure-binding support: the authentication verification trailer
//! (`sec_trailer`) plus Netlogon SSP (`RPC_C_AUTHN_NETLOGON`) PKT_INTEGRITY
//! framing on REQUEST/RESPONSE PDUs (MS-RPCE §2.2.2.11, MS-NRPC §3.3).
//!
//! A signed PDU is laid out as `[common header][pduData][pad to 4][sec_trailer
//! (8)][auth_data]`, where `auth_length` in the header counts only `auth_data`.
//! For Netlogon integrity, `auth_data` is the 48-byte `NL_AUTH_SHA2_SIGNATURE`
//! computed over the stub — see [`crate::netlogon::sign_integrity_aes`].

use crate::netlogon::{seal_response_aes, sign_integrity_aes};
use crate::pdu::{build_pdu_with_auth, ptype, HEADER_LEN};

/// Authentication service identifier for Netlogon (MS-RPCE §2.2.1.1.7).
pub const RPC_C_AUTHN_NETLOGON: u8 = 0x44;
/// Authentication service identifier for NTLM SSP.
pub const RPC_C_AUTHN_WINNT: u8 = 0x0A;
/// Authentication service identifier for SPNEGO/Kerberos (GSS-API).
pub const RPC_C_AUTHN_GSS_NEGOTIATE: u8 = 0x09;
/// Authentication service identifier for raw Kerberos SSP (no SPNEGO) — the framing
/// Samba's own DRSUAPI client uses for a sealed, header-signed bind.
pub const RPC_C_AUTHN_GSS_KERBEROS: u8 = 0x10;
/// Authentication level: packet integrity (signed, not sealed).
pub const RPC_C_AUTHN_LEVEL_PKT_INTEGRITY: u8 = 5;
/// Authentication level: packet privacy (signed and sealed/encrypted).
pub const RPC_C_AUTHN_LEVEL_PKT_PRIVACY: u8 = 6;
/// The auth context id we use (a single security context per connection).
const AUTH_CTX_ID: u32 = 0;

/// The parsed 8-byte `sec_trailer`.
pub struct SecTrailer {
    pub auth_type: u8,
    pub auth_level: u8,
    pub auth_pad_len: u8,
}

impl SecTrailer {
    /// Parse the trailer from its 8 bytes.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        (buf.len() >= 8).then(|| Self {
            auth_type: buf[0],
            auth_level: buf[1],
            auth_pad_len: buf[2],
        })
    }

    /// Serialize a `sec_trailer` for the given auth service, level and pad.
    fn trailer(auth_type: u8, auth_level: u8, auth_pad_len: u8) -> [u8; 8] {
        let mut out = [0u8; 8];
        out[0] = auth_type;
        out[1] = auth_level;
        out[2] = auth_pad_len;
        out[4..8].copy_from_slice(&AUTH_CTX_ID.to_le_bytes());
        out
    }
}

/// The `auth_level` a client negotiated on an authenticated PDU, read from the
/// `sec_trailer` that precedes the auth data.
pub fn negotiated_auth_level(body: &[u8], auth_length: usize) -> Option<u8> {
    let trailer_start = body.len().checked_sub(auth_length + 8)?;
    SecTrailer::parse(&body[trailer_start..trailer_start + 8]).map(|t| t.auth_level)
}

/// The `auth_type` (SSP identifier) a client negotiated on an authenticated PDU.
pub fn negotiated_auth_type(body: &[u8], auth_length: usize) -> Option<u8> {
    let trailer_start = body.len().checked_sub(auth_length + 8)?;
    SecTrailer::parse(&body[trailer_start..trailer_start + 8]).map(|t| t.auth_type)
}

/// The `auth_context_id` a client set in its `sec_trailer`. A DCE-style GSS bind
/// correlates the multi-leg handshake by this id, so the BIND_ACK / ALTER_CONTEXT
/// response must echo it (Samba's DRS client uses 1 and rejects a mismatch).
pub fn negotiated_auth_ctx_id(body: &[u8], auth_length: usize) -> Option<u32> {
    let trailer_start = body.len().checked_sub(auth_length + 8)?;
    let bytes = body.get(trailer_start + 4..trailer_start + 8)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

/// The auth token (SSP data) at the end of an authenticated PDU body.
pub fn auth_token(body: &[u8], auth_length: usize) -> Option<&[u8]> {
    body.get(body.len().checked_sub(auth_length)?..)
}

/// The `NL_AUTH_MESSAGE` a server returns to acknowledge a Netlogon binding:
/// MessageType = RESPONSE(1), Flags = 0, Buffer = 4 zero bytes.
pub fn nl_auth_message_response() -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&1u32.to_le_bytes()); // NL_AUTH_MESSAGE_RESPONSE
    out.extend_from_slice(&0u32.to_le_bytes()); // Flags
    out.extend_from_slice(&[0u8; 4]); // Buffer
    out
}

/// The parsed view of an authenticated REQUEST: its context id, opnum, protection
/// level, the `payload` between the request header and the `sec_trailer` (the
/// signed stub+pad for integrity, or the sealed ciphertext for privacy), the NDR
/// pad length, and the auth data (signature) the client sent.
pub struct SignedRequest<'a> {
    pub context_id: u16,
    pub opnum: u16,
    pub auth_type: u8,
    pub auth_level: u8,
    pub auth_pad_len: usize,
    pub payload: &'a [u8],
    pub signature: &'a [u8],
}

impl SignedRequest<'_> {
    /// The stub with the trailing NDR alignment pad removed (integrity path,
    /// where `payload` is already plaintext).
    pub fn unpadded_stub(&self) -> Option<&[u8]> {
        let end = self.payload.len().checked_sub(self.auth_pad_len)?;
        self.payload.get(..end)
    }
}

/// Split an authenticated REQUEST body into its fields. `auth_length` is from the
/// common header. Layout: `[alloc_hint 4][cont_id 2][opnum 2][payload][sec_trailer
/// 8][auth_data]`, where `payload` is stub+pad (integrity) or ciphertext (privacy).
pub fn parse_signed_request(body: &[u8], auth_length: usize) -> Option<SignedRequest<'_>> {
    let trailer_start = body.len().checked_sub(auth_length + 8)?;
    if trailer_start < 8 {
        return None;
    }
    let sec_trailer = SecTrailer::parse(&body[trailer_start..trailer_start + 8])?;
    Some(SignedRequest {
        context_id: u16::from_le_bytes([body[4], body[5]]),
        opnum: u16::from_le_bytes([body[6], body[7]]),
        auth_type: sec_trailer.auth_type,
        auth_level: sec_trailer.auth_level,
        auth_pad_len: sec_trailer.auth_pad_len as usize,
        payload: &body[8..trailer_start],
        signature: &body[body.len() - auth_length..],
    })
}

/// Assemble a RESPONSE PDU whose `pdu_data` is followed by a `sec_trailer` (at
/// `auth_level`, recording `pad`) and the auth data. The whole PDU is padded to a
/// 4-byte boundary before the trailer.
fn build_auth_response(
    call_id: u32,
    context_id: u16,
    pdu_data: &[u8],
    auth_level: u8,
    pad: usize,
    auth_data: &[u8],
) -> Vec<u8> {
    build_auth_response_typed(
        call_id,
        context_id,
        pdu_data,
        RPC_C_AUTHN_NETLOGON,
        auth_level,
        pad,
        auth_data,
    )
}

/// Like [`build_auth_response`] but for an arbitrary auth service (e.g. NTLM).
#[allow(clippy::too_many_arguments)]
pub fn build_auth_response_typed(
    call_id: u32,
    context_id: u16,
    pdu_data: &[u8],
    auth_type: u8,
    auth_level: u8,
    pad: usize,
    auth_data: &[u8],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + pdu_data.len() + 8 + auth_data.len());
    body.extend_from_slice(&(pdu_data.len() as u32).to_le_bytes()); // alloc_hint
    body.extend_from_slice(&context_id.to_le_bytes());
    body.push(0); // cancel_count
    body.push(0); // reserved
    body.extend_from_slice(pdu_data);
    body.extend_from_slice(&SecTrailer::trailer(auth_type, auth_level, pad as u8));
    body.extend_from_slice(auth_data);
    build_pdu_with_auth(ptype::RESPONSE, call_id, &body, auth_data.len() as u16)
}

/// The NDR pad + padded plaintext for a RESPONSE `stub` (public so callers that
/// sign with an external SSP can compute the exact bytes that get signed).
pub fn padded_response_stub(stub: &[u8]) -> (Vec<u8>, usize) {
    let pad = response_pad(stub.len());
    let mut plain = Vec::with_capacity(stub.len() + pad);
    plain.extend_from_slice(stub);
    plain.extend(std::iter::repeat_n(0u8, pad));
    (plain, pad)
}

/// The NDR pad needed so a RESPONSE stub of `stub_len` bytes leaves the
/// `sec_trailer` 4-aligned. The common header (16) + response header (8) are both
/// 4-aligned, so only the stub length matters.
fn response_pad(stub_len: usize) -> usize {
    (4 - (HEADER_LEN + 8 + stub_len) % 4) % 4
}

/// Build a signed (PKT_INTEGRITY) RESPONSE carrying `stub`, signed under
/// `session_key` at `sequence`. The signature covers the padded stub, matching
/// the sender's `plain_data = stub ‖ pad`.
pub fn build_signed_response(
    call_id: u32,
    context_id: u16,
    stub: &[u8],
    session_key: &[u8; 16],
    sequence: u64,
) -> Vec<u8> {
    let pad = response_pad(stub.len());
    let mut plain = Vec::with_capacity(stub.len() + pad);
    plain.extend_from_slice(stub);
    plain.extend(std::iter::repeat_n(0u8, pad));
    let signature = sign_integrity_aes(session_key, &plain, sequence);
    build_auth_response(
        call_id,
        context_id,
        &plain,
        RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
        pad,
        &signature,
    )
}

/// Build a sealed (PKT_PRIVACY) RESPONSE carrying `stub`, encrypted and signed
/// under `session_key` at `sequence`. The `pdu_data` is the ciphertext of the
/// padded stub; the 56-byte signature carries the encrypted confounder.
pub fn build_sealed_response(
    call_id: u32,
    context_id: u16,
    stub: &[u8],
    session_key: &[u8; 16],
    sequence: u64,
) -> Vec<u8> {
    let pad = response_pad(stub.len());
    let mut plain = Vec::with_capacity(stub.len() + pad);
    plain.extend_from_slice(stub);
    plain.extend(std::iter::repeat_n(0xBBu8, pad));
    let (ciphertext, signature) = seal_response_aes(session_key, &plain, sequence);
    build_auth_response(
        call_id,
        context_id,
        &ciphertext,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        pad,
        &signature,
    )
}
