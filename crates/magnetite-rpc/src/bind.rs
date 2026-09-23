//! BIND negotiation (MS-RPCE §2.2.2.10–13).
//!
//! The client's BIND proposes one or more *presentation contexts*, each pairing
//! an abstract syntax (the interface UUID/version it wants to call) with one or
//! more transfer syntaxes (how arguments are marshalled). We accept any interface
//! (this PoC dispatches purely by opnum) as long as a context offers NDR 2.0, and
//! reply with a BIND_ACK carrying a per-context result.

use crate::error::RpcResult;
use crate::pdu::{build_pdu, ptype, Reader, NDR32_UUID, NDR32_VERSION};

/// A presentation context proposed in a BIND.
pub struct ContextRequest {
    pub context_id: u16,
    /// Offered transfer syntaxes as (uuid, version).
    pub transfer_syntaxes: Vec<([u8; 16], u32)>,
}

/// A parsed BIND (or ALTER_CONTEXT) body.
pub struct BindRequest {
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group_id: u32,
    pub contexts: Vec<ContextRequest>,
}

impl BindRequest {
    /// Parse a BIND body (everything after the 16-byte common header).
    pub fn parse(body: &[u8]) -> RpcResult<Self> {
        let mut r = Reader::new(body);
        let max_xmit_frag = r.u16()?;
        let max_recv_frag = r.u16()?;
        let assoc_group_id = r.u32()?;

        let n_context = r.u8()?;
        r.skip(3)?; // reserved (u8) + reserved2 (u16)

        let mut contexts = Vec::with_capacity(n_context as usize);
        for _ in 0..n_context {
            let context_id = r.u16()?;
            let n_transfer = r.u8()?;
            r.skip(1)?; // reserved
                        // Abstract syntax (interface) — we accept any, so just skip it.
            r.skip(16 + 4)?;
            let mut transfer_syntaxes = Vec::with_capacity(n_transfer as usize);
            for _ in 0..n_transfer {
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(r.take(16)?);
                let version = r.u32()?;
                transfer_syntaxes.push((uuid, version));
            }
            contexts.push(ContextRequest {
                context_id,
                transfer_syntaxes,
            });
        }

        Ok(Self {
            max_xmit_frag,
            max_recv_frag,
            assoc_group_id,
            contexts,
        })
    }
}

/// Negotiated maximum fragment size we advertise.
const MAX_FRAG: u16 = 5840;
/// A non-zero association group id (the client uses this to correlate the assoc).
const ASSOC_GROUP_ID: u32 = 0x4d41_474e; // "MAGN"

/// Per-context result codes (MS-RPCE §2.2.2.4).
const RESULT_ACCEPTANCE: u16 = 0;
const RESULT_PROVIDER_REJECTION: u16 = 2;
const REASON_NONE: u16 = 0;
const REASON_TRANSFER_NOT_SUPPORTED: u16 = 2;

/// Build a BIND_ACK for `req`. Each context that offered NDR 2.0 is accepted; any
/// other is rejected with "transfer syntaxes not supported". `sec_addr` is the
/// secondary address string (the listening port for `ncacn_ip_tcp`).
pub fn build_bind_ack(call_id: u32, req: &BindRequest, sec_addr: &str) -> Vec<u8> {
    build_pdu(ptype::BIND_ACK, call_id, &bind_ack_body(req, sec_addr))
}

/// Build an ALTER_CONTEXT_RESP with **no auth trailer** (`auth_length` = 0). This is
/// the leg-4 completion of a DCE-style GSS handshake: after the client's leg-3
/// (an ALTER_CONTEXT carrying its final AP-REP), the acceptor's GSS context is
/// COMPLETE with an empty output token, so the response carries only the presentation
/// result list. (A `sec_trailer` with `auth_length` = 0 is malformed — a strict client
/// like Samba rejects it with `RPC_PROTOCOL_ERROR`.)
pub fn build_alter_context_resp_noauth(
    call_id: u32,
    req: &BindRequest,
    _sec_addr: &str,
) -> Vec<u8> {
    // ALTER_CONTEXT_RESP carries an empty secondary address.
    build_pdu(ptype::ALTER_CONTEXT_RESP, call_id, &bind_ack_body(req, ""))
}

/// Build an ALTER_CONTEXT_RESP (the authenticated-binding leg): the same result
/// list as a BIND_ACK, followed by a `sec_trailer` + `auth_data` token.
pub fn build_alter_context_resp(
    call_id: u32,
    req: &BindRequest,
    sec_addr: &str,
    auth_type: u8,
    auth_level: u8,
    auth_ctx_id: u32,
    auth_data: &[u8],
) -> Vec<u8> {
    build_authed_bind(
        ptype::ALTER_CONTEXT_RESP,
        call_id,
        req,
        sec_addr,
        auth_type,
        auth_level,
        auth_ctx_id,
        auth_data,
    )
}

/// Build a BIND_ACK carrying an auth token (e.g. the NTLM CHALLENGE, or a Kerberos
/// AP-REP). `auth_ctx_id` echoes the client's `sec_trailer` context id — a DCE-style
/// GSS bind (Samba's DRS) correlates its legs by it and rejects a mismatch.
pub fn build_bind_ack_with_auth(
    call_id: u32,
    req: &BindRequest,
    sec_addr: &str,
    auth_type: u8,
    auth_level: u8,
    auth_ctx_id: u32,
    auth_data: &[u8],
) -> Vec<u8> {
    build_authed_bind(
        ptype::BIND_ACK,
        call_id,
        req,
        sec_addr,
        auth_type,
        auth_level,
        auth_ctx_id,
        auth_data,
    )
}

/// A BIND_ACK / ALTER_CONTEXT_RESP result list plus a `sec_trailer` + auth token.
#[allow(clippy::too_many_arguments)]
fn build_authed_bind(
    ptype: u8,
    call_id: u32,
    req: &BindRequest,
    sec_addr: &str,
    auth_type: u8,
    auth_level: u8,
    auth_ctx_id: u32,
    auth_data: &[u8],
) -> Vec<u8> {
    let mut body = bind_ack_body(req, sec_addr);
    // Pad to 4 so the sec_trailer is aligned, then append it + the auth token.
    let pad = (4 - body.len() % 4) % 4;
    body.extend(std::iter::repeat_n(0u8, pad));
    body.push(auth_type);
    body.push(auth_level);
    body.push(pad as u8);
    body.push(0);
    body.extend_from_slice(&auth_ctx_id.to_le_bytes()); // echo the client's context id
    body.extend_from_slice(auth_data);
    crate::pdu::build_pdu_with_auth(ptype, call_id, &body, auth_data.len() as u16)
}

/// The BIND_ACK / ALTER_CONTEXT_RESP result-list body (without the common header).
fn bind_ack_body(req: &BindRequest, sec_addr: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&req.max_xmit_frag.min(MAX_FRAG).to_le_bytes());
    body.extend_from_slice(&req.max_recv_frag.min(MAX_FRAG).to_le_bytes());
    let assoc = if req.assoc_group_id != 0 {
        req.assoc_group_id
    } else {
        ASSOC_GROUP_ID
    };
    body.extend_from_slice(&assoc.to_le_bytes());

    // Secondary address: length-prefixed, NUL-terminated string. A BIND_ACK carries
    // the endpoint (the port); an ALTER_CONTEXT_RESP carries an EMPTY address (the
    // association is already established) — an empty `sec_addr` writes length 0.
    let addr: Vec<u8> = if sec_addr.is_empty() {
        Vec::new()
    } else {
        let mut a = sec_addr.as_bytes().to_vec();
        a.push(0);
        a
    };
    body.extend_from_slice(&(addr.len() as u16).to_le_bytes());
    body.extend_from_slice(&addr);
    // Pad to a 4-byte boundary (the header is 16 bytes, so body alignment ≡ PDU
    // alignment).
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }

    // Result list, one entry per proposed context.
    body.push(req.contexts.len() as u8);
    body.push(0); // reserved
    body.extend_from_slice(&0u16.to_le_bytes()); // reserved2
    for ctx in &req.contexts {
        let offers_ndr = ctx
            .transfer_syntaxes
            .iter()
            .any(|(uuid, ver)| *uuid == NDR32_UUID && *ver == NDR32_VERSION);
        if offers_ndr {
            body.extend_from_slice(&RESULT_ACCEPTANCE.to_le_bytes());
            body.extend_from_slice(&REASON_NONE.to_le_bytes());
            body.extend_from_slice(&NDR32_UUID);
            body.extend_from_slice(&NDR32_VERSION.to_le_bytes());
        } else {
            body.extend_from_slice(&RESULT_PROVIDER_REJECTION.to_le_bytes());
            body.extend_from_slice(&REASON_TRANSFER_NOT_SUPPORTED.to_le_bytes());
            body.extend_from_slice(&[0u8; 20]); // no agreed syntax
        }
    }

    body
}

/// Build a BIND_NAK rejecting the association (e.g. no acceptable context).
pub fn build_bind_nak(call_id: u32) -> Vec<u8> {
    // provider_reject_reason = 0 (reason_not_specified), no versions offered.
    let body = [0u16.to_le_bytes().as_slice(), &[0u8]].concat();
    build_pdu(ptype::BIND_NAK, call_id, &body)
}
