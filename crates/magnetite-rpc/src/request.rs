//! REQUEST / RESPONSE / FAULT PDUs (MS-RPCE §2.2.2.13, §2.2.2.14, §2.2.2.5).
//!
//! A REQUEST names a presentation context and an `opnum`, followed by the
//! NDR-marshalled `[in]` arguments (the "stub data"). We dispatch on the opnum
//! and return either a RESPONSE (marshalled `[out]` values) or a FAULT.

use crate::error::RpcResult;
use crate::pdu::{build_pdu, pfc, ptype, CommonHeader, Reader};

/// A parsed REQUEST body.
pub struct Request<'a> {
    pub context_id: u16,
    pub opnum: u16,
    /// The NDR-marshalled `[in]` arguments.
    pub stub: &'a [u8],
}

impl<'a> Request<'a> {
    /// Parse a REQUEST body, honouring the object-uuid header flag.
    pub fn parse(header: &CommonHeader, body: &'a [u8]) -> RpcResult<Self> {
        let mut r = Reader::new(body);
        let _alloc_hint = r.u32()?;
        let context_id = r.u16()?;
        let opnum = r.u16()?;
        if header.pfc_flags & pfc::OBJECT_UUID != 0 {
            r.skip(16)?; // an object UUID precedes the stub when the flag is set
        }
        Ok(Self {
            context_id,
            opnum,
            stub: r.rest(),
        })
    }
}

/// Build a RESPONSE carrying `stub` (the marshalled `[out]` values).
pub fn build_response(call_id: u32, context_id: u16, stub: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + stub.len());
    body.extend_from_slice(&(stub.len() as u32).to_le_bytes()); // alloc_hint
    body.extend_from_slice(&context_id.to_le_bytes());
    body.push(0); // cancel_count
    body.push(0); // reserved
    body.extend_from_slice(stub);
    build_pdu(ptype::RESPONSE, call_id, &body)
}

/// Build a FAULT with the given status (e.g. `nca_s_op_rng_error`).
pub fn build_fault(call_id: u32, context_id: u16, status: u32) -> Vec<u8> {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&0u32.to_le_bytes()); // alloc_hint
    body.extend_from_slice(&context_id.to_le_bytes());
    body.push(0); // cancel_count
    body.push(0); // reserved
    body.extend_from_slice(&status.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes()); // reserved2 / padding
    build_pdu(ptype::FAULT, call_id, &body)
}

/// Common NCA fault status codes.
pub mod fault {
    /// The requested opnum is out of range for the interface.
    pub const OP_RNG_ERROR: u32 = 0x1C01_0002;
    /// The stub could not be unmarshalled.
    pub const NDR: u32 = 0x0000_06F7;
    /// `nca_s_fault_access_denied` — the caller is not authorized for the operation.
    pub const ACCESS_DENIED: u32 = 0x0000_0005;
}
