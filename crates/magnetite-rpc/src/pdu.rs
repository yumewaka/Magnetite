//! Connection-oriented RPC PDUs (DCE 1.1 / MS-RPCE §2.2): the 16-byte common
//! header, packet types, and a little-endian reader/builder.
//!
//! Every PDU begins with the common header; the body that follows depends on the
//! packet type (BIND, REQUEST, …). We only speak RPC version 5.0 with the
//! little-endian NDR data representation, which is what Windows and impacket use.

use crate::error::{RpcError, RpcResult};

/// RPC protocol version (major/minor) we implement.
pub const RPC_VERS: u8 = 5;
pub const RPC_VERS_MINOR: u8 = 0;

/// The common header length in bytes.
pub const HEADER_LEN: usize = 16;

/// PDU packet types (`PTYPE`, MS-RPCE §2.2.2.3).
pub mod ptype {
    pub const REQUEST: u8 = 0;
    pub const RESPONSE: u8 = 2;
    pub const FAULT: u8 = 3;
    pub const BIND: u8 = 11;
    pub const BIND_ACK: u8 = 12;
    pub const BIND_NAK: u8 = 13;
    pub const AUTH3: u8 = 16;
    pub const ALTER_CONTEXT: u8 = 14;
    pub const ALTER_CONTEXT_RESP: u8 = 15;
}

/// `pfc_flags` bits (MS-RPCE §2.2.2.3).
pub mod pfc {
    pub const FIRST_FRAG: u8 = 0x01;
    pub const LAST_FRAG: u8 = 0x02;
    /// `PFC_SUPPORT_HEADER_SIGN` — the client offers DCE/RPC header signing in its
    /// BIND; when the acceptor echoes it, each protected PDU's checksum also covers
    /// the PDU header + `sec_trailer` (SIGN_ONLY associated data).
    pub const SUPPORT_HEADER_SIGN: u8 = 0x04;
    pub const OBJECT_UUID: u8 = 0x80;
}

/// Data representation for little-endian, ASCII, IEEE float (`packed_drep`).
pub const DREP_LITTLE_ENDIAN: [u8; 4] = [0x10, 0x00, 0x00, 0x00];

/// Wire bytes of the NDR 2.0 transfer syntax UUID
/// (`8a885d04-1ceb-11c9-9fe8-08002b104860`), first three fields little-endian.
pub const NDR32_UUID: [u8; 16] = [
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
];
/// NDR 2.0 transfer syntax version (major 2, minor 0).
pub const NDR32_VERSION: u32 = 2;

/// The parsed common header.
#[derive(Debug, Clone, Copy)]
pub struct CommonHeader {
    pub ptype: u8,
    pub pfc_flags: u8,
    pub frag_length: u16,
    pub auth_length: u16,
    pub call_id: u32,
}

impl CommonHeader {
    /// Parse the 16-byte common header from the front of `buf`.
    pub fn parse(buf: &[u8]) -> RpcResult<Self> {
        if buf.len() < HEADER_LEN {
            return Err(RpcError::Truncated);
        }
        if buf[0] != RPC_VERS {
            return Err(RpcError::Version(buf[0]));
        }
        Ok(Self {
            ptype: buf[2],
            pfc_flags: buf[3],
            frag_length: u16::from_le_bytes([buf[8], buf[9]]),
            auth_length: u16::from_le_bytes([buf[10], buf[11]]),
            call_id: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
        })
    }
}

/// Assemble a complete PDU: the common header (with `frag_length` computed) plus
/// `body`. `FIRST_FRAG | LAST_FRAG` is always set — this PoC does not fragment.
pub fn build_pdu(ptype: u8, call_id: u32, body: &[u8]) -> Vec<u8> {
    build_pdu_with_auth(ptype, call_id, body, 0)
}

/// The 16-byte DCE/RPC common header. Exposed so the DCE/RPC header-signing path
/// can reproduce the exact on-wire header bytes as SIGN_ONLY associated data.
pub fn common_header(
    ptype: u8,
    pfc_flags: u8,
    frag_length: u16,
    auth_length: u16,
    call_id: u32,
) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0] = RPC_VERS;
    h[1] = RPC_VERS_MINOR;
    h[2] = ptype;
    h[3] = pfc_flags;
    h[4..8].copy_from_slice(&DREP_LITTLE_ENDIAN);
    h[8..10].copy_from_slice(&frag_length.to_le_bytes());
    h[10..12].copy_from_slice(&auth_length.to_le_bytes());
    h[12..16].copy_from_slice(&call_id.to_le_bytes());
    h
}

/// Like [`build_pdu`], but sets the `auth_length` header field. `body` must
/// already include the trailing `[sec_trailer][auth_data]`; `auth_length` counts
/// only the `auth_data` bytes.
pub fn build_pdu_with_auth(ptype: u8, call_id: u32, body: &[u8], auth_length: u16) -> Vec<u8> {
    build_pdu_with_auth_pfc(
        ptype,
        pfc::FIRST_FRAG | pfc::LAST_FRAG,
        call_id,
        body,
        auth_length,
    )
}

/// Like [`build_pdu_with_auth`], but with explicit `pfc_flags` (e.g. to advertise
/// `PFC_SUPPORT_HEADER_SIGN` on a BIND).
pub fn build_pdu_with_auth_pfc(
    ptype: u8,
    pfc_flags: u8,
    call_id: u32,
    body: &[u8],
    auth_length: u16,
) -> Vec<u8> {
    let frag_length = (HEADER_LEN + body.len()) as u16;
    let header = common_header(ptype, pfc_flags, frag_length, auth_length, call_id);
    let mut out = Vec::with_capacity(frag_length as usize);
    out.extend_from_slice(&header);
    out.extend_from_slice(body);
    out
}

/// A little-endian cursor over a PDU body.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A reader positioned at the start of `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Read `n` raw bytes.
    pub fn take(&mut self, n: usize) -> RpcResult<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(RpcError::Truncated)?;
        if end > self.buf.len() {
            return Err(RpcError::Truncated);
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// Skip `n` bytes.
    pub fn skip(&mut self, n: usize) -> RpcResult<()> {
        self.take(n).map(|_| ())
    }

    /// Read a `u8`.
    pub fn u8(&mut self) -> RpcResult<u8> {
        Ok(self.take(1)?[0])
    }

    /// Read a little-endian `u16`.
    pub fn u16(&mut self) -> RpcResult<u16> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }

    /// Read a little-endian `u32`.
    pub fn u32(&mut self) -> RpcResult<u32> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    /// The not-yet-consumed remainder.
    pub fn rest(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }
}
