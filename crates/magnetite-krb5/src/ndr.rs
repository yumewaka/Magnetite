//! A minimal little-endian NDR (MS-RPCE) writer — just enough to marshal the
//! PAC's `KERB_VALIDATION_INFO` (MS-PAC §2.5) in "Type Serialization 1" form.
//!
//! NDR rules we implement: primitive alignment (a field of size N starts on an
//! N-aligned offset, padded with zeros), top-level/embedded pointers as 4-byte
//! referent ids (0 = null), and the "referents are emitted after the containing
//! structure, in declaration order" deferral. This is the miniature of the full
//! DCE/RPC NDR marshaller that a complete DC would need.

/// A growable NDR output buffer with alignment helpers.
#[derive(Default)]
pub struct NdrWriter {
    buf: Vec<u8>,
}

impl NdrWriter {
    /// A fresh, empty writer.
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Consume the writer and return the marshalled bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Pad with zeros until the length is a multiple of `align`.
    pub fn align(&mut self, align: usize) {
        while !self.buf.len().is_multiple_of(align) {
            self.buf.push(0);
        }
    }

    /// Append raw bytes (no alignment).
    pub fn bytes(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Write a `u8`.
    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Write an aligned little-endian `u16`.
    pub fn u16(&mut self, v: u16) {
        self.align(2);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write an aligned little-endian `u32`.
    pub fn u32(&mut self, v: u32) {
        self.align(4);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write an aligned little-endian `u64`.
    pub fn u64(&mut self, v: u64) {
        self.align(8);
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Write a Windows `FILETIME` (a 64-bit value split into low/high `u32`s,
    /// each 4-aligned — i.e. NOT a single 8-aligned `u64`).
    pub fn filetime(&mut self, ticks: u64) {
        self.u32((ticks & 0xffff_ffff) as u32);
        self.u32((ticks >> 32) as u32);
    }
}

/// Convert a Unix timestamp (seconds) to a Windows `FILETIME` (100 ns ticks
/// since 1601-01-01).
pub fn unix_to_filetime(unix_secs: i64) -> u64 {
    // 11644473600 = seconds between 1601-01-01 and 1970-01-01.
    ((unix_secs + 11_644_473_600) as u64) * 10_000_000
}

/// The "never expires" sentinel FILETIME used by AD for logoff/kickoff/etc.
pub const FILETIME_NEVER: u64 = 0x7fff_ffff_ffff_ffff;
