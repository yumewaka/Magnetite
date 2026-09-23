//! A minimal little-endian NDR writer for marshalling RPC `[out]` values.
//!
//! Same shape as the one in `magnetite-krb5` (a candidate to extract into a
//! shared crate later). NDR rules honoured here: primitive alignment (a field of
//! size N starts on an N-aligned offset), and the caller drives the
//! "primitives first, then deferred referents" ordering that impacket's NDR
//! engine expects.

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

    /// Consume and return the marshalled bytes.
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
}

/// A little-endian NDR reader for parsing `[in]` request stubs. Enough to walk
/// over the pointer/string prologue of MS-NRPC requests to reach fixed fields.
pub struct NdrReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> NdrReader<'a> {
    /// A reader at the start of `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// The current byte offset into the buffer.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Advance to the next `align`-aligned offset.
    pub fn align(&mut self, align: usize) {
        while !self.pos.is_multiple_of(align) {
            self.pos += 1;
        }
    }

    /// Read `n` raw bytes (aligned to 1).
    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Some(s)
    }

    /// Read a `u8` (aligned to 1).
    pub fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    /// Read an aligned little-endian `u16`.
    pub fn u16(&mut self) -> Option<u16> {
        self.align(2);
        let s = self.take(2)?;
        Some(u16::from_le_bytes([s[0], s[1]]))
    }

    /// Read an aligned little-endian `u32`.
    pub fn u32(&mut self) -> Option<u32> {
        self.align(4);
        let s = self.take(4)?;
        Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    /// The unread remainder of the buffer (used to reach a trailing fixed-size
    /// `[in]` argument such as an encrypted password blob).
    pub fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    /// Read a fixed-size byte field into an array.
    pub fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        let s = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Some(out)
    }

    /// Skip a conformant+varying wide-char array (`WSTR`): MaxCount, Offset,
    /// ActualCount, then the characters.
    pub fn skip_wstr(&mut self) -> Option<()> {
        self.align(4);
        let _max = self.u32()?;
        let _off = self.u32()?;
        let actual = self.u32()? as usize;
        self.take(actual.checked_mul(2)?)?;
        Some(())
    }

    /// Read a conformant+varying wide-char array (`WSTR`) as a `String`, decoding
    /// the UTF-16LE characters and dropping a trailing NUL.
    pub fn read_wstr(&mut self) -> Option<String> {
        self.align(4);
        let _max = self.u32()?;
        let _off = self.u32()?;
        let actual = self.u32()? as usize;
        let bytes = self.take(actual.checked_mul(2)?)?;
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        let s = String::from_utf16_lossy(&units);
        Some(s.trim_end_matches('\0').to_string())
    }

    /// Skip a `[unique]` pointer to a wide-char string: a referent id and, if
    /// non-null, the string inline.
    pub fn skip_unique_wstr(&mut self) -> Option<()> {
        let referent = self.u32()?;
        if referent != 0 {
            self.skip_wstr()?;
        }
        Some(())
    }
}
