//! SMB2 compression (MS-SMB2 §2.2.42 / MS-XCA §2.4): the "Plain LZ77" algorithm
//! plus the `SMB2_COMPRESSION_TRANSFORM_HEADER` (`\xFCSMB`) that wraps a
//! compressed message. impacket only *negotiates* compression (no compress /
//! decompress code), so the transform + algorithm are unit-validated here; the
//! server decompresses inbound compressed requests but never compresses replies.

/// `SMB2_COMPRESSION_TRANSFORM_HEADER.ProtocolId` (`\xFCSMB`).
pub(crate) const COMPRESSION_PROTOCOL_ID: [u8; 4] = [0xFC, 0x53, 0x4D, 0x42];
/// Fixed size of the (unchained) compression transform header.
const TRANSFORM_HEADER_LEN: usize = 16;
/// MS-XCA compression algorithm id for plain LZ77.
pub(crate) const COMPRESSION_ALGORITHM_LZ77: u16 = 0x0002;
/// Longest match our compressor emits (keeps the length in the 3-bit inline
/// field, so no extended-length encoding is produced — decompression still
/// accepts any length).
const MAX_MATCH: usize = 9;
/// Largest back-reference distance (the offset field is 13 bits).
const MAX_OFFSET: usize = 8192;
/// Hard ceiling on a decompressed message (matches the 16 MiB SMB frame cap in the
/// server). Bounds the memory a compressed request can expand to, defeating a
/// decompression bomb whose declared/back-referenced length is enormous.
const MAX_DECOMPRESSED: usize = 16 * 1024 * 1024;

/// Compress `input` with plain LZ77 (MS-XCA §2.4). A greedy matcher that only
/// emits short matches, so the two-byte token never needs the extended-length
/// escape — the output is still a valid stream any MS-XCA decoder accepts.
pub(crate) fn lz77_compress(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut flags: u32 = 0;
    let mut count: u32 = 0;
    let mut group: Vec<u8> = Vec::new();
    let mut i = 0usize;

    while i < input.len() {
        let (length, offset) = find_match(input, i);
        if length >= 3 {
            flags = (flags << 1) | 1;
            let meta = (((offset - 1) as u16) << 3) | ((length - 3) as u16);
            group.extend_from_slice(&meta.to_le_bytes());
            i += length;
        } else {
            flags <<= 1;
            group.push(input[i]);
            i += 1;
        }
        count += 1;
        if count == 32 {
            out.extend_from_slice(&flags.to_le_bytes());
            out.extend_from_slice(&group);
            flags = 0;
            count = 0;
            group.clear();
        }
    }
    if count > 0 {
        // Left-align the partial group so token 0 stays at bit 31.
        flags <<= 32 - count;
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&group);
    }
    out
}

/// The longest match (capped at [`MAX_MATCH`]) for `input[pos..]` within the
/// preceding [`MAX_OFFSET`] bytes; `(0, 0)` if shorter than 3.
fn find_match(input: &[u8], pos: usize) -> (usize, usize) {
    let max_len = (input.len() - pos).min(MAX_MATCH);
    if max_len < 3 {
        return (0, 0);
    }
    let (mut best_len, mut best_off) = (0usize, 0usize);
    for off in 1..=pos.min(MAX_OFFSET) {
        let start = pos - off;
        let mut len = 0;
        while len < max_len && input[start + len] == input[pos + len] {
            len += 1;
        }
        if len > best_len {
            best_len = len;
            best_off = off;
            if len == max_len {
                break;
            }
        }
    }
    if best_len >= 3 {
        (best_len, best_off)
    } else {
        (0, 0)
    }
}

/// Decompress a plain-LZ77 stream (MS-XCA §2.4.1), handling the full extended
/// length encoding (shared nibble → byte → u16 → u32). `max_out` bounds the produced
/// size: a match/literal that would exceed it aborts with `None`, so a crafted stream
/// with an enormous back-reference length cannot exhaust memory (decompression bomb).
pub(crate) fn lz77_decompress(input: &[u8], max_out: usize) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let mut i = 0usize;
    let mut flags: u32 = 0;
    let mut flag_count: u32 = 0;
    let mut nibble_index: usize = 0; // input index holding a pending high nibble

    while i < input.len() {
        if flag_count == 0 {
            let bytes = input.get(i..i + 4)?;
            flags = u32::from_le_bytes(bytes.try_into().ok()?);
            i += 4;
            flag_count = 32;
        }
        flag_count -= 1;
        let is_match = flags & 0x8000_0000 != 0;
        flags <<= 1;

        if !is_match {
            if out.len() >= max_out {
                return None;
            }
            out.push(*input.get(i)?);
            i += 1;
            continue;
        }
        // A match token at end-of-input is the terminating sentinel.
        if i + 2 > input.len() {
            break;
        }
        let meta = u16::from_le_bytes(input.get(i..i + 2)?.try_into().ok()?);
        i += 2;
        let offset = (meta >> 3) as usize + 1;
        let mut length = (meta & 0x07) as usize;
        if length == 7 {
            if nibble_index == 0 {
                length = (*input.get(i)? & 0x0F) as usize;
                nibble_index = i;
                i += 1;
            } else {
                length = (input[nibble_index] >> 4) as usize;
                nibble_index = 0;
            }
            if length == 15 {
                length = *input.get(i)? as usize;
                i += 1;
                if length == 255 {
                    length = u16::from_le_bytes(input.get(i..i + 2)?.try_into().ok()?) as usize;
                    i += 2;
                    if length == 0 {
                        length = u32::from_le_bytes(input.get(i..i + 4)?.try_into().ok()?) as usize;
                        i += 4;
                    }
                    length = length.checked_sub(15 + 7)?;
                }
                length += 15;
            }
            length += 7;
        }
        length += 3;
        if offset > out.len() {
            return None;
        }
        // Reject a back-reference that would grow the output past the cap.
        if out.len().checked_add(length)? > max_out {
            return None;
        }
        for _ in 0..length {
            out.push(out[out.len() - offset]);
        }
    }
    Some(out)
}

/// Decode an `SMB2_COMPRESSION_TRANSFORM_HEADER`-wrapped message back to the full
/// plaintext SMB2 message (`uncompressed prefix ‖ decompress(rest)`).
pub(crate) fn decompress_message(transform: &[u8]) -> Option<Vec<u8>> {
    if transform.len() < TRANSFORM_HEADER_LEN || transform[0..4] != COMPRESSION_PROTOCOL_ID {
        return None;
    }
    let original_size = u32::from_le_bytes(transform.get(4..8)?.try_into().ok()?) as usize;
    let algorithm = u16::from_le_bytes(transform.get(8..10)?.try_into().ok()?);
    let offset = u32::from_le_bytes(transform.get(12..16)?.try_into().ok()?) as usize;
    if algorithm != COMPRESSION_ALGORITHM_LZ77 {
        return None;
    }
    // A legitimate SMB message never exceeds the frame cap; reject a bogus huge target
    // before decompressing so a tiny packet can't declare a multi-GB expansion.
    if original_size > MAX_DECOMPRESSED {
        return None;
    }
    let payload = &transform[TRANSFORM_HEADER_LEN..];
    let prefix = payload.get(..offset)?;
    let compressed = payload.get(offset..)?;
    let mut out = prefix.to_vec();
    // The decompressed part must fit within `original_size` (checked exactly below).
    out.extend_from_slice(&lz77_decompress(
        compressed,
        original_size.saturating_sub(prefix.len()),
    )?);
    (out.len() == original_size).then_some(out)
}

/// Wrap a plaintext SMB2 message in an LZ77 `SMB2_COMPRESSION_TRANSFORM_HEADER`
/// (fully compressed, `Offset` = 0).
pub(crate) fn compress_message(plaintext: &[u8]) -> Vec<u8> {
    let compressed = lz77_compress(plaintext);
    let mut out = Vec::with_capacity(TRANSFORM_HEADER_LEN + compressed.len());
    out.extend_from_slice(&COMPRESSION_PROTOCOL_ID);
    out.extend_from_slice(&(plaintext.len() as u32).to_le_bytes()); // OriginalCompressedSegmentSize
    out.extend_from_slice(&COMPRESSION_ALGORITHM_LZ77.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // Flags
    out.extend_from_slice(&0u32.to_le_bytes()); // Offset_Length = 0 (nothing uncompressed)
    out.extend_from_slice(&compressed);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_only_stream_is_flags_then_bytes() {
        // "abc" has no 3-byte back-reference → three literals under a zero flags word.
        assert_eq!(lz77_compress(b"abc"), vec![0, 0, 0, 0, b'a', b'b', b'c']);
    }

    #[test]
    fn round_trips_varied_inputs() {
        let cases: &[&[u8]] = &[
            b"",
            b"a",
            b"abcabcabcabcabcabc",
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"the quick brown fox jumps over the lazy dog, the quick brown fox",
            &[0u8; 200],
        ];
        for &c in cases {
            let round = lz77_decompress(&lz77_compress(c), 1 << 20).expect("decompress");
            assert_eq!(round, c, "round-trip failed for {c:?}");
        }
    }

    #[test]
    fn decompress_rejects_output_past_cap() {
        // A run that legitimately expands to 4096 bytes decompresses with a generous cap
        // but is rejected when the cap is below the produced size (bomb guard).
        let data = vec![0x5au8; 4096];
        let compressed = lz77_compress(&data);
        assert!(lz77_decompress(&compressed, 4096).is_some());
        assert!(lz77_decompress(&compressed, 1024).is_none());
    }

    #[test]
    fn transform_wraps_and_unwraps() {
        let mut msg = vec![0u8; 128];
        msg[0..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
        msg[64..96].fill(0x41); // a compressible run
        let wrapped = compress_message(&msg);
        assert_eq!(&wrapped[0..4], &COMPRESSION_PROTOCOL_ID);
        assert!(wrapped.len() < msg.len(), "the run should compress");
        assert_eq!(
            decompress_message(&wrapped).as_deref(),
            Some(msg.as_slice())
        );
    }
}
