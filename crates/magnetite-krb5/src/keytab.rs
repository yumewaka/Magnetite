//! Minimal MIT keytab (`.keytab`) reader.
//!
//! A keytab is the standard on-disk store of a principal's long-term Kerberos keys —
//! how a service (or a replication account) authenticates without a cleartext password
//! in a config file. This parses the MIT **version 2** format (`0x0502`, big-endian),
//! which `ktutil`, `samba-tool domain exportkeytab`, and MIT/Heimdal all write, and
//! extracts the key for a given principal + enctype so the DRS replication agent can
//! obtain a TGT from a keytab instead of a password.
//!
//! Only reading is supported (no write); version 1 (`0x0501`, host byte order) is not
//! parsed — export a version-2 keytab, which is the modern default.

use crate::error::{KdcError, KdcResult};
use std::path::Path;

/// One keytab entry: a principal's key for a single enctype and key-version number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeytabEntry {
    /// The principal's realm (e.g. `EXAMPLE.COM`).
    pub realm: String,
    /// The principal name components (e.g. `["host", "dc1.example.com"]` or `["alice"]`).
    pub components: Vec<String>,
    /// The Kerberos name-type (`KRB5_NT_PRINCIPAL` = 1, etc.).
    pub name_type: u32,
    /// Key-version number; the highest is the current key.
    pub kvno: u32,
    /// The encryption type (e.g. `18` = AES256-CTS-HMAC-SHA1-96).
    pub etype: i32,
    /// The raw long-term key bytes.
    pub key: Vec<u8>,
}

/// A big-endian cursor over the keytab bytes that never panics on a short read.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> KdcResult<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.buf.len())
            .ok_or_else(|| KdcError::Malformed("keytab: truncated".into()))?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn u16(&mut self) -> KdcResult<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("2 bytes"),
        ))
    }

    fn i32(&mut self) -> KdcResult<i32> {
        Ok(i32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    fn u32(&mut self) -> KdcResult<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    fn u8(&mut self) -> KdcResult<u8> {
        Ok(self.take(1)?[0])
    }

    /// A `counted_octet_string`: a `u16` length then that many bytes.
    fn counted(&mut self) -> KdcResult<Vec<u8>> {
        let len = self.u16()? as usize;
        Ok(self.take(len)?.to_vec())
    }

    fn counted_str(&mut self) -> KdcResult<String> {
        String::from_utf8(self.counted()?)
            .map_err(|_| KdcError::Malformed("keytab: non-UTF-8 name component".into()))
    }
}

/// Parse a MIT version-2 keytab, returning every entry. Deleted "hole" entries (a
/// non-positive record length) are skipped.
///
/// # Errors
/// [`KdcError::Malformed`] if the magic is not `0x0502` or the byte stream is truncated.
pub fn parse_keytab(bytes: &[u8]) -> KdcResult<Vec<KeytabEntry>> {
    let mut r = Reader::new(bytes);
    let magic = r.u16()?;
    if magic != 0x0502 {
        return Err(KdcError::Malformed(format!(
            "keytab: unsupported format 0x{magic:04x} (only 0x0502 / MIT v2 is read)"
        )));
    }
    let mut entries = Vec::new();
    while r.remaining() >= 4 {
        let size = r.i32()?;
        if size <= 0 {
            // A hole (deleted entry): skip |size| bytes and continue.
            r.take(size.unsigned_abs() as usize)?;
            continue;
        }
        // Parse the record from its own slice so a `vno32` present/absent decision is
        // bounded by the declared record size, not the whole file.
        let record = r.take(size as usize)?;
        entries.push(parse_entry(record)?);
    }
    Ok(entries)
}

/// Parse one entry record (the bytes after its 4-byte length prefix).
fn parse_entry(record: &[u8]) -> KdcResult<KeytabEntry> {
    let mut r = Reader::new(record);
    let num_components = r.u16()? as usize;
    let realm = r.counted_str()?;
    let mut components = Vec::with_capacity(num_components);
    for _ in 0..num_components {
        components.push(r.counted_str()?);
    }
    let name_type = r.u32()?;
    let _timestamp = r.u32()?;
    let kvno8 = r.u8()? as u32;
    let etype = r.u16()? as i32;
    let key = r.counted()?;
    // An optional 4-byte `vno32` follows the key when the record has room for it; it
    // supersedes the 8-bit `kvno8` (which wraps at 256).
    let kvno = if r.remaining() >= 4 { r.u32()? } else { kvno8 };
    Ok(KeytabEntry {
        realm,
        components,
        name_type,
        kvno,
        etype,
        key,
    })
}

/// The key for `components@realm` at enctype `etype`, choosing the highest `kvno` when
/// several are present (the current key). Realm and components match
/// case-insensitively (Kerberos names are case-insensitive in practice for this use).
/// `None` if no matching entry exists.
pub fn find_key(
    entries: &[KeytabEntry],
    realm: &str,
    components: &[&str],
    etype: i32,
) -> Option<Vec<u8>> {
    entries
        .iter()
        .filter(|e| {
            e.etype == etype
                && e.realm.eq_ignore_ascii_case(realm)
                && e.components.len() == components.len()
                && e.components
                    .iter()
                    .zip(components)
                    .all(|(a, b)| a.eq_ignore_ascii_case(b))
        })
        .max_by_key(|e| e.kvno)
        .map(|e| e.key.clone())
}

/// Load the key for `components@realm` at enctype `etype` from a keytab file.
///
/// # Errors
/// [`KdcError::Malformed`] on an unreadable file, a bad format, or no matching entry.
pub fn load_key(path: &Path, realm: &str, components: &[&str], etype: i32) -> KdcResult<Vec<u8>> {
    let bytes = std::fs::read(path)
        .map_err(|e| KdcError::Malformed(format!("keytab: cannot read {}: {e}", path.display())))?;
    let entries = parse_keytab(&bytes)?;
    find_key(&entries, realm, components, etype).ok_or_else(|| {
        KdcError::Malformed(format!(
            "keytab: no enctype-{etype} key for {}@{realm} in {}",
            components.join("/"),
            path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::AES256_CTS_HMAC_SHA1_96;

    /// Build a minimal MIT v2 keytab with one entry (no trailing vno32).
    fn keytab_with(realm: &str, components: &[&str], etype: i32, kvno8: u8, key: &[u8]) -> Vec<u8> {
        fn counted(out: &mut Vec<u8>, data: &[u8]) {
            out.extend_from_slice(&(data.len() as u16).to_be_bytes());
            out.extend_from_slice(data);
        }
        let mut entry = Vec::new();
        entry.extend_from_slice(&(components.len() as u16).to_be_bytes());
        counted(&mut entry, realm.as_bytes());
        for c in components {
            counted(&mut entry, c.as_bytes());
        }
        entry.extend_from_slice(&1u32.to_be_bytes()); // name_type = KRB5_NT_PRINCIPAL
        entry.extend_from_slice(&0u32.to_be_bytes()); // timestamp
        entry.push(kvno8);
        entry.extend_from_slice(&(etype as u16).to_be_bytes());
        counted(&mut entry, key);

        let mut kt = vec![0x05, 0x02];
        kt.extend_from_slice(&(entry.len() as i32).to_be_bytes());
        kt.extend_from_slice(&entry);
        kt
    }

    #[test]
    fn parses_a_single_entry_and_finds_its_key() {
        let key = vec![0xABu8; 32];
        let kt = keytab_with(
            "EXAMPLE.COM",
            &["host", "dc1.example.com"],
            AES256_CTS_HMAC_SHA1_96,
            3,
            &key,
        );
        let entries = parse_keytab(&kt).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].realm, "EXAMPLE.COM");
        assert_eq!(entries[0].components, vec!["host", "dc1.example.com"]);
        assert_eq!(entries[0].kvno, 3);
        assert_eq!(entries[0].etype, AES256_CTS_HMAC_SHA1_96);

        // Case-insensitive lookup returns the key.
        let got = find_key(
            &entries,
            "example.com",
            &["HOST", "dc1.example.com"],
            AES256_CTS_HMAC_SHA1_96,
        );
        assert_eq!(got, Some(key));
        // A wrong enctype / principal misses.
        assert!(find_key(&entries, "EXAMPLE.COM", &["host", "dc1.example.com"], 17).is_none());
        assert!(find_key(
            &entries,
            "OTHER.COM",
            &["host", "dc1.example.com"],
            AES256_CTS_HMAC_SHA1_96
        )
        .is_none());
    }

    #[test]
    fn highest_kvno_wins_and_holes_are_skipped() {
        // Two entries for the same principal (kvno 1 then 5) plus a deleted hole between.
        let k1 = vec![0x11u8; 32];
        let k5 = vec![0x55u8; 32];
        let e1 = keytab_with("EX.COM", &["alice"], AES256_CTS_HMAC_SHA1_96, 1, &k1);
        let e5 = keytab_with("EX.COM", &["alice"], AES256_CTS_HMAC_SHA1_96, 5, &k5);
        // e1 already carries the 0x0502 magic; take its entry bytes (skip the 2 magic bytes).
        let mut kt = e1.clone();
        // Append a hole: a negative length then 4 bytes of filler.
        kt.extend_from_slice(&(-4i32).to_be_bytes());
        kt.extend_from_slice(&[0u8; 4]);
        // Append e5's entry (its bytes after the 2-byte magic).
        kt.extend_from_slice(&e5[2..]);

        let entries = parse_keytab(&kt).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            find_key(&entries, "EX.COM", &["alice"], AES256_CTS_HMAC_SHA1_96),
            Some(k5)
        );
    }

    #[test]
    fn rejects_wrong_magic() {
        assert!(parse_keytab(&[0x05, 0x01, 0, 0, 0, 0]).is_err());
        assert!(parse_keytab(&[0x05]).is_err());
    }
}
