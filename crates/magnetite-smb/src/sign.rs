//! SMB 3.0 message signing (MS-SMB2 §3.1.4.1): AES-128-CMAC over the whole SMB2
//! message with a signing key derived from the session key via the SP800-108
//! counter-mode KDF. SMB 2.x used HMAC-SHA256; SMB 3.0/3.0.2 switched to CMAC.

use aes::Aes128;
use cmac::Cmac;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// SMB2 header length; the signature is a 16-byte field at offset 48.
const HEADER_LEN: usize = 64;
/// Byte offset of the `Flags` (u32) field in the SMB2 header.
const FLAGS_OFFSET: usize = 16;
/// Byte offset of the 16-byte `Signature` field in the SMB2 header.
const SIGNATURE_OFFSET: usize = 48;
/// `SMB2_FLAGS_SIGNED`: set on a message whose signature is present.
pub const SMB2_FLAGS_SIGNED: u32 = 0x0000_0008;

/// SP800-108 counter-mode KDF with HMAC-SHA256. A single iteration yields the
/// 128 bits SMB 3.0 needs. Mirrors impacket's `crypto.KDF_CounterMode`, which
/// inserts a `0x00` separator between `label` and `context`. Shared by SMB 3.0
/// signing ([`smb3_signing_key`]) and encryption ([`crate::enc`]) key derivation.
pub(crate) fn kdf_counter(ki: &[u8], label: &[u8], context: &[u8], length_bits: u32) -> [u8; 16] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(ki).expect("hmac accepts any key length");
    mac.update(&1u32.to_be_bytes()); // counter i = 1
    mac.update(label);
    mac.update(&[0u8]); // separator
    mac.update(context);
    mac.update(&length_bits.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let mut key = [0u8; 16];
    key.copy_from_slice(&digest[..16]);
    key
}

/// Derive the SMB 3.0 signing key from the 16-byte session key
/// (`KDF(SessionKey, "SMB2AESCMAC\0", "SmbSign\0")`).
pub fn smb3_signing_key(session_key: &[u8; 16]) -> [u8; 16] {
    kdf_counter(session_key, b"SMB2AESCMAC\x00", b"SmbSign\x00", 128)
}

/// Derive the SMB 3.1.1 signing key (MS-SMB2 §3.1.4.2):
/// `KDF(SessionKey, "SMBSigningKey\0", PreauthIntegrityHashValue)`. 3.1.1 folds
/// the negotiate/session-setup preauth hash into the context instead of the fixed
/// `"SmbSign\0"` label 3.0 uses.
pub fn smb311_signing_key(session_key: &[u8; 16], preauth_hash: &[u8]) -> [u8; 16] {
    kdf_counter(session_key, b"SMBSigningKey\x00", preauth_hash, 128)
}

/// Derive the SMB 3.x **application key** (MS-SMB2 §3.1.4.2) — the key the SMB
/// transport hands to an application above it (e.g. DCE/RPC over `ncacn_np`). It is
/// what a SAMR/LSAD password buffer is encrypted with, NOT the raw `Session.SessionKey`
/// (which only seeds the signing/encryption keys). 3.0/3.0.2 use the fixed
/// `"SMB2APP\0"` / `"SmbRpc\0"` pair; 3.1.1 folds in the preauth-integrity hash.
pub fn smb3_application_key(session_key: &[u8; 16]) -> [u8; 16] {
    kdf_counter(session_key, b"SMB2APP\x00", b"SmbRpc\x00", 128)
}

/// The SMB 3.1.1 application key: `KDF(SessionKey, "SMBAppKey\0", PreauthHash)`.
pub fn smb311_application_key(session_key: &[u8; 16], preauth_hash: &[u8]) -> [u8; 16] {
    kdf_counter(session_key, b"SMBAppKey\x00", preauth_hash, 128)
}

/// AES-128-CMAC over `data` under `key` (MS-SMB2's signing primitive for 3.0).
fn aes_cmac(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let mut mac = <Cmac<Aes128> as Mac>::new_from_slice(key).expect("cmac key is 16 bytes");
    mac.update(data);
    let digest = mac.finalize().into_bytes();
    let mut sig = [0u8; 16];
    sig.copy_from_slice(&digest);
    sig
}

/// Sign an assembled SMB2 message in place: set `SMB2_FLAGS_SIGNED`, zero the
/// signature field, then write the AES-CMAC of the whole message into it.
pub fn sign_message(signing_key: &[u8; 16], msg: &mut [u8]) {
    if msg.len() < HEADER_LEN {
        return;
    }
    let flags = u32::from_le_bytes([msg[16], msg[17], msg[18], msg[19]]) | SMB2_FLAGS_SIGNED;
    msg[FLAGS_OFFSET..FLAGS_OFFSET + 4].copy_from_slice(&flags.to_le_bytes());
    msg[SIGNATURE_OFFSET..SIGNATURE_OFFSET + 16].fill(0);
    let sig = aes_cmac(signing_key, msg);
    msg[SIGNATURE_OFFSET..SIGNATURE_OFFSET + 16].copy_from_slice(&sig);
}

/// Verify a signed SMB2 request: recompute the CMAC over the message with the
/// signature field zeroed and compare. Returns `false` if unsigned.
pub fn verify_message(signing_key: &[u8; 16], msg: &[u8]) -> bool {
    if msg.len() < HEADER_LEN {
        return false;
    }
    let flags = u32::from_le_bytes([msg[16], msg[17], msg[18], msg[19]]);
    if flags & SMB2_FLAGS_SIGNED == 0 {
        return false;
    }
    let mut probe = msg.to_vec();
    probe[SIGNATURE_OFFSET..SIGNATURE_OFFSET + 16].fill(0);
    aes_cmac(signing_key, &probe) == msg[SIGNATURE_OFFSET..SIGNATURE_OFFSET + 16]
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ground truth from impacket (probe_smb3sign.py): session_key = 00..0f.
    const SESSION_KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    #[test]
    fn signing_key_matches_impacket_kdf() {
        // Filled from the impacket ground-truth probe.
        let expected = hex16("6234814cbb8ea9227440ebfeb5eacbe1");
        assert_eq!(smb3_signing_key(&SESSION_KEY), expected);
    }

    #[test]
    fn cmac_matches_impacket() {
        let key = smb3_signing_key(&SESSION_KEY);
        assert_eq!(
            aes_cmac(&key, &[0u8; 64]),
            hex16("f1482d102e777669dc4a08d450f23538")
        );
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let key = smb3_signing_key(&SESSION_KEY);
        let mut msg = vec![0u8; 96];
        msg[0..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
        sign_message(&key, &mut msg);
        // The SIGNED flag is set and the signature is non-zero.
        assert_eq!(
            u32::from_le_bytes([msg[16], msg[17], msg[18], msg[19]]) & SMB2_FLAGS_SIGNED,
            SMB2_FLAGS_SIGNED
        );
        assert_ne!(&msg[48..64], &[0u8; 16]);
        assert!(verify_message(&key, &msg));
        // Any tamper breaks verification.
        msg[70] ^= 0xff;
        assert!(!verify_message(&key, &msg));
    }

    fn hex16(s: &str) -> [u8; 16] {
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect();
        let mut out = [0u8; 16];
        out.copy_from_slice(&bytes);
        out
    }
}
