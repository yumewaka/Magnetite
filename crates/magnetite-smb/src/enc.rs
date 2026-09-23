//! SMB 3.x message encryption (MS-SMB2 §3.1.4.3): AES-128 in CCM or GCM inside an
//! `SMB2_TRANSFORM_HEADER`. The plaintext SMB2 message is sealed with a
//! per-message nonce; the 16-byte tag goes in the header's Signature field and
//! the header bytes from the Nonce onward are the additional authenticated data.
//! The cipher is negotiated (3.1.1 `SMB2_ENCRYPTION_CAPABILITIES`); the keys are
//! cipher-independent (same KDF), only the AEAD and nonce length differ.

use aes::{Aes128, Aes256};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use ccm::aead::generic_array::GenericArray;
use ccm::aead::{AeadInPlace, KeyInit};
use ccm::consts::{U11, U16};
use ccm::Ccm;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

use crate::sign::kdf_counter;

/// SP800-108 counter-mode KDF (HMAC-SHA256) producing `length_bits/8` key bytes —
/// 16 for AES-128, 32 for AES-256 (one HMAC-SHA256 block covers both).
fn kdf(ki: &[u8], label: &[u8], context: &[u8], length_bits: u32) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(ki).expect("hmac accepts any key length");
    mac.update(&1u32.to_be_bytes()); // counter i = 1
    mac.update(label);
    mac.update(&[0u8]); // separator
    mac.update(context);
    mac.update(&length_bits.to_be_bytes());
    mac.finalize().into_bytes()[..length_bits as usize / 8].to_vec()
}

/// AES-CCM with a 16-byte tag and an 11-byte nonce, over AES-128 or AES-256.
type Aes128Ccm = Ccm<Aes128, U16, U11>;
type Aes256Ccm = Ccm<Aes256, U16, U11>;

/// A negotiated SMB3 encryption cipher (16-byte tag; the key is 16 or 32 bytes).
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(crate) enum Cipher {
    /// AES-128-CCM (11-byte nonce) — SMB 3.0's only cipher, and the 3.1.1 default.
    #[default]
    Ccm128,
    /// AES-128-GCM (12-byte nonce) — negotiable in SMB 3.1.1.
    Gcm128,
    /// AES-256-CCM (11-byte nonce) — negotiable in SMB 3.1.1.
    Ccm256,
    /// AES-256-GCM (12-byte nonce) — the strongest SMB 3.1.1 cipher.
    Gcm256,
}

impl Cipher {
    /// The cipher's nonce length in bytes (the rest of the 16-byte field is zero).
    fn nonce_len(self) -> usize {
        match self {
            Cipher::Ccm128 | Cipher::Ccm256 => 11,
            Cipher::Gcm128 | Cipher::Gcm256 => 12,
        }
    }

    /// The key length in bytes (16 for AES-128, 32 for AES-256).
    pub(crate) fn key_len(self) -> usize {
        match self {
            Cipher::Ccm128 | Cipher::Gcm128 => 16,
            Cipher::Ccm256 | Cipher::Gcm256 => 32,
        }
    }

    /// The `SMB2_ENCRYPTION_*` id used in negotiate contexts and the header.
    pub(crate) fn algorithm_id(self) -> u16 {
        match self {
            Cipher::Ccm128 => SMB2_ENCRYPTION_AES128_CCM,
            Cipher::Gcm128 => SMB2_ENCRYPTION_AES128_GCM,
            Cipher::Ccm256 => SMB2_ENCRYPTION_AES256_CCM,
            Cipher::Gcm256 => SMB2_ENCRYPTION_AES256_GCM,
        }
    }

    /// The cipher for a negotiate-context id, if we implement it.
    pub(crate) fn from_id(id: u16) -> Option<Cipher> {
        match id {
            SMB2_ENCRYPTION_AES128_CCM => Some(Cipher::Ccm128),
            SMB2_ENCRYPTION_AES128_GCM => Some(Cipher::Gcm128),
            SMB2_ENCRYPTION_AES256_CCM => Some(Cipher::Ccm256),
            SMB2_ENCRYPTION_AES256_GCM => Some(Cipher::Gcm256),
            _ => None,
        }
    }

    /// Server preference order (strongest first) for picking among the client's
    /// offered ciphers: AES-256-GCM > -256-CCM > -128-GCM > -128-CCM. All four key
    /// schedules are interop-validated against real Samba (AES-256 keys the KDF with
    /// the full session key; AES-128 with the 16-byte Session.SessionKey).
    pub(crate) fn preference(self) -> u8 {
        match self {
            Cipher::Gcm256 => 0,
            Cipher::Ccm256 => 1,
            Cipher::Gcm128 => 2,
            Cipher::Ccm128 => 3,
        }
    }
}

/// `SMB2_TRANSFORM_HEADER.ProtocolId` (`\xFDSMB`) marking an encrypted message.
pub(crate) const TRANSFORM_PROTOCOL_ID: [u8; 4] = [0xFD, 0x53, 0x4D, 0x42];
/// Fixed size of the transform header (ProtocolId..SessionId).
const TRANSFORM_HEADER_LEN: usize = 52;
/// The SMB 3.1.1 `SMB2_TRANSFORM_HEADER.Flags` value marking an encrypted message
/// (MS-SMB2 §2.2.41). Occupies the same 2-byte field SMB 3.0 used for
/// `EncryptionAlgorithm` (AES-128-CCM = 0x0001), so this constant serves both.
pub(crate) const TRANSFORM_FLAG_ENCRYPTED: u16 = 0x0001;
/// `EncryptionAlgorithm`/cipher ids (MS-SMB2 §2.2.3.1.2).
pub(crate) const SMB2_ENCRYPTION_AES128_CCM: u16 = 0x0001;
pub(crate) const SMB2_ENCRYPTION_AES128_GCM: u16 = 0x0002;
pub(crate) const SMB2_ENCRYPTION_AES256_CCM: u16 = 0x0003;
pub(crate) const SMB2_ENCRYPTION_AES256_GCM: u16 = 0x0004;

/// Derive the SMB 3.0 encryption keys from the 16-byte session key: the server
/// encrypts responses with the `ServerOut` key and decrypts requests with the
/// `ServerIn ` key (MS-SMB2 §3.1.4.2, label `SMB2AESCCM`).
pub(crate) fn encryption_keys(
    session_key: &[u8; 16],
) -> (/* encrypt */ [u8; 16], /* decrypt */ [u8; 16]) {
    let encrypt = kdf_counter(session_key, b"SMB2AESCCM\x00", b"ServerOut\x00", 128);
    let decrypt = kdf_counter(session_key, b"SMB2AESCCM\x00", b"ServerIn \x00", 128);
    (encrypt, decrypt)
}

/// Derive the SMB 3.1.1 encryption keys. Unlike 3.0 these use per-direction
/// labels (`SMBS2CCipherKey`/`SMBC2SCipherKey`) and the preauth-integrity hash as
/// the KDF context (MS-SMB2 §3.1.4.2). `key_bytes` is 16 (AES-128) or 32
/// (AES-256). Returns `(encrypt ServerOut/S2C, decrypt ServerIn/C2S)`.
///
/// `ki` is the KDF key: the 16-byte `Session.SessionKey` for AES-128, but the
/// **full** session key (up to 32 bytes) for AES-256 — MS-SMB2 uses the untruncated
/// key as `KI` for 256-bit ciphers, while signing always uses the 16-byte key. Using
/// the 16-byte key here yields the wrong AES-256 key and a real peer can't decrypt.
pub(crate) fn encryption_keys_311(
    ki: &[u8],
    preauth: &[u8],
    key_bytes: usize,
) -> (Vec<u8>, Vec<u8>) {
    let bits = key_bytes as u32 * 8;
    let encrypt = kdf(ki, b"SMBS2CCipherKey\x00", preauth, bits);
    let decrypt = kdf(ki, b"SMBC2SCipherKey\x00", preauth, bits);
    (encrypt, decrypt)
}

/// Fold `msg` into the running SMB 3.1.1 preauth-integrity hash (SHA-512):
/// `H = SHA512(H_prev ‖ msg)` (MS-SMB2 §3.1.5.2).
pub(crate) fn preauth_update(hash: &[u8; 64], msg: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(hash);
    h.update(msg);
    let mut out = [0u8; 64];
    out.copy_from_slice(&h.finalize());
    out
}

/// AEAD seal with any of the four ciphers (all have a 16-byte tag; the nonce and
/// key length are fixed by the concrete AEAD type `A`).
fn seal_with<A: KeyInit + AeadInPlace>(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let cipher = A::new_from_slice(key).expect("key length matches the cipher");
    let mut buf = pt.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(nonce), aad, &mut buf)
        .expect("seal");
    let mut t = [0u8; 16];
    t.copy_from_slice(&tag);
    (buf, t)
}

/// AEAD open with any of the four ciphers; verifies the tag.
fn open_with<A: KeyInit + AeadInPlace>(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8],
) -> Option<Vec<u8>> {
    let cipher = A::new_from_slice(key).ok()?;
    let mut buf = ct.to_vec();
    cipher
        .decrypt_in_place_detached(
            GenericArray::from_slice(nonce),
            aad,
            &mut buf,
            GenericArray::from_slice(tag),
        )
        .ok()?;
    Some(buf)
}

/// Seal with the negotiated cipher.
fn seal(cipher: Cipher, key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> (Vec<u8>, [u8; 16]) {
    match cipher {
        Cipher::Ccm128 => seal_with::<Aes128Ccm>(key, nonce, aad, pt),
        Cipher::Gcm128 => seal_with::<Aes128Gcm>(key, nonce, aad, pt),
        Cipher::Ccm256 => seal_with::<Aes256Ccm>(key, nonce, aad, pt),
        Cipher::Gcm256 => seal_with::<Aes256Gcm>(key, nonce, aad, pt),
    }
}

/// Open with the negotiated cipher.
fn open(
    cipher: Cipher,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8],
) -> Option<Vec<u8>> {
    match cipher {
        Cipher::Ccm128 => open_with::<Aes128Ccm>(key, nonce, aad, ct, tag),
        Cipher::Gcm128 => open_with::<Aes128Gcm>(key, nonce, aad, ct, tag),
        Cipher::Ccm256 => open_with::<Aes256Ccm>(key, nonce, aad, ct, tag),
        Cipher::Gcm256 => open_with::<Aes256Gcm>(key, nonce, aad, ct, tag),
    }
}

/// Wrap a plaintext SMB2 message in an encrypted `SMB2_TRANSFORM_HEADER` using
/// the negotiated `cipher`. The caller supplies a per-message nonce counter (must
/// not repeat under one key).
pub(crate) fn encrypt(
    cipher: Cipher,
    enc_key: &[u8],
    session_id: u64,
    nonce_ctr: u64,
    plaintext: &[u8],
) -> Vec<u8> {
    let nonce_len = cipher.nonce_len();
    let mut nonce = vec![0u8; nonce_len];
    nonce[..8].copy_from_slice(&nonce_ctr.to_le_bytes());

    let mut header = Vec::with_capacity(TRANSFORM_HEADER_LEN);
    header.extend_from_slice(&TRANSFORM_PROTOCOL_ID);
    header.extend_from_slice(&[0u8; 16]); // Signature (tag) — filled in below
    let mut nonce_field = [0u8; 16];
    nonce_field[..nonce_len].copy_from_slice(&nonce);
    header.extend_from_slice(&nonce_field);
    header.extend_from_slice(&(plaintext.len() as u32).to_le_bytes()); // OriginalMessageSize
    header.extend_from_slice(&0u16.to_le_bytes()); // Reserved
                                                   // Offset 42: in SMB 3.1.1 this is `Flags` and MUST be 0x0001 (Encrypted) — the
                                                   // cipher comes from the negotiated context, not per message. (In SMB 3.0 the
                                                   // field is `EncryptionAlgorithm`, whose only value is AES-128-CCM = 0x0001, so
                                                   // the constant is correct for both.) Writing the cipher id here instead broke
                                                   // AES-128-GCM (0x0002): it is covered by the AEAD's AAD, so a real peer rejected
                                                   // the message.
    header.extend_from_slice(&TRANSFORM_FLAG_ENCRYPTED.to_le_bytes());
    header.extend_from_slice(&session_id.to_le_bytes());

    let aad = header[20..TRANSFORM_HEADER_LEN].to_vec();
    let (ciphertext, tag) = seal(cipher, enc_key, &nonce, &aad, plaintext);
    header[4..20].copy_from_slice(&tag);
    header.extend_from_slice(&ciphertext);
    header
}

/// Decrypt an `SMB2_TRANSFORM_HEADER`-wrapped message with `cipher`, verifying
/// its tag.
pub(crate) fn decrypt(cipher: Cipher, dec_key: &[u8], transform: &[u8]) -> Option<Vec<u8>> {
    if transform.len() < TRANSFORM_HEADER_LEN || transform[0..4] != TRANSFORM_PROTOCOL_ID {
        return None;
    }
    let tag = &transform[4..20];
    let nonce = &transform[20..20 + cipher.nonce_len()]; // leading bytes of the Nonce field
    let aad = &transform[20..TRANSFORM_HEADER_LEN];
    let original_size =
        u32::from_le_bytes([transform[36], transform[37], transform[38], transform[39]]) as usize;
    let mut plain = open(
        cipher,
        dec_key,
        nonce,
        aad,
        &transform[TRANSFORM_HEADER_LEN..],
        tag,
    )?;
    plain.truncate(original_size);
    Some(plain)
}

/// The `SessionId` from a transform header (echoed into the response header).
pub(crate) fn session_id_of(transform: &[u8]) -> u64 {
    transform
        .get(44..52)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SESSION_KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn encryption_keys_match_impacket() {
        let (enc, dec) = encryption_keys(&SESSION_KEY);
        assert_eq!(enc.as_slice(), hex("95d8b55c852cd25349994b3842fa4105")); // ServerOut
        assert_eq!(dec.as_slice(), hex("8e21f3cae16d07d84c03d74467f57878")); // ServerIn
    }

    #[test]
    fn encryption_keys_311_match_impacket() {
        // Ground truth: session key 00..0f, preauth-integrity hash 00..3f.
        let preauth: Vec<u8> = (0..64).collect();
        let (enc, dec) = encryption_keys_311(&SESSION_KEY, &preauth, 16);
        assert_eq!(enc.as_slice(), hex("99676aedfbfd18e61ca5bb60d502e8f2")); // S2C
        assert_eq!(dec.as_slice(), hex("f1b6250ca4d9f8877e41071f59228ce4")); // C2S
    }

    #[test]
    fn encryption_keys_311_aes256_match_reference() {
        // AES-256 keys the KDF with the FULL (32-byte) session key and L=256.
        // Ground truth from an independent SP800-108 (HMAC-SHA256) reference, itself
        // cross-checked against the impacket 128-bit vectors; this is the path real
        // Samba AES-256-GCM validated e2e.
        let preauth: Vec<u8> = (0..64).collect();
        let (enc, dec) = encryption_keys_311(&KEY_256, &preauth, 32);
        assert_eq!(enc.len(), 32);
        assert_eq!(
            enc.as_slice(),
            hex("53f8b2fb513a90f5231f5ac12ba0a24b9eed8f6e80596136560f1b0003e8d2ae"), // S2C
        );
        assert_eq!(
            dec.as_slice(),
            hex("e568de865ae188f20138931c5423898fc0d5e94fa094b72d474fc56cf5703db6"), // C2S
        );
    }

    #[test]
    fn preauth_update_chains_and_differs() {
        let zero = [0u8; 64];
        let a = preauth_update(&zero, b"negotiate");
        let b = preauth_update(&a, b"session-setup");
        assert_ne!(a, zero);
        assert_ne!(a, b);
        // Deterministic.
        assert_eq!(a, preauth_update(&zero, b"negotiate"));
    }

    /// 32-byte AES-256 key 00..1f, used by the AES-256 ground-truth vectors.
    const KEY_256: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    #[test]
    fn ccm_seal_matches_impacket_vector() {
        let (out_key, _) = encryption_keys(&SESSION_KEY);
        let nonce: Vec<u8> = (0..11).collect();
        let aad: Vec<u8> = (0..32).collect();
        let (ct, tag) = seal(
            Cipher::Ccm128,
            &out_key,
            &nonce,
            &aad,
            b"hello smb3 encryption test!!",
        );
        assert_eq!(
            ct,
            hex("32994c8d2bd0801ce685866fa6b25af40d72b9fdf040b0c07fdf2a4e")
        );
        assert_eq!(tag.as_slice(), hex("2e8c7941f9c4306a0fa4ecbeacac85cd"));
    }

    #[test]
    fn aead_seals_match_pycryptodome_vectors() {
        // Ground truth from pycryptodome (impacket's crypto dep); aad 00..1f.
        let aad: Vec<u8> = (0..32).collect();
        // AES-128-GCM: key 00..0f, nonce 00..0b.
        let n12: Vec<u8> = (0..12).collect();
        let (ct, tag) = seal(
            Cipher::Gcm128,
            &SESSION_KEY,
            &n12,
            &aad,
            b"hello smb3 gcm encryption!!",
        );
        assert_eq!(
            ct,
            hex("fb09cba2093b843929e141ed55ce506ddd45689f239994998800d0")
        );
        assert_eq!(tag.as_slice(), hex("8012919d0ad08fbbd68f1831c01ddb25"));
        // AES-256-GCM: key 00..1f, nonce 00..0b.
        let (ct, tag) = seal(
            Cipher::Gcm256,
            &KEY_256,
            &n12,
            &aad,
            b"hello smb3 aes256 test!!!",
        );
        assert_eq!(
            ct,
            hex("2f67ba77aac5b176ef72b7ead49a4a58b5f6f351830f7e5d19")
        );
        assert_eq!(tag.as_slice(), hex("9c5f852acc034d3facfdf2bfca710acb"));
        // AES-256-CCM: key 00..1f, nonce 00..0a.
        let n11: Vec<u8> = (0..11).collect();
        let (ct, tag) = seal(
            Cipher::Ccm256,
            &KEY_256,
            &n11,
            &aad,
            b"hello smb3 aes256 test!!!",
        );
        assert_eq!(
            ct,
            hex("1ba57d0a3560c0f9ddc736d47db4eeee6ac4f47fd42f8b040b")
        );
        assert_eq!(tag.as_slice(), hex("d74277b4ebebea810e0f60e54325adf8"));
    }

    #[test]
    fn transform_round_trips_all_ciphers() {
        // A minimal SMB2 message (magic + padding) as the plaintext payload.
        let mut plain = vec![0u8; 80];
        plain[0..4].copy_from_slice(&[0xfe, b'S', b'M', b'B']);
        plain[40..48].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
        for cipher in [
            Cipher::Ccm128,
            Cipher::Gcm128,
            Cipher::Ccm256,
            Cipher::Gcm256,
        ] {
            let enc = &KEY_256[..cipher.key_len()]; // ServerOut key of the right length
            let wrong: Vec<u8> = enc.iter().map(|b| b ^ 0xff).collect(); // same length, differs
            let wrapped = encrypt(cipher, enc, 0x1122_3344_5566_7788, 7, &plain);
            assert_eq!(&wrapped[0..4], &TRANSFORM_PROTOCOL_ID);
            assert_eq!(session_id_of(&wrapped), 0x1122_3344_5566_7788);
            // Offset 42 is the SMB 3.1.1 Flags field: always 0x0001 (Encrypted),
            // never the cipher id (which would break the AEAD's AAD on a real peer).
            assert_eq!(le16(&wrapped, 42), TRANSFORM_FLAG_ENCRYPTED);
            assert_eq!(
                decrypt(cipher, enc, &wrapped).as_deref(),
                Some(plain.as_slice())
            );
            // A wrong key fails the tag check.
            assert_eq!(decrypt(cipher, &wrong, &wrapped), None);
        }
    }

    fn le16(b: &[u8], off: usize) -> u16 {
        u16::from_le_bytes([b[off], b[off + 1]])
    }
}
