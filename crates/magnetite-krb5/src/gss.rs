//! GSS-API per-message tokens (RFC 4121) over a Kerberos AES256 subkey — the
//! integrity protection a Kerberos-authenticated DCE/RPC, LDAP or SMB session
//! applies to each message once the security context is established.
//!
//! Only the **MIC token** (integrity, `PKT_INTEGRITY`) with
//! AES256-CTS-HMAC-SHA1-96 is implemented here; the Wrap token (confidentiality,
//! `PKT_PRIVACY`) — which adds a confounder, AES-CTS encryption and the RRC
//! rotation — is a further step.
//!
//! The token (28 bytes, RFC 4121 §4.2.6.1):
//! `TOK_ID(0x0404) ‖ Flags ‖ Filler(0xff×5) ‖ SND_SEQ(big-endian u64) ‖
//! SGN_CKSUM(12)`, where the checksum is
//! `HMAC-SHA1-96(subkey, data ‖ token_header[0..16])` under key usage 25.

use crate::error::{KdcError, KdcResult};
use picky_krb::crypto::{ChecksumSuite, CipherSuite};

/// RFC 3961/3962 AES256-CTS-HMAC-SHA1-96 primitives used to build a CFX Wrap
/// checksum that also covers **SIGN_ONLY associated data** (the DCE/RPC PDU header
/// and `sec_trailer` a real acceptor folds into the seal). picky's `Cipher`
/// hard-codes the checksum to `HMAC(Ki, confounder ‖ plaintext)` with an internal
/// random confounder and no AAD hook, so the AEAD path is spelled out here;
/// `derive_key` (the RFC 3961 DK) is reused from picky so the keys match its
/// enctype exactly.
mod cfx {
    use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
    use aes::Aes256;
    use hmac::{Hmac, Mac};
    use picky_krb::crypto::aes::{derive_key, AesSize};
    use sha1::Sha1;

    const BLOCK: usize = 16;

    /// The RFC 3961 key-derivation constant: the usage as 4 big-endian octets
    /// followed by the one-octet role tag (`0xAA` = Ke, `0x55` = Ki).
    fn usage_const(usage: i32, tag: u8) -> [u8; 5] {
        let mut c = [0u8; 5];
        c[..4].copy_from_slice(&usage.to_be_bytes());
        c[4] = tag;
        c
    }

    /// Derive the AES256 encryption key `Ke` for `usage`.
    pub(super) fn ke(base_key: &[u8], usage: i32) -> Vec<u8> {
        derive_key(base_key, &usage_const(usage, 0xAA), &AesSize::Aes256).unwrap_or_default()
    }

    /// Derive the AES256 integrity key `Ki` for `usage`.
    pub(super) fn ki(base_key: &[u8], usage: i32) -> Vec<u8> {
        derive_key(base_key, &usage_const(usage, 0x55), &AesSize::Aes256).unwrap_or_default()
    }

    fn swap_last_two(data: &mut [u8]) {
        let n = data.len();
        for i in 0..BLOCK {
            data.swap(i + n - 2 * BLOCK, i + n - BLOCK);
        }
    }

    /// AES-256-CBC encrypt `data` (a whole number of blocks) under `key`, IV = 0.
    fn cbc_encrypt_iv0(key: &[u8], data: &[u8]) -> Vec<u8> {
        let Ok(cipher) = Aes256::new_from_slice(key) else {
            return Vec::new();
        };
        let mut prev = [0u8; BLOCK];
        let mut out = Vec::with_capacity(data.len());
        for chunk in data.chunks(BLOCK) {
            let mut block = [0u8; BLOCK];
            for i in 0..BLOCK {
                block[i] = chunk[i] ^ prev[i];
            }
            let mut b = block.into();
            cipher.encrypt_block(&mut b);
            prev = b.into();
            out.extend_from_slice(&prev);
        }
        out
    }

    /// AES-256-CBC decrypt `data` (a whole number of blocks) under `key`, IV = 0.
    fn cbc_decrypt_iv0(key: &[u8], data: &[u8]) -> Vec<u8> {
        let Ok(cipher) = Aes256::new_from_slice(key) else {
            return Vec::new();
        };
        let mut prev = [0u8; BLOCK];
        let mut out = Vec::with_capacity(data.len());
        for chunk in data.chunks(BLOCK) {
            let ct: [u8; BLOCK] = chunk.try_into().unwrap_or([0u8; BLOCK]);
            let mut b = ct.into();
            cipher.decrypt_block(&mut b);
            let plain: [u8; BLOCK] = b.into();
            for i in 0..BLOCK {
                out.push(plain[i] ^ prev[i]);
            }
            prev = ct;
        }
        out
    }

    /// AES-256-CBC-CTS encrypt `data` (a whole number of blocks, ≥ 2) under `key`
    /// with a zero IV — the RFC 3962 cipher with the last two blocks swapped.
    pub(super) fn cts_encrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut buf = cbc_encrypt_iv0(key, data);
        if buf.len() >= 2 * BLOCK {
            swap_last_two(&mut buf);
        }
        buf
    }

    /// The inverse of [`cts_encrypt`] for a whole number of blocks (≥ 2).
    pub(super) fn cts_decrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut buf = data.to_vec();
        if buf.len() >= 2 * BLOCK {
            swap_last_two(&mut buf);
        }
        cbc_decrypt_iv0(key, &buf)
    }

    /// `HMAC-SHA1(key, data)` truncated to the 12-octet CFX integrity tag.
    pub(super) fn hmac_sha1_96(key: &[u8], data: &[u8]) -> [u8; 12] {
        let mut mac =
            <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(data);
        let full = mac.finalize().into_bytes();
        let mut tag = [0u8; 12];
        tag.copy_from_slice(&full[..12]);
        tag
    }
}

/// RFC 4121 §2 key usages for per-message MIC signing. The usage is
/// *direction-specific*: a token sent by the initiator is signed with
/// [`KG_USAGE_INITIATOR_SIGN`] and one sent by the acceptor with
/// [`KG_USAGE_ACCEPTOR_SIGN`]. (The DCE/RPC path historically used the initiator
/// usage in both directions because impacket does not verify the server's MIC;
/// standards-track clients — MIT/Windows GSS for LDAP RFC 4752 and GSS-TSIG
/// RFC 3645 — do verify it and require the acceptor usage on server responses.)
const KG_USAGE_INITIATOR_SIGN: i32 = 25;
const KG_USAGE_ACCEPTOR_SIGN: i32 = 23;
/// RFC 4121 key usages for per-message sealing (direction-specific, unlike sign).
pub const KG_USAGE_ACCEPTOR_SEAL: i32 = 22;
pub const KG_USAGE_INITIATOR_SEAL: i32 = 24;

/// MIC token flags (RFC 4121 §4.2.6.1). Bit 0 `SentByAcceptor`, bit 2
/// `AcceptorSubkey` — the session key is the acceptor subkey from the AP-REP.
const MIC_FLAGS_INITIATOR: u8 = 0x04; // AcceptorSubkey only (sender = initiator)
const MIC_FLAGS_ACCEPTOR: u8 = 0x05; // SentByAcceptor | AcceptorSubkey

/// The fixed 8-byte MIC header prefix (TOK_ID, Flags, Filler) plus SND_SEQ.
fn mic_header(sequence: u64, flags: u8) -> [u8; 16] {
    let mut h = [0u8; 16];
    h[0] = 0x04;
    h[1] = 0x04; // TOK_ID = 0x0404 (MIC)
    h[2] = flags;
    h[3..8].copy_from_slice(&[0xff; 5]); // Filler
    h[8..16].copy_from_slice(&sequence.to_be_bytes()); // SND_SEQ
    h
}

/// Build an RFC 4121 MIC token over `data` at `sequence` with the given header
/// `flags` and RFC 3961 key `usage`.
fn mic(subkey: &[u8], sequence: u64, data: &[u8], flags: u8, usage: i32) -> KdcResult<Vec<u8>> {
    let header = mic_header(sequence, flags);
    // The checksum covers data ‖ MIC-pad ‖ header, where the pad aligns the data
    // to 4 bytes (`n` copies of the byte `n`); the pad is not part of the token.
    let pad = (4 - data.len() % 4) & 3;
    let mut signed = Vec::with_capacity(data.len() + pad + 16);
    signed.extend_from_slice(data);
    signed.extend(std::iter::repeat_n(pad as u8, pad));
    signed.extend_from_slice(&header);
    let cksum = ChecksumSuite::HmacSha196Aes256
        .hasher()
        .checksum(subkey, usage, &signed)
        .map_err(|e| KdcError::Crypto(e.to_string()))?;

    let mut token = header.to_vec();
    token.extend_from_slice(&cksum[..12]);
    Ok(token)
}

/// Build an *initiator* RFC 4121 MIC token over `data` at `sequence` under an
/// AES256 `subkey` (client→server direction; also the DCE/RPC path).
///
/// # Errors
/// Returns [`KdcError::Crypto`] if the RFC 3961 checksum operation fails.
pub fn gss_mic(subkey: &[u8], sequence: u64, data: &[u8]) -> KdcResult<Vec<u8>> {
    mic(
        subkey,
        sequence,
        data,
        MIC_FLAGS_INITIATOR,
        KG_USAGE_INITIATOR_SIGN,
    )
}

/// Build an *acceptor* RFC 4121 MIC token (server→client direction): sets the
/// `SentByAcceptor` flag and signs with [`KG_USAGE_ACCEPTOR_SIGN`], as MIT and
/// Windows GSS require on verified server responses (LDAP RFC 4752, GSS-TSIG).
///
/// # Errors
/// Returns [`KdcError::Crypto`] if the RFC 3961 checksum operation fails.
pub fn gss_mic_acceptor(subkey: &[u8], sequence: u64, data: &[u8]) -> KdcResult<Vec<u8>> {
    mic(
        subkey,
        sequence,
        data,
        MIC_FLAGS_ACCEPTOR,
        KG_USAGE_ACCEPTOR_SIGN,
    )
}

/// Verify a MIC token over `data`, returning its sequence number if the token
/// authenticates. The key usage is chosen from the token's `SentByAcceptor`
/// flag so both initiator (client request) and acceptor (server response)
/// tokens verify.
pub fn verify_gss_mic(subkey: &[u8], data: &[u8], token: &[u8]) -> Option<u64> {
    if token.len() < 28 {
        return None;
    }
    let seq = u64::from_be_bytes(token[8..16].try_into().ok()?);
    let sent_by_acceptor = token[2] & 0x01 != 0;
    let expected = if sent_by_acceptor {
        gss_mic_acceptor(subkey, seq, data).ok()?
    } else {
        gss_mic(subkey, seq, data).ok()?
    };
    (expected == token[..28]).then_some(seq)
}

// --- GSS-API Wrap token (RFC 4121 §4.2.6.2, CFX) — PKT_PRIVACY sealing ---
//
// The Wrap token seals a payload with AES256-CTS-HMAC-SHA1-96: the plaintext,
// `EC` filler bytes and a copy of the header are encrypted (the RFC 3961 cipher
// prepends a confounder and appends an HMAC), then the ciphertext is
// right-rotated by `RRC + EC` so the header sits at the front. Direction chooses
// the key usage: initiator seal (24) for a request, acceptor seal (22) for a
// response.

const WRAP_HEADER_LEN: usize = 16;
const WRAP_RRC: u16 = 28;

/// A CFX Wrap/MIC token flag: the token was produced by the context acceptor.
const CFX_FLAG_ACCEPTOR: u8 = 0x01;
/// A CFX Wrap flag: the payload is sealed (encrypted). Clear ⇒ integrity only.
const CFX_FLAG_SEALED: u8 = 0x02;
/// A CFX flag: an acceptor subkey was used (always the case here).
const CFX_FLAG_ACCEPTOR_SUBKEY: u8 = 0x04;
/// The AES256-CTS-HMAC-SHA1-96 checksum length (the CFX integrity tag).
const CFX_CKSUM_LEN: usize = 12;

/// The 16-byte CFX header (RFC 4121 §4.2.6): TOK_ID(0x0504), Flags, Filler(0xff),
/// EC, RRC, SND_SEQ.
fn cfx_header(flags: u8, ec: u16, rrc: u16, sequence: u64) -> [u8; WRAP_HEADER_LEN] {
    let mut h = [0u8; WRAP_HEADER_LEN];
    h[0] = 0x05;
    h[1] = 0x04; // TOK_ID = Wrap (CFX)
    h[2] = flags;
    h[3] = 0xff; // Filler
    h[4..6].copy_from_slice(&ec.to_be_bytes());
    h[6..8].copy_from_slice(&rrc.to_be_bytes());
    h[8..16].copy_from_slice(&sequence.to_be_bytes());
    h
}

/// The 16-byte Wrap header for a sealed token (Sealed | AcceptorSubkey).
fn wrap_header(flags: u8, ec: u16, rrc: u16, sequence: u64) -> [u8; WRAP_HEADER_LEN] {
    cfx_header(flags, ec, rrc, sequence)
}

/// The CFX Wrap flags for a token produced under `usage`: always Sealed +
/// AcceptorSubkey, plus `SentByAcceptor` when the sender is the acceptor (a server
/// response, `KG_USAGE_ACCEPTOR_SEAL`). A strict initiator (Samba) rejects an
/// acceptor token whose `SentByAcceptor` bit is clear.
fn wrap_flags(usage: i32) -> u8 {
    let mut f = CFX_FLAG_SEALED | CFX_FLAG_ACCEPTOR_SUBKEY;
    if usage == KG_USAGE_ACCEPTOR_SEAL {
        f |= CFX_FLAG_ACCEPTOR;
    }
    f
}

/// Right-rotate `data` by `n` bytes (the last `n` bytes move to the front).
fn rotate_right(data: &[u8], n: usize) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let n = n % data.len();
    let split = data.len() - n;
    let mut out = data[split..].to_vec();
    out.extend_from_slice(&data[..split]);
    out
}

/// Left-rotate `data` by `n` bytes (the inverse of [`rotate_right`]).
fn rotate_left(data: &[u8], n: usize) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let n = n % data.len();
    let mut out = data[n..].to_vec();
    out.extend_from_slice(&data[..n]);
    out
}

/// Seal `data` into a Wrap token under `usage` (24 = initiator, 22 = acceptor).
/// Returns `(sealed, auth_data)` — the ciphertext body and the token that carries
/// the header plus the rotated front of the ciphertext.
///
/// # Errors
/// Returns [`KdcError::Crypto`] if the AES-CTS encryption fails.
pub fn gss_wrap(
    session_key: &[u8],
    usage: i32,
    sequence: u64,
    data: &[u8],
) -> KdcResult<(Vec<u8>, Vec<u8>)> {
    let pad = (16 - data.len() % 16) & 15;
    let ec = pad as u16;
    let flags = wrap_flags(usage);

    // Encrypt data ‖ 0xFF×pad ‖ header(RRC=0).
    let mut plain = data.to_vec();
    plain.extend(std::iter::repeat_n(0xffu8, pad));
    plain.extend_from_slice(&wrap_header(flags, ec, 0, sequence));
    let cipher_text = CipherSuite::Aes256CtsHmacSha196
        .cipher()
        .encrypt(session_key, usage, &plain)
        .map_err(|e| KdcError::Crypto(format!("GSS wrap encrypt failed: {e}")))?;

    let rotate = WRAP_RRC as usize + pad;
    let rotated = rotate_right(&cipher_text, rotate);
    let split = WRAP_HEADER_LEN + rotate;

    let sealed = rotated.get(split..).unwrap_or_default().to_vec();
    let mut auth = wrap_header(flags, ec, WRAP_RRC, sequence).to_vec();
    auth.extend_from_slice(rotated.get(..split).unwrap_or_default());
    Ok((sealed, auth))
}

/// The `EC` (Extra Count) filler and `RRC` (Right Rotation Count) an AES CFX Wrap
/// token carries in Samba/Heimdal's DCE/RPC sealed-in-place layout. Heimdal's
/// `gss_wrap_iov` seals block-aligned data with **no** filler (`EC = 0`) and packs
/// the confounder + header-copy + checksum into the auth trailer, rotated right by
/// `RRC = 28` (their combined length, `16 + 12`). Both are encoded in the header
/// and drive reconstruction. (The caller aligns the stub, so `EC` stays 0.)
const CFX_IOV_RRC: usize = 28;
/// EC filler length. Samba's C `gssapi_seal_packet` (Heimdal `gss_wrap_iov`) emits
/// EC=0 for block-aligned data — the form its own acceptor expects — so we match it
/// (a real DsBind captured from Samba's *python* client shows EC=16, a Windows-compat
/// quirk of that path; the C server accepts EC=0).
const CFX_IOV_EC: usize = 0;

/// Seal `data` into the **MS-RPCE in-place Wrap layout** the DCE/RPC PKT_PRIVACY
/// path uses against a real Kerberos acceptor (Samba/Heimdal, Windows): the
/// ciphertext of `data` stays in the PDU stub body while the token header, the
/// confounder and the checksum trailer travel in the `sec_trailer` auth value.
/// Returns `(body, auth)` where `body` is the in-place stub ciphertext (same
/// length as `data`) and `auth` is the token header plus that trailer.
///
/// This matches the token Samba/Heimdal's DCE/RPC layer emits for AES CFX with
/// `EC = 0, RRC = 28` for block-aligned data. The plaintext is `data ‖ header-copy`;
/// the checksum is `HMAC(Ki, confounder ‖ aad ‖ data ‖ header-copy)` — the CFX Wrap
/// integrity tag over the **SIGN_ONLY** associated data `aad` (the DCE/RPC PDU header
/// with the `sec_trailer` when header signing is negotiated; empty otherwise) plus
/// the sealed plaintext. The RFC 3961 output `confounder ‖ Enc(data) ‖ Enc(header) ‖
/// checksum` is right-rotated by `RRC` and split so `Enc(data)` stays in the stub
/// body (in place) and the rest forms the trailer.
///
/// `data` MUST be a multiple of the 16-byte AES block (the caller aligns the stub
/// with the DCE/RPC `auth_pad`). `usage` is 24 (initiator) or 22 (acceptor). The
/// token is decoded by [`gss_unwrap_iov`] with the same `aad`.
///
/// # Errors
/// Returns [`KdcError::Crypto`] if the base key is not a valid AES256 key.
pub fn gss_wrap_iov(
    session_key: &[u8],
    usage: i32,
    sequence: u64,
    pre_aad: &[u8],
    post_aad: &[u8],
    data: &[u8],
) -> KdcResult<(Vec<u8>, Vec<u8>)> {
    let ec = CFX_IOV_EC;
    let rrc = CFX_IOV_RRC;
    let flags = wrap_flags(usage);

    // plaintext = data ‖ filler(EC, 0xff) ‖ header-copy(RRC=0).
    let header = wrap_header(flags, ec as u16, 0, sequence);
    let mut plain = Vec::with_capacity(data.len() + ec + WRAP_HEADER_LEN);
    plain.extend_from_slice(data);
    plain.extend(std::iter::repeat_n(0xffu8, ec));
    plain.extend_from_slice(&header);

    // e = Enc(Ke, confounder ‖ plaintext) ‖ HMAC(Ki, checksum-input). The two
    // SIGN_ONLY buffers straddle the data (Samba's `gssapi_seal_packet` splits the
    // DCE/RPC PDU into the header/request-header before the stub and the sec_trailer
    // after it): checksum-input = confounder ‖ pre ‖ data ‖ post ‖ filler ‖ header.
    let ke = cfx::ke(session_key, usage);
    let ki = cfx::ki(session_key, usage);
    if ke.is_empty() || ki.is_empty() {
        return Err(KdcError::Crypto("GSS wrap: invalid AES256 key".into()));
    }
    let mut confounder = [0u8; WRAP_HEADER_LEN];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut confounder);
    let mut to_encrypt = confounder.to_vec();
    to_encrypt.extend_from_slice(&plain);
    let mut e = cfx::cts_encrypt(&ke, &to_encrypt);
    let mut mac_input = confounder.to_vec();
    mac_input.extend_from_slice(pre_aad);
    mac_input.extend_from_slice(data);
    mac_input.extend_from_slice(post_aad);
    mac_input.extend(std::iter::repeat_n(0xffu8, ec));
    mac_input.extend_from_slice(&header);
    e.extend_from_slice(&cfx::hmac_sha1_96(&ki, &mac_input));

    // Right-rotate the whole ciphertext by RRC + EC so the token header sits at the
    // front; the in-place stub ciphertext becomes the tail (the PDU body) and the
    // confounder + filler + header-copy + checksum form the auth trailer. This is
    // Samba/Heimdal's DCE/RPC `gse_seal_packet` layout (confirmed by decoding a real
    // sealed DsBind: `e = rotate_left(trailer ‖ body, RRC + EC)`).
    let rotate = rrc + ec;
    let rotated = rotate_right(&e, rotate);
    let split = WRAP_HEADER_LEN + rotate;
    let body = rotated.get(split..).unwrap_or_default().to_vec();
    let mut auth = wrap_header(flags, ec as u16, rrc as u16, sequence).to_vec();
    auth.extend_from_slice(rotated.get(..split).unwrap_or_default());
    Ok((body, auth))
}

/// Unseal an **MS-RPCE in-place Wrap token** (the inverse of [`gss_wrap_iov`], and
/// the decoder for a real acceptor's sealed response). `body` is the in-place stub
/// ciphertext, `auth` the token header plus trailer, and `aad` the same SIGN_ONLY
/// associated data used to seal it. Reads `EC`/`RRC` from the header, so it decodes
/// both the `EC = RRC = 0` and `EC = 16, RRC = 28` forms. Returns the plaintext, or
/// `None` if the token is malformed or fails the integrity check over `confounder ‖
/// aad ‖ plaintext`.
pub fn gss_unwrap_iov(
    session_key: &[u8],
    usage: i32,
    pre_aad: &[u8],
    post_aad: &[u8],
    body: &[u8],
    auth: &[u8],
) -> Option<Vec<u8>> {
    if auth.len() < WRAP_HEADER_LEN {
        return None;
    }
    let ec = u16::from_be_bytes([auth[4], auth[5]]) as usize;
    let rrc = u16::from_be_bytes([auth[6], auth[7]]) as usize;
    let trailer = &auth[WRAP_HEADER_LEN..];

    // Reassemble the ciphertext `e` = rotate_left(trailer ‖ body, RRC + EC): the auth
    // trailer holds the front of the right-rotated ciphertext and the stub body its
    // tail (Samba/Heimdal's DCE/RPC in-place layout).
    let e_len = trailer.len().checked_add(body.len())?;
    if e_len < WRAP_HEADER_LEN + 12 {
        return None;
    }
    let mut rotated = Vec::with_capacity(e_len);
    rotated.extend_from_slice(trailer);
    rotated.extend_from_slice(body);
    let e = rotate_left(&rotated, rrc + ec);

    let ke = cfx::ke(session_key, usage);
    let ki = cfx::ki(session_key, usage);
    if ke.is_empty() || ki.is_empty() {
        return None;
    }
    let (c1, tag) = e.split_at(e.len() - 12);
    let plain_full = cfx::cts_decrypt(&ke, c1);
    let (confounder, plain) = plain_full.split_at(WRAP_HEADER_LEN.min(plain_full.len()));
    // plain = data ‖ filler(EC) ‖ header-copy(16); split off the stub `data`.
    let data_len = plain.len().checked_sub(ec + WRAP_HEADER_LEN)?;
    let (data, filler_hdr) = plain.split_at(data_len);
    // Integrity: HMAC(Ki, confounder ‖ pre ‖ data ‖ post ‖ filler ‖ header) matches.
    let mut mac_input = confounder.to_vec();
    mac_input.extend_from_slice(pre_aad);
    mac_input.extend_from_slice(data);
    mac_input.extend_from_slice(post_aad);
    mac_input.extend_from_slice(filler_hdr);
    if cfx::hmac_sha1_96(&ki, &mac_input) != tag {
        return None;
    }
    Some(data.to_vec())
}

/// Unseal a Wrap token: recover the plaintext from `sealed` (the ciphertext body)
/// and `auth_data` (the Wrap token) under `usage`. Returns `None` if the token is
/// malformed or the integrity check fails.
pub fn gss_unwrap(
    session_key: &[u8],
    usage: i32,
    sealed: &[u8],
    auth_data: &[u8],
) -> Option<Vec<u8>> {
    if auth_data.len() < WRAP_HEADER_LEN {
        return None;
    }
    let ec = u16::from_be_bytes([auth_data[4], auth_data[5]]) as usize;
    let rrc = u16::from_be_bytes([auth_data[6], auth_data[7]]) as usize;

    // Reassemble the rotated ciphertext: token tail ‖ sealed body.
    let mut rotated = auth_data[WRAP_HEADER_LEN..].to_vec();
    rotated.extend_from_slice(sealed);
    let cipher_text = rotate_left(&rotated, rrc + ec);

    let plain = CipherSuite::Aes256CtsHmacSha196
        .cipher()
        .decrypt(session_key, usage, &cipher_text)
        .ok()?;
    // plain = data ‖ pad(EC) ‖ header(16); strip the trailing EC + header.
    let keep = plain.len().checked_sub(ec + WRAP_HEADER_LEN)?;
    Some(plain[..keep].to_vec())
}

// --- Contiguous-token wrappers + the integrity (conf=false) Wrap ---
//
// The SASL GSS security layer (RFC 4752) puts a single contiguous GSS_Wrap token
// on the wire (unlike MS-RPCE, which splits it into a stub body and an auth
// trailer). These helpers produce/consume that contiguous form, and add the
// integrity-only Wrap the layer negotiation requires.

/// Seal `data` into a single contiguous GSS_Wrap token (`header ‖ rotated
/// ciphertext`) — the form a SASL security layer or a GSS client puts on the wire.
///
/// # Errors
/// Returns [`KdcError::Crypto`] if the AES-CTS encryption fails.
pub fn gss_seal_token(subkey: &[u8], usage: i32, sequence: u64, data: &[u8]) -> KdcResult<Vec<u8>> {
    let (sealed, auth) = gss_wrap(subkey, usage, sequence, data)?;
    let mut token = auth; // header ‖ rotated[..split]
    token.extend_from_slice(&sealed); // ‖ rotated[split..]  =>  header ‖ rotated
    Ok(token)
}

/// Unseal a contiguous GSS_Wrap token (from [`gss_seal_token`] or a real GSS
/// client), returning `(sequence, plaintext)`. `None` if malformed or inauthentic.
pub fn gss_unseal_token(subkey: &[u8], usage: i32, token: &[u8]) -> Option<(u64, Vec<u8>)> {
    if token.len() < WRAP_HEADER_LEN {
        return None;
    }
    let seq = u64::from_be_bytes(token[8..16].try_into().ok()?);
    // Split header-only: gss_unwrap reconstructs `rotated` from auth[16..]‖sealed,
    // so a bare 16-byte header + the rest is the equivalent split.
    let plain = gss_unwrap(
        subkey,
        usage,
        &token[WRAP_HEADER_LEN..],
        &token[..WRAP_HEADER_LEN],
    )?;
    Some((seq, plain))
}

/// Wrap `data` for integrity only (RFC 4121 §4.2.6.2, `conf_flag=FALSE`): the token
/// is `header ‖ data ‖ checksum` with the Sealed flag clear and no rotation
/// (`RRC=0`). This is the form the SASL security-layer negotiation uses (it is
/// always integrity-protected, never encrypted).
///
/// # Errors
/// Returns [`KdcError::Crypto`] if the RFC 3961 checksum operation fails.
pub fn gss_wrap_integrity(
    subkey: &[u8],
    usage: i32,
    sequence: u64,
    data: &[u8],
) -> KdcResult<Vec<u8>> {
    let flags = CFX_FLAG_ACCEPTOR | CFX_FLAG_ACCEPTOR_SUBKEY;
    // The checksum covers data ‖ header with EC and RRC zeroed (RFC 4121 §4.2.6.2).
    let mut signed = data.to_vec();
    signed.extend_from_slice(&cfx_header(flags, 0, 0, sequence));
    let cksum = ChecksumSuite::HmacSha196Aes256
        .hasher()
        .checksum(subkey, usage, &signed)
        .map_err(|e| KdcError::Crypto(e.to_string()))?;
    // For conf=false the EC field carries the trailing-checksum length; RRC = 0.
    let mut token = cfx_header(flags, CFX_CKSUM_LEN as u16, 0, sequence).to_vec();
    token.extend_from_slice(data);
    token.extend_from_slice(&cksum[..CFX_CKSUM_LEN]);
    Ok(token)
}

/// Verify and unwrap an integrity (conf=false) Wrap token from [`gss_wrap_integrity`],
/// returning `(sequence, data)` if it authenticates. `None` if malformed, sealed,
/// or the checksum fails.
pub fn gss_unwrap_integrity(subkey: &[u8], usage: i32, token: &[u8]) -> Option<(u64, Vec<u8>)> {
    if token.len() < WRAP_HEADER_LEN + CFX_CKSUM_LEN {
        return None;
    }
    if token[2] & CFX_FLAG_SEALED != 0 {
        return None; // a sealed token belongs to gss_unseal_token
    }
    let rrc = u16::from_be_bytes([token[6], token[7]]) as usize;
    let seq = u64::from_be_bytes(token[8..16].try_into().ok()?);
    // Undo the RRC rotation of (data ‖ checksum), then split off the checksum.
    let body = rotate_left(&token[WRAP_HEADER_LEN..], rrc);
    let split = body.len().checked_sub(CFX_CKSUM_LEN)?;
    let data = &body[..split];
    let expected = gss_wrap_integrity(subkey, usage, seq, data).ok()?;
    (expected[WRAP_HEADER_LEN + split..] == body[split..]).then(|| (seq, data.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn mic_matches_impacket_ground_truth() {
        // Ground truth captured from impacket GSS_GetMIC (AES256 subkey 0..31).
        let subkey: Vec<u8> = (0u8..32).collect();
        assert_eq!(
            hex(&gss_mic(&subkey, 0, b"hello").unwrap()),
            "040404ffffffffff00000000000000009aa448c5ab6619738aed7aa3",
        );
        assert_eq!(
            hex(&gss_mic(&subkey, 1, b"hello").unwrap()),
            "040404ffffffffff00000000000000019e66c0a6a82b4dfff2def54d",
        );
        assert_eq!(
            hex(&gss_mic(&subkey, 2, b"hello").unwrap()),
            "040404ffffffffff0000000000000002058f63d67ae0abf837e747b5",
        );
    }

    #[test]
    fn unwraps_an_impacket_wrap_token() {
        // Ground truth: impacket GSS_Wrap(AES256 subkey 0..31, seq 0, initiator).
        let subkey: Vec<u8> = (0u8..32).collect();
        let sealed = hex_to_bytes("adb513385a3c38fc4b7d9b93c9d1674a6546c47f");
        let token = hex_to_bytes(
            "050406ff000c001c0000000000000000f94e5ae8af1c914e16a2d758e458ad80\
             618986bbf42fb83b4091214ee903bcbda88c380b98611540dbe13562fdcd48cf\
             f3f69a0788a4c001",
        );
        let plain = gss_unwrap(&subkey, KG_USAGE_INITIATOR_SEAL, &sealed, &token).unwrap();
        assert_eq!(plain, b"magnetite drs stub!!");
    }

    #[test]
    fn wrap_then_unwrap_round_trips() {
        let subkey: Vec<u8> = (0u8..32).collect();
        for msg in [
            b"".as_slice(),
            b"x",
            b"sixteen-byte-msg",
            b"a longer replicated stub value",
        ] {
            let (sealed, auth) = gss_wrap(&subkey, KG_USAGE_ACCEPTOR_SEAL, 3, msg).unwrap();
            assert_eq!(sealed.len(), msg.len(), "CFX seals in place (same length)");
            let plain = gss_unwrap(&subkey, KG_USAGE_ACCEPTOR_SEAL, &sealed, &auth).unwrap();
            assert_eq!(plain, msg);
        }
        // A wrong key must fail the integrity check.
        let (sealed, auth) = gss_wrap(&subkey, KG_USAGE_ACCEPTOR_SEAL, 0, b"secret").unwrap();
        let other: Vec<u8> = (1u8..33).collect();
        assert_eq!(
            gss_unwrap(&other, KG_USAGE_ACCEPTOR_SEAL, &sealed, &auth),
            None
        );
    }

    #[test]
    fn wrap_iov_seals_in_place_and_round_trips() {
        // Samba's C DCE/RPC seal (`gssapi_seal_packet`): `data` (block-aligned) stays
        // in the body; confounder + header-copy + checksum form the auth trailer, with
        // EC = 0 and RRC = 28. `gss_unwrap_iov` is its inverse (validated against a
        // real Heimdal `gss_wrap_iov` token built with the same 4-IOV split).
        let subkey: Vec<u8> = (0u8..32).collect();
        for msg in [
            b"".as_slice(),
            b"sixteen-byte-msg",
            b"exactly-32-bytes-of-drs-stub-dat", // 32 bytes
        ] {
            assert_eq!(msg.len() % 16, 0, "test inputs are block-aligned");
            let (body, auth) =
                gss_wrap_iov(&subkey, KG_USAGE_INITIATOR_SEAL, 5, &[], &[], msg).unwrap();
            assert_eq!(body.len(), msg.len(), "stub ciphertext seals in place");
            assert_eq!(auth[4..6], [0, 0], "EC field = 0");
            assert_eq!(auth[6..8], 28u16.to_be_bytes(), "RRC field = 28");
            // auth = header(16) + confounder(16) + header-copy(16) + checksum(12).
            assert_eq!(auth.len(), WRAP_HEADER_LEN + 16 + 16 + 12);
            let plain =
                gss_unwrap_iov(&subkey, KG_USAGE_INITIATOR_SEAL, &[], &[], &body, &auth).unwrap();
            assert_eq!(plain, msg);
            // The two SIGN_ONLY buffers straddle the data; decoding needs the same
            // pre/post, and any mismatch fails the integrity check.
            let (b2, a2) =
                gss_wrap_iov(&subkey, KG_USAGE_INITIATOR_SEAL, 5, b"pre", b"post", msg).unwrap();
            assert_eq!(
                gss_unwrap_iov(&subkey, KG_USAGE_INITIATOR_SEAL, b"pre", b"post", &b2, &a2)
                    .as_deref(),
                Some(msg)
            );
            assert!(gss_unwrap_iov(&subkey, KG_USAGE_INITIATOR_SEAL, &[], &[], &b2, &a2).is_none());
            assert!(
                gss_unwrap_iov(&subkey, KG_USAGE_INITIATOR_SEAL, b"post", b"pre", &b2, &a2)
                    .is_none()
            );
        }
    }

    #[test]
    fn wrap_iov_is_directional() {
        // A token sealed with the acceptor usage unwraps with the same usage, but
        // not with the initiator usage — the direction is bound into the key.
        let subkey: Vec<u8> = (5u8..37).collect();
        let msg = b"thirty-two-byte-drs-stub-payload"; // 32 bytes
        let (body, auth) = gss_wrap_iov(&subkey, KG_USAGE_ACCEPTOR_SEAL, 9, &[], &[], msg).unwrap();
        let plain =
            gss_unwrap_iov(&subkey, KG_USAGE_ACCEPTOR_SEAL, &[], &[], &body, &auth).unwrap();
        assert_eq!(plain, msg);
        assert!(gss_unwrap_iov(&subkey, KG_USAGE_INITIATOR_SEAL, &[], &[], &body, &auth).is_none());
    }

    #[test]
    fn verify_round_trips_and_rejects_tampering() {
        let subkey: Vec<u8> = (0u8..32).collect();
        let token = gss_mic(&subkey, 7, b"magnetite drs stub").unwrap();
        assert_eq!(
            verify_gss_mic(&subkey, b"magnetite drs stub", &token),
            Some(7)
        );
        assert_eq!(verify_gss_mic(&subkey, b"tampered", &token), None);
        // A wrong key must not verify.
        let other: Vec<u8> = (1u8..33).collect();
        assert_eq!(verify_gss_mic(&other, b"magnetite drs stub", &token), None);
    }

    #[test]
    fn acceptor_mic_is_directional_and_verifies() {
        let subkey: Vec<u8> = (0u8..32).collect();
        let data = b"server response payload";
        let init = gss_mic(&subkey, 3, data).unwrap();
        let acc = gss_mic_acceptor(&subkey, 3, data).unwrap();
        // Same key/seq/data but different direction ⇒ different token.
        assert_ne!(
            init, acc,
            "direction changes usage + flag, so tokens differ"
        );
        assert_eq!(init[2] & 0x01, 0x00, "initiator: SentByAcceptor clear");
        assert_eq!(acc[2] & 0x01, 0x01, "acceptor: SentByAcceptor set");
        // verify_gss_mic auto-selects the usage from the flag, so both verify.
        assert_eq!(verify_gss_mic(&subkey, data, &init), Some(3));
        assert_eq!(verify_gss_mic(&subkey, data, &acc), Some(3));
    }

    #[test]
    fn seal_token_round_trips_and_matches_impacket_contiguous_form() {
        let subkey: Vec<u8> = (0u8..32).collect();
        let data = b"a directory search result of some length";
        let token = gss_seal_token(&subkey, KG_USAGE_ACCEPTOR_SEAL, 5, data).unwrap();
        assert_eq!(token[2] & 0x02, 0x02, "Sealed flag set");
        assert!(
            !token.windows(4).any(|w| w == b"dire"),
            "payload is encrypted"
        );
        let (seq, plain) = gss_unseal_token(&subkey, KG_USAGE_ACCEPTOR_SEAL, &token).unwrap();
        assert_eq!((seq, plain), (5, data.to_vec()));

        // The contiguous unseal is wire-compatible with a real GSS client: the
        // impacket ground-truth token (auth ‖ sealed) unseals to the same plaintext.
        let sealed = hex_to_bytes("adb513385a3c38fc4b7d9b93c9d1674a6546c47f");
        let auth = hex_to_bytes(
            "050406ff000c001c0000000000000000f94e5ae8af1c914e16a2d758e458ad80\
             618986bbf42fb83b4091214ee903bcbda88c380b98611540dbe13562fdcd48cf\
             f3f69a0788a4c001",
        );
        let mut contiguous = auth;
        contiguous.extend_from_slice(&sealed);
        let (_, plain) = gss_unseal_token(&subkey, KG_USAGE_INITIATOR_SEAL, &contiguous).unwrap();
        assert_eq!(plain, b"magnetite drs stub!!");
    }

    #[test]
    fn integrity_wrap_round_trips_and_authenticates() {
        let subkey: Vec<u8> = (0u8..32).collect();
        // The 4-octet SASL security-layer negotiation message (layer + max size).
        let data = &[0x06u8, 0x00, 0x40, 0x00];
        let token = gss_wrap_integrity(&subkey, KG_USAGE_ACCEPTOR_SEAL, 0, data).unwrap();
        assert_eq!(token[2] & 0x02, 0x00, "Sealed flag clear (integrity only)");
        assert_eq!(&token[16..16 + data.len()], data, "data is in the clear");

        let (seq, out) = gss_unwrap_integrity(&subkey, KG_USAGE_ACCEPTOR_SEAL, &token).unwrap();
        assert_eq!((seq, out), (0, data.to_vec()));

        // Tampering the data breaks the checksum.
        let mut bad = token.clone();
        bad[16] ^= 0xff;
        assert!(gss_unwrap_integrity(&subkey, KG_USAGE_ACCEPTOR_SEAL, &bad).is_none());
        // The integrity path rejects a sealed token.
        let sealed = gss_seal_token(&subkey, KG_USAGE_ACCEPTOR_SEAL, 0, data).unwrap();
        assert!(gss_unwrap_integrity(&subkey, KG_USAGE_ACCEPTOR_SEAL, &sealed).is_none());
    }
}
