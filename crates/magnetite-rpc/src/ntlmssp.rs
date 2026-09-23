//! NTLM SSP for the RPC layer (MS-NLMP + MS-RPCE §2.2.2.11): the authentication
//! a Windows client negotiates on a DCE/RPC bind when it authenticates with a
//! password/hash rather than the Netlogon secure channel.
//!
//! Flow: BIND carries an NTLMSSP NEGOTIATE token → BIND_ACK returns a CHALLENGE
//! (server challenge + target info) → AUTH3 carries the AUTHENTICATE (the NTLMv2
//! response). The server verifies the response with the user's NT hash, then
//! derives the **exported session key** — the key used both to sign subsequent
//! PDUs (PKT_INTEGRITY) and to encrypt replicated secrets (DRSUAPI DCSync).
//!
//! Implemented for extended session security with key exchange (what impacket
//! and Windows negotiate). Sealing (PKT_PRIVACY) beyond signing is not needed
//! here; the client can request PKT_INTEGRITY.

use hmac::{Hmac, Mac};
use md4::{Digest, Md4};
use md5::Md5;

// NTLMSSP negotiate flags of interest (MS-NLMP §2.2.2.5).
const NTLMSSP_NEGOTIATE_UNICODE: u32 = 0x0000_0001;
const NTLMSSP_REQUEST_TARGET: u32 = 0x0000_0004;
const NTLMSSP_NEGOTIATE_SIGN: u32 = 0x0000_0010;
const NTLMSSP_NEGOTIATE_SEAL: u32 = 0x0000_0020;
const NTLMSSP_NEGOTIATE_NTLM: u32 = 0x0000_0200;
const NTLMSSP_NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
const NTLMSSP_TARGET_TYPE_SERVER: u32 = 0x0002_0000;
const NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
const NTLMSSP_NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
const NTLMSSP_NEGOTIATE_VERSION: u32 = 0x0200_0000;
const NTLMSSP_NEGOTIATE_128: u32 = 0x2000_0000;
const NTLMSSP_NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
const NTLMSSP_NEGOTIATE_56: u32 = 0x8000_0000;

// MsvAvNbComputerName / NbDomainName / DnsComputerName / DnsDomainName / EOL.
const AV_EOL: u16 = 0x0000;
const AV_NB_COMPUTER: u16 = 0x0001;
const AV_NB_DOMAIN: u16 = 0x0002;
const AV_DNS_COMPUTER: u16 = 0x0003;
const AV_DNS_DOMAIN: u16 = 0x0004;
/// `MsvAvTimestamp` (MS-NLMP §2.2.2.1) — the server's current time as a FILETIME.
/// A Windows client that will sign the session (LDAP/SMB) needs it to build the
/// AUTHENTICATE message's MIC; omitting it makes the client abort after the
/// CHALLENGE without sending an AUTHENTICATE.
const AV_TIMESTAMP: u16 = 0x0007;

/// The current time as a little-endian Windows FILETIME (100 ns ticks since 1601).
fn now_filetime() -> [u8; 8] {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // 11_644_473_600 s between 1601-01-01 and the Unix epoch; 10^7 ticks per second.
    ((secs + 11_644_473_600) * 10_000_000).to_le_bytes()
}

/// The fixed server challenge for the PoC (a real server generates this randomly).
const SERVER_CHALLENGE: [u8; 8] = *b"MAGNSSP1";

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = <Hmac<Md5> as Mac>::new_from_slice(key).expect("hmac key");
    mac.update(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

fn md5(parts: &[&[u8]]) -> [u8; 16] {
    let mut h = Md5::new();
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&h.finalize());
    out
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// The NT hash (`NTOWFv1`) of a password.
pub fn nt_hash(password: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&Md4::digest(utf16le(password)));
    out
}

/// `NTOWFv2 = HMAC-MD5(NThash, UPPER(user) ‖ domain)` (UTF-16LE).
fn ntowf_v2(nt_hash: &[u8; 16], user: &str, domain: &str) -> [u8; 16] {
    let mut data = utf16le(&user.to_uppercase());
    data.extend_from_slice(&utf16le(domain));
    hmac_md5(nt_hash, &data)
}

/// A stateful RC4 keystream (the "handle" NTLM threads across messages).
pub struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    fn new(key: &[u8]) -> Self {
        let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }

    /// Apply the keystream to `data`, advancing the internal state.
    fn apply(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        for &b in data {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k =
                self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            out.push(b ^ k);
        }
        out
    }
}

/// Build a CHALLENGE (NTLMSSP type 2) advertising extended session security,
/// carrying the server challenge and a target-info block.
pub fn challenge_message() -> Vec<u8> {
    let target_name = utf16le("EXAMPLE");
    let target_info = target_info_block();

    let flags = NTLMSSP_NEGOTIATE_UNICODE
        | NTLMSSP_REQUEST_TARGET
        | NTLMSSP_NEGOTIATE_SIGN
        | NTLMSSP_NEGOTIATE_SEAL
        | NTLMSSP_NEGOTIATE_NTLM
        | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        | NTLMSSP_TARGET_TYPE_SERVER
        | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        | NTLMSSP_NEGOTIATE_TARGET_INFO
        | NTLMSSP_NEGOTIATE_VERSION
        | NTLMSSP_NEGOTIATE_128
        | NTLMSSP_NEGOTIATE_KEY_EXCH
        | NTLMSSP_NEGOTIATE_56;

    // Fixed 8-byte header + fields; payload begins after the version block.
    let payload_off = 56u32;
    let mut m = Vec::new();
    m.extend_from_slice(b"NTLMSSP\0");
    m.extend_from_slice(&2u32.to_le_bytes()); // MessageType = CHALLENGE
                                              // TargetNameFields
    m.extend_from_slice(&(target_name.len() as u16).to_le_bytes());
    m.extend_from_slice(&(target_name.len() as u16).to_le_bytes());
    m.extend_from_slice(&payload_off.to_le_bytes());
    m.extend_from_slice(&flags.to_le_bytes());
    m.extend_from_slice(&SERVER_CHALLENGE);
    m.extend_from_slice(&[0u8; 8]); // Reserved
                                    // TargetInfoFields
    let info_off = payload_off + target_name.len() as u32;
    m.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
    m.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
    m.extend_from_slice(&info_off.to_le_bytes());
    m.extend_from_slice(&[6, 1, 0, 0, 0, 0, 0, 15]); // Version (Windows-ish)
    m.extend_from_slice(&target_name);
    m.extend_from_slice(&target_info);
    m
}

/// The NTLMSSP NEGOTIATE (type 1) `NegotiateFlags` field, if `msg` is a well-formed
/// type-1 message. Used to log what a client offered so the CHALLENGE can echo a
/// compatible subset.
pub fn negotiate_flags(msg: &[u8]) -> Option<u32> {
    let pos = msg.windows(8).position(|w| w == b"NTLMSSP\0")?;
    let ty = msg.get(pos + 8..pos + 12)?;
    if u32::from_le_bytes([ty[0], ty[1], ty[2], ty[3]]) != 1 {
        return None;
    }
    let f = msg.get(pos + 12..pos + 16)?;
    Some(u32::from_le_bytes([f[0], f[1], f[2], f[3]]))
}

/// A CHALLENGE (NTLMSSP type 2) for the LDAP SASL (GSS-SPNEGO/raw NTLM) bind a
/// Windows domain-join client sends. Unlike the SMB session-setup (which real
/// Windows completes with only integrity implied), the LDAP client (wldap32,
/// "LDAP client signing") requires the negotiated context to support SIGN/SEAL and
/// abandons the bind — sending no AUTHENTICATE — if the CHALLENGE grants neither.
/// So this echoes the client's security flags (SIGN | SEAL | KEY_EXCH), committing
/// the connection to the NTLM sign+seal security layer on the PDUs that follow.
pub fn ldap_challenge_message() -> Vec<u8> {
    let flags = NTLMSSP_NEGOTIATE_UNICODE
        | NTLMSSP_REQUEST_TARGET
        | NTLMSSP_NEGOTIATE_SIGN
        | NTLMSSP_NEGOTIATE_SEAL
        | NTLMSSP_NEGOTIATE_NTLM
        | NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        | NTLMSSP_TARGET_TYPE_SERVER
        | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        | NTLMSSP_NEGOTIATE_TARGET_INFO
        | NTLMSSP_NEGOTIATE_VERSION
        | NTLMSSP_NEGOTIATE_128
        | NTLMSSP_NEGOTIATE_KEY_EXCH
        | NTLMSSP_NEGOTIATE_56;

    // Target info WITHOUT MsvAvTimestamp — matching the SMB CHALLENGE. Present it and
    // the client is obliged to compute an AUTHENTICATE MIC over the session; auth-only
    // binds don't need that, and its absence is what real Windows tolerates here.
    let mut target_info = Vec::new();
    target_info.extend(av_pair(AV_NB_COMPUTER, &utf16le("MAG")));
    target_info.extend(av_pair(AV_NB_DOMAIN, &utf16le("EXAMPLE")));
    target_info.extend(av_pair(AV_DNS_COMPUTER, &utf16le("mag.example.com")));
    target_info.extend(av_pair(AV_DNS_DOMAIN, &utf16le("example.com")));
    target_info.extend(av_pair(AV_EOL, &[]));
    let payload_off = 56u32; // fixed CHALLENGE fields; target name is empty

    let mut m = Vec::new();
    m.extend_from_slice(b"NTLMSSP\0");
    m.extend_from_slice(&2u32.to_le_bytes()); // MessageType = CHALLENGE
                                              // TargetNameFields: empty (the target info carries the names).
    m.extend_from_slice(&0u16.to_le_bytes());
    m.extend_from_slice(&0u16.to_le_bytes());
    m.extend_from_slice(&payload_off.to_le_bytes());
    m.extend_from_slice(&flags.to_le_bytes());
    m.extend_from_slice(&SERVER_CHALLENGE);
    m.extend_from_slice(&[0u8; 8]); // Reserved
                                    // TargetInfoFields.
    m.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
    m.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
    m.extend_from_slice(&payload_off.to_le_bytes());
    m.extend_from_slice(&[10, 0, 0, 0, 0, 0, 0, 15]); // Version (Windows 10, NTLM rev 15)
    m.extend_from_slice(&target_info);
    m
}

fn av_pair(id: u16, value: &[u8]) -> Vec<u8> {
    let mut v = id.to_le_bytes().to_vec();
    v.extend_from_slice(&(value.len() as u16).to_le_bytes());
    v.extend_from_slice(value);
    v
}

fn target_info_block() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&av_pair(AV_NB_COMPUTER, &utf16le("MAG")));
    b.extend_from_slice(&av_pair(AV_NB_DOMAIN, &utf16le("EXAMPLE")));
    b.extend_from_slice(&av_pair(AV_DNS_COMPUTER, &utf16le("mag.example.com")));
    b.extend_from_slice(&av_pair(AV_DNS_DOMAIN, &utf16le("example.com")));
    // A Windows client that signs the session needs the server timestamp to build
    // the AUTHENTICATE MIC (it echoes this whole block in its NTLMv2 response, so
    // the NTProofStr still verifies against the echoed temp).
    b.extend_from_slice(&av_pair(AV_TIMESTAMP, &now_filetime()));
    b.extend_from_slice(&av_pair(AV_EOL, &[]));
    b
}

/// Read an NTLMSSP "field" (Len, MaxLen, Offset) at `pos` and slice the payload.
fn field(msg: &[u8], pos: usize) -> Option<&[u8]> {
    let len = u16::from_le_bytes([*msg.get(pos)?, *msg.get(pos + 1)?]) as usize;
    let off = u32::from_le_bytes([
        *msg.get(pos + 4)?,
        *msg.get(pos + 5)?,
        *msg.get(pos + 6)?,
        *msg.get(pos + 7)?,
    ]) as usize;
    msg.get(off..off + len)
}

/// The account (`UserName`) an NTLMSSP AUTHENTICATE (type 3) is for — used to look
/// up the user's NT hash before verifying the proof. `None` if the blob is not a
/// well-formed AUTHENTICATE.
pub fn ntlm_username(authenticate: &[u8]) -> Option<String> {
    if authenticate.len() < 64 || &authenticate[0..8] != b"NTLMSSP\0" {
        return None;
    }
    let user = field(authenticate, 36)?;
    Some(String::from_utf16_lossy(
        &user
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect::<Vec<_>>(),
    ))
}

/// The negotiated NTLM security context: the exported session key plus the
/// per-direction signing keys and RC4 handles.
pub struct NtlmContext {
    session_key: [u8; 16],
    /// The NTLMv2 session base key (`KeyExchangeKey`) — the pre-KEY_EXCH key. Some
    /// callers (e.g. the SAMR password buffer) may key off this rather than the
    /// exported key; retained here so it can be queried.
    session_base_key: [u8; 16],
    client_sign: [u8; 16],
    server_sign: [u8; 16],
    client_rc4: Rc4,
    server_rc4: Rc4,
    /// Outbound (server→client) sequence for the SASL security layer.
    send_seq: u32,
    /// Inbound (client→server) sequence for the SASL security layer.
    recv_seq: u32,
}

fn sign_key(session_key: &[u8; 16], server: bool) -> [u8; 16] {
    let magic: &[u8] = if server {
        b"session key to server-to-client signing key magic constant\x00"
    } else {
        b"session key to client-to-server signing key magic constant\x00"
    };
    md5(&[session_key, magic])
}

fn seal_key(session_key: &[u8; 16], server: bool) -> [u8; 16] {
    // NTLMSSP_NEGOTIATE_128 → the full session key seeds the seal key.
    let magic: &[u8] = if server {
        b"session key to server-to-client sealing key magic constant\x00"
    } else {
        b"session key to client-to-server sealing key magic constant\x00"
    };
    md5(&[session_key, magic])
}

impl NtlmContext {
    /// Verify an AUTHENTICATE (type 3) against `nt_hash` and derive the context,
    /// using this crate's fixed server challenge (the DCE/RPC path).
    /// Returns `None` if the NTLMv2 proof does not verify.
    pub fn establish(nt_hash: &[u8; 16], authenticate: &[u8]) -> Option<Self> {
        Self::establish_with_challenge(nt_hash, authenticate, &SERVER_CHALLENGE)
    }

    /// As [`Self::establish`], but with the explicit 8-byte `server_challenge` that
    /// was placed in the NTLM CHALLENGE. The SMB session-setup path uses its own
    /// challenge (distinct from this crate's RPC one), so it must verify the NTLMv2
    /// proof against that same value. Returns `None` if the proof does not verify.
    pub fn establish_with_challenge(
        nt_hash: &[u8; 16],
        authenticate: &[u8],
        server_challenge: &[u8; 8],
    ) -> Option<Self> {
        if authenticate.len() < 64 || &authenticate[0..8] != b"NTLMSSP\0" {
            return None;
        }
        let nt_response = field(authenticate, 20)?; // NtChallengeResponse
        let enc_random_key = field(authenticate, 52)?; // EncryptedRandomSessionKey
        let domain = field(authenticate, 28).unwrap_or(&[]);
        let user = field(authenticate, 36).unwrap_or(&[]);
        let flags = u32::from_le_bytes(authenticate[60..64].try_into().ok()?);

        if nt_response.len() < 16 {
            return None;
        }
        let (nt_proof, temp) = nt_response.split_at(16);
        let user = String::from_utf16_lossy(
            &user
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect::<Vec<_>>(),
        );
        let domain = String::from_utf16_lossy(
            &domain
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect::<Vec<_>>(),
        );

        // Verify the NTLMv2 proof, then derive the session base key.
        let ntowf = ntowf_v2(nt_hash, &user, &domain);
        let mut proof_input = server_challenge.to_vec();
        proof_input.extend_from_slice(temp);
        let computed = hmac_md5(&ntowf, &proof_input);
        if computed != *nt_proof {
            return None;
        }
        let session_base_key = hmac_md5(&ntowf, nt_proof);

        // Key exchange: the exported key is the client's random key, RC4-wrapped
        // under the base key.
        let session_key = if flags & NTLMSSP_NEGOTIATE_KEY_EXCH != 0 && enc_random_key.len() == 16 {
            let mut out = [0u8; 16];
            out.copy_from_slice(&Rc4::new(&session_base_key).apply(enc_random_key));
            out
        } else {
            session_base_key
        };

        Some(Self {
            session_key,
            session_base_key,
            client_sign: sign_key(&session_key, false),
            server_sign: sign_key(&session_key, true),
            client_rc4: Rc4::new(&seal_key(&session_key, false)),
            server_rc4: Rc4::new(&seal_key(&session_key, true)),
            send_seq: 0,
            recv_seq: 0,
        })
    }

    /// The exported session key (`get_session_key`) — used to encrypt secrets.
    pub fn session_key(&self) -> [u8; 16] {
        self.session_key
    }

    /// The NTLMv2 session base key (`KeyExchangeKey`).
    pub fn session_base_key(&self) -> [u8; 16] {
        self.session_base_key
    }

    /// Build the 16-byte NTLM message signature for `message` at `seq`, using the
    /// given signing key and RC4 handle (extended session security).
    fn make_signature(sign_key: &[u8; 16], rc4: &mut Rc4, seq: u32, message: &[u8]) -> [u8; 16] {
        let mut hmac_input = seq.to_le_bytes().to_vec();
        hmac_input.extend_from_slice(message);
        let checksum = &hmac_md5(sign_key, &hmac_input)[..8];
        let enc_checksum = rc4.apply(checksum);

        let mut sig = Vec::with_capacity(16);
        sig.extend_from_slice(&1u32.to_le_bytes()); // Version
        sig.extend_from_slice(&enc_checksum); // Checksum (RC4-encrypted)
        sig.extend_from_slice(&seq.to_le_bytes()); // SeqNum
        sig.try_into().expect("16-byte signature")
    }

    /// Verify a client REQUEST signature over `message`. With extended session
    /// security the client signs the whole PDU minus the 16-byte signature, so
    /// `message` must be exactly those bytes. The sequence is read from the
    /// signature. Advances the client RC4 handle.
    pub fn verify_request(&mut self, message: &[u8], signature: &[u8]) -> Option<u32> {
        if signature.len() != 16 {
            return None;
        }
        let seq = u32::from_le_bytes(signature[12..16].try_into().ok()?);
        let expected = Self::make_signature(&self.client_sign, &mut self.client_rc4, seq, message);
        (expected == signature).then_some(seq)
    }

    /// Sign a server RESPONSE over `stub` at `seq`. Advances the server RC4 handle.
    pub fn sign_response(&mut self, stub: &[u8], seq: u32) -> [u8; 16] {
        Self::make_signature(&self.server_sign, &mut self.server_rc4, seq, stub)
    }

    /// Seal (encrypt + sign) an outbound message for the SASL security layer
    /// (server → client). Returns `signature(16) ‖ sealed`. With extended session
    /// security the message is RC4-sealed first, then the MAC's checksum is RC4'd
    /// with the SAME handle (MS-NLMP §3.4.3), so the order here is load-bearing.
    /// Advances the server RC4 handle and the outbound sequence.
    pub fn seal(&mut self, message: &[u8]) -> Vec<u8> {
        let seq = self.send_seq;
        self.send_seq = self.send_seq.wrapping_add(1);
        let sealed = self.server_rc4.apply(message);
        let sig = Self::make_signature(&self.server_sign, &mut self.server_rc4, seq, message);
        let mut out = Vec::with_capacity(16 + sealed.len());
        out.extend_from_slice(&sig);
        out.extend_from_slice(&sealed);
        out
    }

    /// Unseal (decrypt + verify) an inbound `signature(16) ‖ sealed` token from the
    /// SASL security layer (client → server). Returns the plaintext, or `None` if the
    /// signature does not verify. Advances the client RC4 handle and inbound sequence.
    pub fn unseal(&mut self, token: &[u8]) -> Option<Vec<u8>> {
        if token.len() < 16 {
            return None;
        }
        let (sig, sealed) = token.split_at(16);
        let seq = self.recv_seq;
        let plaintext = self.client_rc4.apply(sealed);
        let expected =
            Self::make_signature(&self.client_sign, &mut self.client_rc4, seq, &plaintext);
        if sig != expected {
            return None;
        }
        self.recv_seq = self.recv_seq.wrapping_add(1);
        Some(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "password12";

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn ntlm_key_derivation_matches_impacket() {
        // Ground truth captured from impacket (recon_ntlm_gt.py).
        assert_eq!(hex(&nt_hash(PW)), "1b62018f0d05c737d06402294ce24236");
        let ntowf = ntowf_v2(&nt_hash(PW), "alice", "EXAMPLE");
        assert_eq!(hex(&ntowf), "9be533b6c7955892710ee1b6740497d7");

        // exportedSessionKey → signing/sealing keys (server direction).
        let exported = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        assert_eq!(
            hex(&sign_key(&exported, true)),
            "a41728da3dccb9f2b2cecffb31bdb3c5"
        );
        assert_eq!(
            hex(&seal_key(&exported, true)),
            "675b8f4b00b575c663a7aa96c2acc571"
        );
    }

    #[test]
    fn key_exchange_recovers_exported_key() {
        // Given the session base key, RC4-decrypt the client's wrapped key.
        let base = [
            0x72, 0x95, 0xb4, 0x03, 0x65, 0x0f, 0x1f, 0xa6, 0x17, 0xb0, 0x69, 0x51, 0x6d, 0x1b,
            0x64, 0x8f,
        ];
        let enc = [
            0x62, 0xac, 0x3b, 0xaf, 0x05, 0xdf, 0x53, 0x4a, 0xf6, 0xce, 0xd2, 0x1f, 0xf2, 0x47,
            0x73, 0xdd,
        ];
        let recovered = Rc4::new(&base).apply(&enc);
        assert_eq!(hex(&recovered), "11223344556677889900aabbccddeeff");
    }

    #[test]
    fn signature_round_trips_between_directions() {
        // A context built from a known session key signs and verifies coherently.
        let sk = [7u8; 16];
        let mut server = ctx(sk);
        let mut client = ctx(sk);
        // The "client" produces a request signature; the "server" verifies it by
        // treating its client keys/handle identically.
        let stub = b"drs get-nc-changes stub";
        let sig = NtlmContext::make_signature(&client.client_sign, &mut client.client_rc4, 0, stub);
        assert_eq!(server.verify_request(stub, &sig), Some(0));
        // Tampering fails.
        let mut server2 = ctx(sk);
        assert_eq!(server2.verify_request(b"tampered", &sig), None);
    }

    fn ctx(session_key: [u8; 16]) -> NtlmContext {
        NtlmContext {
            session_key,
            session_base_key: session_key,
            client_sign: sign_key(&session_key, false),
            server_sign: sign_key(&session_key, true),
            client_rc4: Rc4::new(&seal_key(&session_key, false)),
            server_rc4: Rc4::new(&seal_key(&session_key, true)),
            send_seq: 0,
            recv_seq: 0,
        }
    }

    #[test]
    fn seal_then_unseal_round_trips_across_a_peer() {
        // The server seals server→client; a mirror context (client keys swapped in)
        // reproduces the peer that unseals it, proving the sign+seal wire format and
        // the RC4/HMAC ordering are self-consistent.
        let key = [7u8; 16];
        let mut server = ctx(key);
        // The peer's client_rc4/client_sign must equal our server_rc4/server_sign so
        // it can open what we sealed; build it by swapping the direction bit.
        let mut peer = NtlmContext {
            session_key: key,
            session_base_key: key,
            client_sign: sign_key(&key, true),
            server_sign: sign_key(&key, false),
            client_rc4: Rc4::new(&seal_key(&key, true)),
            server_rc4: Rc4::new(&seal_key(&key, false)),
            send_seq: 0,
            recv_seq: 0,
        };
        let msg = b"\x30\x0c\x02\x01\x02\x60\x07\x02\x01\x03\x04\x00\x80\x00";
        let sealed = server.seal(msg);
        assert_eq!(
            &sealed[0..4],
            &[1, 0, 0, 0],
            "signature (version 1) comes first"
        );
        assert_eq!(peer.unseal(&sealed).as_deref(), Some(&msg[..]));
        // A second message advances both sequences and still round-trips.
        let sealed2 = server.seal(msg);
        assert_ne!(sealed, sealed2, "a new sequence changes the ciphertext");
        assert_eq!(peer.unseal(&sealed2).as_deref(), Some(&msg[..]));
    }

    #[test]
    fn challenge_is_well_formed() {
        let c = challenge_message();
        assert_eq!(&c[0..8], b"NTLMSSP\0");
        assert_eq!(
            u32::from_le_bytes(c[8..12].try_into().unwrap()),
            2,
            "CHALLENGE"
        );
        // The server challenge appears at offset 24.
        assert_eq!(&c[24..32], &SERVER_CHALLENGE);
    }
}
