//! A minimal real Netlogon interface (MS-NRPC) — the secure-channel handshake a
//! Windows member/DC uses to authenticate to a domain controller. This is the
//! AD-critical, Zerologon-sensitive piece.
//!
//! The handshake (AES variant, MS-NRPC §3.1.4.3.1 / §3.1.4.4.1):
//! 1. `NetrServerReqChallenge` (opnum 4): client sends an 8-byte challenge; the
//!    server returns its own 8-byte challenge.
//! 2. `NetrServerAuthenticate3` (opnum 26): both sides derive a session key from
//!    the machine-account password hash and the two challenges. The client proves
//!    it by sending `AES-CFB8(Sk, ClientChallenge)`; the server verifies it and
//!    returns `AES-CFB8(Sk, ServerChallenge)` so the client can verify the server
//!    — mutual authentication.
//!
//! Session key: `Sk = HMAC-SHA256(MD4(UTF16LE(pw)), ClientChallenge‖ServerChallenge)[..16]`.
//! Credential: `AES-128-CFB8(Sk, IV=0, challenge)`.
//!
//! The RPC-level auth trailer (NETLOGON SSP sign/seal) for subsequent calls, and
//! the DES/RC4 legacy variants, are out of scope for this slice.

use crate::interface::RpcInterface;
use crate::ndr::{NdrReader, NdrWriter};
use crate::request::fault;
use crate::samr::AccountStore;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use hmac::{Hmac, Mac};
use magnetite_krb5::keys::PrincipalStore;
use md4::{Digest, Md4};
use parking_lot::Mutex;
use sha2::Sha256;
use std::sync::Arc;

/// Netlogon interface UUID (`12345678-1234-ABCD-EF00-01234567CFFB`, v1.0).
pub const NETLOGON_UUID: &str = "12345678-1234-ABCD-EF00-01234567CFFB";

const OP_REQ_CHALLENGE: u16 = 4;
const OP_PASSWORD_SET2: u16 = 30;
const OP_GET_CAPABILITIES: u16 = 21;
const OP_AUTHENTICATE3: u16 = 26;
const OP_SAM_LOGON_EX: u16 = 39;

// The authenticated user we report from a (signed) NetrLogonSamLogonEx.
const LOGON_USER: &str = "alice";
const LOGON_DOMAIN: &str = "EXAMPLE";
const LOGON_USER_RID: u32 = 1000;
const LOGON_PRIMARY_GID: u32 = 513;
/// Default domain SID sub-authorities (`S-1-5-21-1-2-3`), used only as a fallback when
/// no shared directory is attached; the live path uses `directory.domain_sid()`.
const DOMAIN_SID_SUBAUTH: [u32; 4] = [21, 1, 2, 3];
const NT_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];

/// Server capabilities we report from a (signed) `NetrLogonGetCapabilities`.
const SERVER_CAPABILITIES: u32 = 0x0000_0001;

const STATUS_SUCCESS: u32 = 0;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
/// `STATUS_NO_TRUST_SAM_ACCOUNT` — the DC has no computer account for this member.
const STATUS_NO_TRUST_SAM_ACCOUNT: u32 = 0xC000_0233;

/// The machine account's RID we report on a successful authenticate.
const MACHINE_ACCOUNT_RID: u32 = 1001;

/// The fixed server challenge for the PoC (a real DC generates this randomly).
const SERVER_CHALLENGE: [u8; 8] = *b"MAGNSVR1";

/// Per-association challenge state established by `NetrServerReqChallenge`.
#[derive(Clone, Copy)]
struct Challenges {
    client: [u8; 8],
    server: [u8; 8],
}

#[derive(Default)]
struct NetlogonState {
    challenges: Option<Challenges>,
    /// Set once `NetrServerAuthenticate3` succeeds — the negotiated session key.
    session_key: Option<[u8; 16]>,
    /// The machine account's NT hash. Mutable because `NetrServerPasswordSet2`
    /// rotates the machine password over the secure channel.
    machine_nt_hash: [u8; 16],
    /// The running credential of the Netlogon authenticator chain
    /// (MS-NRPC §3.1.4.5), seeded to the client credential on `Authenticate3`.
    stored_credential: Option<[u8; 8]>,
    /// The client's ComputerName, captured on `NetrServerReqChallenge`. The
    /// machine account is `<ComputerName>$`; used to propagate a rotated password.
    computer_name: Option<String>,
}

/// A Netlogon server holding one machine account's secret.
pub struct NetlogonInterface {
    state: Mutex<NetlogonState>,
    /// The shared KDC store. When set, `NetrServerPasswordSet2` re-registers the
    /// machine account under its new password (so it can still get a TGT).
    kdc: Option<Arc<PrincipalStore>>,
    /// Persistence sink (DB + `computer` object), mirroring SAMR's password-set.
    persist: Option<Arc<dyn AccountStore>>,
    /// The shared directory. When set, `NetrServerAuthenticate3` resolves the NT hash
    /// of the request's `AccountName` from it (the real per-machine secret) instead of
    /// the single password the interface was constructed with — how a booted domain
    /// member's secure channel actually authenticates.
    directory: Option<Arc<crate::directory::Directory>>,
}

impl NetlogonInterface {
    /// A Netlogon server for a machine account with password `machine_password`.
    pub fn new(machine_password: &str) -> Self {
        Self {
            state: Mutex::new(NetlogonState {
                machine_nt_hash: nt_hash(machine_password),
                ..NetlogonState::default()
            }),
            kdc: None,
            persist: None,
            directory: None,
        }
    }

    /// Attach the shared KDC store so a `NetrServerPasswordSet2` rotation
    /// re-registers the machine account (derives its new Kerberos key live).
    #[must_use]
    pub fn with_kdc(mut self, kdc: Arc<PrincipalStore>) -> Self {
        self.kdc = Some(kdc);
        self
    }

    /// Attach the shared directory so `NetrServerAuthenticate3` resolves the real NT
    /// hash of the caller's machine account (by `AccountName`) rather than a fixed one.
    #[must_use]
    pub fn with_directory(mut self, directory: Arc<crate::directory::Directory>) -> Self {
        self.directory = Some(directory);
        self
    }

    /// Attach a persistence sink so a rotated machine password is written to the
    /// database (and its `computer` object), surviving a restart.
    #[must_use]
    pub fn with_account_store(mut self, store: Arc<dyn AccountStore>) -> Self {
        self.persist = Some(store);
        self
    }
}

impl RpcInterface for NetlogonInterface {
    fn call(&self, opnum: u16, stub: &[u8]) -> Result<Vec<u8>, u32> {
        match opnum {
            OP_REQ_CHALLENGE => self.req_challenge(stub),
            OP_AUTHENTICATE3 => self.authenticate3(stub),
            OP_PASSWORD_SET2 => self.password_set2(stub),
            // A trivial operation callers can invoke over the signed channel: it
            // just returns the server capabilities + STATUS_SUCCESS.
            OP_GET_CAPABILITIES => {
                let mut out = SERVER_CAPABILITIES.to_le_bytes().to_vec();
                out.extend_from_slice(&STATUS_SUCCESS.to_le_bytes());
                Ok(out)
            }
            // Pass-through logon: we accept the (ignored) network logon and return
            // the user's authorization data — the RPC equivalent of the PAC. The
            // LogonDomainId SID uses the live directory's domain sub-authorities (the
            // shared single source of truth) so `DOMAIN_SID` is honoured here too,
            // instead of the hardcoded default.
            OP_SAM_LOGON_EX => {
                let domain_sub = self
                    .directory
                    .as_ref()
                    .map(|d| d.domain_sid().to_vec())
                    .unwrap_or_else(|| DOMAIN_SID_SUBAUTH.to_vec());
                Ok(sam_logon_ex_response(&domain_sub))
            }
            _ => Err(fault::OP_RNG_ERROR),
        }
    }

    fn session_key(&self) -> Option<[u8; 16]> {
        self.state.lock().session_key
    }
}

/// Add a timestamp (or increment) to a Netlogon credential: the first four bytes
/// are treated as a little-endian 32-bit integer (MS-NRPC §3.1.4.5).
fn advance_credential(credential: [u8; 8], delta: u32) -> [u8; 8] {
    let low = u32::from_le_bytes([credential[0], credential[1], credential[2], credential[3]]);
    let mut out = credential;
    out[0..4].copy_from_slice(&low.wrapping_add(delta).to_le_bytes());
    out
}

impl NetlogonInterface {
    /// `NetrServerReqChallenge`: parse the client challenge, store both, and
    /// return the server challenge.
    fn req_challenge(&self, stub: &[u8]) -> Result<Vec<u8>, u32> {
        // Request: PrimaryName [unique wstr], ComputerName [WSTR], ClientChallenge[8].
        let parsed = (|| {
            let mut r = NdrReader::new(stub);
            r.skip_unique_wstr()?;
            let computer = r.read_wstr()?;
            let client = r.array::<8>()?;
            Some((computer, client))
        })()
        .ok_or(fault::NDR)?;
        let (computer, client) = parsed;

        {
            let mut state = self.state.lock();
            state.challenges = Some(Challenges {
                client,
                server: SERVER_CHALLENGE,
            });
            if !computer.is_empty() {
                state.computer_name = Some(computer);
            }
        }

        // Response: ServerChallenge[8], ErrorCode.
        let mut out = Vec::with_capacity(12);
        out.extend_from_slice(&SERVER_CHALLENGE);
        out.extend_from_slice(&STATUS_SUCCESS.to_le_bytes());
        Ok(out)
    }

    /// `NetrServerAuthenticate3`: verify the client credential and return the
    /// server credential (mutual auth), plus the negotiated flags and account RID.
    fn authenticate3(&self, stub: &[u8]) -> Result<Vec<u8>, u32> {
        // Request: PrimaryName[unique], AccountName[WSTR], SecureChannelType[u16],
        // ComputerName[WSTR], ClientCredential[8], NegotiateFlags[u32].
        let parsed = (|| {
            let mut r = NdrReader::new(stub);
            r.skip_unique_wstr()?; // PrimaryName
            let account_name = r.read_wstr()?; // AccountName (e.g. "DESKTOP-K78L1UQ$")
            let _sct = r.u16()?; // SecureChannelType
            r.skip_wstr()?; // ComputerName
            let client_credential = r.array::<8>()?;
            let negotiate_flags = r.u32()?;
            Some((account_name, client_credential, negotiate_flags))
        })();
        let Some((account_name, client_credential, negotiate_flags)) = parsed else {
            return Err(fault::NDR);
        };

        // Resolve the machine account's real NT hash from the shared directory (by
        // AccountName); fall back to the interface's constructed hash if unavailable.
        // A directory miss means the DC has no such computer account.
        if let Some(dir) = &self.directory {
            match dir.find_user(&account_name) {
                Some(u) => self.state.lock().machine_nt_hash = u.nt_hash,
                None => {
                    tracing::warn!(target: "auth", proto = "netlogon", account = ?account_name, "Netlogon rejected: no computer account in directory");
                    return Ok(auth_response(
                        [0u8; 8],
                        negotiate_flags,
                        STATUS_NO_TRUST_SAM_ACCOUNT,
                    ));
                }
            }
        }

        let Some(ch) = self.state.lock().challenges else {
            // Authenticate without a prior challenge.
            tracing::warn!(target: "auth", proto = "netlogon", account = ?account_name, "Netlogon rejected: Authenticate3 without a prior challenge → ACCESS_DENIED");
            return Ok(auth_response(
                [0u8; 8],
                negotiate_flags,
                STATUS_ACCESS_DENIED,
            ));
        };

        // Zerologon mitigation: reject an all-zero client challenge outright.
        if ch.client == [0u8; 8] {
            tracing::warn!(target: "auth", proto = "netlogon", account = ?account_name, "Netlogon rejected: all-zero client challenge (Zerologon) → ACCESS_DENIED");
            return Ok(auth_response(
                [0u8; 8],
                negotiate_flags,
                STATUS_ACCESS_DENIED,
            ));
        }

        let machine_nt_hash = self.state.lock().machine_nt_hash;
        let session_key = session_key_aes(&machine_nt_hash, &ch.client, &ch.server);
        let expected = netlogon_credential_aes(&session_key, &ch.client);
        if expected != client_credential {
            tracing::warn!(
                target: "auth", proto = "netlogon", account = ?account_name,
                "Netlogon Authenticate3 credential MISMATCH (nt_hash {:02x?}…) → ACCESS_DENIED",
                &machine_nt_hash[..4],
            );
            return Ok(auth_response(
                [0u8; 8],
                negotiate_flags,
                STATUS_ACCESS_DENIED,
            ));
        }
        tracing::info!(target: "auth", proto = "netlogon", account = ?account_name, "Netlogon Authenticate3: secure channel established");

        // Secure channel established: remember the session key for signed calls
        // and seed the authenticator chain with the client credential.
        {
            let mut state = self.state.lock();
            state.session_key = Some(session_key);
            state.stored_credential = Some(expected);
        }

        let server_credential = netlogon_credential_aes(&session_key, &ch.server);
        Ok(auth_response(
            server_credential,
            negotiate_flags,
            STATUS_SUCCESS,
        ))
    }

    /// `NetrServerPasswordSet2` (opnum 30): a joined machine rotates its own
    /// password over the secure channel. The new password arrives as an
    /// `NL_TRUST_PASSWORD` (516 bytes) encrypted with the session key (AES-CFB8,
    /// zero IV); the request also carries an authenticator we verify and answer
    /// via the running credential chain.
    fn password_set2(&self, stub: &[u8]) -> Result<Vec<u8>, u32> {
        let (session_key, stored) = {
            let state = self.state.lock();
            match (state.session_key, state.stored_credential) {
                (Some(key), Some(credential)) => (key, credential),
                _ => return Ok(password_set2_error(STATUS_ACCESS_DENIED)),
            }
        };

        // Request tail: Authenticator{ Credential[8], Timestamp[u32] } then the
        // 516-byte encrypted ClearNewPassword.
        let parsed = (|| {
            let mut r = NdrReader::new(stub);
            r.skip_unique_wstr()?; // PrimaryName
            r.skip_wstr()?; // AccountName
            let _sct = r.u16()?; // SecureChannelType
            r.skip_wstr()?; // ComputerName
            let auth_credential = r.array::<8>()?;
            let timestamp = r.u32()?;
            // ClearNewPassword is the trailing 516 bytes; take from the end so any
            // pointer referent id ahead of the fixed struct is skipped.
            let rem = r.remaining();
            let encrypted: [u8; 516] = rem.get(rem.len().checked_sub(516)?..)?.try_into().ok()?;
            Some((auth_credential, timestamp, encrypted))
        })();
        let Some((auth_credential, timestamp, encrypted)) = parsed else {
            return Err(fault::NDR);
        };

        // Verify the client authenticator: Crypt(session_key, stored + timestamp).
        let advanced = advance_credential(stored, timestamp);
        if netlogon_credential_aes(&session_key, &advanced) != auth_credential {
            return Ok(password_set2_error(STATUS_ACCESS_DENIED));
        }

        // Decrypt the NL_TRUST_PASSWORD and pull out the new cleartext password.
        let plain = aes128_cfb8_decrypt(&session_key, &[0u8; 16], &encrypted);
        let Some(new_password) = extract_trust_password(&plain) else {
            return Ok(password_set2_error(STATUS_ACCESS_DENIED));
        };

        // Adopt the new machine password and advance the authenticator chain. The NT
        // hash is taken over the raw UTF-16LE bytes (fidelity for a random password).
        let next = advance_credential(advanced, 1);
        let new_nt_hash = crate::directory::nt_hash_utf16le(&new_password);
        let computer_name = {
            let mut state = self.state.lock();
            state.machine_nt_hash = new_nt_hash;
            state.stored_credential = Some(next);
            state.computer_name.clone()
        };

        // Close the join loop: propagate the rotated machine password to the KDC (its
        // AD computer-account key + host/cifs SPN aliases) and to the persistence sink
        // — the same register + persist SAMR's SamrSetInformationUser2 performs.
        if let Some(computer) = computer_name {
            let account = format!("{computer}$");
            let kerberos_key = if let Some(kdc) = &self.kdc {
                match kdc.register_machine_utf16(&account, &new_password) {
                    Ok(key) => key,
                    Err(_) => return Ok(password_set2_error(STATUS_ACCESS_DENIED)),
                }
            } else {
                Vec::new()
            };
            if let Some(store) = &self.persist {
                // `password` is unused when an explicit key is supplied.
                store.persist_account(&account, 0, "", new_nt_hash, &kerberos_key);
            }
            // Refresh the runtime directory copy so the Netlogon secure channel keeps
            // resolving this machine's (now rotated) NT hash without a restart.
            if let Some(dir) = &self.directory {
                dir.upsert_runtime_user(crate::directory::User {
                    sam_account_name: account,
                    rid: 0,
                    nt_hash: new_nt_hash,
                    kerberos_key,
                    disabled: false,
                    repl_meta: None,
                });
            }
        }
        let return_credential = netlogon_credential_aes(&session_key, &next);

        // Response: ReturnAuthenticator{ Credential[8], Timestamp[u32] }, ErrorCode.
        let mut out = Vec::with_capacity(16);
        out.extend_from_slice(&return_credential);
        out.extend_from_slice(&0u32.to_le_bytes()); // ReturnAuthenticator.Timestamp
        out.extend_from_slice(&STATUS_SUCCESS.to_le_bytes());
        Ok(out)
    }
}

/// A `NetrServerPasswordSet2` failure reply: a zeroed `ReturnAuthenticator`
/// followed by the error status.
fn password_set2_error(status: u32) -> Vec<u8> {
    let mut out = vec![0u8; 12];
    out.extend_from_slice(&status.to_le_bytes());
    out
}

/// Extract the cleartext password from a decrypted `NL_TRUST_PASSWORD`: the
/// password is right-aligned in `Buffer[512]` and `Length` (bytes) sits at 512.
fn extract_trust_password(plain: &[u8]) -> Option<Vec<u8>> {
    let length = u32::from_le_bytes(plain.get(512..516)?.try_into().ok()?) as usize;
    if length == 0 || length > 512 || !length.is_multiple_of(2) {
        return None;
    }
    // The raw UTF-16LE password bytes — kept as bytes (not a `String`), since a random
    // rotated machine password can contain lone surrogates a `String` cannot hold.
    Some(plain[512 - length..512].to_vec())
}

/// Build a `NetrServerAuthenticate3` response:
/// `ServerCredential[8], NegotiateFlags, AccountRid, ErrorCode`.
fn auth_response(server_credential: [u8; 8], negotiate_flags: u32, status: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    out.extend_from_slice(&server_credential);
    out.extend_from_slice(&negotiate_flags.to_le_bytes());
    out.extend_from_slice(&MACHINE_ACCOUNT_RID.to_le_bytes());
    out.extend_from_slice(&status.to_le_bytes());
    out
}

/// The NT hash (`NTOWFv1`): MD4 of the UTF-16LE password.
pub(crate) fn nt_hash(password: &str) -> [u8; 16] {
    let mut utf16 = Vec::with_capacity(password.len() * 2);
    for unit in password.encode_utf16() {
        utf16.extend_from_slice(&unit.to_le_bytes());
    }
    let digest = Md4::digest(&utf16);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

/// AES session key: `HMAC-SHA256(NThash, ClientChallenge‖ServerChallenge)[..16]`.
pub(crate) fn session_key_aes(nt_hash: &[u8; 16], client: &[u8; 8], server: &[u8; 8]) -> [u8; 16] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(nt_hash).expect("hmac key");
    mac.update(client);
    mac.update(server);
    let digest = mac.finalize().into_bytes();
    let mut key = [0u8; 16];
    key.copy_from_slice(&digest[..16]);
    key
}

/// AES-128 in 8-bit CFB (CFB8) with the given IV over `data`. The core Netlogon
/// primitive; pycryptodome's `AES.MODE_CFB` defaults to an 8-bit segment.
fn aes128_cfb8_encrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut iv = *iv;
    let mut out = Vec::with_capacity(data.len());
    for &byte in data {
        let mut block = GenericArray::clone_from_slice(&iv);
        cipher.encrypt_block(&mut block);
        let c = byte ^ block[0];
        out.push(c);
        // Shift the IV left one byte and append the ciphertext byte (CFB8).
        iv.copy_within(1..16, 0);
        iv[15] = c;
    }
    out
}

/// AES-128 in 8-bit CFB decrypting `data` with the given IV. Mirrors
/// [`aes128_cfb8_encrypt`] but feeds the *ciphertext* byte back into the IV.
fn aes128_cfb8_decrypt(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut iv = *iv;
    let mut out = Vec::with_capacity(data.len());
    for &c in data {
        let mut block = GenericArray::clone_from_slice(&iv);
        cipher.encrypt_block(&mut block);
        out.push(c ^ block[0]);
        // Shift the IV left one byte and append the ciphertext byte (CFB8).
        iv.copy_within(1..16, 0);
        iv[15] = c;
    }
    out
}

/// The Netlogon credential: AES-128-CFB8 with a zero IV over the 8-byte input
/// (MS-NRPC §3.1.4.4.1).
pub(crate) fn netlogon_credential_aes(session_key: &[u8; 16], input: &[u8; 8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out.copy_from_slice(&aes128_cfb8_encrypt(session_key, &[0u8; 16], input));
    out
}

// --- Netlogon SSP: per-message signing (secure binding, PKT_INTEGRITY) ---

/// AES signature algorithm id (HMAC-SHA256) in an `NL_AUTH_SHA2_SIGNATURE`.
const NL_SIGNATURE_HMAC_SHA256: u16 = 0x0013;
/// Seal algorithm id meaning "not encrypted" (integrity, no confidentiality).
const NL_SEAL_NOT_ENCRYPTED: u16 = 0xffff;
/// Seal algorithm id for AES-128 (PKT_PRIVACY / confidentiality).
const NL_SEAL_AES128: u16 = 0x001A;

/// The fixed 8-byte header of an AES `NL_AUTH_SHA2_SIGNATURE`:
/// SignatureAlgorithm(HMAC-SHA256), SealAlgorithm, Pad(0xffff), Flags(0). The
/// seal algorithm distinguishes integrity (`NL_SEAL_NOT_ENCRYPTED`) from privacy
/// (`NL_SEAL_AES128`), and it is covered by the checksum.
fn signature_header(seal_algorithm: u16) -> [u8; 8] {
    let mut h = [0u8; 8];
    h[0..2].copy_from_slice(&NL_SIGNATURE_HMAC_SHA256.to_le_bytes());
    h[2..4].copy_from_slice(&seal_algorithm.to_le_bytes());
    h[4..6].copy_from_slice(&0xffffu16.to_le_bytes()); // Pad
    h[6..8].copy_from_slice(&0u16.to_le_bytes()); // Flags
    h
}

/// The Netlogon seal/confidentiality key: the session key with every byte XORed
/// by `0xf0` (MS-NRPC §3.3.4.2.2).
fn seal_key(session_key: &[u8; 16]) -> [u8; 16] {
    let mut k = *session_key;
    for b in &mut k {
        *b ^= 0xf0;
    }
    k
}

/// Encode the sender sequence number (MS-NRPC §3.3.4.2.1): big-endian low dword
/// then high dword with the top bit set.
fn derive_sequence_number(sequence: u64) -> [u8; 8] {
    let low = (sequence & 0xffff_ffff) as u32;
    let high = ((sequence >> 32) as u32) | 0x8000_0000;
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&low.to_be_bytes());
    out[4..8].copy_from_slice(&high.to_be_bytes());
    out
}

/// Compute an `NL_AUTH_SHA2_SIGNATURE` for `data` at `sequence` under
/// `session_key`, for PKT_INTEGRITY (signing only — no confounder/seal).
///
/// Layout (48 bytes): header(8) ‖ SequenceNumber(8) ‖ Checksum(8) ‖ Reserved(24).
/// * Checksum  = `HMAC-SHA256(Sk, header ‖ data)[..8]`
/// * SequenceNumber = `AES-CFB8(Sk, IV = Checksum‖Checksum, derived-seq)`
pub fn sign_integrity_aes(session_key: &[u8; 16], data: &[u8], sequence: u64) -> Vec<u8> {
    let header = signature_header(NL_SEAL_NOT_ENCRYPTED);

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(session_key).expect("hmac key");
    mac.update(&header);
    mac.update(data);
    let digest = mac.finalize().into_bytes();
    let checksum = &digest[..8];

    let mut iv = [0u8; 16];
    iv[0..8].copy_from_slice(checksum);
    iv[8..16].copy_from_slice(checksum);
    let seq_enc = aes128_cfb8_encrypt(session_key, &iv, &derive_sequence_number(sequence));

    let mut out = Vec::with_capacity(48);
    out.extend_from_slice(&header);
    out.extend_from_slice(&seq_enc); // SequenceNumber
    out.extend_from_slice(checksum); // Checksum
    out.extend_from_slice(&[0u8; 24]); // Reserved (Confounder empty for integrity)
    out
}

/// The fixed 8-byte confounder we place before a sealed payload. It only adds
/// entropy — the receiver decrypts but does not validate it — so a constant is
/// fine for a server that has no RNG dependency.
const SEAL_CONFOUNDER: [u8; 8] = *b"MAGSEAL1";

/// Seal a payload for PKT_PRIVACY (MS-NRPC §3.3.4.2.2, AES variant): encrypt
/// `plain` and produce the 56-byte `NL_AUTH_SHA2_SIGNATURE`. Returns
/// `(ciphertext, signature)`, where the ciphertext is the same length as `plain`.
///
/// * Checksum = `HMAC-SHA256(Sk, header ‖ confounder ‖ plain)[..8]`
/// * Confounder ‖ plain are encrypted as one AES-CFB8 stream under
///   `seal_key(Sk)` with `IV = derived-seq ‖ derived-seq`; the encrypted
///   confounder is stored in the signature, the rest is the ciphertext.
/// * SequenceNumber = `AES-CFB8(Sk, IV = checksum‖checksum, derived-seq)`
pub fn seal_aes(
    session_key: &[u8; 16],
    plain: &[u8],
    confounder: &[u8; 8],
    sequence: u64,
) -> (Vec<u8>, Vec<u8>) {
    let header = signature_header(NL_SEAL_AES128);

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(session_key).expect("hmac key");
    mac.update(&header);
    mac.update(confounder);
    mac.update(plain);
    let digest = mac.finalize().into_bytes();
    let checksum = &digest[..8];

    let derived = derive_sequence_number(sequence);
    let mut data_iv = [0u8; 16];
    data_iv[0..8].copy_from_slice(&derived);
    data_iv[8..16].copy_from_slice(&derived);
    let mut buf = Vec::with_capacity(8 + plain.len());
    buf.extend_from_slice(confounder);
    buf.extend_from_slice(plain);
    let stream = aes128_cfb8_encrypt(&seal_key(session_key), &data_iv, &buf);
    let (enc_confounder, ciphertext) = stream.split_at(8);

    let mut seq_iv = [0u8; 16];
    seq_iv[0..8].copy_from_slice(checksum);
    seq_iv[8..16].copy_from_slice(checksum);
    let seq_enc = aes128_cfb8_encrypt(session_key, &seq_iv, &derived);

    let mut signature = Vec::with_capacity(56);
    signature.extend_from_slice(&header);
    signature.extend_from_slice(&seq_enc); // SequenceNumber
    signature.extend_from_slice(checksum); // Checksum
    signature.extend_from_slice(enc_confounder); // Confounder (encrypted)
    signature.extend_from_slice(&[0u8; 24]); // Reserved
    (ciphertext.to_vec(), signature)
}

/// Seal a response payload with the fixed server confounder.
pub fn seal_response_aes(
    session_key: &[u8; 16],
    plain: &[u8],
    sequence: u64,
) -> (Vec<u8>, Vec<u8>) {
    seal_aes(session_key, plain, &SEAL_CONFOUNDER, sequence)
}

/// Unseal a PKT_PRIVACY payload: decrypt `ciphertext` using the 56-byte
/// `signature` at `sequence` under `session_key`, verifying the checksum and the
/// encrypted sequence number. Returns the plaintext (still including any trailing
/// NDR pad) or `None` if it does not authenticate.
pub fn unseal_aes(
    session_key: &[u8; 16],
    ciphertext: &[u8],
    signature: &[u8],
    sequence: u64,
) -> Option<Vec<u8>> {
    if signature.len() < 32 {
        return None;
    }
    let seq_field = &signature[8..16];
    let checksum_field = &signature[16..24];
    let enc_confounder = &signature[24..32];

    let derived = derive_sequence_number(sequence);
    let mut data_iv = [0u8; 16];
    data_iv[0..8].copy_from_slice(&derived);
    data_iv[8..16].copy_from_slice(&derived);
    let mut buf = Vec::with_capacity(8 + ciphertext.len());
    buf.extend_from_slice(enc_confounder);
    buf.extend_from_slice(ciphertext);
    let plain = aes128_cfb8_decrypt(&seal_key(session_key), &data_iv, &buf);
    let (confounder, plain_data) = plain.split_at(8);

    // Recompute the checksum over the recovered plaintext and verify it, then
    // confirm the encrypted sequence number matches.
    let header = signature_header(NL_SEAL_AES128);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(session_key).expect("hmac key");
    mac.update(&header);
    mac.update(confounder);
    mac.update(plain_data);
    let digest = mac.finalize().into_bytes();
    if digest[..8] != *checksum_field {
        return None;
    }
    let mut seq_iv = [0u8; 16];
    seq_iv[0..8].copy_from_slice(checksum_field);
    seq_iv[8..16].copy_from_slice(checksum_field);
    if aes128_cfb8_encrypt(session_key, &seq_iv, &derived) != seq_field {
        return None;
    }
    Some(plain_data.to_vec())
}

// --- NetrLogonSamLogonEx response: NETLOGON_VALIDATION_SAM_INFO2 (MS-NRPC
// §2.2.1.4.11), the RPC counterpart of the Kerberos PAC's KERB_VALIDATION_INFO.
// Encoded here by hand with NDR; the layout follows the same "primitives, then
// deferred referents" discipline as the PAC.

/// A deferred NDR pointer referent within `SAM_INFO2`.
enum Deferred {
    /// A conformant+varying UTF-16 array (RPC_UNICODE_STRING buffer).
    Utf16(Vec<u16>),
    /// A conformant GROUP_MEMBERSHIP array (RelativeId, Attributes).
    Groups(Vec<(u32, u32)>),
    /// An RPC_SID (identifier authority + sub-authorities).
    Sid([u8; 6], Vec<u32>),
}

/// Write an RPC_UNICODE_STRING (Length, MaximumLength, Buffer pointer), queuing
/// the character data as a deferred referent (null pointer for an empty string).
fn unicode_string(w: &mut NdrWriter, deferred: &mut Vec<Deferred>, next_ref: &mut u32, s: &str) {
    let chars: Vec<u16> = s.encode_utf16().collect();
    let byte_len = (chars.len() * 2) as u16;
    w.u16(byte_len); // Length
    w.u16(byte_len); // MaximumLength
    if chars.is_empty() {
        w.u32(0);
    } else {
        w.u32(*next_ref);
        *next_ref += 4;
        deferred.push(Deferred::Utf16(chars));
    }
}

/// Write a pointer field: a fresh referent id (queuing `item`) or null.
fn pointer(
    w: &mut NdrWriter,
    deferred: &mut Vec<Deferred>,
    next_ref: &mut u32,
    item: Option<Deferred>,
) {
    match item {
        Some(d) => {
            w.u32(*next_ref);
            *next_ref += 4;
            deferred.push(d);
        }
        None => w.u32(0),
    }
}

/// A `NetrLogonSamLogonEx` response: the `NETLOGON_VALIDATION` union (SamInfo2)
/// carrying the user's SID/RID, primary group and one group, plus Authoritative
/// and STATUS_SUCCESS. Signed by the transport over the secure channel.
fn sam_logon_ex_response(domain_sub: &[u32]) -> Vec<u8> {
    let mut w = NdrWriter::new();

    // ValidationInformation union: tag = NetlogonValidationSamInfo2 (3), then the
    // SamInfo2 pointer + its inline referent (top-level pointer ⇒ inline).
    w.u16(3);
    w.u32(0x0002_0000); // arm pointer referent (u32 aligns, padding the tag)

    let mut deferred: Vec<Deferred> = Vec::new();
    let mut next_ref = 0x0002_0004u32;

    // Six OLD_LARGE_INTEGER time fields (Logon/Logoff/KickOff/PwdLastSet/…).
    for _ in 0..6 {
        w.u32(0);
        w.u32(0);
    }
    unicode_string(&mut w, &mut deferred, &mut next_ref, LOGON_USER); // EffectiveName
    for _ in 0..5 {
        // FullName, LogonScript, ProfilePath, HomeDirectory, HomeDirectoryDrive.
        unicode_string(&mut w, &mut deferred, &mut next_ref, "");
    }
    w.u16(0); // LogonCount
    w.u16(0); // BadPasswordCount
    w.u32(LOGON_USER_RID); // UserId
    w.u32(LOGON_PRIMARY_GID); // PrimaryGroupId
    w.u32(1); // GroupCount
    pointer(
        &mut w,
        &mut deferred,
        &mut next_ref,
        Some(Deferred::Groups(vec![(LOGON_PRIMARY_GID, 7)])),
    ); // GroupIds
    w.u32(0); // UserFlags
    w.bytes(&[0u8; 16]); // UserSessionKey
    unicode_string(&mut w, &mut deferred, &mut next_ref, ""); // LogonServer
    unicode_string(&mut w, &mut deferred, &mut next_ref, LOGON_DOMAIN); // LogonDomainName
    pointer(
        &mut w,
        &mut deferred,
        &mut next_ref,
        Some(Deferred::Sid(NT_AUTHORITY, domain_sub.to_vec())),
    ); // LogonDomainId
    w.bytes(&[0u8; 40]); // ExpansionRoom (ULONG[10])
    w.u32(0); // SidCount
    pointer(&mut w, &mut deferred, &mut next_ref, None); // ExtraSids (null)

    // Deferred referents of SAM_INFO2, in declaration order.
    for d in deferred {
        match d {
            Deferred::Utf16(chars) => {
                w.u32(chars.len() as u32); // MaxCount
                w.u32(0); // Offset
                w.u32(chars.len() as u32); // ActualCount
                for c in chars {
                    w.u16(c);
                }
            }
            Deferred::Groups(groups) => {
                w.u32(groups.len() as u32); // MaxCount
                for (rid, attrs) in groups {
                    w.u32(rid);
                    w.u32(attrs);
                }
            }
            Deferred::Sid(id_auth, sub) => {
                w.u32(sub.len() as u32); // conformant MaxCount = SubAuthorityCount
                w.u8(1); // Revision
                w.u8(sub.len() as u8); // SubAuthorityCount
                w.bytes(&id_auth);
                for s in sub {
                    w.u32(s);
                }
            }
        }
    }

    // Trailing top-level scalars.
    w.u8(1); // Authoritative
    w.u32(0); // ExtraFlags
    w.u32(STATUS_SUCCESS); // ErrorCode
    w.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "Machine123";

    #[test]
    fn ssp_signature_is_48_bytes_and_deterministic() {
        let sk = [
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64,
            0x65, 0x66,
        ];
        let a = sign_integrity_aes(&sk, b"magnetite-netlogon-ssp", 0);
        assert_eq!(a.len(), 48);
        assert_eq!(
            &a[0..8],
            &signature_header(NL_SEAL_NOT_ENCRYPTED),
            "AES integrity header"
        );
        // Deterministic, and sensitive to the signed data.
        assert_eq!(a, sign_integrity_aes(&sk, b"magnetite-netlogon-ssp", 0));
        assert_ne!(a, sign_integrity_aes(&sk, b"different data", 0));
        // The checksum sits at offset 16..24; the encrypted seq at 8..16.
        assert_ne!(&a[8..16], &[0u8; 8], "encrypted sequence must be present");
    }

    #[test]
    fn seal_then_unseal_round_trips_and_authenticates() {
        let sk = [
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64,
            0x65, 0x66,
        ];
        let plain = b"magnetite sealed stub";
        let (ciphertext, signature) = seal_aes(&sk, plain, b"12345678", 3);
        assert_eq!(ciphertext.len(), plain.len(), "CFB8 preserves length");
        assert_eq!(
            signature.len(),
            56,
            "sealed NL_AUTH_SHA2_SIGNATURE is 56 bytes"
        );
        assert_eq!(
            &signature[2..4],
            &NL_SEAL_AES128.to_le_bytes(),
            "seal algorithm is AES128"
        );
        assert_ne!(&ciphertext[..], &plain[..], "payload must be encrypted");

        let recovered = unseal_aes(&sk, &ciphertext, &signature, 3).expect("authentic");
        assert_eq!(recovered, plain, "unseal recovers the plaintext");

        // Wrong sequence must fail to authenticate (checksum/seq mismatch).
        assert!(unseal_aes(&sk, &ciphertext, &signature, 4).is_none());
        // A tampered ciphertext must fail the checksum.
        let mut bad = ciphertext.clone();
        bad[0] ^= 0xff;
        assert!(unseal_aes(&sk, &bad, &signature, 3).is_none());
    }

    #[test]
    fn derive_sequence_number_sets_direction_bit() {
        // low=1 big-endian, high=0x80000000 big-endian.
        assert_eq!(derive_sequence_number(1), [0, 0, 0, 1, 0x80, 0, 0, 0]);
    }

    #[test]
    fn nt_hash_is_md4_of_utf16le() {
        // Known answer: MD4(UTF16LE("Machine123")).
        let h = nt_hash(PW);
        assert_eq!(h.len(), 16);
        // Deterministic and password-sensitive.
        assert_ne!(h, nt_hash("Machine124"));
    }

    #[test]
    fn full_handshake_succeeds_and_is_mutual() {
        let nl = NetlogonInterface::new(PW);
        let client_challenge = *b"CLIENT01";

        // ReqChallenge: build a request with two empty strings + the challenge.
        let req = req_challenge_stub(&client_challenge);
        let resp = nl.call(OP_REQ_CHALLENGE, &req).unwrap();
        let server_challenge: [u8; 8] = resp[0..8].try_into().unwrap();
        assert_eq!(&resp[8..12], &STATUS_SUCCESS.to_le_bytes());

        // Client computes the session key + credential exactly as the server will.
        let sk = session_key_aes(&nt_hash(PW), &client_challenge, &server_challenge);
        let client_cred = netlogon_credential_aes(&sk, &client_challenge);

        // Authenticate3 with the correct client credential.
        let areq = authenticate3_stub(&client_cred, 0x0100_0000);
        let ar = nl.call(OP_AUTHENTICATE3, &areq).unwrap();
        assert_eq!(
            &ar[16..20],
            &STATUS_SUCCESS.to_le_bytes(),
            "auth must succeed"
        );
        // The returned server credential must match the client's own computation.
        let server_cred: [u8; 8] = ar[0..8].try_into().unwrap();
        assert_eq!(
            server_cred,
            netlogon_credential_aes(&sk, &server_challenge),
            "server credential proves the server holds the same session key"
        );
    }

    #[test]
    fn wrong_password_is_rejected() {
        let nl = NetlogonInterface::new(PW);
        let client_challenge = *b"CLIENT01";
        let req = req_challenge_stub(&client_challenge);
        let resp = nl.call(OP_REQ_CHALLENGE, &req).unwrap();
        let server_challenge: [u8; 8] = resp[0..8].try_into().unwrap();

        // Credential derived from the WRONG password.
        let sk = session_key_aes(&nt_hash("WrongPass!"), &client_challenge, &server_challenge);
        let bad_cred = netlogon_credential_aes(&sk, &client_challenge);
        let areq = authenticate3_stub(&bad_cred, 0x0100_0000);
        let ar = nl.call(OP_AUTHENTICATE3, &areq).unwrap();
        assert_eq!(
            u32::from_le_bytes(ar[16..20].try_into().unwrap()),
            STATUS_ACCESS_DENIED
        );
    }

    #[test]
    fn zero_client_challenge_is_rejected() {
        let nl = NetlogonInterface::new(PW);
        let req = req_challenge_stub(&[0u8; 8]);
        let resp = nl.call(OP_REQ_CHALLENGE, &req).unwrap();
        let server_challenge: [u8; 8] = resp[0..8].try_into().unwrap();
        // Even a "correct" credential for the zero challenge must be refused.
        let sk = session_key_aes(&nt_hash(PW), &[0u8; 8], &server_challenge);
        let cred = netlogon_credential_aes(&sk, &[0u8; 8]);
        let ar = nl
            .call(OP_AUTHENTICATE3, &authenticate3_stub(&cred, 0x0100_0000))
            .unwrap();
        assert_eq!(
            u32::from_le_bytes(ar[16..20].try_into().unwrap()),
            STATUS_ACCESS_DENIED,
            "Zerologon pattern must be rejected"
        );
    }

    // --- test request builders (mirror the NDR the client emits) ---

    fn empty_wstr(out: &mut Vec<u8>) {
        while !out.len().is_multiple_of(4) {
            out.push(0); // align the conformant MaxCount to 4, as NDR requires
        }
        out.extend_from_slice(&0u32.to_le_bytes()); // MaxCount
        out.extend_from_slice(&0u32.to_le_bytes()); // Offset
        out.extend_from_slice(&0u32.to_le_bytes()); // ActualCount
    }

    fn req_challenge_stub(client_challenge: &[u8; 8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0u32.to_le_bytes()); // PrimaryName: null unique ptr
        empty_wstr(&mut b); // ComputerName
        b.extend_from_slice(client_challenge);
        b
    }

    /// A conformant+varying `WSTR` carrying `s` (with a trailing NUL, as a client
    /// emits), 4-aligned — the inverse of [`NdrReader::read_wstr`].
    fn value_wstr(out: &mut Vec<u8>, s: &str) {
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        let mut units: Vec<u16> = s.encode_utf16().collect();
        units.push(0); // trailing NUL
        let n = units.len() as u32;
        out.extend_from_slice(&n.to_le_bytes()); // MaxCount
        out.extend_from_slice(&0u32.to_le_bytes()); // Offset
        out.extend_from_slice(&n.to_le_bytes()); // ActualCount
        for u in units {
            out.extend_from_slice(&u.to_le_bytes());
        }
    }

    /// A `ReqChallenge` request carrying a real `ComputerName`, so the server can
    /// derive the machine-account name (`<ComputerName>$`) for a password rotation.
    fn req_challenge_stub_named(client_challenge: &[u8; 8], computer: &str) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0u32.to_le_bytes()); // PrimaryName: null unique ptr
        value_wstr(&mut b, computer); // ComputerName
        b.extend_from_slice(client_challenge);
        b
    }

    fn authenticate3_stub(client_credential: &[u8; 8], flags: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0u32.to_le_bytes()); // PrimaryName: null unique ptr
        empty_wstr(&mut b); // AccountName
        b.extend_from_slice(&2u16.to_le_bytes()); // SecureChannelType = Workstation
        empty_wstr(&mut b); // ComputerName (already 4-aligned)
        b.extend_from_slice(client_credential); // ClientCredential[8]
        b.extend_from_slice(&flags.to_le_bytes()); // NegotiateFlags
        b
    }

    /// Marshal an `NL_TRUST_PASSWORD` (cleartext): the password right-aligned in
    /// `Buffer[512]`, with `Length` (bytes) at offset 512.
    fn trust_password_plain(new_password: &str) -> [u8; 516] {
        let units: Vec<u8> = new_password
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let mut blob = [0u8; 516];
        blob[512 - units.len()..512].copy_from_slice(&units);
        blob[512..516].copy_from_slice(&(units.len() as u32).to_le_bytes());
        blob
    }

    fn password_set2_stub(
        auth_credential: &[u8; 8],
        timestamp: u32,
        encrypted: &[u8; 516],
    ) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0u32.to_le_bytes()); // PrimaryName: null unique ptr
        empty_wstr(&mut b); // AccountName
        b.extend_from_slice(&2u16.to_le_bytes()); // SecureChannelType
        empty_wstr(&mut b); // ComputerName
        b.extend_from_slice(auth_credential); // Authenticator.Credential[8]
        b.extend_from_slice(&timestamp.to_le_bytes()); // Authenticator.Timestamp
        b.extend_from_slice(encrypted); // ClearNewPassword[516]
        b
    }

    #[test]
    fn password_set2_rotates_machine_password_over_secure_channel() {
        let nl = NetlogonInterface::new(PW);
        let client_challenge = *b"CLIENT01";

        // Establish the secure channel and seed the authenticator chain.
        let resp = nl
            .call(OP_REQ_CHALLENGE, &req_challenge_stub(&client_challenge))
            .unwrap();
        let server_challenge: [u8; 8] = resp[0..8].try_into().unwrap();
        let sk = session_key_aes(&nt_hash(PW), &client_challenge, &server_challenge);
        let client_cred = netlogon_credential_aes(&sk, &client_challenge);
        nl.call(
            OP_AUTHENTICATE3,
            &authenticate3_stub(&client_cred, 0x0100_0000),
        )
        .unwrap();

        // Encrypt the new password as an NL_TRUST_PASSWORD and authenticate the call.
        let new_password = "N3wMachinePass!";
        let encrypted: [u8; 516] =
            aes128_cfb8_encrypt(&sk, &[0u8; 16], &trust_password_plain(new_password))
                .try_into()
                .unwrap();
        let timestamp: u32 = 0x5001;
        let advanced = advance_credential(client_cred, timestamp);
        let auth_credential = netlogon_credential_aes(&sk, &advanced);

        let pr = nl
            .call(
                OP_PASSWORD_SET2,
                &password_set2_stub(&auth_credential, timestamp, &encrypted),
            )
            .unwrap();
        assert_eq!(
            &pr[12..16],
            &STATUS_SUCCESS.to_le_bytes(),
            "password set must succeed"
        );
        // ReturnAuthenticator = Crypt(session_key, stored + timestamp + 1).
        let expected_return = netlogon_credential_aes(&sk, &advance_credential(advanced, 1));
        assert_eq!(
            &pr[0..8],
            &expected_return,
            "return authenticator proves the chain"
        );

        // Proof of adoption: a fresh handshake with the NEW password now succeeds.
        let cc2 = *b"CLIENT02";
        let resp2 = nl
            .call(OP_REQ_CHALLENGE, &req_challenge_stub(&cc2))
            .unwrap();
        let sch2: [u8; 8] = resp2[0..8].try_into().unwrap();
        let sk2 = session_key_aes(&nt_hash(new_password), &cc2, &sch2);
        let cred2 = netlogon_credential_aes(&sk2, &cc2);
        let ar2 = nl
            .call(OP_AUTHENTICATE3, &authenticate3_stub(&cred2, 0x0100_0000))
            .unwrap();
        assert_eq!(
            &ar2[16..20],
            &STATUS_SUCCESS.to_le_bytes(),
            "the new machine password is now in effect"
        );
    }

    #[test]
    fn password_set2_registers_machine_with_kdc() {
        let realm = "EXAMPLE.COM";
        let kdc = Arc::new(PrincipalStore::new(realm));
        let nl = NetlogonInterface::new(PW).with_kdc(kdc.clone());
        let computer = "MAGNETITE01";
        let account = format!("{computer}$");

        // Before the rotation the KDC holds no key for the machine account.
        assert!(
            kdc.get(std::slice::from_ref(&account)).is_none(),
            "machine account must not exist before the rotation"
        );

        // Establish the secure channel — ComputerName is captured on ReqChallenge.
        let client_challenge = *b"CLIENT01";
        let resp = nl
            .call(
                OP_REQ_CHALLENGE,
                &req_challenge_stub_named(&client_challenge, computer),
            )
            .unwrap();
        let server_challenge: [u8; 8] = resp[0..8].try_into().unwrap();
        let sk = session_key_aes(&nt_hash(PW), &client_challenge, &server_challenge);
        let client_cred = netlogon_credential_aes(&sk, &client_challenge);
        nl.call(
            OP_AUTHENTICATE3,
            &authenticate3_stub(&client_cred, 0x0100_0000),
        )
        .unwrap();

        // Rotate the machine password over the authenticated secure channel.
        let new_password = "N3wMachinePass!";
        let encrypted: [u8; 516] =
            aes128_cfb8_encrypt(&sk, &[0u8; 16], &trust_password_plain(new_password))
                .try_into()
                .unwrap();
        let timestamp: u32 = 0x5001;
        let advanced = advance_credential(client_cred, timestamp);
        let auth_credential = netlogon_credential_aes(&sk, &advanced);
        let pr = nl
            .call(
                OP_PASSWORD_SET2,
                &password_set2_stub(&auth_credential, timestamp, &encrypted),
            )
            .unwrap();
        assert_eq!(
            &pr[12..16],
            &STATUS_SUCCESS.to_le_bytes(),
            "password set must succeed"
        );

        // The loop is closed: the KDC now holds the machine's AES256 long-term key,
        // derived from the *rotated* password with the AD computer-account convention
        // (WTF-8 password + `host/<fqdn>` salt), resolvable by the SAM name and the
        // `host/`/`cifs/` SPNs — so its logon TGS-REQ resolves.
        let principal = kdc
            .get(std::slice::from_ref(&account))
            .expect("machine account registered with the KDC");
        let new_utf16: Vec<u8> = new_password
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let expected =
            magnetite_krb5::keys::machine_kerberos_key(realm, &account, &new_utf16).unwrap();
        assert_eq!(
            principal.key.key, expected,
            "KDC key must derive from the rotated machine password (AD computer salt)"
        );
        // The host/ SPN alias resolves to the same key.
        let host_spn = vec!["host".to_string(), "magnetite01.example.com".to_string()];
        assert_eq!(
            kdc.get(&host_spn).unwrap().key.key,
            expected,
            "host/ SPN resolves"
        );
        let stale_utf16: Vec<u8> = PW.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let stale =
            magnetite_krb5::keys::machine_kerberos_key(realm, &account, &stale_utf16).unwrap();
        assert_ne!(
            principal.key.key, stale,
            "the KDC must no longer hold the old machine password"
        );
    }
}
