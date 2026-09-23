//! A minimal SMB2 server (MS-SMB2) serving a real SYSVOL tree: a client can
//! negotiate, authenticate (NTLM, accepted), connect to `SYSVOL`, browse the
//! Group Policy directories and read `GPT.INI` / `Registry.pol` by path.
//!
//! Scope: SMB dialect 2.1 or 3.0 (negotiated), an in-memory read-only
//! [`crate::vfs`] tree, and file handles whose 16-byte id encodes the vfs node
//! index (so most handling stays stateless — only directory enumeration keeps
//! per-connection progress). Authentication is NTLM (accepted) or, when a
//! service key is configured, Kerberos (the client's AP-REQ is verified via
//! `magnetite-krb5`). When the client negotiates SMB 3.0, traffic is protected:
//! AES-128-CCM encryption (see [`crate::enc`]) if the client advertises
//! encryption, otherwise AES-128-CMAC signing (see [`crate::sign`]).

use crate::comp;
use crate::enc;
use crate::sign;
use crate::vfs::{Kind, Vfs};
use magnetite_rpc::{RpcInterface, RpcPipe};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::spnego::{
    extract_ap_req, extract_ntlmssp, neg_token_init, neg_token_init_kerberos,
    neg_token_resp_accept_completed, neg_token_resp_ap_rep, neg_token_resp_challenge,
    ntlmssp_message_type, SERVER_CHALLENGE,
};

/// The NT-hash lookup (account name → NT hash) the DC supplies to verify an NTLMv2
/// AUTHENTICATE — used both by the SMB session-setup and by the RPC pipe binds, so
/// it is the one type re-exported from magnetite-rpc.
pub use magnetite_rpc::NtHashLookup;

/// A factory producing a fresh RPC interface for each opened pipe instance.
pub type PipeFactory = Arc<dyn Fn() -> Arc<dyn RpcInterface> + Send + Sync>;
/// A map of lower-case named-pipe names (e.g. `"lsarpc"`) to their interfaces.
pub type PipeRegistry = HashMap<String, PipeFactory>;

const SMB2_MAGIC: [u8; 4] = [0xfe, b'S', b'M', b'B'];
const HEADER_LEN: usize = 64;

/// The legacy SMB1 magic (`\xFFSMB`) and its NEGOTIATE command (0x72). A Windows
/// client opens a connection with an SMB1 multi-protocol NEGOTIATE to transition up
/// to SMB2; we answer it with the SMB2 wildcard dialect (below) so the client then
/// sends a real SMB2 NEGOTIATE. (impacket/Samba start at SMB2 directly, so this
/// path only matters for a real Windows client.)
const SMB1_MAGIC: [u8; 4] = [0xff, b'S', b'M', b'B'];
const SMB1_COM_NEGOTIATE: u8 = 0x72;
/// SMB2 wildcard dialect (MS-SMB2 §2.2.4) returned to a multi-protocol NEGOTIATE:
/// it tells the client to re-negotiate with a proper SMB2 NEGOTIATE request.
const SMB2_DIALECT_WILDCARD: u16 = 0x02ff;

// Commands (MS-SMB2 §2.2.1).
const SMB2_NEGOTIATE: u16 = 0x0000;
const SMB2_SESSION_SETUP: u16 = 0x0001;
const SMB2_LOGOFF: u16 = 0x0002;
const SMB2_TREE_CONNECT: u16 = 0x0003;
const SMB2_TREE_DISCONNECT: u16 = 0x0004;
const SMB2_CREATE: u16 = 0x0005;
const SMB2_CLOSE: u16 = 0x0006;
const SMB2_READ: u16 = 0x0008;
const SMB2_WRITE: u16 = 0x0009;
const SMB2_IOCTL: u16 = 0x000B;
const SMB2_QUERY_DIRECTORY: u16 = 0x000E;
const SMB2_QUERY_INFO: u16 = 0x0010;

// NT statuses.
const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
const STATUS_END_OF_FILE: u32 = 0xC000_0011;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_LOGON_FAILURE: u32 = 0xC000_006D;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;

const SMB2_FLAGS_SERVER_TO_REDIR: u32 = 0x0000_0001;
const SMB2_DIALECT_21: u16 = 0x0210;
const SMB2_DIALECT_30: u16 = 0x0300;
const SMB2_DIALECT_311: u16 = 0x0311;
// SMB 3.1.1 negotiate-context types (MS-SMB2 §2.2.3.1).
const SMB2_PREAUTH_INTEGRITY_CAPABILITIES: u16 = 0x0001;
const SMB2_ENCRYPTION_CAPABILITIES: u16 = 0x0002;
const SMB2_COMPRESSION_CAPABILITIES: u16 = 0x0003;
/// Preauth-integrity hash algorithm id for SHA-512.
const SMB2_HASH_SHA512: u16 = 0x0001;
/// Fixed 32-byte preauth salt we place in our negotiate response context.
const PREAUTH_SALT: [u8; 32] = *b"magnetite-smb311-preauth-salt-01";
/// NEGOTIATE `SecurityMode`: signing enabled, and (with REQUIRED) enforced.
const SMB2_NEGOTIATE_SIGNING_ENABLED: u16 = 0x0001;
const SMB2_NEGOTIATE_SIGNING_REQUIRED: u16 = 0x0002;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
/// NEGOTIATE `Capabilities` bit advertising SMB 3.x encryption support.
const SMB2_GLOBAL_CAP_ENCRYPTION: u32 = 0x0000_0040;
/// NEGOTIATE `Capabilities` bit advertising SMB 3.x multi-channel support. Referenced
/// only by the negotiate test, which asserts we do NOT advertise it.
#[cfg(test)]
const SMB2_GLOBAL_CAP_MULTI_CHANNEL: u32 = 0x0000_0008;
/// SESSION_SETUP `SessionFlags` bit requiring the session's traffic be encrypted.
const SMB2_SESSION_FLAG_ENCRYPT_DATA: u16 = 0x0004;
/// SESSION_SETUP request `Flags` bit binding a new channel to an existing session.
const SMB2_SESSION_FLAG_BINDING: u8 = 0x01;
/// FSCTL selecting the multi-channel network-interface query (MS-SMB2 §2.2.31.3).
const FSCTL_QUERY_NETWORK_INTERFACE_INFO: u32 = 0x0014_01FC;
/// SMB3 downgrade protection (MS-SMB2 §2.2.31.4): after session-setup a client may
/// re-verify the NEGOTIATE by asking the server to echo the negotiated dialect,
/// capabilities, security mode and GUID. A wrong/absent answer makes the client
/// disconnect — which a real Windows join does right after connecting to `IPC$`.
const FSCTL_VALIDATE_NEGOTIATE_INFO: u32 = 0x0014_0204;
/// FSCTL for named-pipe RPC transceive (MS-SMB2 §2.2.31): the input is a request
/// PDU and the output its response — how Windows/Samba drive `ncacn_np`.
const FSCTL_PIPE_TRANSCEIVE: u32 = 0x0011_C017;
/// `RSS_CAPABLE` bit in a `NETWORK_INTERFACE_INFO.Capability`.
const NETWORK_INTERFACE_RSS_CAPABLE: u32 = 0x0000_0001;

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;

/// SMB2 QUERY_DIRECTORY `FileInformationClass` values whose entry layout we emit.
const FILE_FULL_DIR_INFO: u8 = 0x02; // FileFullDirectoryInformation (68-byte header)
const FILE_BOTH_DIR_INFO: u8 = 0x03; // FileBothDirectoryInformation (94-byte header)
const FILE_ID_BOTH_DIR_INFO: u8 = 0x25; // FileIdBothDirectoryInformation (104-byte header)

/// SMB2 QUERY_INFO `InfoType` and `FileInformationClass` values we answer.
const INFO_TYPE_FILE: u8 = 0x01; // SMB2_0_INFO_FILE
const INFO_TYPE_FILESYSTEM: u8 = 0x02; // SMB2_0_INFO_FILESYSTEM
const FILE_BASIC_INFO: u8 = 0x04; // FileBasicInformation
const FILE_STANDARD_INFO: u8 = 0x05; // FileStandardInformation
const FILE_ALL_INFO: u8 = 0x12; // FileAllInformation
const FILE_NETWORK_OPEN_INFO: u8 = 0x22; // FileNetworkOpenInformation
const FS_FULL_SIZE_INFO: u8 = 0x07; // FileFsFullSizeInformation

// Fixed identities (no real session/tree state is tracked).
const SESSION_ID: u64 = 0x0000_0000_0000_1234;
const TREE_ID: u32 = 1;
/// Tree id handed out for the `IPC$` (named-pipe) share.
const IPC_TREE_ID: u32 = 2;
/// The NETLOGON disk share (logon scripts). See [`netlogon_slot`].
const NETLOGON_TREE_ID: u32 = 3;
const SHARE_TYPE_DISK: u8 = 0x01;
const SHARE_TYPE_PIPE: u8 = 0x02;
const SERVER_GUID: [u8; 16] = *b"magnetite-smbsrv";
/// An arbitrary recent Windows FILETIME for time fields.
const SYSTEM_TIME: u64 = 133_800_000_000_000_000;

/// The process-wide SYSVOL tree, swappable so a DC can serve a DB-backed tree
/// (and refresh it after SYSVOL replication) rather than the static default.
fn sysvol_slot() -> &'static std::sync::RwLock<Arc<Vfs>> {
    static V: OnceLock<std::sync::RwLock<Arc<Vfs>>> = OnceLock::new();
    V.get_or_init(|| std::sync::RwLock::new(Arc::new(Vfs::sysvol())))
}

/// A snapshot of the current SYSVOL tree (cheap `Arc` clone).
fn vfs() -> Arc<Vfs> {
    sysvol_slot()
        .read()
        .map(|g| g.clone())
        .unwrap_or_else(|e| e.into_inner().clone())
}

/// Replace the served SYSVOL tree, e.g. one built from the replicated DB store
/// via [`Vfs::from_files`]. Takes effect for subsequent requests.
pub fn set_sysvol(tree: Vfs) {
    if let Ok(mut g) = sysvol_slot().write() {
        *g = Arc::new(tree);
    }
}

/// The process-wide NETLOGON tree — the logon-scripts share (the `scripts`
/// subtree of SYSVOL). A member fetches the file named by a user's `scriptPath`
/// from `\\<dc>\NETLOGON\<scriptPath>`. Empty until [`set_netlogon`] populates it.
fn netlogon_slot() -> &'static std::sync::RwLock<Arc<Vfs>> {
    static V: OnceLock<std::sync::RwLock<Arc<Vfs>>> = OnceLock::new();
    V.get_or_init(|| std::sync::RwLock::new(Arc::new(Vfs::from_files(Vec::new()))))
}

/// Replace the served NETLOGON tree (built from the logon scripts via
/// [`Vfs::from_files`]). Takes effect for subsequent requests.
pub fn set_netlogon(tree: Vfs) {
    if let Ok(mut g) = netlogon_slot().write() {
        *g = Arc::new(tree);
    }
}

/// The served tree for a disk share `tree` id: NETLOGON has its own tree, every
/// other disk share is SYSVOL. The file id encodes a node index into whichever tree
/// CREATE resolved against, so read/query MUST re-select the same tree by its id —
/// which is why every file handler passes its `tree` here.
fn vfs_for(tree: u32) -> Arc<Vfs> {
    if tree == NETLOGON_TREE_ID {
        netlogon_slot()
            .read()
            .map(|g| g.clone())
            .unwrap_or_else(|e| e.into_inner().clone())
    } else {
        vfs()
    }
}

/// Serve SMB2 on `addr` (usually `0.0.0.0:445`) with NTLM authentication.
pub async fn serve(addr: SocketAddr) -> io::Result<()> {
    serve_inner(addr, None, PipeRegistry::new(), None).await
}

/// Serve SMB2 accepting Kerberos authentication: a client's AP-REQ for the
/// `cifs` service is verified against `service_key` (the cifs account's AES256
/// key). NTLM is still accepted as a fallback.
pub async fn serve_with_kerberos(addr: SocketAddr, service_key: [u8; 32]) -> io::Result<()> {
    serve_inner(addr, Some(service_key), PipeRegistry::new(), None).await
}

/// Serve SMB2 exposing RPC named pipes over `IPC$` (`ncacn_np`): a client can
/// `connectTree("IPC$")`, open e.g. `lsarpc`/`samr`, and write/read RPC PDUs that
/// are dispatched to the registered [`RpcInterface`]s. NTLM auth is accepted.
pub async fn serve_with_pipes(addr: SocketAddr, pipes: PipeRegistry) -> io::Result<()> {
    serve_inner(addr, None, pipes, None).await
}

/// Serve SMB2 with BOTH Kerberos authentication and RPC named pipes — the
/// configuration a real domain controller presents: a client authenticates with
/// a `cifs` ticket, then reaches SAMR/LSA/Netlogon over `IPC$`. An optional
/// `nt_hash_lookup` turns on real NTLMv2 verification (from the DC's directory) so
/// a Windows client that falls back to NTLM gets a signed, keyed session.
pub async fn serve_with_kerberos_and_pipes(
    addr: SocketAddr,
    service_key: [u8; 32],
    pipes: PipeRegistry,
    nt_hash_lookup: Option<NtHashLookup>,
) -> io::Result<()> {
    serve_inner(addr, Some(service_key), pipes, nt_hash_lookup).await
}

async fn serve_inner(
    addr: SocketAddr,
    service_key: Option<[u8; 32]>,
    pipes: PipeRegistry,
    nt_hash_lookup: Option<NtHashLookup>,
) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let pipes = Arc::new(pipes);
    tracing::info!("magnetite-smb listening on {addr} (SMB2, share SYSVOL + IPC$)");
    loop {
        let (stream, peer) = listener.accept().await?;
        tracing::debug!(target: "conn", %peer, "SMB connection");
        let pipes = pipes.clone();
        let nt_hash_lookup = nt_hash_lookup.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, service_key, pipes, nt_hash_lookup).await {
                tracing::debug!("SMB connection ended: {e}");
            }
        });
    }
}

async fn handle_conn(
    mut stream: TcpStream,
    service_key: Option<[u8; 32]>,
    pipes: Arc<PipeRegistry>,
    nt_hash_lookup: Option<NtHashLookup>,
) -> io::Result<()> {
    let mut conn = Connection {
        service_key,
        pipes,
        nt_hash_lookup,
        ..Default::default()
    };
    loop {
        // Direct TCP transport (MS-SMB2 §2.1): 4-byte length prefix (top byte 0).
        let mut prefix = [0u8; 4];
        if stream.read_exact(&mut prefix).await.is_err() {
            return Ok(()); // clean EOF
        }
        let len = u32::from_be_bytes(prefix) as usize & 0x00ff_ffff;
        if !(HEADER_LEN..=16 * 1024 * 1024).contains(&len) {
            return Ok(());
        }
        let mut msg = vec![0u8; len];
        stream.read_exact(&mut msg).await?;

        let Some(reply) = conn.handle(&msg) else {
            return Ok(());
        };
        let out_prefix = (reply.len() as u32).to_be_bytes();
        stream.write_all(&out_prefix).await?;
        stream.write_all(&reply).await?;
        stream.flush().await?;
    }
}

// Bounds-checked little-endian field reads. An unauthenticated client sends the
// first NEGOTIATE / SESSION_SETUP packets, so a short or empty body must NOT panic
// the connection task (raw `b[off]` indexing did). A truncated field reads as 0,
// which the parsers then treat as "no dialects / empty blob" and reject cleanly.
fn le16(b: &[u8], off: usize) -> u16 {
    match b.get(off..off + 2) {
        Some(s) => u16::from_le_bytes([s[0], s[1]]),
        None => 0,
    }
}
fn le32(b: &[u8], off: usize) -> u32 {
    match b.get(off..off + 4) {
        Some(s) => u32::from_le_bytes([s[0], s[1], s[2], s[3]]),
        None => 0,
    }
}
fn le64(b: &[u8], off: usize) -> u64 {
    let Some(s) = b.get(off..off + 8) else {
        return 0;
    };
    let mut v = [0u8; 8];
    v.copy_from_slice(s);
    u64::from_le_bytes(v)
}

/// Encode a vfs node index into a 16-byte SMB2 FileId.
fn encode_file_id(index: usize) -> [u8; 16] {
    let mut id = *b"\0\0\0\0MAGNETSMBID1";
    id[0..4].copy_from_slice(&(index as u32).to_le_bytes());
    id
}
/// Recover the vfs node index from a FileId at `data[off..off+16]`. Returns `None`
/// unless the id carries the vfs tag (`MAGNETSMBID1` at bytes 4..16) — a pipe handle
/// (`PIPE…MAGNPIPE`) or any other id is not a vfs node and must not be indexed.
fn decode_file_id(data: &[u8], off: usize) -> Option<usize> {
    let id = data.get(off..off + 16)?;
    (&id[4..16] == b"MAGNETSMBID1").then(|| le32(data, off) as usize)
}

/// A directory-listing name/UTF-16 helper.
fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}
fn decode_utf16(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16_lossy(&units)
}

/// An opened RPC named pipe: its dispatcher plus the buffered response bytes the
/// client drains with READ after a WRITE.
struct PipeState {
    rpc: RpcPipe,
    response: Vec<u8>,
    read_pos: usize,
}

/// Per-connection state: the optional Kerberos service key, which directory
/// handles have been fully enumerated (SMB2 QUERY_DIRECTORY returns entries once,
/// then STATUS_NO_MORE_FILES), and the registered/opened RPC pipes.
#[derive(Default)]
struct Connection {
    service_key: Option<[u8; 32]>,
    /// The Kerberos session key established at session-setup (from the AP-REQ), so
    /// RPC over the pipes can decrypt password buffers that ride the SMB session.
    session_key: Option<Vec<u8>>,
    /// The SMB-authenticated principal (Kerberos client name or NTLM username), carried
    /// into RPC pipes so a pipe interface (LSA) can attribute calls to who authenticated.
    session_user: Option<String>,
    /// The negotiated dialect (`SMB2_DIALECT_21`/`_30`); selects the signing scheme.
    dialect: u16,
    /// The SMB 3.0 signing key (derived from the session key) once signing is in
    /// force; when set, responses are signed and signed requests are verified.
    signing_key: Option<[u8; 16]>,
    /// Set when the client offered SMB 3.x encryption in NEGOTIATE; the session
    /// then derives CCM keys and encrypts post-session-setup traffic.
    encrypt_negotiated: bool,
    /// SMB 3.x encryption key (server→client, `ServerOut`/`S2C`); 16 or 32 bytes.
    enc_key: Option<Vec<u8>>,
    /// SMB 3.x decryption key (client→server, `ServerIn`/`C2S`); 16 or 32 bytes.
    dec_key: Option<Vec<u8>>,
    /// SMB 3.x **application key** — the key the transport hands to RPC over the
    /// named pipes, and what a SAMR/LSAD password buffer is sealed with (NOT the raw
    /// `Session.SessionKey`). Derived alongside the signing/encryption keys.
    application_key: Option<Vec<u8>>,
    /// The negotiated AEAD cipher (AES-128/256, CCM or GCM).
    cipher: enc::Cipher,
    /// Per-message nonce counter for outbound encryption (unique under one key).
    nonce_ctr: u64,
    /// SMB 3.1.1 preauth-integrity hash (SHA-512 chain over NEGOTIATE and
    /// SESSION_SETUP messages); the context for 3.1.1 key derivation.
    preauth_hash: PreauthHash,
    listed_dirs: HashSet<[u8; 16]>,
    pipes: Arc<PipeRegistry>,
    open_pipes: HashMap<[u8; 16], PipeState>,
    next_pipe: u32,
    /// NT-hash lookup for verifying an NTLMv2 session-setup (DC directory). When
    /// absent, NTLM is accepted without verification (the standalone PoC servers).
    nt_hash_lookup: Option<NtHashLookup>,
}

/// The SMB 3.1.1 preauth-integrity hash (`[u8; 64]` has no `Default`, so wrap it).
struct PreauthHash([u8; 64]);

impl Default for PreauthHash {
    fn default() -> Self {
        PreauthHash([0u8; 64])
    }
}

/// The response for one SMB2 command: status plus the id fields to echo back.
struct Reply {
    status: u32,
    session_id: u64,
    tree_id: u32,
    body: Vec<u8>,
}

impl Connection {
    /// Turn one inbound message into a reply. Encrypted messages (SMB 3.0
    /// `SMB2_TRANSFORM_HEADER`) are decrypted, processed, and re-encrypted; plain
    /// SMB2 messages go straight through [`Self::handle_plain`].
    fn handle(&mut self, raw: &[u8]) -> Option<Vec<u8>> {
        // Compressed request (SMB2_COMPRESSION_TRANSFORM_HEADER): decompress,
        // reprocess (the inner message may itself be plaintext or encrypted), and
        // compress the reply symmetrically — a peer that sent compression accepts
        // it. We never compress unsolicited (peers that can't decompress break).
        if raw.len() >= 4 && raw[0..4] == comp::COMPRESSION_PROTOCOL_ID {
            let decompressed = comp::decompress_message(raw)?;
            let response = self.handle(&decompressed)?;
            return Some(comp::compress_message(&response));
        }
        if raw.len() >= 4 && raw[0..4] == enc::TRANSFORM_PROTOCOL_ID {
            let Some(dec_key) = self.dec_key.clone() else {
                tracing::warn!("SMB got an encrypted PDU but no decrypt key → dropping connection");
                return None;
            };
            let Some(plaintext) = enc::decrypt(self.cipher, &dec_key, raw) else {
                tracing::warn!(
                    "SMB decrypt FAILED (cipher={:?}, {} B) → dropping connection",
                    self.cipher,
                    raw.len()
                );
                return None;
            };
            let session_id = enc::session_id_of(raw);
            let mut response = self.handle_plain_inner(&plaintext, true)?;
            // An encrypted message must NOT also be signed — the transform header
            // provides integrity (MS-SMB2 §3.1.4.3). Strip any signature/flag
            // handle_plain applied so the peer doesn't reject the decrypted message.
            if response.len() >= HEADER_LEN {
                let flags = le32(&response, 16) & !sign::SMB2_FLAGS_SIGNED;
                response[16..20].copy_from_slice(&flags.to_le_bytes());
                response[48..64].fill(0);
            }
            let enc_key = self.enc_key.clone()?;
            self.nonce_ctr += 1;
            return Some(enc::encrypt(
                self.cipher,
                &enc_key,
                session_id,
                self.nonce_ctr,
                &response,
            ));
        }
        self.handle_plain(raw)
    }

    /// Turn one inbound plaintext SMB2 message into a reply, or `None` to drop.
    fn handle_plain(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
        self.handle_plain_inner(msg, false)
    }

    /// As [`Self::handle_plain`]. `from_encrypted` is true when the message arrived
    /// inside an `SMB2_TRANSFORM_HEADER`: the transform already authenticated it, so
    /// the per-message signature check is skipped (a client that both signs and
    /// encrypts zeroes the inner signature, which would otherwise fail verification).
    fn handle_plain_inner(&mut self, msg: &[u8], from_encrypted: bool) -> Option<Vec<u8>> {
        // A real Windows client opens with an SMB1 multi-protocol NEGOTIATE
        // (`\xFFSMBr`, offering "SMB 2.???"). Reply with an SMB2 NEGOTIATE response
        // carrying the 0x02FF wildcard dialect (MessageId 0); the client then sends a
        // proper SMB2 NEGOTIATE, which the normal path below handles. This is not
        // folded into the 3.1.1 preauth hash — that starts at the SMB2 NEGOTIATE.
        if msg.len() >= 5 && msg[0..4] == SMB1_MAGIC && msg[4] == SMB1_COM_NEGOTIATE {
            let body = negotiate_response(
                SMB2_DIALECT_WILDCARD,
                false,
                self.cipher,
                self.service_key.is_some(),
            );
            return Some(build_message(
                SMB2_NEGOTIATE,
                0,
                1,
                &reply(STATUS_SUCCESS, 0, 0, body),
            ));
        }
        if msg.len() < HEADER_LEN || msg[0..4] != SMB2_MAGIC {
            return None;
        }
        let command = le16(msg, 12);
        let credits = le16(msg, 14).max(1);
        tracing::info!(
            "SMB cmd=0x{command:04x} signed={} encrypted={from_encrypted} len={}",
            le32(msg, 16) & sign::SMB2_FLAGS_SIGNED != 0,
            msg.len()
        );
        let message_id = le64(msg, 24);
        let tree = le32(msg, 36);
        let session = le64(msg, 40);
        let data = &msg[HEADER_LEN..];

        // SMB 3.1.1 preauth integrity: fold the NEGOTIATE request (dialect not yet
        // known) and, once 3.1.1 is negotiated, each SESSION_SETUP request into the
        // hash that will be the key-derivation context.
        if command == SMB2_NEGOTIATE
            || (command == SMB2_SESSION_SETUP && self.dialect == SMB2_DIALECT_311)
        {
            self.preauth_hash.0 = enc::preauth_update(&self.preauth_hash.0, msg);
        }

        // Once signing is in force, a signed request must carry a valid signature
        // (NEGOTIATE/SESSION_SETUP run before the key exists, so are exempt).
        // Messages that arrived encrypted are exempt too: the transform already
        // authenticated them and the inner signature is zeroed.
        if let Some(key) = self.signing_key {
            let signed = le32(msg, 16) & sign::SMB2_FLAGS_SIGNED != 0;
            let exempt = from_encrypted || matches!(command, SMB2_NEGOTIATE | SMB2_SESSION_SETUP);
            if signed && !exempt && !sign::verify_message(&key, msg) {
                tracing::warn!(
                    "SMB signature verify FAILED for cmd=0x{command:04x} → ACCESS_DENIED"
                );
                let r = reply(STATUS_ACCESS_DENIED, session, tree, error_response());
                return Some(build_message(command, message_id, credits, &r));
            }
        }

        let r = match command {
            SMB2_NEGOTIATE => self.negotiate(msg),
            SMB2_SESSION_SETUP => self.session_setup(msg),
            SMB2_TREE_CONNECT => self.tree_connect(msg, session),
            SMB2_CREATE => self.create(msg, session, tree),
            SMB2_READ => self.read(data, session, tree),
            SMB2_WRITE => self.write(msg, session, tree),
            SMB2_IOCTL => self.ioctl(data, session, tree),
            SMB2_QUERY_INFO => query_info(data, session, tree),
            SMB2_QUERY_DIRECTORY => self.query_directory(data, session, tree),
            SMB2_CLOSE => {
                if let Some(id) = data.get(8..24) {
                    let mut fid = [0u8; 16];
                    fid.copy_from_slice(id);
                    self.listed_dirs.remove(&fid);
                    self.open_pipes.remove(&fid);
                }
                reply(STATUS_SUCCESS, session, tree, close_response())
            }
            SMB2_TREE_DISCONNECT | SMB2_LOGOFF => {
                reply(STATUS_SUCCESS, session, tree, small_response(4))
            }
            _ => reply(STATUS_NOT_SUPPORTED, session, tree, error_response()),
        };
        let status = r.status;
        let mut out = build_message(command, message_id, credits, &r);
        // Sign every response once the session key is established (NEGOTIATE has no
        // key yet; the SESSION_SETUP success response is the first signed message).
        if command != SMB2_NEGOTIATE {
            if let Some(key) = self.signing_key {
                sign::sign_message(&key, &mut out);
            }
        }
        // SMB 3.1.1 preauth integrity: fold the NEGOTIATE response and any interim
        // (MORE_PROCESSING) SESSION_SETUP response — but NOT the final success
        // response — into the hash, mirroring the client.
        if self.dialect == SMB2_DIALECT_311
            && (command == SMB2_NEGOTIATE
                || (command == SMB2_SESSION_SETUP && status == STATUS_MORE_PROCESSING_REQUIRED))
        {
            self.preauth_hash.0 = enc::preauth_update(&self.preauth_hash.0, &out);
        }
        Some(out)
    }

    /// NEGOTIATE: pick the highest dialect we support from the client's offer.
    /// SMB 3.0 with a client that advertises encryption → CCM encryption;
    /// SMB 3.0 otherwise → CMAC signing; else 2.1.
    fn negotiate(&mut self, msg: &[u8]) -> Reply {
        let data = &msg[HEADER_LEN..];
        let dialect_count = le16(data, 2) as usize;
        let client_caps = le32(data, 8);
        let offers = |want: u16| {
            (0..dialect_count).any(|i| {
                data.get(36 + i * 2..38 + i * 2)
                    .map(|d| le16(d, 0) == want)
                    .unwrap_or(false)
            })
        };
        self.dialect = if offers(SMB2_DIALECT_311) {
            SMB2_DIALECT_311
        } else if offers(SMB2_DIALECT_30) {
            SMB2_DIALECT_30
        } else {
            SMB2_DIALECT_21
        };
        // 3.1.1 always negotiates encryption (cipher from its context); 3.0 only if
        // the client offered the global encryption capability (always CCM).
        self.encrypt_negotiated = match self.dialect {
            SMB2_DIALECT_311 => true,
            SMB2_DIALECT_30 => client_caps & SMB2_GLOBAL_CAP_ENCRYPTION != 0,
            _ => false,
        };
        if self.dialect == SMB2_DIALECT_311 {
            self.cipher = client_cipher(msg);
        }
        reply(
            STATUS_SUCCESS,
            0,
            0,
            negotiate_response(
                self.dialect,
                self.encrypt_negotiated,
                self.cipher,
                self.service_key.is_some(),
            ),
        )
    }

    /// SESSION_SETUP: NTLM (challenge/authenticate) or, when the security blob is
    /// a Kerberos GSS token, verify the AP-REQ against our cifs service key.
    fn session_setup(&mut self, msg: &[u8]) -> Reply {
        let data = &msg[HEADER_LEN..];
        // Flags (offset 2): SMB2_SESSION_FLAG_BINDING marks a multi-channel bind of
        // this connection to an existing session. We accept it (a real bind would
        // need session state shared across TCP connections, which is out of scope).
        if data
            .get(2)
            .is_some_and(|f| f & SMB2_SESSION_FLAG_BINDING != 0)
        {
            tracing::info!("SMB session-setup channel binding (multi-channel) requested");
        }
        let sec_off = le16(data, 12) as usize;
        let sec_len = le16(data, 14) as usize;
        let blob = msg.get(sec_off..sec_off + sec_len).unwrap_or(&[]);

        // NTLM: type 1 → CHALLENGE (accept-incomplete); type 3 → verify + accept.
        if let Some(msg_type) = ntlmssp_message_type(blob) {
            if msg_type == 1 {
                return reply(
                    STATUS_MORE_PROCESSING_REQUIRED,
                    SESSION_ID,
                    0,
                    session_setup_response(&neg_token_resp_challenge(), 0),
                );
            }
            return self.ntlm_authenticate(blob);
        }

        // Kerberos: verify the AP-REQ against the cifs service key.
        if let (Some(key), Some(ap_req)) = (self.service_key, extract_ap_req(blob)) {
            return match magnetite_krb5::verify_ap_req(&key, ap_req) {
                Ok(v) => {
                    tracing::info!(target: "auth", proto = "smb", principal = ?v.client_name, realm = %v.client_realm, "SMB Kerberos auth ok");
                    // Mutual authentication (MS-KILE/RFC 4121): reply with an AP-REP
                    // sealed under the ticket session key. Its fresh acceptor subkey
                    // becomes the GSS session key — the value BOTH peers use as the
                    // SMB session key (MS-SMB2 §3.2.5.3). Real clients (Samba, Windows)
                    // set MUTUAL-REQUIRED and fail without this AP-REP.
                    let (ap_rep, subkey) = match magnetite_krb5::ap_req::build_ap_rep(
                        &v.session_key,
                        v.ctime,
                        v.cusec,
                        1,
                    ) {
                        Ok(pair) => pair,
                        Err(e) => {
                            tracing::warn!("SMB Kerberos AP-REP build failed: {e}");
                            return reply(
                                STATUS_LOGON_FAILURE,
                                SESSION_ID,
                                0,
                                session_setup_response(&[], 0),
                            );
                        }
                    };
                    // The GSS acceptor subkey is the session key. `Session.SessionKey`
                    // (signing, AES-128, the pipe-SAMR key) is its first 16 bytes; the
                    // FULL key is retained too because AES-256 derives its cipher keys
                    // from the untruncated key (MS-SMB2 §3.1.4.2).
                    let full_key = subkey;
                    let session_key: Vec<u8> = full_key.iter().take(16).copied().collect();
                    // Derive the SMB 3.x keys. The signing key is ALWAYS derived (for
                    // 3.0/3.1.1): even when encryption is negotiated, this SESSION_SETUP
                    // success response is sent in the clear and MUST be signed so the
                    // client can confirm the server holds the session key (MS-SMB2
                    // §3.3.5.5.3) — a real client (Samba) rejects an unsigned one.
                    let mut session_flags = 0u16;
                    if let Ok(key16) = <[u8; 16]>::try_from(session_key.as_slice()) {
                        if self.dialect >= SMB2_DIALECT_30 {
                            // 3.1.1 folds the preauth-integrity hash into the KDF; 3.0
                            // uses the fixed "SmbSign\0" context.
                            self.signing_key = Some(if self.dialect == SMB2_DIALECT_311 {
                                sign::smb311_signing_key(&key16, &self.preauth_hash.0)
                            } else {
                                sign::smb3_signing_key(&key16)
                            });
                        }
                        if self.encrypt_negotiated {
                            // 3.1.1 folds the preauth-integrity hash into the KDF (key
                            // length per the negotiated cipher); 3.0 uses the fixed
                            // ServerIn/ServerOut contexts (always AES-128-CCM).
                            let (enc_key, dec_key) = if self.dialect == SMB2_DIALECT_311 {
                                // AES-256 keys the KDF with the full session key; AES-128
                                // with the 16-byte Session.SessionKey.
                                let ki: &[u8] = if self.cipher.key_len() == 32 {
                                    &full_key
                                } else {
                                    &key16
                                };
                                enc::encryption_keys_311(
                                    ki,
                                    &self.preauth_hash.0,
                                    self.cipher.key_len(),
                                )
                            } else {
                                let (e, d) = enc::encryption_keys(&key16);
                                (e.to_vec(), d.to_vec())
                            };
                            self.enc_key = Some(enc_key);
                            self.dec_key = Some(dec_key);
                            session_flags = SMB2_SESSION_FLAG_ENCRYPT_DATA;
                        }
                    }
                    self.session_key = Some(session_key);
                    self.session_user = Some(v.client_name.join("/"));
                    reply(
                        STATUS_SUCCESS,
                        SESSION_ID,
                        0,
                        session_setup_response(&neg_token_resp_ap_rep(&ap_rep), session_flags),
                    )
                }
                Err(e) => {
                    tracing::warn!(target: "auth", proto = "smb", "SMB Kerberos AP-REQ verification failed: {e}");
                    reply(
                        STATUS_LOGON_FAILURE,
                        SESSION_ID,
                        0,
                        session_setup_response(&[], 0),
                    )
                }
            };
        }

        // No recognised mechanism: accept (an anonymous/continued handshake).
        tracing::debug!(target: "auth", proto = "smb", "SMB session setup accepted without a recognised auth mechanism");
        reply(
            STATUS_SUCCESS,
            SESSION_ID,
            0,
            session_setup_response(&[], 0),
        )
    }

    /// Verify an NTLMv2 AUTHENTICATE (type 3) against the user's NT hash, derive the
    /// SMB session key, and sign the success response (SMB 3.x requires it). When no
    /// directory NT-hash lookup is wired (the standalone PoC servers), NTLM is
    /// accepted without verification and no session key is established.
    fn ntlm_authenticate(&mut self, blob: &[u8]) -> Reply {
        let Some(lookup) = self.nt_hash_lookup.clone() else {
            tracing::debug!(target: "auth", proto = "smb", "SMB NTLM accepted without verification (no directory NT-hash lookup wired)");
            return reply(
                STATUS_SUCCESS,
                SESSION_ID,
                0,
                session_setup_response(&[], 0),
            );
        };
        let ntlm = extract_ntlmssp(blob).unwrap_or(blob);
        let user = magnetite_rpc::ntlmssp::ntlm_username(ntlm);
        // An anonymous (null) session carries an empty user name. A DC accepts it so a
        // just-booted domain member can reach \pipe\netlogon and run the secure-channel
        // credential exchange (which authenticates at the Netlogon RPC layer, not SMB).
        // No session key is established for an anonymous session.
        if user.as_deref().unwrap_or("").is_empty() {
            tracing::debug!("SMB anonymous (null) session accepted");
            return reply(
                STATUS_SUCCESS,
                SESSION_ID,
                0,
                session_setup_response(&neg_token_resp_accept_completed(), 0),
            );
        }
        let ctx = user.as_deref().and_then(|u| lookup(u)).and_then(|h| {
            magnetite_rpc::ntlmssp::NtlmContext::establish_with_challenge(
                &h,
                ntlm,
                &SERVER_CHALLENGE,
            )
        });
        let Some(ctx) = ctx else {
            tracing::warn!(target: "auth", proto = "smb", user = ?user, "SMB NTLM auth failed");
            return reply(
                STATUS_LOGON_FAILURE,
                SESSION_ID,
                0,
                session_setup_response(&[], 0),
            );
        };
        tracing::info!(target: "auth", proto = "smb", user = ?user, "SMB NTLM auth ok");
        // The NTLM exported session key is the SMB `Session.SessionKey` (16 bytes).
        let session_key = ctx.session_key().to_vec();
        let session_flags = self.derive_session_keys(&session_key);
        self.session_key = Some(session_key);
        self.session_user = user;
        reply(
            STATUS_SUCCESS,
            SESSION_ID,
            0,
            session_setup_response(&neg_token_resp_accept_completed(), session_flags),
        )
    }

    /// Derive the SMB 3.x signing key (and, when encryption was negotiated, the CCM/
    /// GCM cipher keys) from `full_key` — the GSS acceptor subkey (32 B) or the NTLM
    /// session key (16 B) — setting `signing_key`/`enc_key`/`dec_key`. Returns the
    /// session flags (`ENCRYPT_DATA` when sealing is on).
    fn derive_session_keys(&mut self, full_key: &[u8]) -> u16 {
        let mut session_flags = 0u16;
        let Some(key16) = full_key
            .get(..16)
            .and_then(|s| <[u8; 16]>::try_from(s).ok())
        else {
            return session_flags;
        };
        if self.dialect >= SMB2_DIALECT_30 {
            self.signing_key = Some(if self.dialect == SMB2_DIALECT_311 {
                sign::smb311_signing_key(&key16, &self.preauth_hash.0)
            } else {
                sign::smb3_signing_key(&key16)
            });
            // The application key seals RPC password buffers (SAMR SetInformationUser2).
            self.application_key = Some(
                if self.dialect == SMB2_DIALECT_311 {
                    sign::smb311_application_key(&key16, &self.preauth_hash.0)
                } else {
                    sign::smb3_application_key(&key16)
                }
                .to_vec(),
            );
        }
        if self.encrypt_negotiated {
            let (enc_key, dec_key) = if self.dialect == SMB2_DIALECT_311 {
                // AES-256 keys the KDF with the full key; AES-128 with the 16-byte key.
                let ki: &[u8] = if self.cipher.key_len() == 32 {
                    full_key
                } else {
                    &key16
                };
                enc::encryption_keys_311(ki, &self.preauth_hash.0, self.cipher.key_len())
            } else {
                let (e, d) = enc::encryption_keys(&key16);
                (e.to_vec(), d.to_vec())
            };
            self.enc_key = Some(enc_key);
            self.dec_key = Some(dec_key);
            session_flags = SMB2_SESSION_FLAG_ENCRYPT_DATA;
        }
        session_flags
    }

    /// IOCTL: the multi-channel network-interface query (the only FSCTL we serve).
    /// A client uses the returned `NETWORK_INTERFACE_INFO` list to discover extra
    /// interfaces on which it may open additional channels for one session.
    fn ioctl(&mut self, data: &[u8], session: u64, tree: u32) -> Reply {
        let ctl_code = le32(data, 4);
        let mut file_id = [0u8; 16];
        if let Some(id) = data.get(8..24) {
            file_id.copy_from_slice(id);
        }
        tracing::info!("SMB IOCTL ctl_code=0x{ctl_code:08x}");
        if ctl_code == FSCTL_QUERY_NETWORK_INTERFACE_INFO {
            let output = network_interface_info();
            reply(
                STATUS_SUCCESS,
                session,
                tree,
                ioctl_response(ctl_code, &file_id, &output),
            )
        } else if ctl_code == FSCTL_VALIDATE_NEGOTIATE_INFO {
            // Echo the negotiated dialect/caps/security-mode/GUID EXACTLY as the
            // NEGOTIATE response did, or the client treats it as a downgrade attack
            // and disconnects (MS-SMB2 §3.2.5.14.12) — which is what a real Windows
            // join was doing right after tree-connecting to IPC$.
            let security_mode = if self.dialect == SMB2_DIALECT_30 && !self.encrypt_negotiated {
                SMB2_NEGOTIATE_SIGNING_ENABLED | SMB2_NEGOTIATE_SIGNING_REQUIRED
            } else {
                SMB2_NEGOTIATE_SIGNING_ENABLED
            };
            let capabilities = if self.encrypt_negotiated {
                SMB2_GLOBAL_CAP_ENCRYPTION
            } else {
                0
            };
            let mut out = Vec::with_capacity(24);
            out.extend_from_slice(&capabilities.to_le_bytes());
            out.extend_from_slice(&SERVER_GUID);
            out.extend_from_slice(&security_mode.to_le_bytes());
            out.extend_from_slice(&self.dialect.to_le_bytes());
            reply(
                STATUS_SUCCESS,
                session,
                tree,
                ioctl_response(ctl_code, &file_id, &out),
            )
        } else if ctl_code == FSCTL_PIPE_TRANSCEIVE {
            // Named-pipe RPC the Windows/Samba way: the IOCTL input is a request PDU
            // and the output its response, in one round-trip (impacket instead uses
            // WRITE then READ — we serve both). InputOffset is from the SMB2 header
            // start; a response larger than MaxOutputResponse returns what fits with
            // STATUS_BUFFER_OVERFLOW and buffers the rest for a follow-up READ.
            let in_off = le32(data, 24) as usize;
            let in_len = le32(data, 28) as usize;
            let max_out = le32(data, 44) as usize;
            let start = in_off.saturating_sub(HEADER_LEN);
            let input = data.get(start..start + in_len).unwrap_or(&[]).to_vec();
            let open = self.open_pipes.keys().cloned().collect::<Vec<_>>();
            let (chunk, status) = match self.open_pipes.get_mut(&file_id) {
                Some(pipe) => {
                    tracing::info!(
                        "SMB IOCTL PIPE_TRANSCEIVE fid={file_id:?} ({in_len} B RPC PDU) → transact"
                    );
                    let full = pipe.rpc.transact(&input).unwrap_or_default();
                    if max_out > 0 && full.len() > max_out {
                        let head = full[..max_out].to_vec();
                        pipe.response = full;
                        pipe.read_pos = max_out;
                        (head, STATUS_BUFFER_OVERFLOW)
                    } else {
                        (full, STATUS_SUCCESS)
                    }
                }
                None => {
                    tracing::warn!(
                        "SMB IOCTL PIPE_TRANSCEIVE fid={file_id:?} not an open pipe (open={open:?})"
                    );
                    (Vec::new(), STATUS_NOT_SUPPORTED)
                }
            };
            reply(
                status,
                session,
                tree,
                ioctl_response(ctl_code, &file_id, &chunk),
            )
        } else {
            reply(STATUS_NOT_SUPPORTED, session, tree, error_response())
        }
    }

    fn query_directory(&mut self, data: &[u8], session: u64, tree: u32) -> Reply {
        // Request: StructureSize(2), FileInfoClass(1), Flags(1), FileIndex(4),
        // FileId(16 @8), FileNameOffset(2), FileNameLength(2), OutputBufferLength(4).
        let mut fid = [0u8; 16];
        if let Some(id) = data.get(8..24) {
            fid.copy_from_slice(id);
        }
        let Some(idx) = decode_file_id(data, 8) else {
            return reply(STATUS_NO_MORE_FILES, session, tree, error_response());
        };
        let vfs = vfs_for(tree);
        let Some(Kind::Dir(children)) = vfs.node(idx).map(|n| &n.kind) else {
            return reply(STATUS_NO_MORE_FILES, session, tree, error_response());
        };
        // Entries are returned on the first call for a handle; then exhausted.
        if !self.listed_dirs.insert(fid) {
            return reply(STATUS_NO_MORE_FILES, session, tree, error_response());
        }
        // FileInformationClass (byte 2) selects the entry layout the client parses.
        let info_class = data.get(2).copied().unwrap_or(FILE_BOTH_DIR_INFO);
        reply(
            STATUS_SUCCESS,
            session,
            tree,
            query_directory_response(&vfs, children, info_class),
        )
    }

    /// TREE_CONNECT: `IPC$` becomes the named-pipe share, everything else the
    /// SYSVOL disk share.
    fn tree_connect(&self, msg: &[u8], session: u64) -> Reply {
        let data = &msg[HEADER_LEN..];
        let path_off = le16(data, 4) as usize;
        let path_len = le16(data, 6) as usize;
        let path = decode_utf16(msg.get(path_off..path_off + path_len).unwrap_or(&[]));
        tracing::info!("SMB TREE_CONNECT path={path:?}");
        let upper = path.to_ascii_uppercase();
        if upper.ends_with("IPC$") {
            reply(
                STATUS_SUCCESS,
                session,
                IPC_TREE_ID,
                tree_connect_response(SHARE_TYPE_PIPE),
            )
        } else if upper.ends_with("NETLOGON") {
            reply(
                STATUS_SUCCESS,
                session,
                NETLOGON_TREE_ID,
                tree_connect_response(SHARE_TYPE_DISK),
            )
        } else {
            reply(
                STATUS_SUCCESS,
                session,
                TREE_ID,
                tree_connect_response(SHARE_TYPE_DISK),
            )
        }
    }

    /// CREATE: a registered pipe name opens an RPC pipe handle; otherwise the
    /// request is resolved against the SYSVOL vfs.
    fn create(&mut self, msg: &[u8], session: u64, tree: u32) -> Reply {
        let data = &msg[HEADER_LEN..];
        let name_off = le16(data, 44) as usize;
        let name_len = le16(data, 46) as usize;
        let name = decode_utf16(msg.get(name_off..name_off + name_len).unwrap_or(&[]));
        let pipe_name = name.trim_matches('\\').to_ascii_lowercase();
        tracing::info!(
            "SMB CREATE name={name:?} pipe_name={pipe_name:?} known_pipes={:?} → {}",
            self.pipes.keys().collect::<Vec<_>>(),
            if self.pipes.contains_key(&pipe_name) {
                "PIPE"
            } else {
                "vfs"
            },
        );

        if let Some(factory) = self.pipes.get(&pipe_name).cloned() {
            let fid = self.alloc_pipe_id();
            // Carry the SMB **application key** (falling back to the raw session key
            // for pre-3.x, which has none) into the pipe so authenticated RPC ops
            // (SamrSetInformationUser2 password set) decrypt with the same key the
            // client sealed them under — the transport's application key, not the raw
            // Session.SessionKey.
            let pipe_key = self
                .application_key
                .clone()
                .or_else(|| self.session_key.clone());
            let rpc =
                RpcPipe::new_with_session_key(factory(), format!("\\PIPE\\{pipe_name}"), pipe_key)
                    // A domain-join client re-authenticates (NTLMSSP) at the RPC layer over
                    // this pipe; verify it against the DC directory (the same lookup the SMB
                    // session-setup used).
                    .with_ntlm_lookup(self.nt_hash_lookup.clone())
                    // Attribute pipe RPC calls (LSA/SAMR) to the SMB-authenticated principal, so
                    // an interface that audits or gates a call knows who is on the session.
                    .with_transport_principal(self.session_user.clone());
            self.open_pipes.insert(
                fid,
                PipeState {
                    rpc,
                    response: Vec::new(),
                    read_pos: 0,
                },
            );
            return reply(STATUS_SUCCESS, session, tree, create_pipe_response(fid));
        }

        match vfs_for(tree).lookup(&name) {
            Some(idx) => reply(STATUS_SUCCESS, session, tree, create_response(idx)),
            None => reply(
                STATUS_OBJECT_NAME_NOT_FOUND,
                session,
                tree,
                error_response(),
            ),
        }
    }

    /// READ: drain an open RPC pipe's buffered response, else read a vfs file.
    fn read(&mut self, data: &[u8], session: u64, tree: u32) -> Reply {
        let mut fid = [0u8; 16];
        if let Some(id) = data.get(16..32) {
            fid.copy_from_slice(id);
        }
        if let Some(pipe) = self.open_pipes.get_mut(&fid) {
            let length = le32(data, 4) as usize;
            let available = pipe.response.len() - pipe.read_pos;
            if available == 0 {
                return reply(STATUS_END_OF_FILE, session, tree, error_response());
            }
            let n = length.min(available);
            let chunk = pipe.response[pipe.read_pos..pipe.read_pos + n].to_vec();
            pipe.read_pos += n;
            return reply(STATUS_SUCCESS, session, tree, read_body(&chunk));
        }
        read_file(data, session, tree)
    }

    /// WRITE: deliver an RPC PDU to an open pipe and buffer the response for the
    /// following READ.
    fn write(&mut self, msg: &[u8], session: u64, tree: u32) -> Reply {
        // Request: StructureSize(2), DataOffset(2 @2), Length(4 @4), Offset(8 @8),
        // FileId(16 @16). DataOffset is measured from the SMB2 header start.
        let data = &msg[HEADER_LEN..];
        let data_off = le16(data, 2) as usize;
        let length = le32(data, 4) as usize;
        let mut fid = [0u8; 16];
        if let Some(id) = data.get(16..32) {
            fid.copy_from_slice(id);
        }
        let open = self.open_pipes.keys().cloned().collect::<Vec<_>>();
        let Some(pipe) = self.open_pipes.get_mut(&fid) else {
            tracing::warn!(
                "SMB WRITE fid={fid:?} not an open pipe (open={open:?}) → NOT_SUPPORTED"
            );
            return reply(STATUS_NOT_SUPPORTED, session, tree, error_response());
        };
        let payload = msg.get(data_off..data_off + length).unwrap_or(&[]);
        tracing::info!("SMB WRITE to pipe fid={fid:?} ({length} B RPC PDU) → transact");
        pipe.response = pipe.rpc.transact(payload).unwrap_or_default();
        pipe.read_pos = 0;
        reply(STATUS_SUCCESS, session, tree, write_response(length as u32))
    }

    /// Allocate a distinct 16-byte FileId for a new pipe handle.
    fn alloc_pipe_id(&mut self) -> [u8; 16] {
        let mut id = *b"PIPE\0\0\0\0MAGNPIPE";
        id[4..8].copy_from_slice(&self.next_pipe.to_le_bytes());
        self.next_pipe += 1;
        id
    }
}

fn reply(status: u32, session_id: u64, tree_id: u32, body: Vec<u8>) -> Reply {
    Reply {
        status,
        session_id,
        tree_id,
        body,
    }
}

/// Assemble the full SMB2 message: response header + command body.
fn build_message(command: u16, message_id: u64, credits: u16, r: &Reply) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + r.body.len());
    out.extend_from_slice(&SMB2_MAGIC);
    out.extend_from_slice(&(HEADER_LEN as u16).to_le_bytes()); // StructureSize
    out.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
    out.extend_from_slice(&r.status.to_le_bytes());
    out.extend_from_slice(&command.to_le_bytes());
    out.extend_from_slice(&credits.to_le_bytes()); // CreditRequestResponse
    out.extend_from_slice(&SMB2_FLAGS_SERVER_TO_REDIR.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    out.extend_from_slice(&message_id.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    out.extend_from_slice(&r.tree_id.to_le_bytes());
    out.extend_from_slice(&r.session_id.to_le_bytes());
    out.extend_from_slice(&[0u8; 16]); // Signature
    out.extend_from_slice(&r.body);
    out
}

fn negotiate_response(dialect: u16, encrypt: bool, cipher: enc::Cipher, kerberos: bool) -> Vec<u8> {
    // A DC advertises Kerberos (ahead of NTLM) so a Kerberos-required client sends
    // an AP-REQ; an NTLM-only server advertises NTLM alone.
    let token = if kerberos {
        neg_token_init_kerberos()
    } else {
        neg_token_init()
    };
    let security_offset: u16 = (HEADER_LEN + 64) as u16;

    // With encryption we don't also require signing (encryption implies
    // integrity); otherwise SMB 3.0 enforces CMAC signing and 2.1 just offers it.
    let security_mode = if dialect == SMB2_DIALECT_30 && !encrypt {
        SMB2_NEGOTIATE_SIGNING_ENABLED | SMB2_NEGOTIATE_SIGNING_REQUIRED
    } else {
        SMB2_NEGOTIATE_SIGNING_ENABLED
    };
    // Advertising the encryption capability is what makes the client encrypt.
    // We do NOT advertise multi-channel: a real Windows client would then query
    // FSCTL_QUERY_NETWORK_INTERFACE_INFO and try to open a second channel to the
    // interface we return — and our single-homed DC has nothing useful to offer
    // (the placeholder 127.0.0.1 makes the client dial its own loopback and time
    // out, aborting the join). Single channel is all a join needs.
    let capabilities = if encrypt {
        SMB2_GLOBAL_CAP_ENCRYPTION
    } else {
        0
    };

    // SMB 3.1.1 appends negotiate contexts after the security buffer, 8-byte
    // aligned; the fixed body is 64 bytes and the token starts at body offset 64.
    let (context_count, context_offset, contexts) = if dialect == SMB2_DIALECT_311 {
        let token_end = 64 + token.len();
        let aligned = token_end.div_ceil(8) * 8;
        let mut blob = vec![0u8; aligned - token_end]; // pad token → 8-aligned
        let (count, ctx) = negotiate_contexts(cipher);
        blob.extend_from_slice(&ctx);
        (count, (HEADER_LEN + aligned) as u32, blob)
    } else {
        (0u16, 0u32, Vec::new())
    };

    let mut b = Vec::new();
    b.extend_from_slice(&65u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&security_mode.to_le_bytes()); // SecurityMode
    b.extend_from_slice(&dialect.to_le_bytes());
    b.extend_from_slice(&context_count.to_le_bytes()); // NegotiateContextCount
    b.extend_from_slice(&SERVER_GUID);
    b.extend_from_slice(&capabilities.to_le_bytes()); // Capabilities
    b.extend_from_slice(&0x0010_0000u32.to_le_bytes()); // MaxTransactSize
    b.extend_from_slice(&0x0010_0000u32.to_le_bytes()); // MaxReadSize
    b.extend_from_slice(&0x0010_0000u32.to_le_bytes()); // MaxWriteSize
    b.extend_from_slice(&SYSTEM_TIME.to_le_bytes());
    b.extend_from_slice(&0u64.to_le_bytes()); // ServerStartTime
    b.extend_from_slice(&security_offset.to_le_bytes());
    b.extend_from_slice(&(token.len() as u16).to_le_bytes());
    b.extend_from_slice(&context_offset.to_le_bytes()); // NegotiateContextOffset
    b.extend_from_slice(&token);
    b.extend_from_slice(&contexts);
    b
}

/// The SMB 3.1.1 negotiate contexts we answer with — SHA-512 preauth integrity,
/// AES-128-CCM encryption, and LZ77 compression — plus their count. Contexts are
/// 8-byte aligned relative to their (already 8-aligned) start (MS-SMB2 §2.2.4).
fn negotiate_contexts(cipher: enc::Cipher) -> (u16, Vec<u8>) {
    let mut c = Vec::new();

    // SMB2_PREAUTH_INTEGRITY_CAPABILITIES: one hash algorithm (SHA-512) + salt.
    let mut preauth = Vec::new();
    preauth.extend_from_slice(&1u16.to_le_bytes()); // HashAlgorithmCount
    preauth.extend_from_slice(&(PREAUTH_SALT.len() as u16).to_le_bytes()); // SaltLength
    preauth.extend_from_slice(&SMB2_HASH_SHA512.to_le_bytes()); // HashAlgorithms[0]
    preauth.extend_from_slice(&PREAUTH_SALT); // Salt
    push_context(&mut c, SMB2_PREAUTH_INTEGRITY_CAPABILITIES, &preauth);
    align8(&mut c);

    // SMB2_ENCRYPTION_CAPABILITIES: the single cipher we chose from the client's list.
    let mut encryption = Vec::new();
    encryption.extend_from_slice(&1u16.to_le_bytes()); // CipherCount
    encryption.extend_from_slice(&cipher.algorithm_id().to_le_bytes()); // Ciphers[0]
    push_context(&mut c, SMB2_ENCRYPTION_CAPABILITIES, &encryption);
    align8(&mut c);

    // SMB2_COMPRESSION_CAPABILITIES: advertise plain LZ77 (unchained).
    let mut compression = Vec::new();
    compression.extend_from_slice(&1u16.to_le_bytes()); // CompressionAlgorithmCount
    compression.extend_from_slice(&0u16.to_le_bytes()); // Padding
    compression.extend_from_slice(&0u32.to_le_bytes()); // Flags (not chained)
    compression.extend_from_slice(&comp::COMPRESSION_ALGORITHM_LZ77.to_le_bytes());
    push_context(&mut c, SMB2_COMPRESSION_CAPABILITIES, &compression);

    (3, c)
}

/// Pick the encryption cipher from a client 3.1.1 NEGOTIATE: the strongest we
/// implement (AES-256-GCM > -256-CCM > -128-GCM) that the client's
/// `SMB2_ENCRYPTION_CAPABILITIES` context offers, else AES-128-CCM.
fn client_cipher(msg: &[u8]) -> enc::Cipher {
    let data = &msg[HEADER_LEN..];
    let context_offset = le32(data, 28) as usize; // from the SMB2 header start
    let context_count = le16(data, 32) as usize;
    let mut best = enc::Cipher::Ccm128;
    let mut pos = context_offset;
    for _ in 0..context_count {
        let Some(context_type) = msg.get(pos..pos + 2).map(|b| le16(b, 0)) else {
            break;
        };
        let Some(data_len) = msg.get(pos + 2..pos + 4).map(|b| le16(b, 0) as usize) else {
            break;
        };
        let body = pos + 8;
        if context_type == SMB2_ENCRYPTION_CAPABILITIES {
            let cipher_count = msg
                .get(body..body + 2)
                .map(|b| le16(b, 0) as usize)
                .unwrap_or(0);
            for i in 0..cipher_count {
                if let Some(offered) = msg
                    .get(body + 2 + i * 2..body + 4 + i * 2)
                    .map(|b| le16(b, 0))
                    .and_then(enc::Cipher::from_id)
                {
                    if offered.preference() < best.preference() {
                        best = offered;
                    }
                }
            }
        }
        pos = (body + data_len).div_ceil(8) * 8; // next context, 8-aligned
    }
    best
}

/// Pad `out` up to the next 8-byte boundary (negotiate-context alignment).
fn align8(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(8) {
        out.push(0);
    }
}

/// Append one `SMB2_NEGOTIATE_CONTEXT` (ContextType, DataLength, Reserved, Data).
fn push_context(out: &mut Vec<u8>, context_type: u16, data: &[u8]) {
    out.extend_from_slice(&context_type.to_le_bytes());
    out.extend_from_slice(&(data.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    out.extend_from_slice(data);
}

fn session_setup_response(token: &[u8], session_flags: u16) -> Vec<u8> {
    let security_offset: u16 = (HEADER_LEN + 8) as u16;
    let mut b = Vec::new();
    b.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&session_flags.to_le_bytes()); // SessionFlags
    b.extend_from_slice(&security_offset.to_le_bytes());
    b.extend_from_slice(&(token.len() as u16).to_le_bytes());
    b.extend_from_slice(token);
    b
}

fn tree_connect_response(share_type: u8) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&16u16.to_le_bytes()); // StructureSize
    b.push(share_type); // ShareType (DISK or PIPE)
    b.push(0); // Reserved
    b.extend_from_slice(&0u32.to_le_bytes()); // ShareFlags
    b.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    b.extend_from_slice(&0x001f_01ffu32.to_le_bytes()); // MaximalAccess
    b
}

/// A CREATE response for an opened named pipe (zero size, normal attributes).
fn create_pipe_response(fid: [u8; 16]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&89u16.to_le_bytes()); // StructureSize
    b.push(0); // OplockLevel
    b.push(0); // Flags
    b.extend_from_slice(&1u32.to_le_bytes()); // CreateAction = FILE_OPENED
    for _ in 0..4 {
        b.extend_from_slice(&SYSTEM_TIME.to_le_bytes());
    }
    b.extend_from_slice(&0u64.to_le_bytes()); // AllocationSize
    b.extend_from_slice(&0u64.to_le_bytes()); // EndofFile
    b.extend_from_slice(&FILE_ATTRIBUTE_NORMAL.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
    b.extend_from_slice(&fid);
    b.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsOffset
    b.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsLength
    b
}

/// A WRITE response reporting `count` bytes accepted (MS-SMB2 §2.2.22).
fn write_response(count: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&17u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    b.extend_from_slice(&count.to_le_bytes()); // Count
    b.extend_from_slice(&0u32.to_le_bytes()); // Remaining
    b.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoOffset
    b.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoLength
    b
}

/// A single-entry `NETWORK_INTERFACE_INFO` list (MS-SMB2 §2.2.32.5): one
/// RSS-capable 10 Gbps IPv4 interface (127.0.0.1). `Next` = 0 marks the last (only)
/// entry; the 128-byte `SockAddr_Storage` holds a `sockaddr_in`.
fn network_interface_info() -> Vec<u8> {
    let mut b = Vec::with_capacity(152);
    b.extend_from_slice(&0u32.to_le_bytes()); // Next (last entry)
    b.extend_from_slice(&1u32.to_le_bytes()); // IfIndex
    b.extend_from_slice(&NETWORK_INTERFACE_RSS_CAPABLE.to_le_bytes()); // Capability
    b.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    b.extend_from_slice(&10_000_000_000u64.to_le_bytes()); // LinkSpeed (10 Gbps)
    let mut sockaddr = [0u8; 128];
    sockaddr[0..2].copy_from_slice(&2u16.to_le_bytes()); // sin_family = AF_INET
    sockaddr[4..8].copy_from_slice(&[127, 0, 0, 1]); // sin_addr
    b.extend_from_slice(&sockaddr);
    b
}

/// An `SMB2 IOCTL` response carrying `output` after the 48-byte fixed fields
/// (MS-SMB2 §2.2.32). `StructureSize` is 49 by the SMB2 "+1" convention.
fn ioctl_response(ctl_code: u32, file_id: &[u8; 16], output: &[u8]) -> Vec<u8> {
    let output_offset = (HEADER_LEN + 48) as u32;
    let mut b = Vec::new();
    b.extend_from_slice(&49u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    b.extend_from_slice(&ctl_code.to_le_bytes());
    b.extend_from_slice(file_id);
    b.extend_from_slice(&0u32.to_le_bytes()); // InputOffset
    b.extend_from_slice(&0u32.to_le_bytes()); // InputCount
    b.extend_from_slice(&output_offset.to_le_bytes()); // OutputOffset
    b.extend_from_slice(&(output.len() as u32).to_le_bytes()); // OutputCount
    b.extend_from_slice(&0u32.to_le_bytes()); // Flags
    b.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
    b.extend_from_slice(output);
    b
}

fn create_response(idx: usize) -> Vec<u8> {
    let v = vfs();
    let is_dir = matches!(v.node(idx).map(|n| &n.kind), Some(Kind::Dir(_)));
    let size = v.size(idx);
    let attrs = if is_dir {
        FILE_ATTRIBUTE_DIRECTORY
    } else {
        FILE_ATTRIBUTE_NORMAL
    };

    let mut b = Vec::new();
    b.extend_from_slice(&89u16.to_le_bytes()); // StructureSize
    b.push(0); // OplockLevel
    b.push(0); // Flags
    b.extend_from_slice(&1u32.to_le_bytes()); // CreateAction = FILE_OPENED
    for _ in 0..4 {
        b.extend_from_slice(&SYSTEM_TIME.to_le_bytes());
    }
    b.extend_from_slice(&size.to_le_bytes()); // AllocationSize
    b.extend_from_slice(&size.to_le_bytes()); // EndofFile
    b.extend_from_slice(&attrs.to_le_bytes()); // FileAttributes
    b.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
    b.extend_from_slice(&encode_file_id(idx));
    b.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsOffset
    b.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsLength
    b
}

/// The body of a READ response carrying `chunk` (MS-SMB2 §2.2.20).
fn read_body(chunk: &[u8]) -> Vec<u8> {
    let data_offset: u8 = (HEADER_LEN + 16) as u8;
    let mut b = Vec::new();
    b.extend_from_slice(&17u16.to_le_bytes()); // StructureSize
    b.push(data_offset);
    b.push(0); // Reserved
    b.extend_from_slice(&(chunk.len() as u32).to_le_bytes()); // DataLength
    b.extend_from_slice(&0u32.to_le_bytes()); // DataRemaining
    b.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
    b.extend_from_slice(chunk);
    b
}

fn read_file(data: &[u8], session: u64, tree: u32) -> Reply {
    // Request: StructureSize(2), Padding(1), Flags(1), Length(4 @4), Offset(8 @8),
    // FileId(16 @16).
    let length = le32(data, 4) as usize;
    let offset = le64(data, 8) as usize;
    let Some(idx) = decode_file_id(data, 16) else {
        return reply(STATUS_END_OF_FILE, session, tree, error_response());
    };
    let vfs = vfs_for(tree);
    let Some(Kind::File(content)) = vfs.node(idx).map(|n| &n.kind) else {
        return reply(STATUS_END_OF_FILE, session, tree, error_response());
    };

    if offset >= content.len() {
        return reply(STATUS_END_OF_FILE, session, tree, error_response());
    }
    let end = (offset + length).min(content.len());
    reply(
        STATUS_SUCCESS,
        session,
        tree,
        read_body(&content[offset..end]),
    )
}

/// SMB2 QUERY_INFO. Request: StructureSize(2), InfoType(1)@2, FileInfoClass(1)@3,
/// … FileId(16)@24. We answer the file-information class the client asked for (a
/// fixed FileStandardInformation was too short for `FileAllInformation`, which
/// `smbclient get` issues — the peer then reports an invalid response).
fn query_info(data: &[u8], session: u64, tree: u32) -> Reply {
    let info_type = data.get(2).copied().unwrap_or(1);
    let info_class = data.get(3).copied().unwrap_or(FILE_STANDARD_INFO);

    // A named-pipe (or otherwise non-vfs) handle has no vfs node — answer as a
    // zero-size regular file rather than indexing the vfs tree (which would panic).
    let v = vfs();
    let (size, is_dir, name) =
        match decode_file_id(data, 24).and_then(|idx| v.node(idx).map(|n| (idx, n))) {
            Some((idx, node)) => (
                v.size(idx),
                matches!(node.kind, Kind::Dir(_)),
                node.name.clone(),
            ),
            None => (0, false, String::new()),
        };
    let attrs = if is_dir {
        FILE_ATTRIBUTE_DIRECTORY
    } else {
        FILE_ATTRIBUTE_NORMAL
    };

    // FILE information (InfoType 1) or FILESYSTEM information (InfoType 2, for a
    // client's free-space query); other info types get an empty OK.
    let info = match info_type {
        INFO_TYPE_FILE => file_information(info_class, size, attrs, is_dir, &name),
        INFO_TYPE_FILESYSTEM => filesystem_information(info_class),
        _ => Vec::new(),
    };

    let output_offset: u16 = (HEADER_LEN + 8) as u16;
    let mut b = Vec::new();
    b.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&output_offset.to_le_bytes());
    b.extend_from_slice(&(info.len() as u32).to_le_bytes()); // OutputBufferLength
    b.extend_from_slice(&info);
    reply(STATUS_SUCCESS, session, tree, b)
}

/// FileBasicInformation (40 bytes): the four timestamps + attributes.
fn file_basic_information(attrs: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(40);
    for _ in 0..4 {
        v.extend_from_slice(&SYSTEM_TIME.to_le_bytes()); // Creation/Access/Write/Change
    }
    v.extend_from_slice(&attrs.to_le_bytes()); // FileAttributes
    v.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    v
}

/// FileStandardInformation (24 bytes): sizes, link count, delete/dir flags.
fn file_standard_information(size: u64, is_dir: bool) -> Vec<u8> {
    let mut v = Vec::with_capacity(24);
    v.extend_from_slice(&size.to_le_bytes()); // AllocationSize
    v.extend_from_slice(&size.to_le_bytes()); // EndOfFile
    v.extend_from_slice(&1u32.to_le_bytes()); // NumberOfLinks
    v.push(0); // DeletePending
    v.push(u8::from(is_dir)); // Directory
    v.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    v
}

/// Build the requested file-information class (MS-FSCC). Falls back to
/// FileStandardInformation for classes we don't specialise.
fn file_information(info_class: u8, size: u64, attrs: u32, is_dir: bool, name: &str) -> Vec<u8> {
    match info_class {
        FILE_BASIC_INFO => file_basic_information(attrs),
        FILE_NETWORK_OPEN_INFO => {
            // 56 bytes: four timestamps, allocation/end-of-file, attributes, reserved.
            let mut v = Vec::with_capacity(56);
            for _ in 0..4 {
                v.extend_from_slice(&SYSTEM_TIME.to_le_bytes());
            }
            v.extend_from_slice(&size.to_le_bytes()); // AllocationSize
            v.extend_from_slice(&size.to_le_bytes()); // EndOfFile
            v.extend_from_slice(&attrs.to_le_bytes()); // FileAttributes
            v.extend_from_slice(&0u32.to_le_bytes()); // Reserved
            v
        }
        FILE_ALL_INFO => {
            // Basic + Standard + Internal + Ea + Access + Position + Mode + Alignment
            // + Name (MS-FSCC §2.4.2), which is what `smbclient get` queries.
            let name_utf16 = utf16le(name);
            let mut v = file_basic_information(attrs);
            v.extend_from_slice(&file_standard_information(size, is_dir));
            v.extend_from_slice(&(idx_index(name)).to_le_bytes()); // InternalInformation.IndexNumber
            v.extend_from_slice(&0u32.to_le_bytes()); // EaInformation.EaSize
            v.extend_from_slice(&0x001f_01ffu32.to_le_bytes()); // AccessInformation.AccessFlags
            v.extend_from_slice(&0u64.to_le_bytes()); // PositionInformation.CurrentByteOffset
            v.extend_from_slice(&0u32.to_le_bytes()); // ModeInformation.Mode
            v.extend_from_slice(&1u32.to_le_bytes()); // AlignmentInformation.AlignmentRequirement
            v.extend_from_slice(&(name_utf16.len() as u32).to_le_bytes()); // NameInformation.FileNameLength
            v.extend_from_slice(&name_utf16);
            v
        }
        _ => file_standard_information(size, is_dir),
    }
}

/// A stable pseudo IndexNumber for FileAllInformation (hash of the name).
fn idx_index(name: &str) -> u64 {
    name.bytes().fold(1469598103934665603u64, |h, b| {
        (h ^ b as u64).wrapping_mul(1099511628211)
    })
}

/// Build a filesystem-information class (MS-FSCC §2.5) for a client free-space
/// query (`smbclient` runs one after a listing). We report a nominal read-only
/// volume; `FileFsFullSizeInformation`/`FileFsSizeInformation` are the ones
/// `dskattr` issues, anything else gets FileFsSizeInformation.
fn filesystem_information(info_class: u8) -> Vec<u8> {
    const UNITS: u64 = 1024; // total allocation units (nominal)
    const SECTORS_PER_UNIT: u32 = 1;
    const BYTES_PER_SECTOR: u32 = 512;
    match info_class {
        FS_FULL_SIZE_INFO => {
            let mut v = Vec::with_capacity(32);
            v.extend_from_slice(&UNITS.to_le_bytes()); // TotalAllocationUnits
            v.extend_from_slice(&0u64.to_le_bytes()); // CallerAvailableAllocationUnits
            v.extend_from_slice(&0u64.to_le_bytes()); // ActualAvailableAllocationUnits
            v.extend_from_slice(&SECTORS_PER_UNIT.to_le_bytes());
            v.extend_from_slice(&BYTES_PER_SECTOR.to_le_bytes());
            v
        }
        _ => {
            // FileFsSizeInformation (24 bytes).
            let mut v = Vec::with_capacity(24);
            v.extend_from_slice(&UNITS.to_le_bytes()); // TotalAllocationUnits
            v.extend_from_slice(&0u64.to_le_bytes()); // AvailableAllocationUnits
            v.extend_from_slice(&SECTORS_PER_UNIT.to_le_bytes());
            v.extend_from_slice(&BYTES_PER_SECTOR.to_le_bytes());
            v
        }
    }
}

/// Build a QUERY_DIRECTORY response with FILE_FULL_DIRECTORY_INFORMATION entries
/// for `children` (MS-FSCC §2.4.14, MS-SMB2 §2.2.34). `vfs` is the tree the
/// directory handle belongs to (its node indices index into it).
fn query_directory_response(vfs: &Vfs, children: &[usize], info_class: u8) -> Vec<u8> {
    // The fixed header size preceding the file name, per FileInformationClass. The
    // shared prefix (NextEntryOffset..EaSize) is 68 bytes; Both/IdBoth add the 8.3
    // short-name fields, IdBoth also a Reserved2 + FileId.
    let header_len = match info_class {
        FILE_FULL_DIR_INFO => 68,
        FILE_ID_BOTH_DIR_INFO => 104,
        _ => 94, // FileBothDirectoryInformation (smbclient's default)
    };
    let mut buffer = Vec::new();
    for (i, &child) in children.iter().enumerate() {
        // `children` hold internal node indices, so this is always Some; skip
        // defensively rather than indexing so a corrupt index can't panic.
        let Some(node) = vfs.node(child) else {
            continue;
        };
        let name = utf16le(&node.name);
        let is_dir = matches!(node.kind, Kind::Dir(_));
        let size = vfs.size(child);

        let unpadded = header_len + name.len();
        let padded = unpadded.div_ceil(8) * 8;
        let next = if i + 1 == children.len() {
            0
        } else {
            padded as u32
        };

        let start = buffer.len();
        buffer.extend_from_slice(&next.to_le_bytes()); // NextEntryOffset
        buffer.extend_from_slice(&0u32.to_le_bytes()); // FileIndex
        for _ in 0..4 {
            buffer.extend_from_slice(&SYSTEM_TIME.to_le_bytes()); // Creation/Access/Write/Change
        }
        buffer.extend_from_slice(&size.to_le_bytes()); // EndOfFile
        buffer.extend_from_slice(&size.to_le_bytes()); // AllocationSize
        buffer.extend_from_slice(
            &(if is_dir {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_NORMAL
            })
            .to_le_bytes(),
        );
        buffer.extend_from_slice(&(name.len() as u32).to_le_bytes()); // FileNameLength
        buffer.extend_from_slice(&0u32.to_le_bytes()); // EaSize
                                                       // Both/IdBoth carry an (empty) 8.3 short name; IdBoth also a 128-bit FileId.
        if info_class != FILE_FULL_DIR_INFO {
            buffer.push(0); // ShortNameLength
            buffer.push(0); // Reserved1
            buffer.extend_from_slice(&[0u8; 24]); // ShortName (8.3, unused)
            if info_class == FILE_ID_BOTH_DIR_INFO {
                buffer.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
                buffer.extend_from_slice(&(child as u64).to_le_bytes()); // FileId
            }
        }
        buffer.extend_from_slice(&name);
        buffer.resize(start + padded, 0); // pad to 8-byte alignment
    }

    let output_offset: u16 = (HEADER_LEN + 8) as u16;
    let mut b = Vec::new();
    b.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&output_offset.to_le_bytes());
    b.extend_from_slice(&(buffer.len() as u32).to_le_bytes()); // OutputBufferLength
    b.extend_from_slice(&buffer);
    b
}

fn close_response() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&60u16.to_le_bytes()); // StructureSize
    b.extend_from_slice(&0u16.to_le_bytes()); // Flags
    b.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    for _ in 0..4 {
        b.extend_from_slice(&SYSTEM_TIME.to_le_bytes());
    }
    b.extend_from_slice(&0u64.to_le_bytes()); // AllocationSize
    b.extend_from_slice(&0u64.to_le_bytes()); // EndofFile
    b.extend_from_slice(&FILE_ATTRIBUTE_NORMAL.to_le_bytes()); // FileAttributes
    b
}

/// A fixed-size trivial response body (`StructureSize` then reserved zeros).
fn small_response(structure_size: u16) -> Vec<u8> {
    let mut b = structure_size.to_le_bytes().to_vec();
    b.extend_from_slice(&0u16.to_le_bytes());
    b
}

/// An SMB2 ERROR response body (MS-SMB2 §2.2.2).
fn error_response() -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
    b.push(0); // ErrorContextCount
    b.push(0); // Reserved
    b.extend_from_slice(&0u32.to_le_bytes()); // ByteCount
    b.push(0); // ErrorData (one byte, per StructureSize convention)
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_reads_are_bounds_checked_and_never_panic() {
        // A short/empty buffer (an unauthenticated NEGOTIATE/SESSION_SETUP with a
        // truncated body) must read as 0, not panic the connection task.
        assert_eq!(le16(&[], 0), 0);
        assert_eq!(le16(&[0x01], 0), 0); // 1 byte, need 2
        assert_eq!(le32(&[0xff, 0xff], 0), 0); // 2 bytes, need 4
        assert_eq!(le64(&[0; 4], 0), 0); // 4 bytes, need 8
        assert_eq!(le16(&[0x34, 0x12], 0), 0x1234); // exact fit still works
        assert_eq!(le32(&[1, 0, 0, 0, 9, 9], 0), 1); // reads only its 4 bytes
    }

    /// Build a request SMB2 message with the given command and body.
    fn request(command: u16, body: &[u8]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&SMB2_MAGIC);
        m.extend_from_slice(&(HEADER_LEN as u16).to_le_bytes());
        m.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
        m.extend_from_slice(&0u32.to_le_bytes()); // Status
        m.extend_from_slice(&command.to_le_bytes());
        m.extend_from_slice(&1u16.to_le_bytes()); // CreditRequest
        m.extend_from_slice(&0u32.to_le_bytes()); // Flags
        m.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
        m.extend_from_slice(&0u64.to_le_bytes()); // MessageID
        m.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        m.extend_from_slice(&0u32.to_le_bytes()); // TreeID
        m.extend_from_slice(&0u64.to_le_bytes()); // SessionID
        m.extend_from_slice(&[0u8; 16]); // Signature
        m.extend_from_slice(body);
        m
    }

    fn status(reply: &[u8]) -> u32 {
        le32(reply, 8)
    }
    fn body(reply: &[u8]) -> &[u8] {
        &reply[HEADER_LEN..]
    }

    /// Build a CREATE request for `path` (returns the whole SMB2 message).
    fn create_request(path: &str) -> Vec<u8> {
        let name = utf16le(path);
        let mut b = vec![0u8; 56];
        b[0..2].copy_from_slice(&57u16.to_le_bytes()); // StructureSize
        let name_off = HEADER_LEN + 56;
        b[44..46].copy_from_slice(&(name_off as u16).to_le_bytes());
        b[46..48].copy_from_slice(&(name.len() as u16).to_le_bytes());
        b.extend_from_slice(&name);
        request(SMB2_CREATE, &b)
    }

    #[test]
    fn negotiate_offers_smb21() {
        let mut c = Connection::default();
        let reply = c.handle(&request(SMB2_NEGOTIATE, &[0u8; 36])).unwrap();
        assert_eq!(status(&reply), STATUS_SUCCESS);
        assert_eq!(le16(&reply, HEADER_LEN + 4), SMB2_DIALECT_21);
    }

    #[test]
    fn smb1_multiprotocol_negotiate_gets_smb2_wildcard() {
        let mut c = Connection::default();
        // A real Windows client's first packet: SMB1 NEGOTIATE (`\xFFSMBr` …).
        let smb1 = [0xff, b'S', b'M', b'B', SMB1_COM_NEGOTIATE, 0, 0, 0];
        let reply = c
            .handle(&smb1)
            .expect("SMB1 negotiate must get a reply, not a drop");
        // Reply is an SMB2 NEGOTIATE response advertising the 0x02FF wildcard dialect.
        assert_eq!(&reply[0..4], &SMB2_MAGIC, "SMB2 header");
        assert_eq!(le16(&reply, 12), SMB2_NEGOTIATE, "Command = NEGOTIATE");
        assert_eq!(status(&reply), STATUS_SUCCESS);
        assert_eq!(
            le16(&reply, HEADER_LEN + 4),
            SMB2_DIALECT_WILDCARD,
            "DialectRevision"
        );
        // No dialect is fixed yet — the client re-negotiates with a real SMB2 request.
        assert_eq!(c.dialect, 0);
    }

    #[test]
    fn negotiate_311_selects_dialect_and_contexts() {
        let mut c = Connection::default();
        // Negotiate request offering SMB 3.1.1 with the encryption capability.
        let mut body = vec![0u8; 38];
        body[0..2].copy_from_slice(&36u16.to_le_bytes()); // StructureSize
        body[2..4].copy_from_slice(&1u16.to_le_bytes()); // DialectCount
        body[8..12].copy_from_slice(&SMB2_GLOBAL_CAP_ENCRYPTION.to_le_bytes()); // Capabilities
        body[36..38].copy_from_slice(&SMB2_DIALECT_311.to_le_bytes()); // Dialects[0]

        let reply = c.handle(&request(SMB2_NEGOTIATE, &body)).unwrap();
        assert_eq!(le16(&reply, HEADER_LEN + 4), SMB2_DIALECT_311); // DialectRevision
        assert_eq!(le16(&reply, HEADER_LEN + 6), 3); // NegotiateContextCount
        let caps = le32(&reply, HEADER_LEN + 24); // Capabilities
        assert_ne!(caps & SMB2_GLOBAL_CAP_ENCRYPTION, 0);
        // Multi-channel is intentionally NOT advertised (a single-homed DC would send
        // a placeholder interface that makes a real client dial its own loopback).
        assert_eq!(caps & SMB2_GLOBAL_CAP_MULTI_CHANNEL, 0);
        assert!(c.encrypt_negotiated);
        // Request + response were folded into the preauth hash.
        assert_ne!(c.preauth_hash.0, [0u8; 64]);
        // The NegotiateContextOffset points 8-aligned past the header.
        let ctx_off = le32(&reply, HEADER_LEN + 60) as usize;
        assert_eq!(ctx_off % 8, 0);
        assert_eq!(le16(&reply, ctx_off), SMB2_PREAUTH_INTEGRITY_CAPABILITIES);
    }

    #[test]
    fn negotiate_311_picks_gcm_when_offered() {
        let mut c = Connection::default();
        // 3.1.1 negotiate whose encryption context (at message offset 104) offers
        // AES-128-GCM.
        let mut body = vec![0u8; 40];
        body[0..2].copy_from_slice(&36u16.to_le_bytes()); // StructureSize
        body[2..4].copy_from_slice(&1u16.to_le_bytes()); // DialectCount
        body[8..12].copy_from_slice(&SMB2_GLOBAL_CAP_ENCRYPTION.to_le_bytes());
        body[28..32].copy_from_slice(&104u32.to_le_bytes()); // NegotiateContextOffset
        body[32..34].copy_from_slice(&1u16.to_le_bytes()); // NegotiateContextCount
        body[36..38].copy_from_slice(&SMB2_DIALECT_311.to_le_bytes()); // Dialects[0]
                                                                       // body[38..40] is padding; the context begins at body offset 40 (msg 104).
        body.extend_from_slice(&SMB2_ENCRYPTION_CAPABILITIES.to_le_bytes()); // ContextType
        body.extend_from_slice(&4u16.to_le_bytes()); // DataLength
        body.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        body.extend_from_slice(&1u16.to_le_bytes()); // CipherCount
        body.extend_from_slice(&enc::SMB2_ENCRYPTION_AES128_GCM.to_le_bytes());

        let reply = c.handle(&request(SMB2_NEGOTIATE, &body)).unwrap();
        assert_eq!(status(&reply), STATUS_SUCCESS);
        assert_eq!(
            c.cipher,
            enc::Cipher::Gcm128,
            "GCM offered → GCM negotiated"
        );
    }

    #[test]
    fn negotiate_311_prefers_aes256_gcm() {
        let mut c = Connection::default();
        // Client offers [AES-128-CCM, AES-256-GCM]; the server prefers AES-256-GCM
        // (strongest), now that its key schedule is interop-verified.
        let mut body = vec![0u8; 40];
        body[0..2].copy_from_slice(&36u16.to_le_bytes());
        body[2..4].copy_from_slice(&1u16.to_le_bytes());
        body[8..12].copy_from_slice(&SMB2_GLOBAL_CAP_ENCRYPTION.to_le_bytes());
        body[28..32].copy_from_slice(&104u32.to_le_bytes()); // NegotiateContextOffset
        body[32..34].copy_from_slice(&1u16.to_le_bytes()); // NegotiateContextCount
        body[36..38].copy_from_slice(&SMB2_DIALECT_311.to_le_bytes());
        body.extend_from_slice(&SMB2_ENCRYPTION_CAPABILITIES.to_le_bytes()); // ContextType
        body.extend_from_slice(&6u16.to_le_bytes()); // DataLength
        body.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        body.extend_from_slice(&2u16.to_le_bytes()); // CipherCount
        body.extend_from_slice(&enc::SMB2_ENCRYPTION_AES128_CCM.to_le_bytes());
        body.extend_from_slice(&enc::SMB2_ENCRYPTION_AES256_GCM.to_le_bytes());

        c.handle(&request(SMB2_NEGOTIATE, &body)).unwrap();
        assert_eq!(
            c.cipher,
            enc::Cipher::Gcm256,
            "AES-256-GCM is the strongest offered"
        );
        assert_eq!(c.cipher.key_len(), 32);
    }

    #[test]
    fn create_read_serves_gpt_ini_by_path() {
        let mut c = Connection::default();
        let path = "example.com\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\GPT.INI";
        let create = c.handle(&create_request(path)).unwrap();
        assert_eq!(status(&create), STATUS_SUCCESS);
        // FileId is at body offset 64..80 in the CREATE response.
        let file_id = &body(&create)[64..80];

        // READ request with that FileId.
        let mut rb = vec![0u8; 48];
        rb[0..2].copy_from_slice(&49u16.to_le_bytes());
        rb[4..8].copy_from_slice(&4096u32.to_le_bytes()); // Length
        rb[16..32].copy_from_slice(file_id);
        let reply = c.handle(&request(SMB2_READ, &rb)).unwrap();
        assert_eq!(status(&reply), STATUS_SUCCESS);
        let n = le32(&reply, HEADER_LEN + 4) as usize;
        let content = &reply[HEADER_LEN + 16..HEADER_LEN + 16 + n];
        assert!(content.starts_with(b"[General]"));
        assert!(content.windows(9).any(|w| w == b"Magnetite"));
    }

    #[test]
    fn missing_path_is_not_found() {
        let mut c = Connection::default();
        let reply = c.handle(&create_request("example.com\\nope.txt")).unwrap();
        assert_eq!(status(&reply), STATUS_OBJECT_NAME_NOT_FOUND);
    }

    #[test]
    fn query_directory_lists_children_then_exhausts() {
        let mut c = Connection::default();
        let create = c.handle(&create_request("example.com\\Policies")).unwrap();
        let file_id = body(&create)[64..80].to_vec();

        let mut qd = vec![0u8; 32];
        qd[0..2].copy_from_slice(&33u16.to_le_bytes());
        qd[8..24].copy_from_slice(&file_id);
        let reply = c.handle(&request(SMB2_QUERY_DIRECTORY, &qd)).unwrap();
        assert_eq!(status(&reply), STATUS_SUCCESS);
        // The policy GUID directory name appears (UTF-16) in the entry buffer.
        let buf = body(&reply);
        let needle = utf16le("31B2F340");
        assert!(buf.windows(needle.len()).any(|w| w == needle));

        // A second query on the same handle is exhausted.
        let reply2 = c.handle(&request(SMB2_QUERY_DIRECTORY, &qd)).unwrap();
        assert_eq!(status(&reply2), STATUS_NO_MORE_FILES);
    }

    #[test]
    fn session_setup_challenges_then_accepts() {
        let mut c = Connection::default();
        let mut type1 = b"NTLMSSP\0".to_vec();
        type1.extend_from_slice(&1u32.to_le_bytes());
        let sec_off = HEADER_LEN + 24;
        let mut sbody = vec![0u8; 24];
        sbody[0..2].copy_from_slice(&25u16.to_le_bytes());
        sbody[12..14].copy_from_slice(&(sec_off as u16).to_le_bytes());
        sbody[14..16].copy_from_slice(&(type1.len() as u16).to_le_bytes());
        sbody.extend_from_slice(&type1);
        let reply = c.handle(&request(SMB2_SESSION_SETUP, &sbody)).unwrap();
        assert_eq!(status(&reply), STATUS_MORE_PROCESSING_REQUIRED);

        let mut type3 = b"NTLMSSP\0".to_vec();
        type3.extend_from_slice(&3u32.to_le_bytes());
        let mut sbody = vec![0u8; 24];
        sbody[0..2].copy_from_slice(&25u16.to_le_bytes());
        sbody[12..14].copy_from_slice(&(sec_off as u16).to_le_bytes());
        sbody[14..16].copy_from_slice(&(type3.len() as u16).to_le_bytes());
        sbody.extend_from_slice(&type3);
        let reply = c.handle(&request(SMB2_SESSION_SETUP, &sbody)).unwrap();
        assert_eq!(status(&reply), STATUS_SUCCESS);
        assert_eq!(le64(&reply, 40), SESSION_ID);
    }
}
