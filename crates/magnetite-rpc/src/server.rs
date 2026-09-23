//! `ncacn_ip_tcp` transport: a TCP server that speaks connection-oriented RPC.
//!
//! Per connection we read one PDU at a time (framed by `frag_length`), dispatch
//! BIND → BIND_ACK and REQUEST → RESPONSE/FAULT, and write the reply. Netlogon
//! SSP PKT_INTEGRITY is supported: an authenticated ALTER_CONTEXT binds a session
//! key to the connection, after which REQUEST/RESPONSE PDUs are signed and
//! verified. Fragmentation, sealing (PKT_PRIVACY), and `ncacn_np` are out of
//! scope for this tracer bullet.

use crate::auth::{
    auth_token, build_auth_response_typed, build_sealed_response, build_signed_response,
    negotiated_auth_ctx_id, negotiated_auth_level, negotiated_auth_type, nl_auth_message_response,
    padded_response_stub, parse_signed_request, RPC_C_AUTHN_GSS_NEGOTIATE,
    RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_NETLOGON,
    RPC_C_AUTHN_WINNT,
};
use crate::bind::{
    build_alter_context_resp, build_alter_context_resp_noauth, build_bind_ack,
    build_bind_ack_with_auth, build_bind_nak, BindRequest,
};
use crate::interface::RpcInterface;
use crate::netlogon::{sign_integrity_aes, unseal_aes};
use crate::ntlmssp::{challenge_message, ntlm_username, NtlmContext};
use crate::pdu::{common_header, pfc, ptype, CommonHeader, HEADER_LEN};
use crate::request::{build_fault, build_response, fault, Request};
use magnetite_krb5::ap_req::build_ap_rep;
use magnetite_krb5::gss::{
    gss_mic, gss_mic_acceptor, gss_unwrap, gss_unwrap_iov, gss_wrap, gss_wrap_iov, verify_gss_mic,
    KG_USAGE_ACCEPTOR_SEAL, KG_USAGE_INITIATOR_SEAL,
};
use magnetite_krb5::spnego::{
    extract_ap_req, first_mech_oid, mech_list_der, wrap_accept_completed_mic, wrap_ap_rep,
};
use magnetite_krb5::verify_ap_req;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Maximum accepted PDU size (defensive bound).
const MAX_PDU: usize = 64 * 1024;

/// The acceptor's initial GSS send sequence, declared in the AP-REP's seq-number and
/// used for the leg-4 mechListMIC, then incremented per sealed/signed response.
const GSS_ACCEPTOR_SEQ_BASE: u64 = 1;

/// The fixed auth-trailer length of an in-place GSS Wrap (header-signed) seal: token
/// header 16 + confounder 16 + EC 0 + header-copy 16 + checksum 12 = 60 bytes.
const SEAL_AUTH_LEN: u16 = 60;

/// Authentication material an endpoint accepts on a bind.
#[derive(Clone, Default)]
struct AuthConfig {
    /// The NT hash for NTLM SSP binds (`serve_with_ntlm`).
    ntlm_nt_hash: Option<[u8; 16]>,
    /// The Kerberos service (AES256) key for GSS binds (`serve_with_kerberos`).
    gss_service_key: Option<Vec<u8>>,
}

/// Serve connection-oriented RPC for `iface` on `addr` until an I/O error.
pub async fn serve(addr: SocketAddr, iface: Arc<dyn RpcInterface>) -> io::Result<()> {
    serve_inner(addr, iface, AuthConfig::default()).await
}

/// Serve RPC accepting NTLM SSP-authenticated binds: a client authenticating as
/// the account whose NT hash is `nt_hash` establishes a session key used to sign
/// PDUs and to encrypt replicated secrets (DRSUAPI DCSync).
pub async fn serve_with_ntlm(
    addr: SocketAddr,
    iface: Arc<dyn RpcInterface>,
    nt_hash: [u8; 16],
) -> io::Result<()> {
    serve_inner(
        addr,
        iface,
        AuthConfig {
            ntlm_nt_hash: Some(nt_hash),
            ..Default::default()
        },
    )
    .await
}

/// Serve RPC accepting Kerberos (SPNEGO/GSS) authenticated binds: a client's
/// AP-REQ for the service whose AES256 key is `service_key` is verified, a
/// mutual-auth AP-REP is returned, and the negotiated acceptor subkey signs PDUs
/// (GSS MIC) and encrypts replicated secrets.
pub async fn serve_with_kerberos(
    addr: SocketAddr,
    iface: Arc<dyn RpcInterface>,
    service_key: Vec<u8>,
) -> io::Result<()> {
    serve_inner(
        addr,
        iface,
        AuthConfig {
            gss_service_key: Some(service_key),
            ..Default::default()
        },
    )
    .await
}

async fn serve_inner(
    addr: SocketAddr,
    iface: Arc<dyn RpcInterface>,
    auth: AuthConfig,
) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let sec_addr = addr.port().to_string();
    tracing::info!("magnetite-rpc listening on {addr} (ncacn_ip_tcp)");
    loop {
        let (stream, peer) = listener.accept().await?;
        tracing::debug!(target: "conn", %peer, "RPC connection (ncacn_ip_tcp)");
        let iface = iface.clone();
        let sec_addr = sec_addr.clone();
        let auth = auth.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, iface, sec_addr, auth).await {
                tracing::debug!("RPC connection ended: {e}");
            }
        });
    }
}

async fn handle_conn(
    mut stream: TcpStream,
    iface: Arc<dyn RpcInterface>,
    sec_addr: String,
    auth: AuthConfig,
) -> io::Result<()> {
    let mut conn = Connection {
        ntlm_nt_hash: auth.ntlm_nt_hash,
        gss_service_key: auth.gss_service_key,
        ..Default::default()
    };
    loop {
        // Read the common header, then the rest of the fragment.
        let mut header_buf = [0u8; HEADER_LEN];
        if stream.read_exact(&mut header_buf).await.is_err() {
            return Ok(()); // clean EOF
        }
        let Ok(header) = CommonHeader::parse(&header_buf) else {
            return Ok(()); // unparseable header: drop the connection
        };
        let frag_length = header.frag_length as usize;
        if !(HEADER_LEN..=MAX_PDU).contains(&frag_length) {
            return Ok(());
        }
        let mut body = vec![0u8; frag_length - HEADER_LEN];
        stream.read_exact(&mut body).await?;

        let Some(reply) = conn.handle(&header, &header_buf, &body, iface.as_ref(), &sec_addr)
        else {
            continue; // nothing to send (e.g. an unsupported PDU we ignore)
        };
        stream.write_all(&reply).await?;
        stream.flush().await?;
    }
}

/// An RPC endpoint reachable over a message transport that delivers whole PDUs
/// (an SMB named pipe, `ncacn_np`), rather than the byte stream [`serve`] frames.
///
/// Each inbound message is one complete RPC PDU; [`RpcPipe::transact`] dispatches
/// it (BIND/ALTER_CONTEXT/REQUEST) and returns the response PDU to write back.
/// Per-pipe auth state (session key, sequence) lives here, so one `RpcPipe`
/// corresponds to one opened pipe handle.
/// Looks up a user's NT hash by account name — supplied by the DC (from its
/// directory) so an authenticated NTLMSSP bind over a pipe can be verified against
/// whoever authenticates, not a single fixed principal.
pub type NtHashLookup = Arc<dyn Fn(&str) -> Option<[u8; 16]> + Send + Sync>;

pub struct RpcPipe {
    iface: Arc<dyn RpcInterface>,
    conn: Connection,
    sec_addr: String,
}

impl RpcPipe {
    /// A pipe bound to `iface`, advertising `sec_addr` (the pipe name) in binds.
    pub fn new(iface: Arc<dyn RpcInterface>, sec_addr: impl Into<String>) -> Self {
        Self {
            iface,
            conn: Connection::default(),
            sec_addr: sec_addr.into(),
        }
    }

    /// A pipe that also carries a transport-provided session key (the SMB Kerberos
    /// session key from the authenticated SMB session), exposed to the interface so
    /// pipe SAMR can decrypt a `SamrSetInformationUser2` password buffer.
    pub fn new_with_session_key(
        iface: Arc<dyn RpcInterface>,
        sec_addr: impl Into<String>,
        session_key: Option<Vec<u8>>,
    ) -> Self {
        Self {
            iface,
            conn: Connection {
                transport_session_key: session_key,
                ..Connection::default()
            },
            sec_addr: sec_addr.into(),
        }
    }

    /// Enable NTLMSSP bind authentication over this pipe, verifying the client's
    /// AUTHENTICATE against the NT hash `lookup` returns for the account it names.
    /// A Windows domain join re-authenticates (NTLM) at the SAMR/LSA RPC layer.
    #[must_use]
    pub fn with_ntlm_lookup(mut self, lookup: Option<NtHashLookup>) -> Self {
        self.conn.ntlm_lookup = lookup;
        self
    }

    /// Attribute calls on this pipe to the transport-authenticated principal (the SMB
    /// session user), so a pipe interface can audit or gate a call by who is bound.
    #[must_use]
    pub fn with_transport_principal(mut self, principal: Option<String>) -> Self {
        self.conn.transport_principal = principal;
        self
    }

    /// Dispatch one complete inbound PDU, returning the response PDU (or `None`
    /// for a PDU that produces no reply / cannot be parsed).
    pub fn transact(&mut self, pdu: &[u8]) -> Option<Vec<u8>> {
        if pdu.len() < HEADER_LEN {
            return None;
        }
        let header = CommonHeader::parse(&pdu[..HEADER_LEN]).ok()?;
        let frag_length = (header.frag_length as usize).min(pdu.len());
        let body = pdu.get(HEADER_LEN..frag_length)?;
        self.conn.handle(
            &header,
            &pdu[..HEADER_LEN],
            body,
            self.iface.as_ref(),
            &self.sec_addr,
        )
    }
}

/// Fault status returned when a request signature fails to verify.
const FAULT_ACCESS_DENIED: u32 = 0x0000_0005;

/// Per-connection state: the negotiated auth context (if any) and the running
/// message sequence number for the signed exchange.
#[derive(Default)]
struct Connection {
    session_key: Option<[u8; 16]>,
    sequence: u64,
    /// The NT hash this endpoint accepts for NTLM SSP binds (if enabled) — the
    /// single-principal path (impacket DCSync).
    ntlm_nt_hash: Option<[u8; 16]>,
    /// A directory NT-hash lookup for NTLM SSP binds — verifies whoever
    /// authenticates (a domain-join client at the SAMR/LSA layer).
    ntlm_lookup: Option<NtHashLookup>,
    /// The established NTLM security context (after AUTH3).
    ntlm: Option<NtlmContext>,
    /// The Kerberos service key this endpoint accepts for GSS binds (if enabled).
    gss_service_key: Option<Vec<u8>>,
    /// The negotiated Kerberos acceptor subkey (after a GSS bind) — the GSS
    /// session key used for MIC signing and secret encryption.
    gss_subkey: Option<Vec<u8>>,
    /// The client's SPNEGO `MechTypeList` DER from the BIND — carried to the
    /// DCE-style leg-4 `ALTER_CONTEXT_RESP`, whose `mechListMIC` is a GSS MIC over it.
    gss_mech_list: Option<Vec<u8>>,
    /// The acceptor's own GSS send sequence — INDEPENDENT of the client's. It starts
    /// at the AP-REP's declared seq-number and increments per acceptor token (the
    /// leg-4 mechListMIC, then each sealed/signed response). A strict initiator (Samba)
    /// verifies each acceptor token against this expected sequence.
    gss_acceptor_seq: u64,
    /// Whether the client negotiated DCE/RPC header signing (`PFC_SUPPORT_HEADER_SIGN`)
    /// on the BIND. Samba's DRS client always does; impacket does not. When set, the
    /// per-message seal signs the PDU header + sec_trailer as GSS SIGN_ONLY AAD
    /// (`gss_wrap_iov`), matching what the peer verifies.
    header_signing: bool,
    /// A transport-provided session key (e.g. the SMB Kerberos session key when
    /// this RPC rides an authenticated `ncacn_np` pipe). Exposed to the interface
    /// on unauthenticated REQUESTs so pipe SAMR can decrypt password buffers.
    transport_session_key: Option<Vec<u8>>,
    /// The authenticated bind's principal (Kerberos AP-REQ client name), captured on a
    /// GSS bind so a sensitive call (DRSUAPI DCSync) can be attributed and gated.
    gss_principal: Option<String>,
    /// The authenticated principal from an NTLM AUTH3 (the username the client proved).
    ntlm_principal: Option<String>,
    /// A transport-provided principal (e.g. the SMB-authenticated user when this RPC
    /// rides an `ncacn_np` pipe), attributed to pipe calls (LSA/SAMR) when known.
    transport_principal: Option<String>,
}

impl Connection {
    /// Handle one inbound PDU, updating auth state as needed.
    fn handle(
        &mut self,
        header: &CommonHeader,
        header_bytes: &[u8],
        body: &[u8],
        iface: &dyn RpcInterface,
        sec_addr: &str,
    ) -> Option<Vec<u8>> {
        // Diagnostic: every PDU reaching the pipe (so the RPC flow of a real join is
        // visible in the DC log while the ncacn_np auth path is being brought up).
        tracing::info!(
            "RPC pipe PDU on {sec_addr}: ptype={} auth_len={} frag_len={} call_id={}",
            header.ptype,
            header.auth_length,
            header.frag_length,
            header.call_id,
        );

        // Kerberos (SPNEGO/GSS) bind: a BIND carrying an AP-REQ → verify it and
        // reply with a BIND_ACK carrying the mutual-auth AP-REP.
        let auth_len = header.auth_length as usize;
        if (header.ptype == ptype::BIND || header.ptype == ptype::ALTER_CONTEXT)
            && header.auth_length > 0
            && self.gss_service_key.is_some()
            && negotiated_auth_type(body, auth_len) == Some(RPC_C_AUTHN_GSS_NEGOTIATE)
        {
            return self.handle_gss_bind(header, body, sec_addr);
        }

        // Diagnostic: surface the auth service every authenticated BIND/ALTER used,
        // so a real Windows client's RPC auth choice (raw NTLM 10 vs SPNEGO 9) is
        // visible in the DC log while the pipe auth path is being brought up.
        if (header.ptype == ptype::BIND || header.ptype == ptype::ALTER_CONTEXT)
            && header.auth_length > 0
        {
            tracing::info!(
                "RPC pipe {} on {sec_addr}: auth_type={:?} auth_level={:?} auth_len={}",
                if header.ptype == ptype::BIND {
                    "BIND"
                } else {
                    "ALTER"
                },
                negotiated_auth_type(body, auth_len),
                negotiated_auth_level(body, auth_len),
                header.auth_length,
            );
        }

        // NTLM SSP bind: a BIND carrying an NTLMSSP NEGOTIATE token → reply with a
        // BIND_ACK carrying the CHALLENGE. Only for the WinNT auth service (raw
        // NTLM); a SPNEGO-wrapped bind is a different framing handled elsewhere.
        if header.ptype == ptype::BIND
            && header.auth_length > 0
            && negotiated_auth_type(body, auth_len) == Some(RPC_C_AUTHN_WINNT)
            && (self.ntlm_nt_hash.is_some() || self.ntlm_lookup.is_some())
        {
            let Ok(req) = BindRequest::parse(body) else {
                return Some(build_bind_nak(header.call_id));
            };
            let level = negotiated_auth_level(body, header.auth_length as usize)
                .unwrap_or(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY);
            tracing::info!("RPC pipe NTLM bind → sending CHALLENGE (level {level})");
            let ctx_id = negotiated_auth_ctx_id(body, auth_len).unwrap_or(0);
            return Some(build_bind_ack_with_auth(
                header.call_id,
                &req,
                sec_addr,
                RPC_C_AUTHN_WINNT,
                level,
                ctx_id,
                &challenge_message(),
            ));
        }

        // NTLM AUTH3: verify the AUTHENTICATE and establish the context; no reply.
        if header.ptype == ptype::AUTH3 && header.auth_length > 0 {
            let auth_len = header.auth_length as usize;
            if let Some(start) = body.len().checked_sub(auth_len) {
                let auth = &body[start..];
                // Prefer the directory lookup (verify whoever authenticates — the
                // join client authenticates as the joining user); fall back to the
                // single configured NT hash (the impacket DCSync path).
                let user = ntlm_username(auth);
                let nt_hash = self
                    .ntlm_lookup
                    .as_ref()
                    .and_then(|lk| user.as_deref().and_then(|u| lk(u)))
                    .or(self.ntlm_nt_hash);
                if let Some(h) = nt_hash {
                    self.ntlm = NtlmContext::establish(&h, auth);
                    if self.ntlm.is_some() {
                        // Attribute subsequent calls on this connection to the verified user.
                        self.ntlm_principal = user.clone();
                        tracing::info!(target: "auth", proto = "rpc", user = ?user, "RPC NTLM AUTH3 verified");
                    } else {
                        tracing::warn!(target: "auth", proto = "rpc", user = ?user, "RPC NTLM AUTH3 proof failed");
                    }
                } else {
                    tracing::warn!(target: "auth", proto = "rpc", user = ?user, "RPC NTLM AUTH3 rejected: no NT hash (unknown user)");
                }
            }
            return None;
        }

        // Authenticated ALTER_CONTEXT: bind the security context to this
        // connection using the session key the secure channel established.
        if header.ptype == ptype::ALTER_CONTEXT && header.auth_length > 0 {
            let Ok(req) = BindRequest::parse(body) else {
                return Some(build_bind_nak(header.call_id));
            };
            self.session_key = iface.session_key();
            self.sequence = 0;
            // Echo back the protection level the client negotiated (integrity or
            // privacy); requests then arrive at that level.
            let level = negotiated_auth_level(body, header.auth_length as usize)
                .unwrap_or(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY);
            let ctx_id = negotiated_auth_ctx_id(body, header.auth_length as usize).unwrap_or(0);
            return Some(build_alter_context_resp(
                header.call_id,
                &req,
                sec_addr,
                RPC_C_AUTHN_NETLOGON,
                level,
                ctx_id,
                &nl_auth_message_response(),
            ));
        }

        // A signed REQUEST: verify, dispatch, and sign the response. Netlogon,
        // NTLM (WINNT) and Kerberos (GSS) differ in the SSP; distinguish by the
        // sec_trailer's auth type.
        if header.ptype == ptype::REQUEST && header.auth_length > 0 {
            let sst: Option<u8> =
                parse_signed_request(body, header.auth_length as usize).map(|r| r.auth_type);
            return Some(match sst {
                Some(RPC_C_AUTHN_WINNT) => {
                    self.handle_ntlm_request(header, header_bytes, body, iface)
                }
                Some(RPC_C_AUTHN_GSS_NEGOTIATE) => self.handle_gss_request(header, body, iface),
                _ => self.handle_signed_request(header, body, iface),
            });
        }

        // Everything else uses the unauthenticated path — but on a pipe riding an
        // authenticated SMB session, expose that session key AND the SMB-authenticated
        // principal to the interface (so pipe SAMR can decrypt a password buffer, and a
        // gated interface can attribute the call). A true unauthenticated RPC bind passes
        // no principal, so a DCSync-class call is refused.
        dispatch(
            header,
            body,
            iface,
            sec_addr,
            self.transport_session_key.as_deref(),
            self.transport_principal.as_deref(),
        )
    }

    /// Verify an NTLM-signed REQUEST, dispatch it (exposing the session key to the
    /// interface), and sign the response.
    fn handle_ntlm_request(
        &mut self,
        header: &CommonHeader,
        header_bytes: &[u8],
        body: &[u8],
        iface: &dyn RpcInterface,
    ) -> Vec<u8> {
        let principal = self.ntlm_principal.clone();
        let Some(ctx) = self.ntlm.as_mut() else {
            return build_fault(header.call_id, 0, FAULT_ACCESS_DENIED);
        };
        let Some(req) = parse_signed_request(body, header.auth_length as usize) else {
            return build_fault(header.call_id, 0, fault::NDR);
        };
        // Extended session security signs the whole PDU minus the 16-byte
        // signature (common header ‖ body-without-auth-token).
        let Some(signed_end) = body.len().checked_sub(header.auth_length as usize) else {
            return build_fault(header.call_id, req.context_id, fault::NDR);
        };
        let mut message = header_bytes.to_vec();
        message.extend_from_slice(&body[..signed_end]);
        let Some(seq) = ctx.verify_request(&message, req.signature) else {
            return build_fault(header.call_id, req.context_id, FAULT_ACCESS_DENIED);
        };
        let Some(stub) = req.unpadded_stub() else {
            return build_fault(header.call_id, req.context_id, fault::NDR);
        };

        let session = ctx.session_key();
        let out =
            match iface.call_authenticated(req.opnum, stub, Some(&session), principal.as_deref()) {
                Ok(out) => {
                    tracing::info!(
                        "RPC pipe NTLM request opnum={} → OK ({} B)",
                        req.opnum,
                        out.len()
                    );
                    out
                }
                Err(status) => {
                    tracing::warn!(
                        "RPC pipe NTLM request opnum={} → fault 0x{status:08x}",
                        req.opnum
                    );
                    return build_fault(header.call_id, req.context_id, status);
                }
            };

        // Sign the response over its padded stub at the client's sequence + 1.
        let (plain, pad) = padded_response_stub(&out);
        let signature = ctx.sign_response(&plain, seq + 1);
        build_auth_response_typed(
            header.call_id,
            req.context_id,
            &plain,
            RPC_C_AUTHN_WINNT,
            req.auth_level,
            pad,
            &signature,
        )
    }

    /// Handle a Kerberos (SPNEGO/GSS) BIND or ALTER_CONTEXT. The BIND carries an
    /// AP-REQ; we verify it, mint a mutual-auth AP-REP (its acceptor subkey
    /// becomes the GSS session key), and return it in the BIND_ACK. The following
    /// ALTER_CONTEXT (the client's AP-REP) is simply acknowledged.
    fn handle_gss_bind(
        &mut self,
        header: &CommonHeader,
        body: &[u8],
        sec_addr: &str,
    ) -> Option<Vec<u8>> {
        let Ok(req) = BindRequest::parse(body) else {
            return Some(build_bind_nak(header.call_id));
        };
        let level = negotiated_auth_level(body, header.auth_length as usize)
            .unwrap_or(RPC_C_AUTHN_LEVEL_PKT_INTEGRITY);
        let ctx_id = negotiated_auth_ctx_id(body, header.auth_length as usize).unwrap_or(0);

        // ALTER_CONTEXT (the DCE-style leg-3: the client's final AP-REP + its
        // mechListMIC): complete the SPNEGO exchange with a leg-4 ALTER_CONTEXT_RESP
        // carrying `NegTokenResp { negState = accept-completed, mechListMIC }`, the MIC
        // being a GSS MIC (acceptor-signed with the subkey) over the client's
        // MechTypeList. Samba requires this final MIC; an empty leg-4 is rejected.
        if header.ptype == ptype::ALTER_CONTEXT {
            if let (Some(subkey), Some(mech_list)) =
                (self.gss_subkey.clone(), self.gss_mech_list.clone())
            {
                // The SPNEGO mechListMIC is signed but its sequence is not tracked by
                // the per-message data stream — that starts fresh at the AP-REP base.
                if let Ok(mic) = gss_mic_acceptor(&subkey, 0, &mech_list) {
                    let token = wrap_accept_completed_mic(&mic);
                    return Some(build_alter_context_resp(
                        header.call_id,
                        &req,
                        "",
                        RPC_C_AUTHN_GSS_NEGOTIATE,
                        level,
                        ctx_id,
                        &token,
                    ));
                }
            }
            return Some(build_alter_context_resp_noauth(
                header.call_id,
                &req,
                sec_addr,
            ));
        }

        // BIND: verify the AP-REQ and produce the AP-REP.
        let service_key = self.gss_service_key.as_ref()?;
        let token = auth_token(body, header.auth_length as usize)?;
        let verified =
            extract_ap_req(token).and_then(|ap_req| verify_ap_req(service_key, ap_req).ok());
        // Keep the client principal for the auth log before `verified` is consumed below.
        let client_name = verified.as_ref().map(|v| v.client_name.clone());
        let outcome = verified.and_then(|v| {
            build_ap_rep(
                &v.session_key,
                v.ctime,
                v.cusec,
                GSS_ACCEPTOR_SEQ_BASE as u32,
            )
            .ok()
        });
        let Some((ap_rep, subkey)) = outcome else {
            tracing::warn!(target: "auth", proto = "rpc", "RPC GSS bind failed: AP-REQ verification failed");
            return Some(build_bind_nak(header.call_id));
        };
        tracing::info!(target: "auth", proto = "rpc", principal = ?client_name, "RPC GSS bind ok");
        // Remember the authenticated principal so a sensitive call (DRSUAPI DCSync) can
        // be attributed to and gated on it. A Kerberos principal name is a sequence of
        // components (e.g. `host`/`fqdn`); join them for the audit string. If a verified
        // AP-REQ somehow carries no client name, log it distinctly rather than storing an
        // empty principal — a principal-gated call then fails closed, and the warning tells
        // ops to check the client's ticket (H-3b: a verified peer must not be silently
        // denied without a trace).
        self.gss_principal = client_name.and_then(|parts| {
            let joined = parts.join("/");
            if joined.is_empty() {
                tracing::warn!(
                    target: "auth", proto = "rpc",
                    "RPC GSS bind verified but the AP-REQ carried no client name — principal-gated calls (DCSync) will be refused; check the client's ticket"
                );
                None
            } else {
                Some(joined)
            }
        });
        self.gss_subkey = Some(subkey);
        // The acceptor's send sequence starts at the AP-REP's declared seq-number.
        self.gss_acceptor_seq = GSS_ACCEPTOR_SEQ_BASE;
        // Honour DCE/RPC header signing if the client offered it on the BIND.
        self.header_signing = header.pfc_flags & pfc::SUPPORT_HEADER_SIGN != 0;
        // Remember the client's MechTypeList — the DCE-style leg-4 mechListMIC signs it.
        self.gss_mech_list = mech_list_der(token);
        // Confirm the client's most-preferred mech (Samba: MS-KRB5) so it accepts the
        // AP-REP directly instead of re-negotiating.
        let mech = first_mech_oid(token).unwrap_or_default();
        let mut ack = build_bind_ack_with_auth(
            header.call_id,
            &req,
            sec_addr,
            RPC_C_AUTHN_GSS_NEGOTIATE,
            level,
            ctx_id,
            &wrap_ap_rep(&ap_rep, &mech),
        );
        // Confirm DCE/RPC header signing in the BIND_ACK's pfc_flags (byte 3) when the
        // client offered it, so both sides then sign the PDU header + sec_trailer.
        if self.header_signing {
            if let Some(pfc_byte) = ack.get_mut(3) {
                *pfc_byte |= pfc::SUPPORT_HEADER_SIGN;
            }
        }
        Some(ack)
    }

    /// Verify a Kerberos GSS-protected REQUEST, dispatch it (exposing the acceptor
    /// subkey to the interface), and protect the response. PKT_INTEGRITY uses a
    /// MIC over the padded stub; PKT_PRIVACY seals it with a Wrap token. The client
    /// uses the initiator seal usage (requests) and expects the acceptor usage
    /// (responses).
    fn handle_gss_request(
        &mut self,
        header: &CommonHeader,
        body: &[u8],
        iface: &dyn RpcInterface,
    ) -> Vec<u8> {
        let Some(subkey) = self.gss_subkey.clone() else {
            return build_fault(header.call_id, 0, FAULT_ACCESS_DENIED);
        };
        let Some(req) = parse_signed_request(body, header.auth_length as usize) else {
            return build_fault(header.call_id, 0, fault::NDR);
        };
        let sealed = req.auth_level == RPC_C_AUTHN_LEVEL_PKT_PRIVACY;

        // When header signing is negotiated (Samba's DRS), the seal covers the PDU
        // header + sec_trailer as GSS SIGN_ONLY AAD: `pre` = PDU header + the 8-byte
        // request/response header (before the stub), `post` = the sec_trailer.
        let auth_len = header.auth_length as usize;
        let trailer_start = body.len().saturating_sub(auth_len + 8);
        let (req_pre, req_post): (Vec<u8>, Vec<u8>) = if self.header_signing {
            let rh = common_header(
                ptype::REQUEST,
                header.pfc_flags,
                header.frag_length,
                header.auth_length,
                header.call_id,
            );
            let pre = [rh.as_slice(), body.get(0..8).unwrap_or_default()].concat();
            let post = body
                .get(trailer_start..trailer_start + 8)
                .unwrap_or_default()
                .to_vec();
            (pre, post)
        } else {
            (Vec::new(), Vec::new())
        };

        // Recover the request stub. The client's own sequence (in the token) is used
        // only to unwrap/verify; the RESPONSE uses the acceptor's independent counter.
        let stub = if sealed {
            if req.signature.len() < 16 {
                return build_fault(header.call_id, req.context_id, fault::NDR);
            }
            let plain = if self.header_signing {
                gss_unwrap_iov(
                    &subkey,
                    KG_USAGE_INITIATOR_SEAL,
                    &req_pre,
                    &req_post,
                    req.payload,
                    req.signature,
                )
            } else {
                gss_unwrap(&subkey, KG_USAGE_INITIATOR_SEAL, req.payload, req.signature)
            };
            let Some(plain) = plain else {
                return build_fault(header.call_id, req.context_id, FAULT_ACCESS_DENIED);
            };
            let Some(end) = plain.len().checked_sub(req.auth_pad_len) else {
                return build_fault(header.call_id, req.context_id, fault::NDR);
            };
            plain[..end].to_vec()
        } else {
            if verify_gss_mic(&subkey, req.payload, req.signature).is_none() {
                return build_fault(header.call_id, req.context_id, FAULT_ACCESS_DENIED);
            }
            let Some(stub) = req.unpadded_stub() else {
                return build_fault(header.call_id, req.context_id, fault::NDR);
            };
            stub.to_vec()
        };

        let out = match iface.call_authenticated(
            req.opnum,
            &stub,
            Some(&subkey),
            self.gss_principal.as_deref(),
        ) {
            Ok(out) => out,
            Err(status) => return build_fault(header.call_id, req.context_id, status),
        };

        // Protect the response with the acceptor usage at the acceptor's OWN next
        // send sequence (independent of the client's request sequence) — a strict
        // initiator (Samba) verifies it against the AP-REP-declared sequence.
        let resp_seq = self.gss_acceptor_seq;
        self.gss_acceptor_seq += 1;
        let (plain, pad) = padded_response_stub(&out);
        let ctx_id = negotiated_auth_ctx_id(body, auth_len).unwrap_or(0);

        // Header-signed seal: build the in-place-sealed RESPONSE PDU directly, signing
        // the PDU header + response header (pre) and sec_trailer (post) as AAD — the
        // layout Samba's DCE/RPC `gssapi_seal_packet` verifies. PKT_PRIVACY seals in
        // place, so the stub is padded to the 16-byte AES block (gss_wrap_iov, unlike
        // the plain gss_wrap, does not pad internally).
        if sealed && self.header_signing {
            let pad = (16 - out.len() % 16) % 16;
            let mut plain = out.clone();
            plain.resize(plain.len() + pad, 0);
            let frag_length = (HEADER_LEN + 8 + plain.len() + 8 + SEAL_AUTH_LEN as usize) as u16;
            let rh = common_header(
                ptype::RESPONSE,
                pfc::FIRST_FRAG | pfc::LAST_FRAG,
                frag_length,
                SEAL_AUTH_LEN,
                header.call_id,
            );
            let mut resp_hdr = Vec::with_capacity(8);
            resp_hdr.extend_from_slice(&(plain.len() as u32).to_le_bytes()); // alloc_hint
            resp_hdr.extend_from_slice(&req.context_id.to_le_bytes());
            resp_hdr.push(0); // cancel_count
            resp_hdr.push(0); // reserved
            let mut sec_tr = vec![RPC_C_AUTHN_GSS_NEGOTIATE, req.auth_level, pad as u8, 0];
            sec_tr.extend_from_slice(&ctx_id.to_le_bytes());
            let pre = [rh.as_slice(), &resp_hdr].concat();
            let Ok((pdu_stub, auth)) = gss_wrap_iov(
                &subkey,
                KG_USAGE_ACCEPTOR_SEAL,
                resp_seq,
                &pre,
                &sec_tr,
                &plain,
            ) else {
                return build_fault(header.call_id, req.context_id, fault::NDR);
            };
            let mut out_pdu = rh.to_vec();
            out_pdu.extend_from_slice(&resp_hdr);
            out_pdu.extend_from_slice(&pdu_stub);
            out_pdu.extend_from_slice(&sec_tr);
            out_pdu.extend_from_slice(&auth);
            return out_pdu;
        }

        let (pdu_data, auth_data) = if sealed {
            match gss_wrap(&subkey, KG_USAGE_ACCEPTOR_SEAL, resp_seq, &plain) {
                Ok((body, auth)) => (body, auth),
                Err(_) => return build_fault(header.call_id, req.context_id, fault::NDR),
            }
        } else {
            let sig = gss_mic(&subkey, resp_seq, &plain).unwrap_or_default();
            (plain, sig)
        };
        build_auth_response_typed(
            header.call_id,
            req.context_id,
            &pdu_data,
            RPC_C_AUTHN_GSS_NEGOTIATE,
            req.auth_level,
            pad,
            &auth_data,
        )
    }

    fn handle_signed_request(
        &mut self,
        header: &CommonHeader,
        body: &[u8],
        iface: &dyn RpcInterface,
    ) -> Vec<u8> {
        let Some(session_key) = self.session_key else {
            return build_fault(header.call_id, 0, FAULT_ACCESS_DENIED);
        };
        let Some(req) = parse_signed_request(body, header.auth_length as usize) else {
            return build_fault(header.call_id, 0, fault::NDR);
        };

        // Recover the plaintext stub according to the negotiated protection level:
        // PKT_PRIVACY decrypts, PKT_INTEGRITY verifies the signature. Either way we
        // authenticate the client against the current sequence number.
        let sealed = req.auth_level == RPC_C_AUTHN_LEVEL_PKT_PRIVACY;
        let stub = if sealed {
            let Some(plain) = unseal_aes(&session_key, req.payload, req.signature, self.sequence)
            else {
                return build_fault(header.call_id, req.context_id, FAULT_ACCESS_DENIED);
            };
            let Some(end) = plain.len().checked_sub(req.auth_pad_len) else {
                return build_fault(header.call_id, req.context_id, fault::NDR);
            };
            plain[..end].to_vec()
        } else {
            let expected = sign_integrity_aes(&session_key, req.payload, self.sequence);
            if expected != req.signature {
                return build_fault(header.call_id, req.context_id, FAULT_ACCESS_DENIED);
            }
            let Some(stub) = req.unpadded_stub() else {
                return build_fault(header.call_id, req.context_id, fault::NDR);
            };
            stub.to_vec()
        };

        // Client used `sequence`; our response uses `sequence + 1`, then both
        // sides advance by two (request/response pair).
        let reply = match iface.call(req.opnum, &stub) {
            Ok(out) if sealed => build_sealed_response(
                header.call_id,
                req.context_id,
                &out,
                &session_key,
                self.sequence + 1,
            ),
            Ok(out) => build_signed_response(
                header.call_id,
                req.context_id,
                &out,
                &session_key,
                self.sequence + 1,
            ),
            Err(status) => build_fault(header.call_id, req.context_id, status),
        };
        self.sequence += 2;
        reply
    }
}

/// Turn one inbound PDU into an optional reply PDU. `transport_key`, when present,
/// is a session key the transport authenticated (e.g. an SMB Kerberos session on a
/// pipe) and is passed to the interface via `call_with_session`.
fn dispatch(
    header: &CommonHeader,
    body: &[u8],
    iface: &dyn RpcInterface,
    sec_addr: &str,
    transport_key: Option<&[u8]>,
    transport_principal: Option<&str>,
) -> Option<Vec<u8>> {
    match header.ptype {
        ptype::BIND | ptype::ALTER_CONTEXT => Some(match BindRequest::parse(body) {
            Ok(req) if !req.contexts.is_empty() => {
                tracing::info!("RPC pipe (unauth) BIND on {sec_addr} → BIND_ACK");
                build_bind_ack(header.call_id, &req, sec_addr)
            }
            _ => {
                tracing::warn!("RPC pipe (unauth) BIND on {sec_addr} → BIND_NAK (parse/context)");
                build_bind_nak(header.call_id)
            }
        }),
        ptype::REQUEST => {
            let req = match Request::parse(header, body) {
                Ok(r) => r,
                Err(_) => return Some(build_fault(header.call_id, 0, fault::NDR)),
            };
            // Route through call_authenticated so a gated interface (DRSUAPI DCSync) sees
            // the principal — which is present only when the transport authenticated the
            // caller (an SMB-session pipe), and None for a bare unauthenticated bind.
            let result =
                iface.call_authenticated(req.opnum, req.stub, transport_key, transport_principal);
            Some(match result {
                Ok(out) => {
                    tracing::info!(
                        "RPC pipe (unauth) request opnum={} → OK ({} B, session_key={})",
                        req.opnum,
                        out.len(),
                        transport_key.is_some(),
                    );
                    build_response(header.call_id, req.context_id, &out)
                }
                Err(status) => {
                    tracing::warn!(
                        "RPC pipe (unauth) request opnum={} → fault 0x{status:08x}",
                        req.opnum
                    );
                    build_fault(header.call_id, req.context_id, status)
                }
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::DemoInterface;
    use crate::pdu::{
        build_pdu, pfc, Reader, DREP_LITTLE_ENDIAN, NDR32_UUID, NDR32_VERSION, RPC_VERS,
    };

    /// Build a BIND body proposing one context (id 0) offering NDR32.
    fn bind_body() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&5840u16.to_le_bytes()); // max_xmit
        b.extend_from_slice(&5840u16.to_le_bytes()); // max_recv
        b.extend_from_slice(&0u32.to_le_bytes()); // assoc_group_id
        b.push(1); // n_context_elem
        b.extend_from_slice(&[0, 0, 0]); // reserved + reserved2
        b.extend_from_slice(&0u16.to_le_bytes()); // p_cont_id
        b.push(1); // n_transfer_syn
        b.push(0); // reserved
        b.extend_from_slice(&[0xAA; 16]); // abstract syntax uuid (any)
        b.extend_from_slice(&1u32.to_le_bytes()); // abstract version
        b.extend_from_slice(&NDR32_UUID); // transfer syntax
        b.extend_from_slice(&NDR32_VERSION.to_le_bytes());
        b
    }

    #[test]
    fn bind_is_acknowledged_with_ndr_acceptance() {
        let bind = build_pdu(ptype::BIND, 1, &bind_body());
        let header = CommonHeader::parse(&bind[..HEADER_LEN]).unwrap();
        let reply = dispatch(
            &header,
            &bind[HEADER_LEN..],
            &DemoInterface,
            "8890",
            None,
            None,
        )
        .unwrap();

        let rh = CommonHeader::parse(&reply).unwrap();
        assert_eq!(rh.ptype, ptype::BIND_ACK);
        assert_eq!(rh.frag_length as usize, reply.len());
        assert_eq!(&reply[4..8], &DREP_LITTLE_ENDIAN);
        assert_eq!(reply[0], RPC_VERS);

        // Walk the BIND_ACK body to the result: acceptance + echoed NDR syntax.
        let mut r = Reader::new(&reply[HEADER_LEN..]);
        r.skip(2 + 2 + 4).unwrap(); // max_xmit, max_recv, assoc_group
        let sec_len = r.u16().unwrap() as usize;
        r.skip(sec_len).unwrap();
        // Re-align to 4 relative to PDU start.
        let consumed = HEADER_LEN + 8 + 2 + sec_len;
        let pad = (4 - consumed % 4) % 4;
        r.skip(pad).unwrap();
        let n_results = r.u8().unwrap();
        assert_eq!(n_results, 1);
        r.skip(3).unwrap(); // reserved + reserved2
        let result = r.u16().unwrap();
        assert_eq!(result, 0, "context must be accepted");
        let _reason = r.u16().unwrap();
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(r.take(16).unwrap());
        assert_eq!(uuid, NDR32_UUID, "accepted transfer syntax must be NDR");
    }

    #[test]
    fn request_add_returns_response_with_sum() {
        // opnum 0: Add(40, 2) -> 42.
        let mut stub = Vec::new();
        stub.extend_from_slice(&40u32.to_le_bytes());
        stub.extend_from_slice(&2u32.to_le_bytes());
        let mut body = Vec::new();
        body.extend_from_slice(&(stub.len() as u32).to_le_bytes()); // alloc_hint
        body.extend_from_slice(&0u16.to_le_bytes()); // context_id
        body.extend_from_slice(&0u16.to_le_bytes()); // opnum 0
        body.extend_from_slice(&stub);
        let req = build_pdu(ptype::REQUEST, 7, &body);
        let header = CommonHeader::parse(&req[..HEADER_LEN]).unwrap();
        assert_eq!(header.pfc_flags & pfc::OBJECT_UUID, 0);

        let reply = dispatch(
            &header,
            &req[HEADER_LEN..],
            &DemoInterface,
            "8890",
            None,
            None,
        )
        .unwrap();
        let rh = CommonHeader::parse(&reply).unwrap();
        assert_eq!(rh.ptype, ptype::RESPONSE);
        assert_eq!(rh.call_id, 7);
        // Response stub begins after alloc_hint(4)+cont_id(2)+cancel(1)+reserved(1).
        let stub_out = &reply[HEADER_LEN + 8..];
        assert_eq!(u32::from_le_bytes(stub_out[0..4].try_into().unwrap()), 42);
    }

    #[test]
    fn unknown_opnum_faults() {
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes()); // alloc_hint
        body.extend_from_slice(&0u16.to_le_bytes()); // context_id
        body.extend_from_slice(&99u16.to_le_bytes()); // opnum 99 (unknown)
        let req = build_pdu(ptype::REQUEST, 3, &body);
        let header = CommonHeader::parse(&req[..HEADER_LEN]).unwrap();
        let reply = dispatch(
            &header,
            &req[HEADER_LEN..],
            &DemoInterface,
            "8890",
            None,
            None,
        )
        .unwrap();
        let rh = CommonHeader::parse(&reply).unwrap();
        assert_eq!(rh.ptype, ptype::FAULT);
        let status = u32::from_le_bytes(reply[HEADER_LEN + 8..HEADER_LEN + 12].try_into().unwrap());
        assert_eq!(status, fault::OP_RNG_ERROR);
    }

    // --- full authenticated (Netlogon SSP signed) round trip ---

    use crate::netlogon::{
        netlogon_credential_aes, nt_hash, session_key_aes, sign_integrity_aes, NetlogonInterface,
    };
    use crate::pdu::build_pdu_with_auth;

    /// Run one PDU through the connection and return the reply bytes.
    fn run(conn: &mut Connection, iface: &dyn RpcInterface, pdu: &[u8]) -> Vec<u8> {
        let header = CommonHeader::parse(&pdu[..HEADER_LEN]).unwrap();
        conn.handle(&header, &pdu[..HEADER_LEN], &pdu[HEADER_LEN..], iface, "0")
            .unwrap()
    }

    fn request_pdu(call_id: u32, opnum: u16, stub: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&(stub.len() as u32).to_le_bytes()); // alloc_hint
        body.extend_from_slice(&0u16.to_le_bytes()); // context_id
        body.extend_from_slice(&opnum.to_le_bytes());
        body.extend_from_slice(stub);
        build_pdu(ptype::REQUEST, call_id, &body)
    }

    fn empty_wstr(out: &mut Vec<u8>) {
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out.extend_from_slice(&[0u8; 12]); // MaxCount, Offset, ActualCount = 0
    }

    /// The unauthenticated RESPONSE stub (after the 8-byte response header).
    fn resp_stub(reply: &[u8]) -> &[u8] {
        &reply[HEADER_LEN + 8..]
    }

    #[test]
    fn netlogon_signed_call_round_trip() {
        let iface = NetlogonInterface::new("Machine123");
        let mut conn = Connection::default();
        let client_challenge = *b"CLIENT01";

        // 1. ReqChallenge (unauthenticated) → server challenge.
        let mut rc = Vec::new();
        rc.extend_from_slice(&0u32.to_le_bytes()); // PrimaryName null unique ptr
        empty_wstr(&mut rc); // ComputerName
        rc.extend_from_slice(&client_challenge);
        let reply = run(&mut conn, &iface, &request_pdu(1, 4, &rc));
        let server_challenge: [u8; 8] = resp_stub(&reply)[0..8].try_into().unwrap();

        // 2. Derive session key + client credential and Authenticate3.
        let sk = session_key_aes(&nt_hash("Machine123"), &client_challenge, &server_challenge);
        let client_cred = netlogon_credential_aes(&sk, &client_challenge);
        let mut a3 = Vec::new();
        a3.extend_from_slice(&0u32.to_le_bytes()); // PrimaryName null
        empty_wstr(&mut a3); // AccountName
        a3.extend_from_slice(&2u16.to_le_bytes()); // SecureChannelType
        empty_wstr(&mut a3); // ComputerName (self-aligns)
        a3.extend_from_slice(&client_cred);
        a3.extend_from_slice(&0x0100_0000u32.to_le_bytes()); // NegotiateFlags (AES)
        let reply = run(&mut conn, &iface, &request_pdu(2, 26, &a3));
        assert_eq!(
            u32::from_le_bytes(resp_stub(&reply)[16..20].try_into().unwrap()),
            0,
            "Authenticate3 must succeed"
        );
        assert_eq!(iface.session_key(), Some(sk), "session key established");

        // 3. ALTER_CONTEXT carrying a (dummy) NL_AUTH_MESSAGE → the signed binding.
        let mut alter_body = bind_body();
        while !alter_body.len().is_multiple_of(4) {
            alter_body.push(0);
        }
        alter_body.extend_from_slice(&[
            crate::auth::RPC_C_AUTHN_NETLOGON,
            crate::auth::RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
            0,
            0,
        ]);
        alter_body.extend_from_slice(&0u32.to_le_bytes()); // auth_ctx_id
        let nl_auth = [0u8; 12]; // NL_AUTH_MESSAGE request (contents ignored here)
        alter_body.extend_from_slice(&nl_auth);
        let alter = build_pdu_with_auth(ptype::ALTER_CONTEXT, 3, &alter_body, nl_auth.len() as u16);
        let reply = run(&mut conn, &iface, &alter);
        assert_eq!(
            CommonHeader::parse(&reply).unwrap().ptype,
            ptype::ALTER_CONTEXT_RESP
        );

        // 4. A SIGNED request to opnum 21 (empty stub), verified by the server.
        let stub: &[u8] = &[];
        let signature = sign_integrity_aes(&sk, stub, 0); // client sequence 0
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes()); // alloc_hint
        body.extend_from_slice(&0u16.to_le_bytes()); // context_id
        body.extend_from_slice(&21u16.to_le_bytes()); // opnum
        body.extend_from_slice(stub);
        // stub already 8-aligned → no pad; sec_trailer + signature follow.
        body.extend_from_slice(&[
            crate::auth::RPC_C_AUTHN_NETLOGON,
            crate::auth::RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
            0,
            0,
        ]);
        body.extend_from_slice(&0u32.to_le_bytes()); // auth_ctx_id
        body.extend_from_slice(&signature);
        let signed = build_pdu_with_auth(ptype::REQUEST, 4, &body, signature.len() as u16);
        let reply = run(&mut conn, &iface, &signed);

        // 5. The reply is a signed RESPONSE; verify its signature (server seq 1).
        let rh = CommonHeader::parse(&reply).unwrap();
        assert_eq!(rh.ptype, ptype::RESPONSE, "signed request must be accepted");
        assert_eq!(rh.auth_length, 48, "response must carry a signature");
        let rbody = &reply[HEADER_LEN..];
        let sig_start = rbody.len() - 48;
        let stub_end = sig_start - 8; // minus sec_trailer (no pad on 8-byte stub)
        let out_stub = &rbody[8..stub_end];
        assert_eq!(
            u32::from_le_bytes(out_stub[0..4].try_into().unwrap()),
            1,
            "server capabilities returned over the signed channel"
        );
        assert_eq!(
            &rbody[sig_start..],
            sign_integrity_aes(&sk, out_stub, 1).as_slice(),
            "server response signature must verify at sequence 1"
        );
    }

    #[test]
    fn signed_request_with_bad_signature_is_denied() {
        let iface = NetlogonInterface::new("Machine123");
        // A session key is established, but the request carries a bogus signature.
        let mut conn = Connection {
            session_key: Some([7u8; 16]),
            sequence: 0,
            ..Default::default()
        };
        let stub: &[u8] = &[];
        let bad_sig = [0u8; 48]; // not a valid signature for [7;16]
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&21u16.to_le_bytes());
        body.extend_from_slice(&[
            crate::auth::RPC_C_AUTHN_NETLOGON,
            crate::auth::RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
            0,
            0,
        ]);
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&bad_sig);
        let signed = build_pdu_with_auth(ptype::REQUEST, 1, &body, 48);
        let _ = stub;
        let reply = run(&mut conn, &iface, &signed);
        assert_eq!(
            CommonHeader::parse(&reply).unwrap().ptype,
            ptype::FAULT,
            "an invalid signature must fault"
        );
    }
}
