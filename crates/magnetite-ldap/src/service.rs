//! The embedded LDAPv3 server. Binds a TCP port and runs an LDAP session per
//! connection using the `ldap3_proto` codec: bind (simple/anonymous), search
//! (base/one/subtree + filter), RootDSE, modify (RFC 4511 §4.6 — authenticated,
//! ACL-gated attribute writes, e.g. a domain join setting `dNSHostName` /
//! `servicePrincipalName`) and unbind. Add/delete/modifyDN remain read-only over
//! LDAP (use the management UI). Registered as an [`EmbeddedService`] (09b §-1).

use crate::filter;
use chrono::Utc;
use futures::{SinkExt, StreamExt};
use ldap3_proto::control::LdapControl;
use ldap3_proto::proto::{
    LdapAddRequest, LdapBindCred, LdapBindResponse, LdapExtendedResponse, LdapModifyDNRequest,
    LdapModifyRequest, LdapModifyType, LdapMsg, LdapOp, LdapPartialAttribute, LdapResult,
    LdapSearchRequest, LdapSearchResultEntry, LdapSearchScope, SyncRequestMode, SyncStateValue,
};
use ldap3_proto::LdapResultCode;
use magnetite_core::domain::DomainKey;
use magnetite_core::domains::ldap::model::{DirectoryEntry, LdapAclOperation};
use magnetite_core::domains::ldap::validate::normalize_dn;
use magnetite_core::models::common::{LogKind, LogLevel};
use magnetite_db::{
    Db, DbError, EmbeddedService, LdapAttrChange, LdapModifyOp, NewLogEntry, ServiceHealth,
};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tokio_util::codec::Framed;
use uuid::Uuid;

const H_STARTING: u8 = 0;
const H_HEALTHY: u8 = 1;
const H_ERROR: u8 = 2;

const DEFAULT_SIZE_LIMIT: usize = 1000;

/// The StartTLS extended-operation OID (RFC 4511).
const STARTTLS_OID: &str = "1.3.6.1.4.1.1466.20037";

/// Outcome of one LDAP dialog: the client finished, or it requested StartTLS and
/// the caller must upgrade the connection.
enum Flow {
    Done,
    StartTls,
}

/// A sink that registers a machine account's Kerberos key when a `computer` object
/// is created over LDAP (the write half of a domain join), so the joined machine
/// can immediately obtain a TGT (`kinit <NAME>$`). The AD DC (`magnetite-addc`)
/// implements this over the shared KDC [`PrincipalStore`](magnetite_krb5) plus the
/// database, mirroring how SAMR / Netlogon register machine accounts. Defining it
/// here keeps `magnetite-ldap` free of a Kerberos dependency (inversion of control).
pub trait MachineKeyRegistrar: Send + Sync {
    /// Register (or replace) the machine account `sam_account_name` (e.g. `PC$`)
    /// with the cleartext machine `password`, deriving its Kerberos long-term key.
    fn register_machine(&self, sam_account_name: &str, password: &str);

    /// Provision an LDAP-created **user**'s AD identity (`ad_principal`: RID + NT hash +
    /// Kerberos key) from `password`, so a user added over LDAP (e.g. a bulk `ldapadd`
    /// migration) can log on to Windows, exactly like the Web `CreateUser` path — not
    /// just simple-bind. `rid` (from a supplied `objectSid`) inherits the old domain's
    /// exact SID; `None` allocates a fresh one. Awaited by the Add handler so a later
    /// group Add can resolve this user as a member. Default: no-op.
    fn register_user<'a>(
        &'a self,
        _sam_account_name: &'a str,
        _password: &'a str,
        _rid: Option<u32>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }

    /// Provision an LDAP-created **group**'s AD identity (`ad_group`: RID + objectSid) and
    /// link its members (given by `sAMAccountName`), so a group added over LDAP reaches
    /// the KDC/PAC like the Web `CreateGroup` + `AddMember` paths. `rid` inherits a
    /// supplied objectSid's RID; `None` allocates a fresh one. Default: no-op.
    fn register_group<'a>(
        &'a self,
        _sam_account_name: &'a str,
        _member_sams: &'a [String],
        _rid: Option<u32>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }
}

/// Embedded LDAP server bound to `addr` (usually `0.0.0.0:389`).
pub struct LdapService {
    addr: SocketAddr,
    log_events: bool,
    /// Certificate name presented on StartTLS (`None` disables StartTLS).
    tls_cert_name: Option<String>,
    /// Configured base DN (naming context), used to seed the directory root.
    base_dn: String,
    /// DC computer label (lowercase DNS host label, e.g. `magnetite`) used in the
    /// RootDSE identity attributes and the seeded FSMO role owners; the NetBIOS
    /// form is the uppercased label (≤15 chars).
    dc_label: String,
    /// The `ldap/<dc-fqdn>` AES256 service key for GSS-SPNEGO SASL binds (a
    /// domain-join client authenticates with a Kerberos ticket for it). `None`
    /// leaves only simple bind available.
    gss_service_key: Option<Vec<u8>>,
    /// Registers a machine account with the KDC when a `computer` object is added
    /// (`None` = LDAP writes stay directory-only, no live Kerberos registration).
    machine_registrar: Option<Arc<dyn MachineKeyRegistrar>>,
    /// NT-hash lookup so a GSS-SPNEGO SASL bind carrying NTLM (a Windows join with
    /// no Kerberos ticket) can be verified against the DC directory.
    nt_hash_lookup: Option<magnetite_rpc::NtHashLookup>,
    health: Arc<AtomicU8>,
}

impl LdapService {
    /// `log_events` ⇒ write a LogEntry per bind / search (S-Logs ingestion).
    /// `tls_cert_name` names the certificate presented on StartTLS. `base_dn` is
    /// the configured naming context (used only to seed an empty directory).
    pub fn new(
        addr: SocketAddr,
        log_events: bool,
        tls_cert_name: Option<String>,
        base_dn: String,
    ) -> Self {
        Self {
            addr,
            log_events,
            tls_cert_name,
            base_dn,
            dc_label: "magnetite".to_string(),
            gss_service_key: None,
            machine_registrar: None,
            nt_hash_lookup: None,
            health: Arc::new(AtomicU8::new(H_STARTING)),
        }
    }

    /// Enable NTLM for the GSS-SPNEGO SASL bind: a Windows join that can't get a
    /// Kerberos ticket authenticates with NTLM, verified against the NT hash the
    /// `lookup` returns for the account (the DC supplies it from its directory).
    #[must_use]
    pub fn with_nt_hash_lookup(mut self, lookup: magnetite_rpc::NtHashLookup) -> Self {
        self.nt_hash_lookup = Some(lookup);
        self
    }

    /// Enable GSS-SPNEGO SASL binds by supplying the `ldap/<dc-fqdn>` service key
    /// (the AES256 key the KDC issues LDAP service tickets against). Used by the
    /// AD DC so `net ads join` can Kerberos-authenticate to LDAP.
    #[must_use]
    pub fn with_gss_key(mut self, key: Vec<u8>) -> Self {
        self.gss_service_key = Some(key);
        self
    }

    /// Attach a [`MachineKeyRegistrar`] so that adding a `computer` object over
    /// LDAP registers the machine account with the KDC (and persists it), letting
    /// the joined machine obtain a TGT.
    #[must_use]
    pub fn with_machine_registrar(mut self, registrar: Arc<dyn MachineKeyRegistrar>) -> Self {
        self.machine_registrar = Some(registrar);
        self
    }

    /// Override the DC computer label (lowercase DNS host label, e.g. `dc2`) used in
    /// the RootDSE `serverName`/`dsServiceName`/`dnsHostName`/`ldapServiceName` and the
    /// seeded FSMO role owners. Defaults to `magnetite`; the NetBIOS form is the
    /// uppercased label (≤15 chars).
    #[must_use]
    pub fn with_dc_label(mut self, label: String) -> Self {
        self.dc_label = label;
        self
    }
}

impl EmbeddedService for LdapService {
    fn domain(&self) -> DomainKey {
        DomainKey::Ldap
    }

    fn health(&self) -> ServiceHealth {
        match self.health.load(Ordering::Relaxed) {
            H_HEALTHY => ServiceHealth::Healthy,
            H_ERROR => ServiceHealth::Error,
            _ => ServiceHealth::Unknown,
        }
    }

    fn start(&self, db: Db, shutdown: watch::Receiver<bool>) {
        let addr = self.addr;
        let health = self.health.clone();
        let log_events = self.log_events;
        let tls_cert_name = self.tls_cert_name.clone();
        let base_dn = self.base_dn.clone();
        let dc_label = self.dc_label.clone();
        let gss_service_key = self.gss_service_key.clone();
        let machine_registrar = self.machine_registrar.clone();
        let nt_hash_lookup = self.nt_hash_lookup.clone();
        magnetite_db::spawn_health_guarded("ldap", health.clone(), H_ERROR, async move {
            if let Err(e) = run(
                addr,
                db,
                shutdown,
                health.clone(),
                log_events,
                tls_cert_name,
                base_dn,
                dc_label,
                gss_service_key,
                machine_registrar,
                nt_hash_lookup,
            )
            .await
            {
                tracing::error!("LDAP server on {addr} failed: {e}");
                health.store(H_ERROR, Ordering::Relaxed);
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn run(
    addr: SocketAddr,
    db: Db,
    mut shutdown: watch::Receiver<bool>,
    health: Arc<AtomicU8>,
    log_events: bool,
    tls_cert_name: Option<String>,
    base_dn: String,
    dc_label: String,
    gss_service_key: Option<Vec<u8>>,
    machine_registrar: Option<Arc<dyn MachineKeyRegistrar>>,
    nt_hash_lookup: Option<magnetite_rpc::NtHashLookup>,
) -> std::io::Result<()> {
    let gss_service_key = gss_service_key.map(Arc::new);
    // Seed the base DN if the directory is empty; use it as the naming context.
    let base_dn = db
        .ensure_ldap_base(&base_dn, "system")
        .await
        .unwrap_or(base_dn);
    // The NetBIOS computer name is the uppercased DNS host label, ≤15 chars.
    let dc_netbios: String = dc_label
        .chars()
        .flat_map(char::to_uppercase)
        .take(15)
        .collect();
    // Seed the AD well-known containers (CN=Computers etc.) so a domain-join client
    // has somewhere to add its machine object. Best-effort: a failure here must not
    // stop the server from serving reads.
    if let Err(e) = db.seed_domain_containers(&base_dn, "system").await {
        tracing::warn!("LDAP: seeding domain containers failed: {e}");
    }
    // Seed the FSMO role objects. A single-DC forest reports this DC as the holder of
    // every operation-master role; a multi-DC domain assigns individual roles to peers
    // via `FSMO_OWNERS` (comma `role=owner_dc`, same keys as the addc daemon), so the
    // served `fSMORoleOwner` points at the true holder's nTDSDSA. Best-effort — a
    // failure must not stop reads.
    let fsmo_owners = std::env::var("FSMO_OWNERS")
        .ok()
        .map(|s| magnetite_db::FsmoOwners::from_spec(&s))
        .unwrap_or_default();
    if let Err(e) = db
        .seed_fsmo_roles_owned(&base_dn, &dc_netbios, &fsmo_owners, "system")
        .await
    {
        tracing::warn!("LDAP: seeding FSMO roles failed: {e}");
    }
    // StartTLS acceptor (built once from the configured certificate).
    let acceptor = crate::tls::build_acceptor(&db, tls_cert_name.as_deref()).await;
    let listener = TcpListener::bind(addr).await?;
    health.store(H_HEALTHY, Ordering::Relaxed);
    tracing::info!(
        "LDAP server listening on {addr} (base {base_dn}, StartTLS {})",
        if acceptor.is_some() { "on" } else { "off" }
    );

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted { Ok(v) => v, Err(_) => continue };
                let db = db.clone();
                let base_dn = base_dn.clone();
                let dc_label = dc_label.clone();
                let acceptor = acceptor.clone();
                let gss_service_key = gss_service_key.clone();
                let machine_registrar = machine_registrar.clone();
                let nt_hash_lookup = nt_hash_lookup.clone();
                tokio::spawn(handle_connection(
                    stream,
                    peer,
                    db,
                    base_dn,
                    dc_label,
                    log_events,
                    acceptor,
                    gss_service_key,
                    machine_registrar,
                    nt_hash_lookup,
                ));
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    stream: TcpStream,
    peer: std::net::SocketAddr,
    db: Db,
    base_dn: String,
    dc_label: String,
    log_events: bool,
    acceptor: Option<TlsAcceptor>,
    gss_service_key: Option<Arc<Vec<u8>>>,
    machine_registrar: Option<Arc<dyn MachineKeyRegistrar>>,
    nt_hash_lookup: Option<magnetite_rpc::NtHashLookup>,
) {
    tracing::debug!(target: "conn", %peer, "LDAP connection");
    let mut framed = Framed::new(stream, crate::codec::SaslAwareCodec::default());
    let mut bound_dn: Option<String> = None;
    let mut sasl = crate::sasl::SaslState::default();

    let flow = dialog(
        &mut framed,
        &db,
        &base_dn,
        &dc_label,
        log_events,
        &mut bound_dn,
        acceptor.is_some(),
        gss_service_key.as_deref().map(Vec::as_slice),
        &mut sasl,
        machine_registrar.as_ref(),
        nt_hash_lookup.as_ref(),
    )
    .await;
    if let Flow::StartTls = flow {
        // Upgrade the underlying stream; `into_inner` drops buffered bytes (a
        // StartTLS command-injection defense). Authentication resets to
        // anonymous per RFC 4513 §3.1.1, so the client re-binds over TLS.
        let acceptor = acceptor.expect("StartTLS only signalled when acceptor present");
        let Ok(tls) = acceptor.accept(framed.into_inner()).await else {
            return;
        };
        let mut framed = Framed::new(tls, crate::codec::SaslAwareCodec::default());
        bound_dn = None;
        let mut sasl = crate::sasl::SaslState::default();
        let _ = dialog(
            &mut framed,
            &db,
            &base_dn,
            &dc_label,
            log_events,
            &mut bound_dn,
            false,
            gss_service_key.as_deref().map(Vec::as_slice),
            &mut sasl,
            machine_registrar.as_ref(),
            nt_hash_lookup.as_ref(),
        )
        .await;
    }
}

/// The LDAP message loop over one (possibly TLS-wrapped) stream. Returns
/// [`Flow::StartTls`] when the client issued StartTLS and it was offered.
#[allow(clippy::too_many_arguments)]
async fn dialog<S>(
    framed: &mut Framed<S, crate::codec::SaslAwareCodec>,
    db: &Db,
    base_dn: &str,
    dc_label: &str,
    log_events: bool,
    bound_dn: &mut Option<String>,
    starttls_available: bool,
    gss_key: Option<&[u8]>,
    sasl: &mut crate::sasl::SaslState,
    machine_registrar: Option<&Arc<dyn MachineKeyRegistrar>>,
    nt_hash_lookup: Option<&magnetite_rpc::NtHashLookup>,
) -> Flow
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    while let Some(item) = framed.next().await {
        let msg = match item {
            Ok(m) => m,
            Err(_) => return Flow::Done, // malformed PDU; drop the connection
        };

        // StartTLS is handled here so the caller can upgrade the stream.
        if let LdapOp::ExtendedRequest(req) = &msg.op {
            if req.name == STARTTLS_OID {
                if starttls_available {
                    let _ = framed.send(starttls_response(msg.msgid)).await;
                    return Flow::StartTls;
                }
                let _ = framed
                    .send(extended_response(
                        msg.msgid,
                        LdapResultCode::ProtocolError,
                        "StartTLS is not available",
                    ))
                    .await;
                continue;
            }
        }

        let unbind = matches!(msg.op, LdapOp::UnbindRequest);
        let mut pending_layer = None;
        let responses = handle_message(
            &msg,
            db,
            base_dn,
            dc_label,
            log_events,
            bound_dn,
            gss_key,
            sasl,
            machine_registrar,
            nt_hash_lookup,
            &mut pending_layer,
        )
        .await;
        for r in &responses {
            match &r.op {
                LdapOp::SearchResultEntry(e) => tracing::info!(
                    "LDAP resp: SearchResultEntry dn={:?} attrs={:?}",
                    e.dn,
                    e.attributes
                        .iter()
                        .map(|a| a.atype.as_str())
                        .collect::<Vec<_>>()
                ),
                LdapOp::SearchResultDone(res) => {
                    tracing::info!("LDAP resp: SearchResultDone code={:?}", res.code)
                }
                LdapOp::AddResponse(res) => {
                    tracing::info!(
                        "LDAP resp: AddResponse code={:?} msg={:?}",
                        res.code,
                        res.message
                    )
                }
                LdapOp::ModifyResponse(res) => {
                    tracing::info!("LDAP resp: ModifyResponse code={:?}", res.code)
                }
                _ => {}
            }
        }
        for r in responses {
            if framed.send(r).await.is_err() {
                return Flow::Done;
            }
        }
        // A GSS-SPNEGO bind that negotiated a security layer: turn on per-PDU GSS
        // protection now, AFTER the bind's success response went out in the clear.
        if let Some(layer) = pending_layer {
            framed.codec_mut().activate_security_layer(layer);
        }
        if unbind {
            return Flow::Done;
        }
    }
    Flow::Done
}

#[allow(clippy::too_many_arguments)]
async fn handle_message(
    msg: &LdapMsg,
    db: &Db,
    base_dn: &str,
    dc_label: &str,
    log_events: bool,
    bound_dn: &mut Option<String>,
    gss_key: Option<&[u8]>,
    sasl: &mut crate::sasl::SaslState,
    machine_registrar: Option<&Arc<dyn MachineKeyRegistrar>>,
    nt_hash_lookup: Option<&magnetite_rpc::NtHashLookup>,
    pending_layer: &mut Option<crate::seclayer::SecurityLayer>,
) -> Vec<LdapMsg> {
    let msgid = msg.msgid;
    // Ungated op trace (query_log-independent) — for diagnosing the Windows join's
    // post-bind LDAP directory operations, which are NTLM-sealed on the wire.
    match &msg.op {
        LdapOp::SearchRequest(r) => tracing::info!(
            "LDAP op: SearchRequest base={:?} scope={:?} filter={:?} attrs={:?}",
            r.base,
            r.scope,
            r.filter,
            r.attrs
        ),
        LdapOp::AddRequest(r) => tracing::info!(
            "LDAP op: AddRequest dn={:?} attrs={:?}",
            r.dn,
            r.attributes
                .iter()
                .map(|a| a.atype.as_str())
                .collect::<Vec<_>>()
        ),
        LdapOp::ModifyRequest(r) => tracing::info!("LDAP op: ModifyRequest dn={:?}", r.dn),
        LdapOp::DelRequest(dn) => tracing::info!("LDAP op: DelRequest dn={dn:?}"),
        LdapOp::ExtendedRequest(r) => tracing::info!("LDAP op: ExtendedRequest oid={:?}", r.name),
        LdapOp::UnbindRequest => tracing::info!("LDAP op: UnbindRequest"),
        other => tracing::info!("LDAP op: {other:?}"),
    }
    match &msg.op {
        LdapOp::BindRequest(req) => match &req.cred {
            LdapBindCred::Simple(password) => {
                // Anonymous bind: empty DN and password.
                if req.dn.is_empty() && password.is_empty() {
                    *bound_dn = None;
                    log(db, log_events, LogLevel::Info, "bind anonymous").await;
                    return vec![bind_response(msgid, LdapResultCode::Success, "")];
                }
                let ok = db
                    .verify_ldap_bind(&req.dn, password)
                    .await
                    .unwrap_or(false);
                if ok {
                    *bound_dn = Some(req.dn.clone());
                    tracing::info!(target: "auth", proto = "ldap", dn = %req.dn, "LDAP simple bind ok");
                    log(
                        db,
                        log_events,
                        LogLevel::Info,
                        &format!("bind ok dn={}", req.dn),
                    )
                    .await;
                    vec![bind_response(msgid, LdapResultCode::Success, "")]
                } else {
                    *bound_dn = None;
                    tracing::warn!(target: "auth", proto = "ldap", dn = %req.dn, "LDAP simple bind failed: invalid credentials");
                    log(
                        db,
                        log_events,
                        LogLevel::Warn,
                        &format!("bind failed dn={}", req.dn),
                    )
                    .await;
                    vec![bind_response(
                        msgid,
                        LdapResultCode::InvalidCredentials,
                        "invalid credentials",
                    )]
                }
            }
            LdapBindCred::SASL(creds) => {
                // GSS-SPNEGO (or raw GSSAPI) SASL bind: Kerberos authentication for a
                // domain-join client. Needs the LDAP service key to verify the AP-REQ.
                let mech = creds.mechanism.as_str();
                tracing::info!(
                    "LDAP SASL bind mech={mech:?} cred_len={} ntlmssp={} ap_req={} spnego_oid={}",
                    creds.credentials.len(),
                    creds.credentials.windows(8).any(|w| w == b"NTLMSSP\0"),
                    creds
                        .credentials
                        .windows(3)
                        .any(|w| w == [0x01, 0x00, 0x6e]),
                    creds
                        .credentials
                        .windows(6)
                        .any(|w| w == [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]),
                );
                if !matches!(mech, "GSS-SPNEGO" | "GSSAPI") {
                    return vec![bind_response(
                        msgid,
                        LdapResultCode::AuthMethodNotSupported,
                        "unsupported SASL mechanism",
                    )];
                }
                let Some(key) = gss_key else {
                    return vec![bind_response(
                        msgid,
                        LdapResultCode::AuthMethodNotSupported,
                        "SASL Kerberos not configured",
                    )];
                };
                tracing::info!(
                    "LDAP SASL in  ({} B): {}",
                    creds.credentials.len(),
                    hex_dump(&creds.credentials)
                );
                match crate::sasl::gss_spnego_step(sasl, key, nt_hash_lookup, &creds.credentials) {
                    crate::sasl::SaslOutcome::Continue(server_creds) => {
                        tracing::info!(
                            "LDAP SASL out ({} B): {}",
                            server_creds.len(),
                            hex_dump(&server_creds)
                        );
                        // An empty token ⇒ absent serverSaslCreds (a bare challenge).
                        vec![sasl_bind_response(
                            msgid,
                            LdapResultCode::SaslBindInProgress,
                            (!server_creds.is_empty()).then_some(server_creds),
                        )]
                    }
                    crate::sasl::SaslOutcome::Done(principal, server_creds, security) => {
                        // Map the Kerberos principal (`name@REALM`) to its directory DN
                        // so ACLs and write authorization apply under its real identity;
                        // fall back to the principal string when no entry matches.
                        let account = principal.split('@').next().unwrap_or(&principal);
                        let bind_dn = db
                            .resolve_account_dn(account)
                            .await
                            .ok()
                            .flatten()
                            .unwrap_or_else(|| principal.clone());
                        *bound_dn = Some(bind_dn.clone());
                        // Build the per-message layer the bind negotiated. Kerberos:
                        // the first GSS-protected PDU is sequence 1 (the layer offer was
                        // sequence 0). NTLM: the context's own seq starts at 0. Either
                        // way the bind-success reply below still goes out in the clear.
                        *pending_layer = security.map(|n| match n {
                            crate::sasl::NegotiatedSecurity::Gss {
                                subkey,
                                confidential,
                            } => crate::seclayer::SecurityLayer::Gss(
                                crate::seclayer::GssSecurityLayer::new(subkey, confidential, 1),
                            ),
                            crate::sasl::NegotiatedSecurity::Ntlm(ctx) => {
                                crate::seclayer::SecurityLayer::Ntlm(
                                    crate::seclayer::NtlmSecurityLayer::new(ctx),
                                )
                            }
                        });
                        let layer = if pending_layer.is_some() {
                            " (security layer on)"
                        } else {
                            ""
                        };
                        tracing::info!(
                            target: "auth", proto = "ldap", principal = %principal, dn = %bind_dn,
                            security_layer = pending_layer.is_some(), "LDAP SASL bind ok"
                        );
                        log(
                            db,
                            log_events,
                            LogLevel::Info,
                            &format!("SASL bind ok principal={principal} dn={bind_dn}{layer}"),
                        )
                        .await;
                        vec![sasl_bind_response(
                            msgid,
                            LdapResultCode::Success,
                            server_creds,
                        )]
                    }
                    crate::sasl::SaslOutcome::Fail(reason) => {
                        *bound_dn = None;
                        tracing::warn!(target: "auth", proto = "ldap", "LDAP SASL bind failed → invalidCredentials: {reason}");
                        log(
                            db,
                            log_events,
                            LogLevel::Warn,
                            &format!("SASL bind failed: {reason}"),
                        )
                        .await;
                        vec![bind_response(
                            msgid,
                            LdapResultCode::InvalidCredentials,
                            &reason,
                        )]
                    }
                }
            }
        },
        LdapOp::SearchRequest(req) => {
            // RFC 4533 content synchronization: a SyncRequest control turns an
            // ordinary search into a syncrepl refresh (provider side).
            if let Some((mode, cookie)) = msg.ctrl.iter().find_map(|c| match c {
                LdapControl::SyncRequest { mode, cookie, .. } => {
                    Some((mode.clone(), cookie.clone()))
                }
                _ => None,
            }) {
                handle_syncrepl_search(
                    msgid,
                    req,
                    db,
                    log_events,
                    bound_dn.as_deref(),
                    mode,
                    cookie.as_deref(),
                )
                .await
            } else {
                handle_search(
                    msgid,
                    req,
                    db,
                    base_dn,
                    dc_label,
                    log_events,
                    bound_dn.as_deref(),
                )
                .await
            }
        }
        LdapOp::ModifyRequest(req) => {
            handle_modify(
                msgid,
                req,
                db,
                base_dn,
                dc_label,
                log_events,
                bound_dn.as_deref(),
            )
            .await
        }
        LdapOp::AddRequest(req) => {
            handle_add(
                msgid,
                req,
                db,
                log_events,
                bound_dn.as_deref(),
                machine_registrar,
            )
            .await
        }
        LdapOp::DelRequest(dn) => {
            handle_delete(msgid, dn, db, log_events, bound_dn.as_deref()).await
        }
        LdapOp::ModifyDNRequest(req) => {
            handle_moddn(msgid, req, db, log_events, bound_dn.as_deref()).await
        }
        LdapOp::UnbindRequest => Vec::new(),
        LdapOp::AbandonRequest(_) => Vec::new(),
        LdapOp::ExtendedRequest(_) => vec![extended_response(
            msgid,
            LdapResultCode::UnwillingToPerform,
            "extended operations are not supported",
        )],
        // Other writes (add/delete/modifyDN) still go through the management UI.
        _ => vec![result_done(
            msgid,
            LdapResultCode::UnwillingToPerform,
            "the directory is read-only over LDAP; use the management UI",
        )],
    }
}

async fn handle_search(
    msgid: i32,
    req: &LdapSearchRequest,
    db: &Db,
    base_dn: &str,
    dc_label: &str,
    log_events: bool,
    bound_dn: Option<&str>,
) -> Vec<LdapMsg> {
    // RootDSE: base "" with scope base.
    if req.base.is_empty() && req.scope == LdapSearchScope::Base {
        return root_dse(msgid, base_dn, dc_label, &req.attrs);
    }
    // The subschema subentry: the schema itself, for schema discovery. Answered
    // for any scope (a client reads it with scope base).
    if normalize_dn(&req.base) == normalize_dn(&subschema_dn(base_dn)) {
        return subschema_subentry(msgid, base_dn, &req.attrs);
    }

    // ACL: gate the search by the bound identity + search base (S-LDAP-07).
    // Per-entry/attribute filtering is deferred.
    let allowed = db
        .evaluate_ldap_acl(bound_dn, LdapAclOperation::Search, &req.base)
        .await
        .unwrap_or(true);
    if !allowed {
        log(
            db,
            log_events,
            LogLevel::Warn,
            &format!("search denied by ACL base={} dn={:?}", req.base, bound_dn),
        )
        .await;
        return vec![result_done(
            msgid,
            LdapResultCode::InsufficentAccessRights,
            "access denied by ACL",
        )];
    }

    let base_norm = normalize_dn(&req.base);
    let limit = if req.sizelimit > 0 {
        (req.sizelimit as usize).min(DEFAULT_SIZE_LIMIT)
    } else {
        DEFAULT_SIZE_LIMIT
    };

    // The domain sub-authorities the base object's objectSid is rendered from — the
    // DB-persisted single source of truth (so `DOMAIN_SID` is honoured on the LDAP path
    // exactly as on the KDC/SAMR path). Default when unseeded.
    let domain_sub = db
        .get_domain_sid()
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| vec![21, 1, 2, 3]);
    // Scope the DB query instead of loading the whole directory and filtering in Rust:
    // base = one entry, one-level = indexed children, subtree = DN-suffix match.
    let entries = match req.scope {
        LdapSearchScope::Base => db
            .get_entry_full(&base_norm)
            .await
            .ok()
            .flatten()
            .into_iter()
            .collect::<Vec<_>>(),
        LdapSearchScope::OneLevel | LdapSearchScope::Children => db
            .list_entries_by_parent(&base_norm)
            .await
            .unwrap_or_default(),
        LdapSearchScope::Subtree => db
            .list_entries_subtree(&base_norm)
            .await
            .unwrap_or_default(),
    };
    let mut out = Vec::new();
    for entry in &entries {
        if out.len() >= limit {
            break;
        }
        if !filter::matches(&req.filter, &filter::attribute_view(entry)) {
            continue;
        }
        out.push(search_entry(
            msgid,
            entry,
            &req.attrs,
            Some(base_dn),
            &domain_sub,
        ));
    }

    log(
        db,
        log_events,
        LogLevel::Info,
        &format!(
            "search base={} scope={:?} results={}",
            req.base,
            req.scope,
            out.len()
        ),
    )
    .await;

    out.push(result_done(msgid, LdapResultCode::Success, ""));
    out
}

/// Serve a search carrying a SyncRequest control (RFC 4533 content sync,
/// provider/refresh side). The consumer's `cookie` carries its last-seen context
/// CSN (an RFC3339 timestamp); on first sync it is empty. We reply with:
///   * changed in-scope entries as `SearchResultEntry` + SyncState(Add|Modify),
///   * for an incremental sync, deleted DNs as SyncState(Delete),
///   * `SearchResultDone` + SyncDone carrying the new cookie (current context CSN).
///
/// `refreshAndPersist` is served as a one-shot refresh (no persist phase); the
/// consumer re-polls, which is sufficient for interop with existing servers.
async fn handle_syncrepl_search(
    msgid: i32,
    req: &LdapSearchRequest,
    db: &Db,
    log_events: bool,
    bound_dn: Option<&str>,
    _mode: SyncRequestMode,
    cookie: Option<&[u8]>,
) -> Vec<LdapMsg> {
    let allowed = db
        .evaluate_ldap_acl(bound_dn, LdapAclOperation::Search, &req.base)
        .await
        .unwrap_or(true);
    if !allowed {
        return vec![result_done(
            msgid,
            LdapResultCode::InsufficentAccessRights,
            "access denied by ACL",
        )];
    }

    // The cookie is the consumer's last-seen context CSN (RFC3339). Empty ⇒
    // initial full refresh.
    let since = cookie
        .and_then(|c| std::str::from_utf8(c).ok())
        .unwrap_or("")
        .to_string();
    let incremental = !since.is_empty();
    let context_csn = db.ldap_context_csn().await.unwrap_or_default();
    let base_norm = normalize_dn(&req.base);

    let mut out = Vec::new();

    // Present phase: in-scope entries changed since the cookie CSN, each tagged
    // SyncState(Add). On a refresh the consumer upserts by entryUUID, so Add
    // serves both first-time adds and subsequent modifications.
    let entries = db.ldap_entries_since(&since).await.unwrap_or_default();
    for entry in &entries {
        if !in_scope(entry, &base_norm, &req.scope) {
            continue;
        }
        if !filter::matches(&req.filter, &filter::attribute_view(entry)) {
            continue;
        }
        out.push(sync_entry(msgid, entry, &req.attrs, SyncStateValue::Add));
    }

    // Delete phase: only meaningful for an incremental sync (a full refresh
    // implicitly replaces the consumer's view).
    if incremental {
        let deletions = db.ldap_deletions_since(&since).await.unwrap_or_default();
        for dn in deletions {
            let dn_norm = normalize_dn(&dn);
            let in_subtree = dn_norm == base_norm || dn_norm.ends_with(&format!(",{base_norm}"));
            if in_subtree {
                out.push(sync_delete(msgid, &dn));
            }
        }
    }

    log(
        db,
        log_events,
        LogLevel::Info,
        &format!(
            "syncrepl base={} since={:?} messages={}",
            req.base,
            if since.is_empty() { "<full>" } else { &since },
            out.len()
        ),
    )
    .await;

    // SearchResultDone carrying the new sync cookie (current context CSN).
    out.push(LdapMsg::new_with_ctrls(
        msgid,
        LdapOp::SearchResultDone(ldap_result(LdapResultCode::Success, "")),
        vec![LdapControl::SyncDone {
            cookie: Some(context_csn.into_bytes()),
            refresh_deletes: incremental,
        }],
    ));
    out
}

/// The RFC 4533 sync UUID for an entry, derived deterministically from its
/// normalised DN (URL namespace). This avoids a schema-level UUID column while
/// keeping a stable identity across syncs for the same DN.
fn entry_sync_uuid(dn: &str) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_URL, normalize_dn(dn).as_bytes())
}

/// A present/changed entry tagged with a SyncState control (Add or Modify).
fn sync_entry(
    msgid: i32,
    entry: &DirectoryEntry,
    requested: &[String],
    state: SyncStateValue,
) -> LdapMsg {
    // Syncrepl replicates the raw directory to a consumer, which does its own AD
    // mapping — so no AD operational-attribute synthesis here (domain SID unused).
    let mut msg = search_entry(msgid, entry, requested, None, &[]);
    msg.ctrl = vec![LdapControl::SyncState {
        state,
        entry_uuid: entry_sync_uuid(&entry.dn),
        cookie: None,
    }];
    msg
}

/// A deleted DN reported as an (attribute-less) entry with SyncState(Delete).
fn sync_delete(msgid: i32, dn: &str) -> LdapMsg {
    LdapMsg::new_with_ctrls(
        msgid,
        LdapOp::SearchResultEntry(LdapSearchResultEntry {
            dn: dn.to_string(),
            attributes: vec![],
        }),
        vec![LdapControl::SyncState {
            state: SyncStateValue::Delete,
            entry_uuid: entry_sync_uuid(dn),
            cookie: None,
        }],
    )
}

/// Whether `entry` falls within `scope` relative to the normalised base DN.
fn in_scope(entry: &DirectoryEntry, base_norm: &str, scope: &LdapSearchScope) -> bool {
    let dn = normalize_dn(&entry.dn);
    match scope {
        LdapSearchScope::Base => dn == base_norm,
        LdapSearchScope::OneLevel | LdapSearchScope::Children => entry
            .parent_dn
            .as_deref()
            .is_some_and(|p| normalize_dn(p) == base_norm),
        LdapSearchScope::Subtree => dn == base_norm || dn.ends_with(&format!(",{base_norm}")),
    }
}

/// AD `whenCreated`/`whenChanged` GeneralizedTime (`YYYYMMDDHHMMSS.0Z`).
fn generalized_time(dt: chrono::DateTime<chrono::Utc>) -> String {
    dt.format("%Y%m%d%H%M%S.0Z").to_string()
}

/// The RDN's value (`uid=alice` → `alice`) — the AD `name` attribute.
fn rdn_value(rdn: &str) -> &str {
    rdn.split_once('=').map(|(_, v)| v).unwrap_or(rdn)
}

/// The `objectCategory` DN for a structural class (the classSchema object DN;
/// note AD uses `CN=Person` for user, and hyphenated class CNs).
fn object_category(structural_class: &str, base_dn: &str) -> String {
    let cn = match structural_class.to_ascii_lowercase().as_str() {
        "user" | "person" | "organizationalperson" | "inetorgperson" => "Person".to_string(),
        "computer" => "Computer".to_string(),
        "group" | "groupofnames" => "Group".to_string(),
        "organizationalunit" => "Organizational-Unit".to_string(),
        "container" => "Container".to_string(),
        "domain" | "domaindns" => "Domain-DNS".to_string(),
        "builtindomain" => "Builtin-Domain".to_string(),
        other => {
            let mut c = other.chars();
            c.next()
                .map(|f| f.to_ascii_uppercase().to_string() + c.as_str())
                .unwrap_or_default()
        }
    };
    format!("CN={cn},{}", schema_nc(base_dn))
}

/// Decode a lowercase/uppercase hex string into bytes (AD-imported `objectSid`
/// is stored hex-encoded; AD returns it as a binary value).
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Build a search-result entry, honouring the requested attribute list
/// (empty or `*` ⇒ all user attributes). `objectClass` is synthesised from the
/// entry's classes; the password never appears in `DirectoryEntry`. When
/// `ad_base` is `Some`, AD operational attributes are synthesised so a client
/// sees the entry as an Active Directory object (`objectGUID`, `distinguishedName`,
/// `objectCategory`, `whenCreated`/`whenChanged`, `name`); a stored value always
/// wins over the synthesised one.
fn search_entry(
    msgid: i32,
    entry: &DirectoryEntry,
    requested: &[String],
    ad_base: Option<&str>,
    domain_sub: &[u32],
) -> LdapMsg {
    let wants = |name: &str| -> bool {
        requested.is_empty()
            || requested
                .iter()
                .any(|r| r == "*" || r == "+" || r.eq_ignore_ascii_case(name))
    };
    let has = |name: &str| {
        entry
            .attributes
            .keys()
            .any(|k| k.eq_ignore_ascii_case(name))
    };
    let string_attr = |name: &str, val: String| LdapPartialAttribute {
        atype: name.into(),
        vals: vec![val.into_bytes()],
    };
    let binary_attr = |name: &str, val: Vec<u8>| LdapPartialAttribute {
        atype: name.into(),
        vals: vec![val],
    };

    let mut attributes: Vec<LdapPartialAttribute> = Vec::new();
    if wants("objectClass") {
        attributes.push(LdapPartialAttribute {
            atype: "objectClass".into(),
            vals: entry
                .object_classes
                .iter()
                .map(|s| s.clone().into_bytes())
                .collect(),
        });
    }
    for (name, values) in &entry.attributes {
        if !wants(name) {
            continue;
        }
        // AD returns objectSid as a binary SID; we store it hex-encoded.
        if ad_base.is_some() && name.eq_ignore_ascii_case("objectSid") {
            if let Some(sid) = values.first().and_then(|v| decode_hex(v)) {
                attributes.push(binary_attr("objectSid", sid));
                continue;
            }
        }
        attributes.push(LdapPartialAttribute {
            atype: name.clone(),
            vals: values.iter().map(|s| s.clone().into_bytes()).collect(),
        });
    }

    // Synthesised AD operational attributes (constructed; a stored value wins).
    if let Some(base) = ad_base {
        if wants("distinguishedName") && !has("distinguishedName") {
            attributes.push(string_attr("distinguishedName", entry.dn.clone()));
        }
        if wants("name") && !has("name") {
            attributes.push(string_attr("name", rdn_value(&entry.rdn).to_string()));
        }
        if wants("objectGUID") && !has("objectGUID") {
            attributes.push(binary_attr(
                "objectGUID",
                entry_sync_uuid(&entry.dn).as_bytes().to_vec(),
            ));
        }
        // The domain naming-context object carries the domain SID — a join client
        // reads it to derive the machine account's SID, and aborts (INVALID_PARAMETER)
        // without it. Synthesise it for the base object from the configured domain
        // sub-authorities (the DB-persisted single source of truth, matching the addc
        // Directory / KDC / SAMR / netlogon), so `DOMAIN_SID` is honoured here too.
        if wants("objectSid") && !has("objectSid") && entry.dn.eq_ignore_ascii_case(base) {
            attributes.push(binary_attr("objectSid", domain_sid_bytes(domain_sub)));
        }
        if wants("objectCategory") && !has("objectCategory") {
            attributes.push(string_attr(
                "objectCategory",
                object_category(&entry.structural_class, base),
            ));
        }
        if wants("whenCreated") && !has("whenCreated") {
            attributes.push(string_attr(
                "whenCreated",
                generalized_time(entry.created_at),
            ));
        }
        if wants("whenChanged") && !has("whenChanged") {
            attributes.push(string_attr(
                "whenChanged",
                generalized_time(entry.updated_at),
            ));
        }
        if wants("instanceType") && !has("instanceType") {
            attributes.push(string_attr("instanceType", "4".into()));
        }
    }

    LdapMsg {
        msgid,
        op: LdapOp::SearchResultEntry(LdapSearchResultEntry {
            dn: entry.dn.clone(),
            attributes,
        }),
        ctrl: vec![],
    }
}

/// The domain SID as a binary `objectSid` (revision 1, NT authority 5) from the given
/// sub-authorities (e.g. `[21, 1, 2, 3]` ⇒ S-1-5-21-1-2-3), so a domain-join client can
/// derive account SIDs from the domain object. Falls back to the default sub-authorities
/// when none are configured. The sub-authorities are the DB-persisted single source of
/// truth shared with the addc `Directory` / KDC / SAMR / netlogon.
fn domain_sid_bytes(domain_sub: &[u32]) -> Vec<u8> {
    let default = [21u32, 1, 2, 3];
    let sub: &[u32] = if domain_sub.is_empty() {
        &default
    } else {
        domain_sub
    };
    let count = u8::try_from(sub.len()).unwrap_or(4);
    let mut sid = vec![0x01, count, 0, 0, 0, 0, 0, 0x05]; // rev, sub-auth count, IdentifierAuthority=NT(5)
    for s in sub {
        sid.extend_from_slice(&s.to_le_bytes());
    }
    sid
}

/// The Configuration naming context DN for a base (`CN=Configuration,<base>`).
fn configuration_nc(base_dn: &str) -> String {
    format!("CN=Configuration,{base_dn}")
}

/// The Schema naming context DN (`CN=Schema,CN=Configuration,<base>`).
fn schema_nc(base_dn: &str) -> String {
    format!("CN=Schema,{}", configuration_nc(base_dn))
}

/// The subschema subentry DN (`CN=Aggregate,CN=Schema,CN=Configuration,<base>`).
fn subschema_dn(base_dn: &str) -> String {
    format!("CN=Aggregate,{}", schema_nc(base_dn))
}

/// The DNS domain built from the base DN's `dc=` components (`example.com`).
fn dns_domain(base_dn: &str) -> String {
    base_dn
        .split(',')
        .filter_map(|c| c.trim().strip_prefix("dc="))
        .collect::<Vec<_>>()
        .join(".")
}

/// The RootDSE (base `""`, scope base) — now advertising the Active Directory
/// naming contexts, capabilities and the subschema subentry so a client detects
/// an AD-like DC and can discover the schema (MS-ADTS §3.1.1.3.2).
fn root_dse(msgid: i32, base_dn: &str, dc_label: &str, requested: &[String]) -> Vec<LdapMsg> {
    let wants = |name: &str| {
        requested.is_empty()
            || requested
                .iter()
                .any(|r| r == "*" || r == "+" || r.eq_ignore_ascii_case(name))
    };
    let config_nc = configuration_nc(base_dn);
    let schema_nc = schema_nc(base_dn);
    let dns = dns_domain(base_dn);
    // The NetBIOS computer name is the uppercased DNS host label, ≤15 chars.
    let dc_netbios: String = dc_label
        .chars()
        .flat_map(char::to_uppercase)
        .take(15)
        .collect();

    let mut attributes: Vec<LdapPartialAttribute> = Vec::new();
    let mut single = |name: &str, val: &str| {
        if wants(name) {
            attributes.push(LdapPartialAttribute {
                atype: name.into(),
                vals: vec![val.as_bytes().to_vec()],
            });
        }
    };
    single("objectClass", "top");
    single("subschemaSubentry", &subschema_dn(base_dn));
    single("defaultNamingContext", base_dn);
    single("rootDomainNamingContext", base_dn);
    single("configurationNamingContext", &config_nc);
    single("schemaNamingContext", &schema_nc);
    single("supportedLDAPVersion", "3");
    single("vendorName", "Magnetite");
    single("dnsHostName", &format!("{dc_label}.{dns}"));
    single(
        "serverName",
        &format!("CN={dc_netbios},CN=Servers,CN=Default-First-Site-Name,CN=Sites,{config_nc}"),
    );
    single("dsServiceName", &format!("CN=NTDS Settings,CN={dc_netbios},CN=Servers,CN=Default-First-Site-Name,CN=Sites,{config_nc}"));
    single(
        "ldapServiceName",
        &format!("{dns}:{dc_label}$@{}", dns.to_ascii_uppercase()),
    );
    // Advertised AD functional level. Defaults to 7 (Windows Server 2016); set
    // `AD_FUNCTIONAL_LEVEL` to match the domain being joined (e.g. 4 = 2008 R2), so a
    // client/tool does not see magnetite claim a higher level than the real domain.
    let functional_level = std::env::var("AD_FUNCTIONAL_LEVEL").unwrap_or_else(|_| "7".to_string());
    single("domainFunctionality", &functional_level);
    single("forestFunctionality", &functional_level);
    single("domainControllerFunctionality", &functional_level);
    single("isGlobalCatalogReady", "TRUE");
    single("isSynchronized", "TRUE");
    // The server's wall-clock time (AD Generalized-Time). A domain-join client reads
    // this from the RootDSE for clock-skew/time-offset checks; without it, Samba's
    // `ads_connect` fails with "No results returned".
    single("currentTime", &generalized_time(chrono::Utc::now()));

    let multi = |name: &str, vals: &[&str]| LdapPartialAttribute {
        atype: name.into(),
        vals: vals.iter().map(|v| v.as_bytes().to_vec()).collect(),
    };
    if wants("namingContexts") {
        attributes.push(multi("namingContexts", &[base_dn, &config_nc, &schema_nc]));
    }
    if wants("supportedControl") {
        attributes.push(multi(
            "supportedControl",
            &[
                "1.2.840.113556.1.4.319",   // paged results
                "1.2.840.113556.1.4.473",   // server-side sort
                "1.2.840.113556.1.4.417",   // show deleted
                "1.2.840.113556.1.4.801",   // SD flags
                "1.2.840.113556.1.4.805",   // tree delete
                "1.2.840.113556.1.4.841",   // DirSync
                "1.2.840.113556.1.4.1413",  // permissive modify
                "1.3.6.1.4.1.4203.1.9.1.1", // syncrepl (RFC 4533)
            ],
        ));
    }
    if wants("supportedCapabilities") {
        attributes.push(multi(
            "supportedCapabilities",
            &[
                "1.2.840.113556.1.4.800",  // LDAP_CAP_ACTIVE_DIRECTORY_OID
                "1.2.840.113556.1.4.1670", // _V51_OID
                "1.2.840.113556.1.4.1791", // _LDAP_INTEG_OID
                "1.2.840.113556.1.4.1935", // _V60_OID
            ],
        ));
    }
    if wants("supportedSASLMechanisms") {
        attributes.push(multi(
            "supportedSASLMechanisms",
            &["GSSAPI", "GSS-SPNEGO", "EXTERNAL"],
        ));
    }

    vec![
        LdapMsg {
            msgid,
            op: LdapOp::SearchResultEntry(LdapSearchResultEntry {
                dn: String::new(),
                attributes,
            }),
            ctrl: vec![],
        },
        result_done(msgid, LdapResultCode::Success, ""),
    ]
}

/// The subschema subentry: a synthetic entry carrying the core AD schema as
/// RFC 4512 `attributeTypes` / `objectClasses`, so a client's schema reader (e.g.
/// ldap3 `get_info=ALL`) can discover the classes and attributes we serve.
fn subschema_subentry(msgid: i32, base_dn: &str, requested: &[String]) -> Vec<LdapMsg> {
    let wants = |name: &str| {
        requested.is_empty()
            || requested
                .iter()
                .any(|r| r == "*" || r == "+" || r.eq_ignore_ascii_case(name))
    };
    let bytes = |v: Vec<String>| v.into_iter().map(String::into_bytes).collect::<Vec<_>>();
    let mut attributes: Vec<LdapPartialAttribute> = Vec::new();
    if wants("objectClass") {
        attributes.push(LdapPartialAttribute {
            atype: "objectClass".into(),
            vals: bytes(vec!["top".into(), "subSchema".into()]),
        });
    }
    if wants("cn") {
        attributes.push(LdapPartialAttribute {
            atype: "cn".into(),
            vals: bytes(vec!["Aggregate".into()]),
        });
    }
    if wants("attributeTypes") {
        attributes.push(LdapPartialAttribute {
            atype: "attributeTypes".into(),
            vals: bytes(crate::schema::attribute_types()),
        });
    }
    if wants("objectClasses") {
        attributes.push(LdapPartialAttribute {
            atype: "objectClasses".into(),
            vals: bytes(crate::schema::object_classes()),
        });
    }
    if wants("ldapSyntaxes") {
        attributes.push(LdapPartialAttribute {
            atype: "ldapSyntaxes".into(),
            vals: bytes(crate::schema::ldap_syntaxes()),
        });
    }
    vec![
        LdapMsg {
            msgid,
            op: LdapOp::SearchResultEntry(LdapSearchResultEntry {
                dn: subschema_dn(base_dn),
                attributes,
            }),
            ctrl: vec![],
        },
        result_done(msgid, LdapResultCode::Success, ""),
    ]
}

/// Apply an LDAP modify (RFC 4511 §4.6) — the operation a domain join uses to set
/// a computer object's `dNSHostName` / `servicePrincipalName` (and similar). Writes
/// require an authenticated bind and pass the ACL for `Modify` on the target DN.
async fn handle_modify(
    msgid: i32,
    req: &LdapModifyRequest,
    db: &Db,
    base_dn: &str,
    dc_label: &str,
    log_events: bool,
    bound_dn: Option<&str>,
) -> Vec<LdapMsg> {
    // Writes require authentication (the default open ACL would otherwise permit
    // anonymous modifies).
    if bound_dn.is_none() {
        return vec![modify_result(
            msgid,
            LdapResultCode::InsufficentAccessRights,
            "authentication required for modify",
        )];
    }
    let allowed = db
        .evaluate_ldap_acl(bound_dn, LdapAclOperation::Modify, &req.dn)
        .await
        .unwrap_or(true);
    if !allowed {
        log(
            db,
            log_events,
            LogLevel::Warn,
            &format!("modify denied by ACL dn={} by={:?}", req.dn, bound_dn),
        )
        .await;
        return vec![modify_result(
            msgid,
            LdapResultCode::InsufficentAccessRights,
            "access denied by ACL",
        )];
    }

    // FSMO role seizure: a Windows admin tool (`ntdsutil` /
    // `Move-ADDirectoryServerOperationMasterRole`) or `samba-tool fsmo seize`
    // requests a role by writing a `becomeXMaster` operational attribute to the
    // rootDSE. Seize each named role to THIS DC — rewrite the role object's
    // `fSMORoleOwner` to this DC's nTDSDSA — so the role actually moves here (and a
    // later `fsmo show` reports it). Idempotent when this DC already holds the role.
    let seizes: Vec<String> = if req.dn.is_empty() {
        req.changes
            .iter()
            .map(|c| c.modification.atype.to_ascii_lowercase())
            .filter(|a| {
                matches!(
                    a.as_str(),
                    "becomeschemamaster"
                        | "becomeridmaster"
                        | "becomepdc"
                        | "becomedomainmaster"
                        | "becomeinfrastructuremaster"
                )
            })
            .collect()
    } else {
        Vec::new()
    };
    if !seizes.is_empty() {
        let dc_netbios: String = dc_label
            .chars()
            .flat_map(char::to_uppercase)
            .take(15)
            .collect();
        for attr in &seizes {
            match db.seize_fsmo_role(base_dn, &dc_netbios, attr).await {
                Ok(Some(dn)) => {
                    log(
                        db,
                        log_events,
                        LogLevel::Info,
                        &format!("FSMO role seized to this DC: {attr} → {dn}"),
                    )
                    .await;
                }
                Ok(None) => {}
                Err(e) => {
                    log(
                        db,
                        log_events,
                        LogLevel::Warn,
                        &format!("FSMO role seizure failed for {attr}: {e}"),
                    )
                    .await;
                    return vec![modify_result(
                        msgid,
                        LdapResultCode::Other,
                        "FSMO role seizure failed",
                    )];
                }
            }
        }
        return vec![modify_result(msgid, LdapResultCode::Success, "")];
    }

    let changes: Vec<LdapAttrChange> = req
        .changes
        .iter()
        .map(|c| LdapAttrChange {
            op: match c.operation {
                LdapModifyType::Add => LdapModifyOp::Add,
                LdapModifyType::Delete => LdapModifyOp::Delete,
                LdapModifyType::Replace => LdapModifyOp::Replace,
            },
            attr: c.modification.atype.clone(),
            values: c
                .modification
                .vals
                .iter()
                .map(|v| String::from_utf8_lossy(v).into_owned())
                .collect(),
        })
        .collect();

    // Schema enforcement: an add/replace must target a defined attribute type.
    if let Some(bad) = changes.iter().find(|c| {
        matches!(c.op, LdapModifyOp::Add | LdapModifyOp::Replace)
            && !crate::schema::is_known_attribute(&c.attr)
    }) {
        return vec![modify_result(
            msgid,
            LdapResultCode::UndefinedAttributeType,
            &format!("undefined attribute type '{}'", bad.attr),
        )];
    }

    match db.modify_entry(&req.dn, &changes).await {
        Ok(true) => {
            log(
                db,
                log_events,
                LogLevel::Info,
                &format!("modify dn={}", req.dn),
            )
            .await;
            vec![modify_result(msgid, LdapResultCode::Success, "")]
        }
        Ok(false) => vec![modify_result(
            msgid,
            LdapResultCode::NoSuchObject,
            "no such entry",
        )],
        Err(e) => vec![modify_result(
            msgid,
            LdapResultCode::OperationsError,
            &e.to_string(),
        )],
    }
}

fn ldap_result(code: LdapResultCode, message: &str) -> LdapResult {
    LdapResult {
        code,
        matcheddn: String::new(),
        message: message.to_string(),
        referral: vec![],
    }
}

/// A ModifyResponse (LDAPResult) — the correct response variant for a modify.
fn modify_result(msgid: i32, code: LdapResultCode, message: &str) -> LdapMsg {
    LdapMsg {
        msgid,
        op: LdapOp::ModifyResponse(ldap_result(code, message)),
        ctrl: vec![],
    }
}

/// Handle an LDAP `AddRequest` (RFC 4511 §4.7) — how a domain join creates a
/// `computer` object. Authenticated + ACL-gated; `objectClass` values become the
/// entry's object classes, the rest become its attributes.
async fn handle_add(
    msgid: i32,
    req: &LdapAddRequest,
    db: &Db,
    log_events: bool,
    bound_dn: Option<&str>,
    machine_registrar: Option<&Arc<dyn MachineKeyRegistrar>>,
) -> Vec<LdapMsg> {
    if bound_dn.is_none() {
        return vec![add_result(
            msgid,
            LdapResultCode::InsufficentAccessRights,
            "authentication required for add",
        )];
    }
    let allowed = db
        .evaluate_ldap_acl(bound_dn, LdapAclOperation::Add, &req.dn)
        .await
        .unwrap_or(true);
    if !allowed {
        return vec![add_result(
            msgid,
            LdapResultCode::InsufficentAccessRights,
            "access denied by ACL",
        )];
    }

    let mut object_classes: Vec<String> = Vec::new();
    let mut attributes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for attr in &req.attributes {
        // `unicodePwd` is a write-only secret (UTF-16LE): never store it and keep it
        // out of schema validation — it is consumed only to register the machine's
        // Kerberos key (see `machine_password`, which reads it from the raw request).
        if attr.atype.eq_ignore_ascii_case("unicodePwd") {
            continue;
        }
        let values: Vec<String> = attr
            .vals
            .iter()
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .collect();
        if attr.atype.eq_ignore_ascii_case("objectClass") {
            object_classes = values;
        } else {
            attributes.insert(attr.atype.clone(), values);
        }
    }
    if object_classes.is_empty() {
        object_classes.push("top".to_string());
    }

    // Schema enforcement (RFC 4512): the RDN attribute counts as present.
    let rdn_attr = req
        .dn
        .split(',')
        .next()
        .and_then(|r| r.split_once('='))
        .map(|(a, _)| a.trim())
        .unwrap_or("");
    if let Err(v) = crate::schema::validate_new_entry(&object_classes, &attributes, rdn_attr) {
        let (code, msg) = match v {
            crate::schema::Violation::ObjectClassViolation(m) => {
                (LdapResultCode::ObjectClassViolation, m)
            }
            crate::schema::Violation::UndefinedAttributeType(m) => {
                (LdapResultCode::UndefinedAttributeType, m)
            }
        };
        log(
            db,
            log_events,
            LogLevel::Warn,
            &format!("add schema violation dn={}: {msg}", req.dn),
        )
        .await;
        return vec![add_result(msgid, code, &msg)];
    }

    // A domain join adds a `computer` object carrying a machine password; capture
    // whether this is one before `object_classes` is moved into `create_entry`.
    let is_computer = object_classes
        .iter()
        .any(|c| c.eq_ignore_ascii_case("computer"));
    // A user/group added over LDAP (e.g. a bulk `ldapadd` migration) must also be
    // provisioned into ad_principal/ad_group, or it stays invisible to Kerberos — the
    // same gap the Web CreateUser/CreateGroup paths close. `computer` is a user subclass
    // but keeps its dedicated machine registration, so exclude it from `is_user`.
    let is_user = !is_computer
        && object_classes.iter().any(|c| {
            c.eq_ignore_ascii_case("user")
                || c.eq_ignore_ascii_case("inetOrgPerson")
                || c.eq_ignore_ascii_case("person")
        });
    let is_group = object_classes
        .iter()
        .any(|c| c.eq_ignore_ascii_case("group"));

    match db
        .create_entry(
            &req.dn,
            object_classes,
            &attributes,
            bound_dn.unwrap_or("ldap"),
        )
        .await
    {
        Ok(_) => {
            log(
                db,
                log_events,
                LogLevel::Info,
                &format!("add dn={}", req.dn),
            )
            .await;
            // Register the machine account with the KDC so it can obtain a TGT.
            if is_computer {
                if let Some(registrar) = machine_registrar {
                    if let (Some(sam), Some(pw)) = (
                        machine_sam(&attributes, &req.dn),
                        machine_password(req, &attributes),
                    ) {
                        registrar.register_machine(&sam, &pw);
                        log(
                            db,
                            log_events,
                            LogLevel::Info,
                            &format!("registered machine account {sam} with the KDC"),
                        )
                        .await;
                    }
                }
            } else if is_user {
                // Provision the ad_principal so an LDAP-created user can log on to Windows.
                if let Some(registrar) = machine_registrar {
                    let sam = account_sam(&attributes, &req.dn);
                    let pw = machine_password(req, &attributes).unwrap_or_default();
                    let rid = rid_from_object_sid(req);
                    registrar.register_user(&sam, &pw, rid).await;
                    log(
                        db,
                        log_events,
                        LogLevel::Info,
                        &format!("provisioned ad_principal for LDAP-created user {sam}"),
                    )
                    .await;
                }
            } else if is_group {
                // Provision the ad_group + member links so the group reaches the KDC/PAC.
                if let Some(registrar) = machine_registrar {
                    let sam = account_sam(&attributes, &req.dn);
                    let members = group_member_sams(&attributes);
                    let rid = rid_from_object_sid(req);
                    registrar.register_group(&sam, &members, rid).await;
                    log(
                        db,
                        log_events,
                        LogLevel::Info,
                        &format!("provisioned ad_group for LDAP-created group {sam}"),
                    )
                    .await;
                }
            }
            vec![add_result(msgid, LdapResultCode::Success, "")]
        }
        Err(e) => {
            let msg = e.to_string();
            // Distinguish a duplicate DN (EntryAlreadyExists) from other failures.
            let code = if msg.contains("既に存在") {
                LdapResultCode::EntryAlreadyExists
            } else {
                LdapResultCode::OperationsError
            };
            vec![add_result(msgid, code, &msg)]
        }
    }
}

/// The machine account name (`sAMAccountName`, e.g. `PC$`) for a `computer` Add,
/// falling back to `<CN>$` derived from the RDN when the attribute is absent.
fn machine_sam(attributes: &BTreeMap<String, Vec<String>>, dn: &str) -> Option<String> {
    if let Some((_, vals)) = attributes
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("sAMAccountName"))
    {
        if let Some(sam) = vals.first().filter(|s| !s.is_empty()) {
            return Some(sam.clone());
        }
    }
    let cn = dn.split(',').next()?.split_once('=')?.1.trim();
    (!cn.is_empty()).then(|| format!("{}$", cn.trim_end_matches('$')))
}

/// The cleartext machine password from a `computer` Add: `unicodePwd` (the AD
/// attribute — UTF-16LE, double-quoted, read from the raw request) if present,
/// else `userPassword` (the portable plaintext fallback).
/// The `sAMAccountName` for a user/group Add: the explicit attribute, else the RDN value
/// (`uid=alice,…` / `cn=Admins,…` ⇒ `alice` / `Admins`).
fn account_sam(attributes: &BTreeMap<String, Vec<String>>, dn: &str) -> String {
    if let Some((_, vals)) = attributes
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("sAMAccountName"))
    {
        if let Some(sam) = vals.first().filter(|s| !s.is_empty()) {
            return sam.clone();
        }
    }
    dn.split(',')
        .next()
        .and_then(|r| r.split_once('='))
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_default()
}

/// The RID from a supplied binary `objectSid` (last little-endian u32), so an LDIF import
/// can inherit an old domain's exact SID. Read from the RAW request because the string
/// attribute map would have lossily decoded the binary SID. `None` when absent/too short.
fn rid_from_object_sid(req: &LdapAddRequest) -> Option<u32> {
    for attr in &req.attributes {
        if attr.atype.eq_ignore_ascii_case("objectSid") {
            if let Some(bytes) = attr.vals.first() {
                if bytes.len() >= 4 {
                    let tail = &bytes[bytes.len() - 4..];
                    return Some(u32::from_le_bytes([tail[0], tail[1], tail[2], tail[3]]));
                }
            }
        }
    }
    None
}

/// The member `sAMAccountName`s of a group Add, taken from each `member` DN's RDN value.
fn group_member_sams(attributes: &BTreeMap<String, Vec<String>>) -> Vec<String> {
    attributes
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("member"))
        .map(|(_, dns)| {
            dns.iter()
                .filter_map(|dn| {
                    dn.split(',')
                        .next()
                        .and_then(|r| r.split_once('='))
                        .map(|(_, v)| v.trim().to_string())
                        .filter(|s| !s.is_empty())
                })
                .collect()
        })
        .unwrap_or_default()
}

fn machine_password(
    req: &LdapAddRequest,
    attributes: &BTreeMap<String, Vec<String>>,
) -> Option<String> {
    for attr in &req.attributes {
        if attr.atype.eq_ignore_ascii_case("unicodePwd") {
            if let Some(pw) = attr.vals.first().and_then(|v| decode_unicode_pwd(v)) {
                return Some(pw);
            }
        }
    }
    attributes
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("userPassword"))
        .and_then(|(_, v)| v.first().filter(|s| !s.is_empty()).cloned())
}

/// Decode an AD `unicodePwd` value: UTF-16LE with the password wrapped in double
/// quotes (`"secret"`). Returns the unquoted cleartext, or `None` if malformed.
fn decode_unicode_pwd(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 || !bytes.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    let s = String::from_utf16(&units).ok()?;
    let unquoted = s
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(&s);
    (!unquoted.is_empty()).then(|| unquoted.to_string())
}

/// An AddResponse (LDAPResult) — the correct response variant for an add.
fn add_result(msgid: i32, code: LdapResultCode, message: &str) -> LdapMsg {
    LdapMsg {
        msgid,
        op: LdapOp::AddResponse(ldap_result(code, message)),
        ctrl: vec![],
    }
}

/// Handle an LDAP `DelRequest` (RFC 4511 §4.8). Authenticated + ACL-gated; only a
/// leaf entry is removable (one with children yields `NotAllowedOnNonLeaf`).
async fn handle_delete(
    msgid: i32,
    dn: &str,
    db: &Db,
    log_events: bool,
    bound_dn: Option<&str>,
) -> Vec<LdapMsg> {
    if bound_dn.is_none() {
        return vec![del_result(
            msgid,
            LdapResultCode::InsufficentAccessRights,
            "authentication required for delete",
        )];
    }
    let allowed = db
        .evaluate_ldap_acl(bound_dn, LdapAclOperation::Delete, dn)
        .await
        .unwrap_or(true);
    if !allowed {
        log(
            db,
            log_events,
            LogLevel::Warn,
            &format!("delete denied by ACL dn={dn} by={bound_dn:?}"),
        )
        .await;
        return vec![del_result(
            msgid,
            LdapResultCode::InsufficentAccessRights,
            "access denied by ACL",
        )];
    }
    match db.delete_entry(dn).await {
        Ok(()) => {
            log(db, log_events, LogLevel::Info, &format!("delete dn={dn}")).await;
            vec![del_result(msgid, LdapResultCode::Success, "")]
        }
        Err(DbError::NotFound) => {
            vec![del_result(
                msgid,
                LdapResultCode::NoSuchObject,
                "no such entry",
            )]
        }
        Err(DbError::Constraint(msg)) => {
            vec![del_result(msgid, LdapResultCode::NotAllowedOnNonLeaf, &msg)]
        }
        Err(e) => vec![del_result(
            msgid,
            LdapResultCode::OperationsError,
            &e.to_string(),
        )],
    }
}

/// A DelResponse (LDAPResult).
fn del_result(msgid: i32, code: LdapResultCode, message: &str) -> LdapMsg {
    LdapMsg {
        msgid,
        op: LdapOp::DelResponse(ldap_result(code, message)),
        ctrl: vec![],
    }
}

/// Handle an LDAP `ModifyDNRequest` (RFC 4511 §4.9) — rename or move an entry.
/// Authenticated + ACL-gated; only leaf entries move.
async fn handle_moddn(
    msgid: i32,
    req: &LdapModifyDNRequest,
    db: &Db,
    log_events: bool,
    bound_dn: Option<&str>,
) -> Vec<LdapMsg> {
    if bound_dn.is_none() {
        return vec![moddn_result(
            msgid,
            LdapResultCode::InsufficentAccessRights,
            "authentication required for modifyDN",
        )];
    }
    let allowed = db
        .evaluate_ldap_acl(bound_dn, LdapAclOperation::ModifyDn, &req.dn)
        .await
        .unwrap_or(true);
    if !allowed {
        log(
            db,
            log_events,
            LogLevel::Warn,
            &format!("modifyDN denied by ACL dn={} by={:?}", req.dn, bound_dn),
        )
        .await;
        return vec![moddn_result(
            msgid,
            LdapResultCode::InsufficentAccessRights,
            "access denied by ACL",
        )];
    }
    match db
        .rename_entry(
            &req.dn,
            &req.newrdn,
            req.deleteoldrdn,
            req.new_superior.as_deref(),
        )
        .await
    {
        Ok(entry) => {
            log(
                db,
                log_events,
                LogLevel::Info,
                &format!("modifyDN dn={} -> {}", req.dn, entry.dn),
            )
            .await;
            vec![moddn_result(msgid, LdapResultCode::Success, "")]
        }
        Err(DbError::NotFound) => {
            vec![moddn_result(
                msgid,
                LdapResultCode::NoSuchObject,
                "no such entry",
            )]
        }
        Err(DbError::Constraint(msg)) => {
            let code = if msg.contains("配下") {
                LdapResultCode::NotAllowedOnNonLeaf
            } else if msg.contains("既に存在") {
                LdapResultCode::EntryAlreadyExists
            } else {
                LdapResultCode::UnwillingToPerform
            };
            vec![moddn_result(msgid, code, &msg)]
        }
        Err(e) => vec![moddn_result(
            msgid,
            LdapResultCode::OperationsError,
            &e.to_string(),
        )],
    }
}

/// A ModifyDNResponse (LDAPResult).
fn moddn_result(msgid: i32, code: LdapResultCode, message: &str) -> LdapMsg {
    LdapMsg {
        msgid,
        op: LdapOp::ModifyDNResponse(ldap_result(code, message)),
        ctrl: vec![],
    }
}

/// A space-separated hex dump of up to 512 bytes, for diagnosing SASL tokens.
fn hex_dump(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(512)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn bind_response(msgid: i32, code: LdapResultCode, message: &str) -> LdapMsg {
    LdapMsg {
        msgid,
        op: LdapOp::BindResponse(LdapBindResponse {
            res: ldap_result(code, message),
            saslcreds: None,
        }),
        ctrl: vec![],
    }
}

/// A bind response carrying `serverSaslCreds` (a SASL server token) — used for the
/// `saslBindInProgress` continuation and the final success of a GSS-SPNEGO bind.
fn sasl_bind_response(msgid: i32, code: LdapResultCode, saslcreds: Option<Vec<u8>>) -> LdapMsg {
    LdapMsg {
        msgid,
        op: LdapOp::BindResponse(LdapBindResponse {
            res: ldap_result(code, ""),
            saslcreds,
        }),
        ctrl: vec![],
    }
}

/// A generic completion result (carried as `SearchResultDone`; clients correlate
/// by message id).
fn result_done(msgid: i32, code: LdapResultCode, message: &str) -> LdapMsg {
    LdapMsg {
        msgid,
        op: LdapOp::SearchResultDone(ldap_result(code, message)),
        ctrl: vec![],
    }
}

fn extended_response(msgid: i32, code: LdapResultCode, message: &str) -> LdapMsg {
    LdapMsg {
        msgid,
        op: LdapOp::ExtendedResponse(LdapExtendedResponse {
            res: ldap_result(code, message),
            name: None,
            value: None,
        }),
        ctrl: vec![],
    }
}

/// A successful StartTLS extended response (echoes the OID).
fn starttls_response(msgid: i32) -> LdapMsg {
    LdapMsg {
        msgid,
        op: LdapOp::ExtendedResponse(LdapExtendedResponse {
            res: ldap_result(LdapResultCode::Success, ""),
            name: Some(STARTTLS_OID.to_string()),
            value: None,
        }),
        ctrl: vec![],
    }
}

async fn log(db: &Db, enabled: bool, level: LogLevel, message: &str) {
    if !enabled {
        return;
    }
    let _ = db
        .append_log(NewLogEntry {
            domain: DomainKey::Ldap,
            log_kind: LogKind::Query,
            level,
            message: message.to_string(),
            at: Utc::now(),
            meta: None,
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ldap3::{LdapConnAsync, Mod, Scope, SearchEntry};
    use std::collections::HashSet;

    async fn seeded_db() -> (Db, tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        let base = db
            .ensure_ldap_base("dc=example,dc=com", "admin")
            .await
            .unwrap();
        db.create_ou(&base, "people", None, "admin").await.unwrap();
        let people = format!("ou=people,{base}");
        db.create_user(
            &people,
            "alice",
            "Alice A",
            "A",
            Some("alice@x.test"),
            "admin",
        )
        .await
        .unwrap();
        db.reset_password(&format!("uid=alice,{people}"), "password12")
            .await
            .unwrap();
        (db, dir, base)
    }

    async fn start_server(db: Db) -> (SocketAddr, watch::Sender<bool>) {
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        let svc = LdapService::new(addr, true, None, "dc=example,dc=com".into());
        let (tx, rx) = watch::channel(false);
        svc.start(db, rx);
        for _ in 0..50 {
            if svc.health() == ServiceHealth::Healthy {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(svc.health(), ServiceHealth::Healthy);
        (addr, tx)
    }

    /// One recorded group registration: (sam_account_name, members, explicit RID).
    type GroupCall = (String, Vec<String>, Option<u32>);

    /// A [`MachineKeyRegistrar`] that records every registration, so a test can
    /// assert the KDC hook fired with the right machine account + password.
    #[derive(Default)]
    struct RecordingRegistrar {
        calls: std::sync::Mutex<Vec<(String, String)>>,
        users: std::sync::Mutex<Vec<(String, String, Option<u32>)>>,
        groups: std::sync::Mutex<Vec<GroupCall>>,
    }
    impl MachineKeyRegistrar for RecordingRegistrar {
        fn register_machine(&self, sam_account_name: &str, password: &str) {
            self.calls
                .lock()
                .expect("registrar lock")
                .push((sam_account_name.to_string(), password.to_string()));
        }
        fn register_user<'a>(
            &'a self,
            sam_account_name: &'a str,
            password: &'a str,
            rid: Option<u32>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
            self.users.lock().expect("registrar lock").push((
                sam_account_name.to_string(),
                password.to_string(),
                rid,
            ));
            Box::pin(async {})
        }
        fn register_group<'a>(
            &'a self,
            sam_account_name: &'a str,
            member_sams: &'a [String],
            rid: Option<u32>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
            self.groups.lock().expect("registrar lock").push((
                sam_account_name.to_string(),
                member_sams.to_vec(),
                rid,
            ));
            Box::pin(async {})
        }
    }

    async fn start_server_with_registrar(
        db: Db,
        registrar: Arc<dyn MachineKeyRegistrar>,
    ) -> (SocketAddr, watch::Sender<bool>) {
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        let svc = LdapService::new(addr, true, None, "dc=example,dc=com".into())
            .with_machine_registrar(registrar);
        let (tx, rx) = watch::channel(false);
        svc.start(db, rx);
        for _ in 0..50 {
            if svc.health() == ServiceHealth::Healthy {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(svc.health(), ServiceHealth::Healthy);
        (addr, tx)
    }

    /// Open an `ldap3` async client against the running server.
    async fn connect(addr: SocketAddr) -> ldap3::Ldap {
        let (conn, ldap) = LdapConnAsync::new(&format!("ldap://{addr}"))
            .await
            .expect("connect");
        tokio::spawn(async move {
            let _ = conn.drive().await;
        });
        ldap
    }

    #[tokio::test]
    async fn simple_bind_success_and_failure() {
        let (db, _dir, base) = seeded_db().await;
        let (addr, _tx) = start_server(db).await;
        let mut ldap = connect(addr).await;
        let dn = format!("uid=alice,ou=people,{base}");

        let ok = ldap.simple_bind(&dn, "password12").await.unwrap();
        assert_eq!(ok.rc, 0, "good bind rc={} {}", ok.rc, ok.text);

        let bad = ldap.simple_bind(&dn, "wrong").await.unwrap();
        assert_ne!(bad.rc, 0, "bad password should fail");
    }

    #[tokio::test]
    async fn modify_sets_computer_attributes() {
        let (db, _dir, base) = seeded_db().await;
        let (addr, _tx) = start_server(db).await;
        let mut ldap = connect(addr).await;
        let dn = format!("uid=alice,ou=people,{base}");

        // Anonymous modify is rejected (writes require authentication).
        ldap.simple_bind("", "").await.unwrap();
        let anon = ldap
            .modify(
                &dn,
                vec![Mod::Replace(
                    "dNSHostName".to_string(),
                    HashSet::from(["x".to_string()]),
                )],
            )
            .await
            .unwrap();
        assert_ne!(anon.rc, 0, "anonymous modify must be denied");

        // Authenticated: set dNSHostName + servicePrincipalName (the join's writes).
        ldap.simple_bind(&dn, "password12")
            .await
            .unwrap()
            .success()
            .unwrap();
        let res = ldap
            .modify(
                &dn,
                vec![
                    Mod::Replace(
                        "dNSHostName".to_string(),
                        HashSet::from(["alice.example.com".to_string()]),
                    ),
                    Mod::Add(
                        "servicePrincipalName".to_string(),
                        HashSet::from([
                            "HOST/alice".to_string(),
                            "HOST/alice.example.com".to_string(),
                        ]),
                    ),
                ],
            )
            .await
            .unwrap();
        assert_eq!(res.rc, 0, "modify rc={} {}", res.rc, res.text);

        // Read the attributes back over LDAP.
        let (rs, _) = ldap
            .search(
                &dn,
                Scope::Base,
                "(objectClass=*)",
                vec!["dNSHostName", "servicePrincipalName"],
            )
            .await
            .unwrap()
            .success()
            .unwrap();
        let entry = SearchEntry::construct(rs.into_iter().next().unwrap());
        assert_eq!(
            entry.attrs.get("dNSHostName"),
            Some(&vec!["alice.example.com".to_string()])
        );
        assert_eq!(entry.attrs.get("servicePrincipalName").unwrap().len(), 2);
    }

    #[tokio::test]
    async fn add_creates_computer_object() {
        let (db, _dir, base) = seeded_db().await;
        let (addr, _tx) = start_server(db).await;
        let mut ldap = connect(addr).await;
        let alice = format!("uid=alice,ou=people,{base}");
        let computer = format!("cn=WIN10PC,{base}");

        // Anonymous add is rejected.
        ldap.simple_bind("", "").await.unwrap();
        let anon = ldap
            .add(
                &computer,
                vec![("objectClass", HashSet::from(["computer"]))],
            )
            .await
            .unwrap();
        assert_ne!(anon.rc, 0, "anonymous add must be denied");

        // Authenticated: add a computer object (the join's LDAP AddRequest).
        ldap.simple_bind(&alice, "password12")
            .await
            .unwrap()
            .success()
            .unwrap();
        let res = ldap
            .add(
                &computer,
                vec![
                    ("objectClass", HashSet::from(["top", "computer"])),
                    ("sAMAccountName", HashSet::from(["WIN10PC$"])),
                    ("dNSHostName", HashSet::from(["win10pc.example.com"])),
                ],
            )
            .await
            .unwrap();
        assert_eq!(res.rc, 0, "add rc={} {}", res.rc, res.text);

        // Read it back over LDAP.
        let (rs, _) = ldap
            .search(&computer, Scope::Base, "(objectClass=*)", vec!["*"])
            .await
            .unwrap()
            .success()
            .unwrap();
        let entry = SearchEntry::construct(rs.into_iter().next().unwrap());
        assert_eq!(
            entry.attrs.get("sAMAccountName"),
            Some(&vec!["WIN10PC$".to_string()])
        );
        assert!(entry
            .attrs
            .get("objectClass")
            .unwrap()
            .contains(&"computer".to_string()));

        // Re-adding the same DN fails with entryAlreadyExists (68).
        let dup = ldap
            .add(
                &computer,
                vec![("objectClass", HashSet::from(["computer"]))],
            )
            .await
            .unwrap();
        assert_eq!(dup.rc, 68, "duplicate add → entryAlreadyExists");
    }

    #[tokio::test]
    async fn fsmo_become_master_seizes_the_role_over_ldap() {
        // End-to-end over LDAP: a role parked on a peer is seized to this DC by a
        // rootDSE `becomeXMaster` write (what samba-tool / ntdsutil send).
        let (db, _dir, base) = seeded_db().await;
        let (addr, _tx) = start_server(db).await;
        let mut ldap = connect(addr).await;
        let alice = format!("uid=alice,ou=people,{base}");
        ldap.simple_bind(&alice, "password12")
            .await
            .unwrap()
            .success()
            .unwrap();

        let infra = format!("cn=Infrastructure,{base}");
        let peer = format!(
            "CN=NTDS Settings,CN=PEERDC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,{base}"
        );

        // Park the role on the peer.
        ldap.modify(
            &infra,
            vec![Mod::Replace(
                "fSMORoleOwner".to_string(),
                HashSet::from([peer]),
            )],
        )
        .await
        .unwrap()
        .success()
        .unwrap();

        // `becomeInfrastructureMaster` on the rootDSE seizes it to THIS DC.
        let res = ldap
            .modify(
                "",
                vec![Mod::Replace(
                    "becomeInfrastructureMaster".to_string(),
                    HashSet::from(["".to_string()]),
                )],
            )
            .await
            .unwrap();
        assert_eq!(res.rc, 0, "seize over LDAP succeeds: {}", res.text);

        let (rs, _) = ldap
            .search(
                &infra,
                Scope::Base,
                "(objectClass=*)",
                vec!["fSMORoleOwner"],
            )
            .await
            .unwrap()
            .success()
            .unwrap();
        let owner = SearchEntry::construct(rs.into_iter().next().expect("role object")).attrs
            ["fSMORoleOwner"][0]
            .clone();
        assert!(
            owner.contains("cn=ntds settings,cn=magnetite"),
            "role now owned by this DC's nTDSDSA: {owner}"
        );
    }

    #[tokio::test]
    async fn all_seven_fsmo_role_objects_report_this_dc() {
        // `samba-tool fsmo show` base-searches each of the seven role objects (the five
        // core roles plus the two DNS application-partition Infrastructure roles) and
        // reads `fSMORoleOwner`. A single-DC magnetite must serve all seven, each
        // resolving to this DC's nTDSDSA (NTDS Settings) object; a missing object makes
        // samba-tool raise IndexError on the empty result.
        let (db, _dir, base) = seeded_db().await;
        let (addr, _tx) = start_server(db).await;
        let mut ldap = connect(addr).await;
        let alice = format!("uid=alice,ou=people,{base}");
        ldap.simple_bind(&alice, "password12")
            .await
            .unwrap()
            .success()
            .unwrap();

        let config = format!("cn=Configuration,{base}");
        let role_objects = [
            ("Schema Master", format!("cn=Schema,{config}")),
            ("Domain Naming Master", format!("cn=Partitions,{config}")),
            ("RID Master", format!("cn=RID Manager$,cn=System,{base}")),
            ("Infrastructure Master", format!("cn=Infrastructure,{base}")),
            ("PDC Emulator", base.clone()),
            (
                "DomainDnsZones Master",
                format!("cn=Infrastructure,dc=DomainDnsZones,{base}"),
            ),
            (
                "ForestDnsZones Master",
                format!("cn=Infrastructure,dc=ForestDnsZones,{base}"),
            ),
        ];
        for (role, dn) in role_objects {
            let (rs, _) = ldap
                .search(&dn, Scope::Base, "(objectClass=*)", vec!["fSMORoleOwner"])
                .await
                .unwrap()
                .success()
                .unwrap();
            let entry = SearchEntry::construct(
                rs.into_iter()
                    .next()
                    .unwrap_or_else(|| panic!("{role} object {dn} not served")),
            );
            let owner = entry
                .attrs
                .get("fSMORoleOwner")
                .and_then(|v| v.first())
                .unwrap_or_else(|| panic!("{role}: fSMORoleOwner missing on {dn}"));
            assert!(
                owner.contains("cn=ntds settings,cn=magnetite"),
                "{role} owner resolves to this DC's nTDSDSA, got {owner}"
            );
        }
    }

    #[tokio::test]
    async fn add_computer_under_computers_registers_machine_with_kdc() {
        let (db, _dir, base) = seeded_db().await;
        let recorder = Arc::new(RecordingRegistrar::default());
        let (addr, _tx) = start_server_with_registrar(db, recorder.clone()).await;
        let mut ldap = connect(addr).await;
        let alice = format!("uid=alice,ou=people,{base}");
        ldap.simple_bind(&alice, "password12")
            .await
            .unwrap()
            .success()
            .unwrap();

        // The join adds a `computer` object under CN=Computers (seeded at startup),
        // carrying the machine password as AD's `unicodePwd` (UTF-16LE, quoted).
        let computer = format!("cn=WIN11PC,cn=Computers,{base}");
        let pw = "M@chineSecret1";
        let unicode_pwd: Vec<u8> = format!("\"{pw}\"")
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let attrs: Vec<(&[u8], HashSet<&[u8]>)> = vec![
            (
                &b"objectClass"[..],
                HashSet::from([&b"top"[..], &b"computer"[..]]),
            ),
            (&b"sAMAccountName"[..], HashSet::from([&b"WIN11PC$"[..]])),
            (
                &b"dNSHostName"[..],
                HashSet::from([&b"win11pc.example.com"[..]]),
            ),
            (&b"unicodePwd"[..], HashSet::from([unicode_pwd.as_slice()])),
        ];
        let res = ldap.add(&computer, attrs).await.unwrap();
        assert_eq!(res.rc, 0, "add rc={} {}", res.rc, res.text);

        // unicodePwd is write-only: it must NOT be stored as a directory attribute.
        let (entries, _) = ldap
            .search(&computer, Scope::Base, "(objectClass=*)", vec!["*"])
            .await
            .unwrap()
            .success()
            .unwrap();
        let entry = SearchEntry::construct(entries.into_iter().next().unwrap());
        assert!(
            !entry.attrs.contains_key("unicodePwd"),
            "secret must not be stored"
        );

        // The KDC hook fired with the machine account name + its password, so the
        // machine can obtain a TGT — the LDAP write half of the join loop.
        let calls = recorder.calls.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec![("WIN11PC$".to_string(), "M@chineSecret1".to_string())],
            "registrar must be called once with the machine account + password"
        );

        // A non-computer add must NOT trigger machine registration.
        db_noop_registrar_check(&mut ldap, &base, &recorder).await;
    }

    #[tokio::test]
    async fn add_user_and_group_provision_ad_identity() {
        let (db, _dir, base) = seeded_db().await;
        let recorder = Arc::new(RecordingRegistrar::default());
        let (addr, _tx) = start_server_with_registrar(db, recorder.clone()).await;
        let mut ldap = connect(addr).await;
        let alice = format!("uid=alice,ou=people,{base}");
        ldap.simple_bind(&alice, "password12")
            .await
            .unwrap()
            .success()
            .unwrap();

        // A user added over LDAP (a bulk migration ldapadd) must provision an ad_principal
        // from its password — the same parity the Web CreateUser path gives. The password
        // is carried as AD's write-only `unicodePwd` (UTF-16LE, quoted), as a migration
        // LDIF would (a plain `userPassword` is not permitted by the AD user classes).
        let bob = format!("cn=bob,ou=people,{base}");
        let bob_pwd: Vec<u8> = "\"secret123\""
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let res = ldap
            .add(
                &bob,
                vec![
                    (
                        &b"objectClass"[..],
                        HashSet::from([&b"top"[..], &b"person"[..], &b"user"[..]]),
                    ),
                    (&b"cn"[..], HashSet::from([&b"bob"[..]])),
                    (&b"sn"[..], HashSet::from([&b"Bob"[..]])),
                    (&b"sAMAccountName"[..], HashSet::from([&b"bob"[..]])),
                    (&b"unicodePwd"[..], HashSet::from([bob_pwd.as_slice()])),
                ],
            )
            .await
            .unwrap();
        assert_eq!(res.rc, 0, "user add rc={} {}", res.rc, res.text);
        assert!(
            recorder
                .users
                .lock()
                .unwrap()
                .iter()
                .any(|(s, p, _)| s == "bob" && p == "secret123"),
            "an LDAP user add must provision the ad_principal from its password"
        );
        // ...and it must NOT be treated as a machine account.
        assert!(
            recorder.calls.lock().unwrap().is_empty(),
            "a user add must not register a machine account"
        );

        // A group added over LDAP must provision an ad_group and link its members by sam.
        let eng = format!("cn=Eng,ou=people,{base}");
        let res = ldap
            .add(
                &eng,
                vec![
                    ("objectClass", HashSet::from(["top", "group"])),
                    ("cn", HashSet::from(["Eng"])),
                    ("member", HashSet::from([bob.as_str()])),
                ],
            )
            .await
            .unwrap();
        assert_eq!(res.rc, 0, "group add rc={} {}", res.rc, res.text);
        let groups = recorder.groups.lock().unwrap().clone();
        assert!(
            groups
                .iter()
                .any(|(s, m, _)| s == "Eng" && m.iter().any(|x| x == "bob")),
            "an LDAP group add must provision the ad_group with its member sams, got {groups:?}"
        );
    }

    /// Adding a non-`computer` object must not invoke the machine registrar.
    async fn db_noop_registrar_check(
        ldap: &mut ldap3::Ldap,
        base: &str,
        recorder: &Arc<RecordingRegistrar>,
    ) {
        let before = recorder.calls.lock().unwrap().len();
        let ou = format!("ou=eng,{base}");
        let res = ldap
            .add(
                &ou,
                vec![("objectClass", HashSet::from(["top", "organizationalUnit"]))],
            )
            .await
            .unwrap();
        assert_eq!(res.rc, 0, "ou add rc={} {}", res.rc, res.text);
        assert_eq!(
            recorder.calls.lock().unwrap().len(),
            before,
            "a non-computer add must not register a machine account"
        );
    }

    #[tokio::test]
    async fn add_enforces_schema() {
        let (db, _dir, base) = seeded_db().await;
        let (addr, _tx) = start_server(db).await;
        let mut ldap = connect(addr).await;
        let alice = format!("uid=alice,ou=people,{base}");
        ldap.simple_bind(&alice, "password12")
            .await
            .unwrap()
            .success()
            .unwrap();

        // Unknown objectClass → objectClassViolation (65).
        let r = ldap
            .add(
                &format!("cn=x,{base}"),
                vec![("objectClass", HashSet::from(["widget"]))],
            )
            .await
            .unwrap();
        assert_eq!(r.rc, 65, "unknown class: {}", r.text);

        // Missing a MUST attribute — person needs `cn` but the RDN is `sn` → 65.
        let r = ldap
            .add(
                &format!("sn=Smith,{base}"),
                vec![("objectClass", HashSet::from(["top", "person"]))],
            )
            .await
            .unwrap();
        assert_eq!(r.rc, 65, "missing MUST cn: {}", r.text);

        // Undefined attribute type → undefinedAttributeType (17).
        let r = ldap
            .add(
                &format!("cn=y,{base}"),
                vec![
                    ("objectClass", HashSet::from(["top", "computer"])),
                    ("frobnicate", HashSet::from(["z"])),
                ],
            )
            .await
            .unwrap();
        assert_eq!(r.rc, 17, "undefined attr: {}", r.text);

        // A defined attribute not permitted by the object classes → 65.
        let r = ldap
            .add(
                &format!("cn=z,{base}"),
                vec![
                    ("objectClass", HashSet::from(["top", "container"])),
                    ("dNSHostName", HashSet::from(["h"])),
                ],
            )
            .await
            .unwrap();
        assert_eq!(r.rc, 65, "attr not permitted: {}", r.text);

        // Two structural classes → 65.
        let r = ldap
            .add(
                &format!("cn=m,{base}"),
                vec![("objectClass", HashSet::from(["top", "user", "group"]))],
            )
            .await
            .unwrap();
        assert_eq!(r.rc, 65, "multiple structural: {}", r.text);

        // A schema-valid computer add still succeeds.
        let r = ldap
            .add(
                &format!("cn=ok,{base}"),
                vec![
                    ("objectClass", HashSet::from(["top", "computer"])),
                    ("sAMAccountName", HashSet::from(["OK$"])),
                ],
            )
            .await
            .unwrap();
        assert_eq!(r.rc, 0, "valid add: {}", r.text);
    }

    #[tokio::test]
    async fn modify_rejects_undefined_attribute() {
        let (db, _dir, base) = seeded_db().await;
        let (addr, _tx) = start_server(db).await;
        let mut ldap = connect(addr).await;
        let alice = format!("uid=alice,ou=people,{base}");
        ldap.simple_bind(&alice, "password12")
            .await
            .unwrap()
            .success()
            .unwrap();

        let r = ldap
            .modify(
                &alice,
                vec![Mod::Replace(
                    "frobnicate".to_string(),
                    HashSet::from(["x".to_string()]),
                )],
            )
            .await
            .unwrap();
        assert_eq!(r.rc, 17, "modify undefined attr: {}", r.text);
    }

    #[tokio::test]
    async fn subtree_search_finds_user() {
        let (db, _dir, base) = seeded_db().await;
        let (addr, _tx) = start_server(db).await;
        let mut ldap = connect(addr).await;

        // Anonymous bind, then subtree search.
        ldap.simple_bind("", "").await.unwrap().success().unwrap();
        let (rs, _res) = ldap
            .search(&base, Scope::Subtree, "(uid=alice)", vec!["*"])
            .await
            .unwrap()
            .success()
            .unwrap();
        let entries: Vec<SearchEntry> = rs.into_iter().map(SearchEntry::construct).collect();
        assert_eq!(entries.len(), 1);
        assert!(
            entries[0].dn.to_lowercase().contains("uid=alice"),
            "dn: {}",
            entries[0].dn
        );
        // objectClass is projected; userPassword never is.
        assert!(entries[0].attrs.contains_key("objectClass"));
        assert!(!entries[0]
            .attrs
            .keys()
            .any(|k| k.eq_ignore_ascii_case("userpassword")));
        let _ = ldap.unbind().await;
    }

    #[tokio::test]
    async fn onelevel_scope_excludes_grandchildren() {
        let (db, _dir, base) = seeded_db().await;
        let (addr, _tx) = start_server(db).await;
        let mut ldap = connect(addr).await;
        ldap.simple_bind("", "").await.unwrap().success().unwrap();

        // One-level under the base sees `ou=people` but not the user beneath it.
        let (rs, _res) = ldap
            .search(&base, Scope::OneLevel, "(objectClass=*)", vec!["*"])
            .await
            .unwrap()
            .success()
            .unwrap();
        let dns: Vec<String> = rs
            .into_iter()
            .map(|e| SearchEntry::construct(e).dn.to_lowercase())
            .collect();
        assert!(
            dns.iter().any(|d| d.starts_with("ou=people")),
            "dns: {dns:?}"
        );
        assert!(!dns.iter().any(|d| d.contains("uid=alice")), "dns: {dns:?}");
    }

    #[tokio::test]
    async fn rootdse_reports_naming_context() {
        let (db, _dir, base) = seeded_db().await;
        let (addr, _tx) = start_server(db).await;
        let mut ldap = connect(addr).await;

        let (rs, _res) = ldap
            .search("", Scope::Base, "(objectClass=*)", vec!["*"])
            .await
            .unwrap()
            .success()
            .unwrap();
        assert_eq!(rs.len(), 1);
        let dse = SearchEntry::construct(rs.into_iter().next().unwrap());
        let ctx = dse.attrs.get("namingContexts").expect("namingContexts");
        assert_eq!(ctx[0], base);
    }

    #[tokio::test]
    async fn rootdse_exposes_current_time() {
        // A domain-join client (Samba `ads_connect`) reads currentTime from the
        // RootDSE and fails the connect without it. It is an AD Generalized-Time.
        let (db, _dir, _base) = seeded_db().await;
        let (addr, _tx) = start_server(db).await;
        let mut ldap = connect(addr).await;
        let (rs, _res) = ldap
            .search("", Scope::Base, "(objectClass=*)", vec!["currentTime"])
            .await
            .unwrap()
            .success()
            .unwrap();
        let dse = SearchEntry::construct(rs.into_iter().next().unwrap());
        let t = dse.attrs.get("currentTime").expect("currentTime present");
        assert_eq!(t.len(), 1);
        // Generalized time: 14 digits + ".0Z" (e.g. 20260809....0Z).
        assert!(
            t[0].ends_with("Z") && t[0].len() >= 15,
            "generalized time: {}",
            t[0]
        );
    }

    #[tokio::test]
    async fn rootdse_and_subschema_expose_ad_schema() {
        let (db, _dir, _base) = seeded_db().await;
        let (addr, _tx) = start_server(db).await;
        let mut ldap = connect(addr).await;

        // RootDSE advertises the AD naming contexts, the subschema pointer, and
        // the Active Directory capability — a client detects an AD-like DC.
        let (rs, _res) = ldap
            .search("", Scope::Base, "(objectClass=*)", vec!["*"])
            .await
            .unwrap()
            .success()
            .unwrap();
        let dse = SearchEntry::construct(rs.into_iter().next().unwrap());
        assert!(dse.attrs.contains_key("schemaNamingContext"));
        assert!(dse.attrs.contains_key("configurationNamingContext"));
        let caps = dse
            .attrs
            .get("supportedCapabilities")
            .expect("supportedCapabilities");
        assert!(
            caps.iter().any(|c| c == "1.2.840.113556.1.4.800"),
            "LDAP_CAP_ACTIVE_DIRECTORY_OID missing: {caps:?}"
        );
        let subschema = dse
            .attrs
            .get("subschemaSubentry")
            .expect("subschemaSubentry")[0]
            .clone();

        // Follow the pointer and read the schema: the client discovers our classes
        // and attributes (this is what ldap3's `get_info=ALL` does under the hood).
        let (rs, _res) = ldap
            .search(
                &subschema,
                Scope::Base,
                "(objectClass=*)",
                vec!["attributeTypes", "objectClasses"],
            )
            .await
            .unwrap()
            .success()
            .unwrap();
        let schema = SearchEntry::construct(rs.into_iter().next().unwrap());
        let classes = schema.attrs.get("objectClasses").expect("objectClasses");
        let attrs = schema.attrs.get("attributeTypes").expect("attributeTypes");
        assert!(
            classes
                .iter()
                .any(|c| c.contains("NAME 'user'") && c.contains("SUP organizationalPerson")),
            "user class missing"
        );
        assert!(classes
            .iter()
            .any(|c| c.contains("NAME 'computer'") && c.contains("SUP user")));
        assert!(attrs.iter().any(|a| a.contains("NAME 'sAMAccountName'")));
        assert!(attrs.iter().any(|a| a.contains("NAME 'objectGUID'")));
    }

    #[tokio::test]
    async fn search_synthesizes_ad_operational_attributes() {
        let (db, _dir, base) = seeded_db().await;
        let (addr, _tx) = start_server(db).await;
        let mut ldap = connect(addr).await;

        let dn = format!("uid=alice,ou=people,{base}");
        let (rs, _res) = ldap
            .search(&dn, Scope::Base, "(objectClass=*)", vec!["*"])
            .await
            .unwrap()
            .success()
            .unwrap();
        let e = SearchEntry::construct(rs.into_iter().next().unwrap());

        // distinguishedName echoes the DN; name is the RDN value.
        assert_eq!(
            e.attrs.get("distinguishedName").expect("distinguishedName")[0],
            dn
        );
        assert_eq!(e.attrs.get("name").expect("name")[0], "alice");
        // objectCategory points at the classSchema object (AD uses CN=Person for user-like).
        let cat = &e.attrs.get("objectCategory").expect("objectCategory")[0];
        assert!(
            cat.starts_with("CN=Person,CN=Schema,CN=Configuration,"),
            "cat: {cat}"
        );
        // whenCreated / whenChanged are GeneralizedTime (YYYYMMDDHHMMSS.0Z).
        let wc = &e.attrs.get("whenCreated").expect("whenCreated")[0];
        assert!(wc.ends_with(".0Z") && wc.len() == 17, "whenCreated: {wc}");
        // objectGUID is a 16-byte binary value (ldap3 puts non-UTF-8 into bin_attrs).
        let guid = e
            .bin_attrs
            .get("objectGUID")
            .map(|v| v[0].clone())
            .or_else(|| e.attrs.get("objectGUID").map(|v| v[0].clone().into_bytes()))
            .expect("objectGUID");
        assert_eq!(guid.len(), 16);
    }

    #[tokio::test]
    async fn acl_denies_anonymous_search() {
        use magnetite_core::domains::ldap::model::{
            LdapAclEffect, LdapAclOperation, LdapAclRule, LdapAclSubject,
        };
        let (db, _dir, base) = seeded_db().await;
        db.create_ldap_acl(&LdapAclRule {
            id: String::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            created_by: "admin".into(),
            priority: 10,
            target_dn: "*".into(),
            operations: vec![LdapAclOperation::Search],
            subject: LdapAclSubject::Anonymous,
            effect: LdapAclEffect::Deny,
            enabled: true,
        })
        .await
        .unwrap();
        let (addr, _tx) = start_server(db).await;
        let mut ldap = connect(addr).await;
        ldap.simple_bind("", "").await.unwrap().success().unwrap(); // anonymous

        let result = ldap
            .search(&base, Scope::Subtree, "(uid=alice)", vec!["*"])
            .await
            .unwrap();
        // insufficientAccessRights (50) — the search is refused by ACL.
        assert_ne!(result.1.rc, 0, "anonymous search must be ACL-denied");
    }

    /// A rustls client that accepts any certificate (test only).
    fn danger_connector() -> tokio_rustls::TlsConnector {
        use std::sync::Arc;
        #[derive(Debug)]
        struct NoVerify(Arc<rustls::crypto::CryptoProvider>);
        impl rustls::client::danger::ServerCertVerifier for NoVerify {
            fn verify_server_cert(
                &self,
                _: &rustls::pki_types::CertificateDer<'_>,
                _: &[rustls::pki_types::CertificateDer<'_>],
                _: &rustls::pki_types::ServerName<'_>,
                _: &[u8],
                _: rustls::pki_types::UnixTime,
            ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                m: &[u8],
                c: &rustls::pki_types::CertificateDer<'_>,
                d: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                rustls::crypto::verify_tls12_signature(
                    m,
                    c,
                    d,
                    &self.0.signature_verification_algorithms,
                )
            }
            fn verify_tls13_signature(
                &self,
                m: &[u8],
                c: &rustls::pki_types::CertificateDer<'_>,
                d: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                rustls::crypto::verify_tls13_signature(
                    m,
                    c,
                    d,
                    &self.0.signature_verification_algorithms,
                )
            }
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                self.0.signature_verification_algorithms.supported_schemes()
            }
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth();
        tokio_rustls::TlsConnector::from(Arc::new(config))
    }

    #[tokio::test]
    async fn starttls_upgrades_then_binds() {
        use ldap3_proto::proto::{LdapBindRequest, LdapExtendedRequest};

        let (db, _dir, base) = seeded_db().await;
        let cert = rcgen::generate_simple_self_signed(vec!["ldap.test".to_string()]).unwrap();
        db.create_certificate(
            "ldapcert",
            "CN=ldap.test",
            "self",
            &["ldap.test".to_string()],
            chrono::Utc::now(),
            chrono::Utc::now() + chrono::Duration::days(90),
            &cert.cert.pem(),
            None,
            Some(&cert.key_pair.serialize_pem()),
            "admin",
        )
        .await
        .unwrap();

        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        let svc = LdapService::new(
            addr,
            true,
            Some("ldapcert".into()),
            "dc=example,dc=com".into(),
        );
        let (_tx, rx) = watch::channel(false);
        svc.start(db, rx);
        for _ in 0..50 {
            if svc.health() == ServiceHealth::Healthy {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        let tcp = {
            let mut s = None;
            for _ in 0..50 {
                if let Ok(c) = TcpStream::connect(addr).await {
                    s = Some(c);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            s.expect("LDAP not listening")
        };
        let mut client = Framed::new(tcp, ldap3_proto::LdapCodec::default());

        // StartTLS extended request → success.
        client
            .send(LdapMsg {
                msgid: 1,
                op: LdapOp::ExtendedRequest(LdapExtendedRequest {
                    name: STARTTLS_OID.to_string(),
                    value: None,
                }),
                ctrl: vec![],
            })
            .await
            .unwrap();
        match client.next().await.unwrap().unwrap().op {
            LdapOp::ExtendedResponse(r) => assert_eq!(r.res.code, LdapResultCode::Success),
            other => panic!("expected StartTLS success, got {other:?}"),
        }

        // Upgrade the raw stream to TLS, then bind over it.
        let tcp = client.into_inner();
        let server_name = rustls::pki_types::ServerName::try_from("ldap.test").unwrap();
        let tls = danger_connector().connect(server_name, tcp).await.unwrap();
        let mut tclient = Framed::new(tls, ldap3_proto::LdapCodec::default());

        let dn = format!("uid=alice,ou=people,{base}");
        tclient
            .send(LdapMsg {
                msgid: 2,
                op: LdapOp::BindRequest(LdapBindRequest {
                    dn,
                    cred: LdapBindCred::Simple("password12".into()),
                }),
                ctrl: vec![],
            })
            .await
            .unwrap();
        match tclient.next().await.unwrap().unwrap().op {
            LdapOp::BindResponse(r) => {
                assert_eq!(r.res.code, LdapResultCode::Success, "bind over TLS")
            }
            other => panic!("expected bind response, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn syncrepl_provider_full_then_incremental() {
        use ldap3_proto::proto::{LdapDerefAliases, LdapFilter, LdapSearchRequest};

        let (db, _dir, base) = seeded_db().await;

        let make_req = |base: &str| LdapSearchRequest {
            base: base.to_string(),
            scope: LdapSearchScope::Subtree,
            aliases: LdapDerefAliases::Never,
            sizelimit: 0,
            timelimit: 0,
            typesonly: false,
            filter: LdapFilter::Present("objectClass".into()),
            attrs: vec!["*".into()],
        };

        // Cookie helper: pull the SyncDone cookie off the final message.
        let done_cookie = |msgs: &[LdapMsg]| -> Vec<u8> {
            match msgs.last().map(|m| &m.op) {
                Some(LdapOp::SearchResultDone(_)) => {}
                other => panic!("last message should be SearchResultDone, got {other:?}"),
            }
            match msgs.last().and_then(|m| m.ctrl.first()) {
                Some(LdapControl::SyncDone {
                    cookie: Some(c), ..
                }) => c.clone(),
                other => panic!("expected SyncDone cookie, got {other:?}"),
            }
        };

        // Initial full refresh (no cookie): every present entry tagged Add.
        let full = handle_syncrepl_search(
            1,
            &make_req(&base),
            &db,
            false,
            None,
            SyncRequestMode::RefreshOnly,
            None,
        )
        .await;
        let entries = &full[..full.len() - 1];
        assert!(
            entries.len() >= 3,
            "root + ou + user expected, got {}",
            entries.len()
        );
        for m in entries {
            assert!(matches!(&m.op, LdapOp::SearchResultEntry(_)));
            assert!(
                m.ctrl.iter().any(|c| matches!(
                    c,
                    LdapControl::SyncState {
                        state: SyncStateValue::Add,
                        ..
                    }
                )),
                "present entry must carry SyncState(Add)"
            );
        }
        let cookie = done_cookie(&full);
        assert!(!cookie.is_empty(), "full refresh must yield a cookie");

        // Mutate: add bob, delete alice.
        let people = format!("ou=people,{base}");
        db.create_user(&people, "bob", "Bob B", "B", Some("bob@x.test"), "admin")
            .await
            .unwrap();
        db.delete_entry(&format!("uid=alice,{people}"))
            .await
            .unwrap();

        // Incremental refresh with the prior cookie.
        let inc = handle_syncrepl_search(
            2,
            &make_req(&base),
            &db,
            false,
            None,
            SyncRequestMode::RefreshOnly,
            Some(&cookie),
        )
        .await;
        let mut saw_bob_present = false;
        let mut saw_alice_delete = false;
        for m in &inc[..inc.len() - 1] {
            let LdapOp::SearchResultEntry(e) = &m.op else {
                continue;
            };
            let dn = e.dn.to_lowercase();
            for c in &m.ctrl {
                if let LdapControl::SyncState { state, .. } = c {
                    if dn.contains("uid=bob") && *state == SyncStateValue::Add {
                        saw_bob_present = true;
                    }
                    if dn.contains("uid=alice") && *state == SyncStateValue::Delete {
                        saw_alice_delete = true;
                    }
                }
            }
        }
        assert!(
            saw_bob_present,
            "incremental should surface the new entry bob"
        );
        assert!(
            saw_alice_delete,
            "incremental should report alice as deleted"
        );

        // The advertised context CSN must not regress.
        let cookie2 = done_cookie(&inc);
        assert!(cookie2 >= cookie, "context CSN regressed across syncs");
    }

    #[tokio::test]
    async fn consumer_applies_upserts_deletes_and_tracks_state() {
        use std::collections::BTreeMap;

        let (db, _dir, base) = seeded_db().await;
        let dn = format!("uid=bob,{base}");
        let mut attrs = BTreeMap::new();
        attrs.insert("cn".to_string(), vec!["Bob".to_string()]);

        // First apply inserts the entry (returns true = newly created).
        assert!(db
            .apply_ldap_sync_entry(
                &dn,
                "uuid-bob",
                vec!["top".into(), "inetOrgPerson".into()],
                &attrs,
                true,
            )
            .await
            .unwrap());
        // Re-apply updates in place (returns false = not newly created).
        assert!(!db
            .apply_ldap_sync_entry(
                &dn,
                "uuid-bob",
                vec!["top".into(), "inetOrgPerson".into()],
                &attrs,
                true,
            )
            .await
            .unwrap());

        // Delete by upstream entryUUID.
        assert!(db.apply_ldap_sync_delete("uuid-bob").await.unwrap());
        assert!(!db.apply_ldap_sync_delete("uuid-bob").await.unwrap());

        // Sync state accumulates across passes.
        db.record_ldap_sync("cookie-1", 1, 0, None).await.unwrap();
        db.record_ldap_sync("cookie-2", 0, 1, Some("transient"))
            .await
            .unwrap();
        let st = db.get_ldap_sync_state().await.unwrap();
        assert_eq!(st.cookie, "cookie-2");
        assert_eq!(st.applied, 1);
        assert_eq!(st.deleted, 1);
        assert_eq!(st.last_error.as_deref(), Some("transient"));
        assert!(st.last_sync.is_some());
    }
}
