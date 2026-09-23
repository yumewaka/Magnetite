//! The embedded HTTP reverse proxy (E3). Binds a listen port, matches requests
//! by `Host` to a virtual host, enforces the IP blocklist and ACL rules, and
//! forwards to the vhost's upstream. Registered as an [`EmbeddedService`] so
//! `magnetite-server` runs it in-process (09b §-1).
//!
//! Scope: HTTP/1.1 + HTTP/2 (ALPN) + HTTPS (TLS termination, per-vhost cert by SNI)
//! reverse proxy over the magnetite proxy model (VirtualHost/Upstream/AclRule/
//! IpBlock/Certificate), forwarding to `http://` or `https://` upstreams, with
//! WebSocket / HTTP-Upgrade passthrough, and streaming request/response bodies with
//! an optional size cap. Raw L4/TCP stream forwarding (SNI-preread) runs alongside.

use crate::router::{
    acl_decision, is_blocked, match_tcp_vhost, match_vhost, parse_sni, select_upstream,
};
use bytes::Bytes;
use chrono::Utc;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{HOST, LOCATION};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Uri};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use magnetite_core::domain::DomainKey;
use magnetite_core::domains::proxy::model::{
    AclAction, AclRule, IpBlock, Upstream, UpstreamScheme, VirtualHost,
};
use magnetite_core::models::common::{LogKind, LogLevel};
use magnetite_db::{Db, EmbeddedService, NewLogEntry, ServiceHealth};
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

const H_STARTING: u8 = 0;
const H_HEALTHY: u8 = 1;
const H_ERROR: u8 = 2;

/// The response body returned to the client — a boxed stream, so the upstream's body is
/// relayed incrementally (not buffered) and status/redirect bodies share one type.
type ResBody = BoxBody<Bytes, hyper::Error>;
/// The request body forwarded to the upstream — the client's body streamed (optionally
/// size-capped), boxed.
type ReqBody = BoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;
type ProxyClient = Client<HttpsConnector<HttpConnector>, ReqBody>;

/// Box a fully-materialised byte body (status/redirect responses) as a [`ResBody`].
fn full_body(bytes: Bytes) -> ResBody {
    Full::new(bytes)
        .map_err(|e: std::convert::Infallible| match e {})
        .boxed()
}

/// A rustls verifier that accepts any upstream certificate. Reverse-proxy upstreams are
/// internal backends, commonly with a self-signed / private-CA cert; TLS to them is for
/// confidentiality, not peer identity (the same posture as the mail/LDAP/repl internal-TLS
/// paths). Public exposure is the front (client→proxy) TLS, which IS properly configured.
#[derive(Debug)]
struct NoUpstreamCertVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoUpstreamCertVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// The upstream HTTP client — an HTTPS-or-HTTP connector so a vhost can forward to either a
/// plaintext (`http://`) or a TLS (`https://`) backend, per each upstream's scheme.
fn upstream_client() -> ProxyClient {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("rustls default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoUpstreamCertVerify(provider)))
        .with_no_client_auth();
    let connector = HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(connector)
}

/// Embedded HTTP reverse proxy bound to `addr` (plus an optional HTTPS/TLS
/// listener on `tls_addr` and an optional forward-proxy listener on `forward_addr`).
pub struct ProxyService {
    addr: SocketAddr,
    tls_addr: Option<SocketAddr>,
    forward_addr: Option<SocketAddr>,
    /// Raw L4/TCP stream listeners (e.g. RDP :3389, PostgreSQL :5432). Each binds a port
    /// and forwards to a `Tcp`-mode vhost, routed by TLS SNI (ssl_preread) or the port.
    tcp_addrs: Vec<SocketAddr>,
    /// Maximum request body size in bytes (`None` = unlimited). An over-limit declared
    /// Content-Length is rejected with 413; larger chunked bodies are capped mid-stream.
    max_body_bytes: Option<u64>,
    /// Automatic-TLS (ACME) seed from the file config. The effective settings are DB-backed
    /// and hot-reloadable (edited from the Web UI); this seeds them on first run. The ACME
    /// manager always runs (answering HTTP-01 on `addr`) and idles when ACME is unconfigured.
    acme_seed: Option<magnetite_core::config::AcmeConfig>,
    log_access: bool,
    health: Arc<AtomicU8>,
}

impl ProxyService {
    /// `tls_addr` ⇒ also terminate TLS there (per-vhost certs by SNI).
    /// `forward_addr` ⇒ also run an HTTP forward proxy there (absolute-URI + CONNECT).
    /// `tcp_addrs` ⇒ also run raw L4/TCP stream listeners on these ports.
    /// `max_body_bytes` ⇒ reject request bodies larger than this (413).
    /// `log_access` ⇒ write an access LogEntry per proxied request.
    pub fn new(
        addr: SocketAddr,
        tls_addr: Option<SocketAddr>,
        forward_addr: Option<SocketAddr>,
        tcp_addrs: Vec<SocketAddr>,
        max_body_bytes: Option<u64>,
        log_access: bool,
    ) -> Self {
        Self {
            addr,
            tls_addr,
            forward_addr,
            tcp_addrs,
            max_body_bytes,
            acme_seed: None,
            log_access,
            health: Arc::new(AtomicU8::new(H_STARTING)),
        }
    }

    /// Provide the file-config ACME settings as the seed for the DB-backed settings (used
    /// only on first run — an operator edit via the Web UI wins thereafter). The ACME
    /// manager runs regardless and picks up runtime changes; passing `None` just means no
    /// seed (ACME can still be enabled later from the Web UI).
    pub fn with_acme(mut self, acme: Option<magnetite_core::config::AcmeConfig>) -> Self {
        self.acme_seed = acme;
        self
    }
}

/// How often the cached proxy config (vhosts / IP blocks / ACL rules) is re-read from
/// the DB. The request path reads the cache instead of hitting the DB per request;
/// Web-UI edits (incl. an IP block) take effect within this window.
const CONFIG_REFRESH: Duration = Duration::from_secs(3);

/// How long to wait for an upstream to send its WebSocket-upgrade response head before
/// giving up (a slow/hung backend must not pin the proxy connection open forever).
const WS_UPSTREAM_HEAD_TIMEOUT: Duration = Duration::from_secs(30);

/// A cached snapshot of the routing/access config, refreshed from the DB by a
/// background task so the hot path does not run three DB queries per request.
#[derive(Default)]
struct ProxyCfgSnapshot {
    vhosts: Vec<VirtualHost>,
    blocks: Vec<IpBlock>,
    acls: Vec<AclRule>,
}

/// The live config cache: a background task swaps in a fresh `Arc` snapshot; readers
/// clone the `Arc` under a brief read lock (never held across an await).
type ConfigCache = Arc<RwLock<Arc<ProxyCfgSnapshot>>>;

/// Shared per-request context.
#[derive(Clone)]
struct Ctx {
    db: Db,
    client: ProxyClient,
    log_access: bool,
    max_body_bytes: Option<u64>,
    counter: Arc<AtomicUsize>,
    /// In-flight request counts per upstream ("host:port"), for least-conn.
    inflight: Arc<Mutex<HashMap<String, usize>>>,
    /// Pending ACME HTTP-01 challenge responses (token → key authorization), served on
    /// the plain HTTP listener. Empty when ACME is disabled.
    acme_challenges: crate::acme::ChallengeStore,
    /// Cached vhosts / IP blocks / ACL rules, refreshed from the DB every
    /// [`CONFIG_REFRESH`] instead of loaded per request.
    config: ConfigCache,
    /// Set once the cache has been populated at least once, so the request path can
    /// fall back to a direct DB load during the brief startup window before then.
    config_ready: Arc<AtomicBool>,
}

impl Ctx {
    /// A cheap clone of the current config snapshot (clones an `Arc`, not the data).
    fn config(&self) -> Arc<ProxyCfgSnapshot> {
        self.config
            .read()
            .ok()
            .map(|g| Arc::clone(&g))
            .unwrap_or_default()
    }

    /// The config snapshot to route with: the cache once warm, else a one-shot direct DB
    /// load (only during the startup window before the refresh task's first pass).
    async fn warm_config(&self) -> Arc<ProxyCfgSnapshot> {
        if self.config_ready.load(Ordering::Relaxed) {
            return self.config();
        }
        match (
            self.db.list_vhosts().await,
            self.db.list_ip_blocks().await,
            self.db.list_acl_rules().await,
        ) {
            (Ok(vhosts), Ok(blocks), Ok(acls)) => Arc::new(ProxyCfgSnapshot {
                vhosts,
                blocks,
                acls,
            }),
            _ => self.config(),
        }
    }
}

/// Seed and then periodically refresh the config cache from the DB until shutdown. On a
/// load error the previous snapshot is kept (the proxy keeps serving the last-known config).
async fn refresh_proxy_config(
    db: Db,
    cache: ConfigCache,
    ready: Arc<AtomicBool>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        if let (Ok(vhosts), Ok(blocks), Ok(acls)) = (
            db.list_vhosts().await,
            db.list_ip_blocks().await,
            db.list_acl_rules().await,
        ) {
            if let Ok(mut guard) = cache.write() {
                *guard = Arc::new(ProxyCfgSnapshot {
                    vhosts,
                    blocks,
                    acls,
                });
            }
            ready.store(true, Ordering::Relaxed);
        }
        tokio::select! {
            _ = tokio::time::sleep(CONFIG_REFRESH) => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
        }
    }
}

fn upstream_key(u: &Upstream) -> String {
    format!("{}:{}", u.host, u.port)
}

/// Increments an upstream's in-flight count on creation and decrements on drop.
struct InflightGuard {
    inflight: Arc<Mutex<HashMap<String, usize>>>,
    key: String,
}

impl InflightGuard {
    fn acquire(inflight: &Arc<Mutex<HashMap<String, usize>>>, key: String) -> Self {
        if let Ok(mut map) = inflight.lock() {
            *map.entry(key.clone()).or_insert(0) += 1;
        }
        Self {
            inflight: inflight.clone(),
            key,
        }
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        if let Ok(mut map) = self.inflight.lock() {
            if let Some(c) = map.get_mut(&self.key) {
                *c = c.saturating_sub(1);
            }
        }
    }
}

impl EmbeddedService for ProxyService {
    fn domain(&self) -> DomainKey {
        DomainKey::Proxy
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
        let acme_challenges: crate::acme::ChallengeStore = Arc::new(Mutex::new(HashMap::new()));
        // Config cache: a background task keeps vhosts/blocks/acls fresh so the request
        // path reads memory instead of running three DB queries per request.
        let config: ConfigCache = Arc::new(RwLock::new(Arc::new(ProxyCfgSnapshot::default())));
        let config_ready = Arc::new(AtomicBool::new(false));
        tokio::spawn(refresh_proxy_config(
            db.clone(),
            config.clone(),
            config_ready.clone(),
            shutdown.clone(),
        ));
        let ctx = Ctx {
            db,
            client: upstream_client(),
            log_access: self.log_access,
            max_body_bytes: self.max_body_bytes,
            counter: Arc::new(AtomicUsize::new(0)),
            inflight: Arc::new(Mutex::new(HashMap::new())),
            acme_challenges: acme_challenges.clone(),
            config,
            config_ready,
        };

        // Automatic TLS (ACME): a background task obtains/renews the certificate. It always
        // runs — settings are DB-backed (seeded from the file config, editable via the Web
        // UI) and hot-reloaded — so ACME can be enabled/changed at runtime without a restart.
        // The challenge token is served by the HTTP handler below via `acme_challenges`.
        {
            let acme_db = ctx.db.clone();
            let acme_seed = self.acme_seed.clone();
            let acme_shutdown = shutdown.clone();
            tokio::spawn(async move {
                crate::acme::run_acme_manager(acme_db, acme_seed, acme_challenges, acme_shutdown)
                    .await;
            });
        }

        // Optional HTTPS/TLS listener (T2): terminates TLS, then reuses the
        // same handler. Certs are loaded once at startup.
        if let Some(tls_addr) = self.tls_addr {
            let tls_ctx = ctx.clone();
            let tls_shutdown = shutdown.clone();
            tokio::spawn(async move {
                if let Err(e) = run_tls(tls_addr, tls_ctx, tls_shutdown).await {
                    tracing::error!("proxy TLS server on {tls_addr} failed: {e}");
                }
            });
        }

        // Optional HTTP forward-proxy listener (absolute-URI + CONNECT), gated by
        // the forward source/destination rules and client credentials.
        if let Some(forward_addr) = self.forward_addr {
            let fwd_ctx =
                crate::forward::ForwardCtx::new(ctx.db.clone(), ctx.log_access, ctx.max_body_bytes);
            let fwd_shutdown = shutdown.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    crate::forward::run_forward(forward_addr, fwd_ctx, fwd_shutdown).await
                {
                    tracing::error!("proxy forward server on {forward_addr} failed: {e}");
                }
            });
        }

        // Raw L4/TCP stream listeners (RDP/PostgreSQL/…): one accept loop per port.
        for tcp_addr in &self.tcp_addrs {
            let tcp_addr = *tcp_addr;
            let tcp_ctx = ctx.clone();
            let tcp_shutdown = shutdown.clone();
            tokio::spawn(async move {
                if let Err(e) = run_tcp(tcp_addr, tcp_ctx, tcp_shutdown).await {
                    tracing::error!("proxy TCP stream on {tcp_addr} failed: {e}");
                }
            });
        }

        magnetite_db::spawn_health_guarded("proxy", health.clone(), H_ERROR, async move {
            if let Err(e) = run(addr, ctx, shutdown, health.clone()).await {
                tracing::error!("proxy server on {addr} failed: {e}");
                health.store(H_ERROR, Ordering::Relaxed);
            }
        });
    }
}

/// Serve an ACME HTTP-01 challenge when `path` is a challenge URL: 200 with the token's
/// key authorization if pending, else 404. Returns `None` for any other path so normal
/// routing proceeds. Kept separate from [`handle`] to be directly testable.
fn acme_challenge_response(
    challenges: &crate::acme::ChallengeStore,
    path: &str,
) -> Option<Response<ResBody>> {
    let token = path.strip_prefix("/.well-known/acme-challenge/")?;
    let response = match challenges.lock().ok().and_then(|m| m.get(token).cloned()) {
        Some(key_auth) => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/octet-stream")
            .body(full_body(Bytes::from(key_auth)))
            .unwrap_or_else(|_| {
                status_response(StatusCode::INTERNAL_SERVER_ERROR, "acme challenge")
            }),
        None => status_response(StatusCode::NOT_FOUND, "unknown acme challenge"),
    };
    Some(response)
}

fn status_response(code: StatusCode, message: &str) -> Response<ResBody> {
    Response::builder()
        .status(code)
        .header("content-type", "text/plain; charset=utf-8")
        .body(full_body(Bytes::from(message.to_string())))
        .unwrap_or_else(|_| Response::new(full_body(Bytes::from_static(b"error"))))
}

/// Handle one request: route, enforce access control, forward to the upstream.
/// `secure` is true when the request arrived over TLS (suppresses the
/// force_https redirect to avoid a loop).
async fn handle(
    req: Request<Incoming>,
    peer: IpAddr,
    ctx: &Ctx,
    secure: bool,
) -> Response<ResBody> {
    // ACME HTTP-01 challenge (FR-9): answer the CA's validation request with the pending
    // key authorization for this token. Served before any routing or force_https redirect,
    // on the plain HTTP listener, so certificate issuance/renewal succeeds.
    if let Some(resp) = acme_challenge_response(&ctx.acme_challenges, req.uri().path()) {
        return resp;
    }

    // Resolve the request host for vhost routing. HTTP/1.1 carries it in the `Host`
    // header, but HTTP/2 (offered via ALPN `h2`) sends it in the `:authority` pseudo-header
    // and omits `Host` — so fall back to the URI authority, else every vhost 404s under h2.
    let host = req
        .headers()
        .get(HOST)
        .and_then(|h| h.to_str().ok())
        .map(str::to_string)
        .or_else(|| req.uri().authority().map(|a| a.to_string()))
        .unwrap_or_default();

    // Read the current proxy config from the in-memory cache (refreshed from the DB by
    // a background task) instead of running three DB queries on every request.
    let cfg = ctx.warm_config().await;

    if is_blocked(&cfg.blocks, peer, Utc::now()) {
        return status_response(StatusCode::FORBIDDEN, "blocked");
    }

    let host_only = host.split(':').next().unwrap_or(&host).to_string();
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();

    // Route by Host + path prefix (longest-prefix wins — nginx `location`).
    let Some(vhost) = match_vhost(&cfg.vhosts, &host, &path) else {
        return status_response(StatusCode::NOT_FOUND, "no matching virtual host");
    };

    // force_https: redirect plaintext requests to the HTTPS scheme.
    if vhost.force_https && !secure {
        return Response::builder()
            .status(StatusCode::PERMANENT_REDIRECT)
            .header(LOCATION, format!("https://{host_only}{path}"))
            .body(full_body(Bytes::new()))
            .unwrap_or_else(|_| status_response(StatusCode::BAD_GATEWAY, "redirect failed"));
    }

    if acl_decision(&cfg.acls, peer, &vhost.id) == AclAction::Deny {
        return status_response(StatusCode::FORBIDDEN, "denied by ACL");
    }

    // Choose an upstream per the vhost's load-balancing strategy.
    let idx = ctx.counter.fetch_add(1, Ordering::Relaxed);
    let counts = ctx.inflight.lock().map(|m| m.clone()).unwrap_or_default();
    let Some(upstream) = select_upstream(&vhost.upstream, vhost.lb_strategy, peer, idx, |u| {
        counts.get(&upstream_key(u)).copied().unwrap_or(0)
    }) else {
        return status_response(StatusCode::BAD_GATEWAY, "no upstream configured");
    };
    let _guard = InflightGuard::acquire(&ctx.inflight, upstream_key(upstream));

    // WebSocket / HTTP Upgrade passthrough (FR-2): forward the handshake to the upstream
    // and splice the two connections, instead of buffering (which would break streaming
    // protocols). All six migration vhosts are WebSocket-dependent.
    if is_upgrade(req.headers()) {
        return proxy_upgrade(
            req,
            peer,
            upstream.host.clone(),
            upstream.port,
            host_only.clone(),
            secure,
            path.clone(),
        )
        .await;
    }

    // Build the forwarded request, STREAMING the body (no full buffering — avoids the
    // memory-exhaustion DoS on large uploads). Reject an over-limit declared
    // Content-Length upfront (413); a chunked body is hard-capped mid-stream.
    let (parts, body) = req.into_parts();
    if let Some(max) = ctx.max_body_bytes {
        let declared = parts
            .headers
            .get(hyper::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());
        if declared.is_some_and(|len| len > max) {
            return status_response(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
        }
    }
    let req_body: ReqBody = match ctx.max_body_bytes {
        Some(max) => Limited::new(body, max as usize).boxed(),
        None => body
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
            .boxed(),
    };
    let upstream_scheme = match upstream.scheme {
        UpstreamScheme::Https => "https",
        UpstreamScheme::Http => "http",
    };
    let Ok(uri) = format!(
        "{upstream_scheme}://{}:{}{}",
        upstream.host, upstream.port, path
    )
    .parse::<Uri>() else {
        return status_response(StatusCode::BAD_GATEWAY, "invalid upstream URI");
    };

    let mut builder = Request::builder().method(parts.method.clone()).uri(uri);
    // Copy the client headers, DROPPING the ones the proxy sets authoritatively — the
    // original `Host` and any client-supplied forwarding headers (which an edge proxy must
    // never trust, or a client could spoof its source IP / scheme). We re-add them below.
    for (name, value) in parts.headers.iter() {
        let n = name.as_str();
        if n == "host"
            || n == "x-forwarded-for"
            || n == "x-real-ip"
            || n == "x-forwarded-proto"
            || n == "x-forwarded-host"
            // `cookie` is handled separately below: HTTP/2 may split it across several
            // fields, which must be re-joined into one header for an HTTP/1.1 upstream.
            || n == "cookie"
            // Drop hop-by-hop headers too (e.g. an h1 client's `Connection: keep-alive`):
            // they describe this hop, not the upstream one, and the client sets framing.
            || is_hop_by_hop_header(n)
        {
            continue;
        }
        builder = builder.header(name, value);
    }
    // Re-join any `Cookie` fields into a single header. HTTP/2 permits the cookie header to
    // be split across multiple fields (RFC 7540 §8.1.2.5); when bridging to HTTP/1.1 they
    // MUST be concatenated with "; " into one `Cookie` header, or an h1 upstream sees
    // multiple Cookie lines and may parse only one — dropping the session (Nextcloud 302
    // loop / GitLab 422). A single-field cookie request is unaffected.
    let cookies: Vec<&str> = parts
        .headers
        .get_all(hyper::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .collect();
    if !cookies.is_empty() {
        builder = builder.header(hyper::header::COOKIE, cookies.join("; "));
    }
    // Standard reverse-proxy forwarding headers (nginx parity): preserve the client's
    // original Host to the upstream, and record the real client + scheme + host.
    let scheme = if secure { "https" } else { "http" };
    builder = builder
        .header(HOST, host_only.as_str())
        .header("x-real-ip", peer.to_string())
        .header("x-forwarded-for", peer.to_string())
        .header("x-forwarded-proto", scheme)
        .header("x-forwarded-host", host_only.as_str());
    let Ok(forward) = builder.body(req_body) else {
        return status_response(StatusCode::BAD_GATEWAY, "failed to build upstream request");
    };

    let upstream_label = format!("{}:{}", upstream.host, upstream.port);
    match ctx.client.request(forward).await {
        Ok(resp) => {
            let (mut rparts, rbody) = resp.into_parts();
            // Strip the upstream's hop-by-hop headers before relaying. Leaving e.g.
            // `connection` or `transfer-encoding` on the response is illegal over HTTP/2 and
            // makes strict browsers reset the stream (curl tolerates it) — which broke
            // session cookies / redirects for real browsers while curl tests passed.
            strip_hop_by_hop(&mut rparts.headers);
            access_log(
                ctx,
                peer,
                &parts.method,
                &host,
                &path,
                &upstream_label,
                rparts.status.as_u16(),
            )
            .await;
            // Relay the upstream body as a stream (no buffering).
            Response::from_parts(rparts, rbody.boxed())
        }
        Err(_) => {
            access_log(ctx, peer, &parts.method, &host, &path, &upstream_label, 502).await;
            status_response(StatusCode::BAD_GATEWAY, "upstream request failed")
        }
    }
}

/// Whether the request is an HTTP Upgrade (WebSocket etc.): `Connection: upgrade` plus an
/// `Upgrade` header.
fn is_upgrade(headers: &hyper::HeaderMap) -> bool {
    let conn_upgrade = headers
        .get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.to_ascii_lowercase()
                .split(',')
                .any(|t| t.trim() == "upgrade")
        })
        .unwrap_or(false);
    conn_upgrade && headers.contains_key(hyper::header::UPGRADE)
}

/// Connection-specific / hop-by-hop headers (RFC 7230 §6.1) that must not cross a proxy
/// hop. Relaying any of these into an HTTP/2 message is a protocol violation (RFC 7540
/// §8.1.2.2): strict clients (browsers) reset the stream, while lenient ones (curl) tolerate
/// it — which is exactly why leaking them only broke real browsers over h2. In particular a
/// leftover `transfer-encoding: chunked` or `connection` from an HTTP/1.1 upstream response
/// would break the h2 stream carrying a login/redirect + `Set-Cookie`, dropping the session.
fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Remove hop-by-hop headers from a proxied message, including any header named in the
/// `Connection` header's token list. End-to-end headers (notably every `Set-Cookie`) are
/// left untouched — only single-valued connection headers are removed, so multi-valued
/// cookies are preserved.
fn strip_hop_by_hop(headers: &mut hyper::HeaderMap) {
    let listed: Vec<String> = headers
        .get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            v.split(',')
                .map(|t| t.trim().to_ascii_lowercase())
                .filter(|t| !t.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let to_remove: Vec<hyper::header::HeaderName> = headers
        .keys()
        .filter(|name| {
            let n = name.as_str().to_ascii_lowercase();
            is_hop_by_hop_header(&n) || listed.contains(&n)
        })
        .cloned()
        .collect();
    for name in to_remove {
        headers.remove(&name);
    }
}

/// The byte offset just past the `\r\n\r\n` that ends an HTTP head, if present.
fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Parse an HTTP response head into `(status, headers)`.
fn parse_response_head(head: &str) -> (u16, Vec<(String, String)>) {
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or(502);
    let headers = lines
        .filter(|l| !l.is_empty())
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect();
    (status, headers)
}

/// WebSocket / HTTP-Upgrade passthrough for the reverse path: forward the handshake to a
/// raw-TCP (`http`/`ws`) upstream, relay its `101`, then splice the client and upstream
/// bidirectionally (mirrors the forward proxy's CONNECT tunnel). A `wss://` upstream would
/// need upstream TLS — future work; the migration's WebSocket upstreams are all http.
#[allow(clippy::too_many_arguments)]
async fn proxy_upgrade(
    mut req: Request<Incoming>,
    peer: IpAddr,
    host: String,
    port: u16,
    host_only: String,
    secure: bool,
    path: String,
) -> Response<ResBody> {
    // Capture the client-side upgrade future before consuming the request.
    let on_upgrade = hyper::upgrade::on(&mut req);
    let (parts, _body) = req.into_parts();

    let mut server = match TcpStream::connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(_) => return status_response(StatusCode::BAD_GATEWAY, "upstream connect failed"),
    };

    // Rebuild the handshake request for the upstream: keep the Upgrade/WebSocket headers,
    // drop client-supplied forwarding headers, preserve Host and add the forwarded set.
    let scheme = if secure { "https" } else { "http" };
    let mut head = format!("{} {} HTTP/1.1\r\n", parts.method, path);
    for (name, value) in parts.headers.iter() {
        let n = name.as_str();
        if n == "host"
            || n == "x-forwarded-for"
            || n == "x-real-ip"
            || n == "x-forwarded-proto"
            || n == "x-forwarded-host"
        {
            continue;
        }
        if let Ok(v) = value.to_str() {
            head.push_str(&format!("{n}: {v}\r\n"));
        }
    }
    head.push_str(&format!("host: {host_only}\r\n"));
    head.push_str(&format!("x-real-ip: {peer}\r\n"));
    head.push_str(&format!("x-forwarded-for: {peer}\r\n"));
    head.push_str(&format!("x-forwarded-proto: {scheme}\r\n"));
    head.push_str(&format!("x-forwarded-host: {host_only}\r\n\r\n"));
    if server.write_all(head.as_bytes()).await.is_err() {
        return status_response(StatusCode::BAD_GATEWAY, "upstream write failed");
    }

    // Read the upstream response head (up to CRLFCRLF), keeping any trailing bytes. Bounded
    // by a timeout so an upstream that accepts the socket but never sends the 101 head can't
    // pin this task/connection open indefinitely.
    let head_read = tokio::time::timeout(WS_UPSTREAM_HEAD_TIMEOUT, async {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            match server.read(&mut tmp).await {
                Ok(0) => return Err("upstream closed"),
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(pos) = find_headers_end(&buf) {
                        return Ok((buf, pos));
                    }
                    if buf.len() > 65_536 {
                        return Err("upstream header too large");
                    }
                }
                Err(_) => return Err("upstream read failed"),
            }
        }
    })
    .await;
    let (buf, head_end) = match head_read {
        Ok(Ok(v)) => v,
        Ok(Err(msg)) => return status_response(StatusCode::BAD_GATEWAY, msg),
        Err(_) => return status_response(StatusCode::GATEWAY_TIMEOUT, "upstream header timeout"),
    };
    let leftover = buf[head_end..].to_vec();
    let (status, resp_headers) = parse_response_head(&String::from_utf8_lossy(&buf[..head_end]));

    // Build the response to return to the client from the upstream's status + headers. For a
    // non-101 (upstream declined the upgrade) we relay it as an ordinary response.
    let mut builder =
        Response::builder().status(StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY));
    for (k, v) in &resp_headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    if status != 101 {
        return builder
            .body(full_body(Bytes::from(leftover)))
            .unwrap_or_else(|_| status_response(StatusCode::BAD_GATEWAY, "bad upstream response"));
    }
    let response = match builder.body(full_body(Bytes::new())) {
        Ok(r) => r,
        Err(_) => return status_response(StatusCode::BAD_GATEWAY, "bad upgrade response"),
    };

    // After the client connection upgrades, flush any early upstream bytes then splice.
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                let mut client_io = TokioIo::new(upgraded);
                if !leftover.is_empty() {
                    let _ = client_io.write_all(&leftover).await;
                }
                let _ = tokio::io::copy_bidirectional(&mut client_io, &mut server).await;
            }
            Err(e) => tracing::debug!("proxy upgrade failed: {e}"),
        }
    });
    response
}

#[allow(clippy::too_many_arguments)]
async fn access_log(
    ctx: &Ctx,
    peer: IpAddr,
    method: &hyper::Method,
    host: &str,
    path: &str,
    upstream: &str,
    status: u16,
) {
    if !ctx.log_access {
        return;
    }
    let _ = ctx
        .db
        .append_log(NewLogEntry {
            domain: DomainKey::Proxy,
            log_kind: LogKind::Access,
            level: if status >= 500 {
                LogLevel::Warn
            } else {
                LogLevel::Info
            },
            message: format!("{peer} {method} {host}{path} -> {upstream} {status}"),
            at: Utc::now(),
            meta: None,
        })
        .await;
}

async fn run(
    addr: SocketAddr,
    ctx: Ctx,
    mut shutdown: watch::Receiver<bool>,
    health: Arc<AtomicU8>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    health.store(H_HEALTHY, Ordering::Relaxed);
    tracing::info!("proxy server listening on {addr} (HTTP)");

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted { Ok(v) => v, Err(_) => continue };
                let io = TokioIo::new(stream);
                let ctx = ctx.clone();
                let peer_ip = peer.ip();
                tokio::spawn(async move {
                    let service = service_fn(move |req| {
                        let ctx = ctx.clone();
                        async move { Ok::<_, Infallible>(handle(req, peer_ip, &ctx, false).await) }
                    });
                    // `auto` serves HTTP/1.1 or HTTP/2 by ALPN; `_with_upgrades` keeps the
                    // HTTP/1.1 Upgrade path working (WebSocket).
                    if let Err(e) = auto::Builder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(io, service)
                        .await
                    {
                        tracing::debug!("proxy connection error: {e}");
                    }
                });
            }
        }
    }
    Ok(())
}

/// HTTPS listener: terminate TLS (per-vhost cert by SNI), then serve HTTP.
async fn run_tls(
    addr: SocketAddr,
    ctx: Ctx,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let Some((server_config, certs)) = crate::tls::build_dynamic_config(&ctx.db).await else {
        tracing::warn!(
            "proxy TLS on {addr}: crypto provider init failed; HTTPS listener not started"
        );
        return Ok(());
    };
    if certs.read().map(|m| m.is_empty()).unwrap_or(true) {
        tracing::warn!("proxy TLS on {addr}: no TLS-enabled vhost has a usable certificate yet; serving once one is added (hot reload)");
    }
    // Hot reload: periodically refresh the SNI cert map from the DB, so adding / rotating /
    // removing a certificate or TLS vhost applies without a restart.
    {
        let db = ctx.db.clone();
        let certs = certs.clone();
        let mut refresh_shutdown = shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                        let fresh = crate::tls::load_sni_map(&db).await;
                        if let Ok(mut w) = certs.write() {
                            *w = fresh;
                        }
                    }
                    changed = refresh_shutdown.changed() => {
                        if changed.is_err() || *refresh_shutdown.borrow() { break; }
                    }
                }
            }
        });
    }
    let acceptor = TlsAcceptor::from(server_config);
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("proxy server listening on {addr} (HTTPS)");

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted { Ok(v) => v, Err(_) => continue };
                let acceptor = acceptor.clone();
                let ctx = ctx.clone();
                let peer_ip = peer.ip();
                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::debug!("proxy TLS handshake error: {e}");
                            return;
                        }
                    };
                    let io = TokioIo::new(tls_stream);
                    let service = service_fn(move |req| {
                        let ctx = ctx.clone();
                        async move { Ok::<_, Infallible>(handle(req, peer_ip, &ctx, true).await) }
                    });
                    if let Err(e) = auto::Builder::new(TokioExecutor::new())
                        .serve_connection_with_upgrades(io, service)
                        .await
                    {
                        tracing::debug!("proxy TLS connection error: {e}");
                    }
                });
            }
        }
    }
    Ok(())
}

/// Raw L4/TCP stream listener: accept a connection, sniff TLS SNI from its first bytes
/// (ssl_preread), route to a `Tcp`-mode vhost by SNI or by `port`, then splice it to the
/// upstream. TLS is passed through untouched (no termination), so RDP/PostgreSQL/etc. work.
async fn run_tcp(
    addr: SocketAddr,
    ctx: Ctx,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let port = addr.port();
    tracing::info!("proxy server listening on {addr} (TCP stream)");
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
            accepted = listener.accept() => {
                let (client, peer) = match accepted { Ok(v) => v, Err(_) => continue };
                let ctx = ctx.clone();
                let peer_ip = peer.ip();
                tokio::spawn(async move {
                    if let Err(e) = handle_tcp(client, peer_ip, port, &ctx).await {
                        tracing::debug!("proxy TCP stream error: {e}");
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle_tcp(
    mut client: TcpStream,
    peer: IpAddr,
    port: u16,
    ctx: &Ctx,
) -> std::io::Result<()> {
    // Preread the client's first bytes (with a timeout, so a server-speaks-first protocol
    // falls through to port routing) to sniff the TLS SNI without terminating TLS.
    let mut prefix = vec![0u8; 4096];
    let n = match tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut prefix))
        .await
    {
        Ok(Ok(n)) => n,
        _ => 0,
    };
    prefix.truncate(n);
    let sni = parse_sni(&prefix);

    let cfg = ctx.warm_config().await;
    if is_blocked(&cfg.blocks, peer, Utc::now()) {
        return Ok(());
    }
    let Some(vhost) = match_tcp_vhost(&cfg.vhosts, sni.as_deref(), port) else {
        tracing::debug!("proxy TCP :{port}: no matching stream vhost (sni={sni:?})");
        return Ok(());
    };
    if acl_decision(&cfg.acls, peer, &vhost.id) == AclAction::Deny {
        return Ok(());
    }
    let idx = ctx.counter.fetch_add(1, Ordering::Relaxed);
    let counts = ctx.inflight.lock().map(|m| m.clone()).unwrap_or_default();
    let Some(upstream) = select_upstream(&vhost.upstream, vhost.lb_strategy, peer, idx, |u| {
        counts.get(&upstream_key(u)).copied().unwrap_or(0)
    }) else {
        return Ok(());
    };
    let _guard = InflightGuard::acquire(&ctx.inflight, upstream_key(upstream));

    let mut server = match TcpStream::connect((upstream.host.as_str(), upstream.port)).await {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("proxy TCP upstream connect failed: {e}");
            return Ok(());
        }
    };
    // Replay the preread bytes to the upstream, then splice the two streams.
    if !prefix.is_empty() {
        server.write_all(&prefix).await?;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetite_core::domains::proxy::model::{
        IpBlock, LbStrategy, ProxyMode, Upstream, UpstreamScheme, VirtualHost,
    };

    async fn test_db() -> (Db, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        (db, dir)
    }

    /// A raw-TCP upstream that answers every request with `200 OK <body>`.
    async fn spawn_upstream(body: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    continue;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = stream.read(&mut buf).await;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    async fn seed_vhost(db: &Db, hostname: &str, upstream: SocketAddr) -> VirtualHost {
        let vhost = VirtualHost {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "admin".into(),
            hostname: hostname.into(),
            path_prefix: None,
            listen_port: 80,
            upstream: vec![Upstream {
                host: upstream.ip().to_string(),
                port: upstream.port(),
                weight: 1,
                scheme: UpstreamScheme::Http,
            }],
            tls_enabled: false,
            certificate_ref: None,
            force_https: false,
            proxy_mode: ProxyMode::Http,
            lb_strategy: LbStrategy::RoundRobin,
            enabled: true,
        };
        db.save_vhost(&vhost).await.unwrap()
    }

    /// Returns the proxy address and the shutdown sender — callers must keep the
    /// sender alive (dropping it stops the server).
    async fn start_proxy(db: Db) -> (SocketAddr, watch::Sender<bool>) {
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        let svc = ProxyService::new(addr, None, None, Vec::new(), None, true);
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

    /// GET `/` from the proxy with the given Host header (raw TCP so we fully
    /// control the request line and headers); returns (status, body).
    async fn get(proxy: SocketAddr, host: &str) -> (u16, String) {
        let mut stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse::<u16>().ok())
            .unwrap_or(0);
        let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
        (status, body)
    }

    /// GET `/` from the proxy over a real HTTP/2 (prior-knowledge, cleartext) connection.
    /// hyper's h2 client carries the host in the `:authority` pseudo-header and sends *no*
    /// `Host` header — exactly the request shape that used to 404 before routing learned to
    /// fall back to the URI authority. Returns the status code.
    async fn get_h2(proxy: SocketAddr, host: &str) -> u16 {
        use http_body_util::Empty;
        let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = Request::builder()
            .method("GET")
            .uri(format!("http://{host}/"))
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        resp.status().as_u16()
    }

    /// Like [`get_h2`] but returns the response status and headers, for asserting exactly
    /// what the proxy emits to an h2 client.
    async fn get_h2_full(proxy: SocketAddr, host: &str) -> (u16, hyper::HeaderMap) {
        use http_body_util::Empty;
        let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = Request::builder()
            .method("GET")
            .uri(format!("http://{host}/"))
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        (resp.status().as_u16(), resp.headers().clone())
    }

    /// Send `GET /` over HTTP/2 with several `cookie` request fields, returning the status
    /// and the upstream-echoed request head (so a test can assert how the proxy re-emitted
    /// the cookies to the HTTP/1.1 upstream).
    async fn get_h2_with_cookies(proxy: SocketAddr, host: &str, cookies: &[&str]) -> (u16, String) {
        use http_body_util::Empty;
        let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut rb = Request::builder()
            .method("GET")
            .uri(format!("http://{host}/"));
        for c in cookies {
            rb = rb.header(hyper::header::COOKIE, *c);
        }
        let req = rb.body(Empty::<Bytes>::new()).unwrap();
        let resp = sender.send_request(req).await.unwrap();
        let status = resp.status().as_u16();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&body).to_string())
    }

    /// An upstream returning hop-by-hop headers (one named in `Connection`, plus a bare
    /// `Keep-Alive`) alongside two `Set-Cookie`s — to prove the proxy strips the former and
    /// preserves the latter when relaying to an h2 client.
    async fn spawn_upstream_hopbyhop() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    continue;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = stream.read(&mut buf).await;
                    let resp = "HTTP/1.1 200 OK\r\n\
                         Content-Length: 2\r\n\
                         Connection: keep-alive, X-Hop-Secret\r\n\
                         Keep-Alive: timeout=5\r\n\
                         X-Hop-Secret: leak\r\n\
                         X-End-To-End: keep\r\n\
                         Set-Cookie: sid=abc; Path=/; Secure; HttpOnly\r\n\
                         Set-Cookie: csrf=xyz; Path=/\r\n\
                         \r\nok";
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn proxies_to_upstream() {
        let (db, _dir) = test_db().await;
        let upstream = spawn_upstream("hello from upstream").await;
        seed_vhost(&db, "test.local", upstream).await;
        let (proxy, _tx) = start_proxy(db.clone()).await;

        let (status, body) = get(proxy, "test.local").await;
        assert_eq!(status, 200);
        assert_eq!(body, "hello from upstream");

        // The request was access-logged.
        let logs = db
            .query_logs(Some("proxy"), Some("access"), None, 10)
            .await
            .unwrap();
        assert!(logs.iter().any(|l| l.message.contains("test.local")));
    }

    #[tokio::test]
    async fn routes_http2_request_by_authority_pseudo_header() {
        let (db, _dir) = test_db().await;
        let upstream = spawn_upstream("h2 ok").await;
        seed_vhost(&db, "h2.local", upstream).await;
        let (proxy, _tx) = start_proxy(db).await;

        // Over HTTP/2 the Host header is absent; routing must use `:authority`. Before the
        // fix this returned 404 ("no matching virtual host") for every h2 request.
        let status = get_h2(proxy, "h2.local").await;
        assert_eq!(
            status, 200,
            "h2 request must route to the vhost via :authority"
        );

        // A non-matching authority still 404s — proving routing actually ran on the host.
        let status = get_h2(proxy, "nope.local").await;
        assert_eq!(status, 404);
    }

    #[test]
    fn strip_hop_by_hop_removes_connection_headers_keeps_end_to_end() {
        use hyper::header::{HeaderMap, HeaderName, HeaderValue, CONNECTION, SET_COOKIE};
        let mut h = HeaderMap::new();
        h.insert(CONNECTION, HeaderValue::from_static("keep-alive, X-Hop"));
        h.insert(
            HeaderName::from_static("keep-alive"),
            HeaderValue::from_static("timeout=5"),
        );
        h.insert(
            HeaderName::from_static("transfer-encoding"),
            HeaderValue::from_static("chunked"),
        );
        h.insert(
            HeaderName::from_static("x-hop"),
            HeaderValue::from_static("secret"),
        );
        h.insert(
            HeaderName::from_static("x-keep"),
            HeaderValue::from_static("v"),
        );
        h.append(SET_COOKIE, HeaderValue::from_static("a=1"));
        h.append(SET_COOKIE, HeaderValue::from_static("b=2"));

        strip_hop_by_hop(&mut h);

        assert!(!h.contains_key(CONNECTION));
        assert!(!h.contains_key("keep-alive"));
        assert!(!h.contains_key("transfer-encoding"));
        assert!(!h.contains_key("x-hop"), "connection-listed header removed");
        assert!(h.contains_key("x-keep"), "end-to-end header kept");
        assert_eq!(
            h.get_all(SET_COOKIE).iter().count(),
            2,
            "both Set-Cookie preserved"
        );
    }

    #[tokio::test]
    async fn h2_response_strips_hop_by_hop_and_preserves_multiple_set_cookie() {
        let (db, _dir) = test_db().await;
        let upstream = spawn_upstream_hopbyhop().await;
        seed_vhost(&db, "cookie.local", upstream).await;
        let (proxy, _tx) = start_proxy(db).await;

        let (status, headers) = get_h2_full(proxy, "cookie.local").await;
        assert_eq!(status, 200);
        // Hop-by-hop headers from the h1 upstream must not reach the h2 client (they would
        // otherwise be an h2 protocol violation and break the browser stream).
        assert!(!headers.contains_key("keep-alive"), "keep-alive stripped");
        assert!(
            !headers.contains_key("x-hop-secret"),
            "connection-listed header stripped"
        );
        // Both session cookies survive intact (the actual Nextcloud/GitLab failure mode).
        assert_eq!(
            headers.get_all(hyper::header::SET_COOKIE).iter().count(),
            2,
            "both Set-Cookie preserved over h2"
        );
        assert!(headers.contains_key("x-end-to-end"), "end-to-end kept");
    }

    #[tokio::test]
    async fn h2_split_cookie_fields_are_joined_into_one_upstream_header() {
        let (db, _dir) = test_db().await;
        let upstream = spawn_echo_headers_upstream().await;
        seed_vhost(&db, "cjoin.local", upstream).await;
        let (proxy, _tx) = start_proxy(db).await;

        // HTTP/2 may carry the cookie as multiple fields; the h1 upstream must receive ONE
        // `Cookie` header with them re-joined by "; " (RFC 7540 §8.1.2.5), or it drops the
        // session (Nextcloud 302 loop / GitLab 422).
        let (status, echoed) = get_h2_with_cookies(proxy, "cjoin.local", &["a=1", "b=2"]).await;
        assert_eq!(status, 200);
        let head = echoed.to_lowercase();
        assert_eq!(
            head.matches("cookie:").count(),
            1,
            "exactly one Cookie header reaches the upstream: {echoed}"
        );
        assert!(
            head.contains("cookie: a=1; b=2"),
            "cookie fields joined with '; ': {echoed}"
        );
    }

    /// An upstream that echoes the request head (start line + headers) back as the body,
    /// so a test can assert exactly which headers the proxy forwarded.
    async fn spawn_echo_headers_upstream() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    continue;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let head = req.split("\r\n\r\n").next().unwrap_or("").to_string();
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        head.len(),
                        head
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn forwards_standard_proxy_headers_and_strips_spoofed_xff() {
        let (db, _dir) = test_db().await;
        let upstream = spawn_echo_headers_upstream().await;
        seed_vhost(&db, "hdr.local", upstream).await;
        let (proxy, _tx) = start_proxy(db).await;

        // Send a SPOOFED X-Forwarded-For / X-Real-IP — the edge proxy must not trust them.
        let mut stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let request = "GET / HTTP/1.1\r\nHost: hdr.local\r\nX-Forwarded-For: 1.2.3.4\r\n\
             X-Real-IP: 1.2.3.4\r\nConnection: close\r\n\r\n";
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let body = String::from_utf8_lossy(&buf);
        let low = body.to_lowercase();

        assert!(low.contains("host: hdr.local"), "Host preserved: {body}");
        assert!(
            low.contains("x-real-ip: 127.0.0.1"),
            "X-Real-IP=peer: {body}"
        );
        assert!(low.contains("x-forwarded-proto: http"), "XFP: {body}");
        assert!(low.contains("x-forwarded-host: hdr.local"), "XFH: {body}");
        // The spoofed values were replaced with the real peer, and not duplicated.
        assert!(
            !low.contains("1.2.3.4"),
            "spoofed IP must be stripped: {body}"
        );
        assert_eq!(
            low.matches("x-forwarded-for:").count(),
            1,
            "exactly one XFF (= peer): {body}"
        );
        assert!(
            low.contains("x-forwarded-for: 127.0.0.1"),
            "XFF=peer: {body}"
        );
    }

    /// A minimal WebSocket-ish upstream: answers the handshake with `101` then echoes any
    /// bytes it receives — enough to prove the reverse proxy splices the upgraded tunnel.
    async fn spawn_ws_echo_upstream() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    continue;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = stream.read(&mut buf).await; // consume the handshake request
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                              Connection: Upgrade\r\nSec-WebSocket-Accept: test\r\n\r\n",
                        )
                        .await;
                    loop {
                        let mut b = [0u8; 1024];
                        match stream.read(&mut b).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if stream.write_all(&b[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn websocket_upgrade_is_spliced() {
        let (db, _dir) = test_db().await;
        let upstream = spawn_ws_echo_upstream().await;
        seed_vhost(&db, "ws.local", upstream).await;
        let (proxy, _tx) = start_proxy(db).await;

        let mut stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
        let handshake = "GET /socket HTTP/1.1\r\nHost: ws.local\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n";
        stream.write_all(handshake.as_bytes()).await.unwrap();

        // Read the 101 response head byte-by-byte (don't over-read into the tunnel).
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        loop {
            let n = stream.read(&mut b).await.unwrap();
            assert_ne!(n, 0, "connection closed before a response");
            head.push(b[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        assert!(
            String::from_utf8_lossy(&head).contains("101"),
            "expected 101 Switching Protocols, got: {}",
            String::from_utf8_lossy(&head)
        );

        // The connection is now a raw tunnel to the echo upstream.
        stream.write_all(b"HELLO-WS").await.unwrap();
        let mut echo = [0u8; 8];
        stream.read_exact(&mut echo).await.unwrap();
        assert_eq!(
            &echo, b"HELLO-WS",
            "upgraded stream echoes through the upstream"
        );
    }

    /// A raw byte-echo upstream (no HTTP) for the L4/TCP stream test.
    async fn spawn_raw_echo_upstream() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    continue;
                };
                tokio::spawn(async move {
                    let mut b = [0u8; 1024];
                    loop {
                        match s.read(&mut b).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&b[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn tcp_stream_forwards_by_port() {
        let (db, _dir) = test_db().await;
        let upstream = spawn_raw_echo_upstream().await;

        // A free port for the L4 listener; a `Tcp` vhost bound to it → the echo upstream.
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = probe.local_addr().unwrap();
        drop(probe);
        db.save_vhost(&VirtualHost {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "admin".into(),
            hostname: "stream.local".into(),
            path_prefix: None,
            listen_port: tcp_addr.port(),
            upstream: vec![Upstream {
                host: upstream.ip().to_string(),
                port: upstream.port(),
                weight: 1,
                scheme: UpstreamScheme::Http,
            }],
            tls_enabled: false,
            certificate_ref: None,
            force_https: false,
            proxy_mode: ProxyMode::Tcp,
            lb_strategy: LbStrategy::RoundRobin,
            enabled: true,
        })
        .await
        .unwrap();

        let probe2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = probe2.local_addr().unwrap();
        drop(probe2);
        let svc = ProxyService::new(http_addr, None, None, vec![tcp_addr], None, true);
        let (_tx, rx) = watch::channel(false);
        svc.start(db, rx);
        for _ in 0..50 {
            if svc.health() == ServiceHealth::Healthy {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        // Connect to the L4 port (retry until it binds) and echo bytes through the splice.
        let mut echoed = [0u8; 8];
        for attempt in 0..50 {
            let Ok(mut stream) = tokio::net::TcpStream::connect(tcp_addr).await else {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                continue;
            };
            stream.write_all(b"L4-HELLO").await.unwrap();
            match stream.read_exact(&mut echoed).await {
                Ok(_) => break,
                Err(_) if attempt < 49 => {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                Err(e) => panic!("L4 echo failed: {e}"),
            }
        }
        assert_eq!(
            &echoed, b"L4-HELLO",
            "the raw stream is spliced to the upstream"
        );
    }

    #[tokio::test]
    async fn oversized_request_body_is_rejected_413() {
        let (db, _dir) = test_db().await;
        let upstream = spawn_upstream("ok").await;
        seed_vhost(&db, "cap.local", upstream).await;
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        // A 10-byte body cap.
        let svc = ProxyService::new(addr, None, None, Vec::new(), Some(10), true);
        let (_tx, rx) = watch::channel(false);
        svc.start(db, rx);
        for _ in 0..50 {
            if svc.health() == ServiceHealth::Healthy {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let body = "x".repeat(100);
        let req = format!(
            "POST / HTTP/1.1\r\nHost: cap.local\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let status = String::from_utf8_lossy(&buf)
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse::<u16>().ok())
            .unwrap_or(0);
        assert_eq!(status, 413, "an over-limit Content-Length must be rejected");
    }

    #[tokio::test]
    async fn unknown_host_is_404() {
        let (db, _dir) = test_db().await;
        let (proxy, _tx) = start_proxy(db).await;
        let (status, _) = get(proxy, "nope.local").await;
        assert_eq!(status, 404);
    }

    #[tokio::test]
    async fn blocked_client_is_403() {
        let (db, _dir) = test_db().await;
        let upstream = spawn_upstream("secret").await;
        seed_vhost(&db, "test.local", upstream).await;
        db.save_ip_block(&IpBlock {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "admin".into(),
            cidr: "127.0.0.1/32".into(),
            reason: Some("test".into()),
            order: 0,
            expires_at: None,
            enabled: true,
        })
        .await
        .unwrap();
        let (proxy, _tx) = start_proxy(db).await;

        let (status, _) = get(proxy, "test.local").await;
        assert_eq!(status, 403);
    }

    #[tokio::test]
    async fn force_https_redirects() {
        let (db, _dir) = test_db().await;
        db.save_vhost(&VirtualHost {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "admin".into(),
            hostname: "secure.local".into(),
            path_prefix: None,
            listen_port: 80,
            upstream: vec![Upstream {
                host: "127.0.0.1".into(),
                port: 9,
                weight: 1,
                scheme: UpstreamScheme::Http,
            }],
            tls_enabled: false,
            certificate_ref: None,
            force_https: true,
            proxy_mode: ProxyMode::Http,
            lb_strategy: LbStrategy::RoundRobin,
            enabled: true,
        })
        .await
        .unwrap();
        let (proxy, _tx) = start_proxy(db).await;

        let (status, _) = get(proxy, "secure.local").await;
        assert_eq!(status, 308); // permanent redirect to https
    }

    #[tokio::test]
    async fn acme_challenge_served_for_known_token_and_404_otherwise() {
        let store: crate::acme::ChallengeStore = Arc::new(Mutex::new(HashMap::from([(
            "tok123".to_string(),
            "keyauth-value".to_string(),
        )])));

        // Non-challenge path is not intercepted (normal routing proceeds).
        assert!(acme_challenge_response(&store, "/index.html").is_none());

        // Known token → 200 with the key authorization as the body.
        let resp = acme_challenge_response(&store, "/.well-known/acme-challenge/tok123")
            .expect("challenge path handled");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"keyauth-value");

        // Unknown token → 404.
        let resp = acme_challenge_response(&store, "/.well-known/acme-challenge/nope")
            .expect("challenge path handled");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// A rustls verifier that accepts any server certificate (test client).
    #[derive(Debug)]
    struct NoVerify(std::sync::Arc<rustls::crypto::CryptoProvider>);
    impl rustls::client::danger::ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }
        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    #[tokio::test]
    async fn https_terminates_and_proxies() {
        use tokio_rustls::TlsConnector;

        let (db, _dir) = test_db().await;
        let upstream = spawn_upstream("hello over tls").await;

        // Self-signed cert for test.local, stored with its private key.
        let cert = rcgen::generate_simple_self_signed(vec!["test.local".to_string()]).unwrap();
        db.create_certificate(
            "web",
            "CN=test.local",
            "self",
            &["test.local".to_string()],
            Utc::now(),
            Utc::now() + chrono::Duration::days(90),
            &cert.cert.pem(),
            None,
            Some(&cert.key_pair.serialize_pem()),
            "admin",
        )
        .await
        .unwrap();

        db.save_vhost(&VirtualHost {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "admin".into(),
            hostname: "test.local".into(),
            path_prefix: None,
            listen_port: 443,
            upstream: vec![Upstream {
                host: upstream.ip().to_string(),
                port: upstream.port(),
                weight: 1,
                scheme: UpstreamScheme::Http,
            }],
            tls_enabled: true,
            certificate_ref: Some("web".into()),
            force_https: false,
            proxy_mode: ProxyMode::Http,
            lb_strategy: LbStrategy::RoundRobin,
            enabled: true,
        })
        .await
        .unwrap();

        // Two free ports: HTTP (health source) + HTTPS.
        let http = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http.local_addr().unwrap();
        let https = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tls_addr = https.local_addr().unwrap();
        drop(http);
        drop(https);

        let svc = ProxyService::new(http_addr, Some(tls_addr), None, Vec::new(), None, true);
        let (_tx, rx) = watch::channel(false);
        svc.start(db, rx);
        for _ in 0..50 {
            if svc.health() == ServiceHealth::Healthy {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        // TLS client accepting any cert.
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify(provider)))
            .with_no_client_auth();
        let connector = TlsConnector::from(std::sync::Arc::new(config));
        let server_name = rustls::pki_types::ServerName::try_from("test.local").unwrap();

        // Retry until the HTTPS listener is up.
        let mut buf = Vec::new();
        for attempt in 0..50 {
            let Ok(tcp) = tokio::net::TcpStream::connect(tls_addr).await else {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                continue;
            };
            match connector.connect(server_name.clone(), tcp).await {
                Ok(mut tls) => {
                    tls.write_all(
                        b"GET / HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
                    tls.read_to_end(&mut buf).await.unwrap();
                    break;
                }
                Err(_) if attempt < 49 => {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                Err(e) => panic!("TLS handshake failed: {e}"),
            }
        }
        let text = String::from_utf8_lossy(&buf);
        assert!(text.contains("200"), "unexpected response: {text}");
        assert!(text.contains("hello over tls"), "body missing: {text}");
    }
}
