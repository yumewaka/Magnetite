//! The embedded HTTP **forward** proxy. Unlike the reverse proxy (which fronts
//! configured virtual hosts), this listens on a dedicated port that clients set as
//! their HTTP proxy: it serves absolute-URI `GET/POST http://host/…` requests by
//! fetching them, and `CONNECT host:port` by opening a raw TCP tunnel (so HTTPS
//! flows through opaquely).
//!
//! Three gates guard every request, all read live from the DB:
//! 1. **Source** — the client IP against the forward `Source` rules.
//! 2. **Auth** — if any enabled forward user exists, a valid `Proxy-Authorization:
//!    Basic` credential is required (otherwise `407`).
//! 3. **Destination** — the requested host against the forward `Destination` rules.

use crate::router::{forward_dest_decision, forward_source_decision};
use base64::Engine;
use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use magnetite_core::domain::DomainKey;
use magnetite_core::domains::proxy::model::AclAction;
use magnetite_core::models::common::{LogKind, LogLevel};
use magnetite_db::{Db, NewLogEntry};
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

type ForwardClient = Client<HttpConnector, Full<Bytes>>;

/// A type-erased forward-proxy response body: either a small buffered body (error/status
/// pages, the CONNECT 200) or a STREAMED upstream response. Streaming (rather than
/// `collect()`-ing the whole response) keeps per-connection memory to about one chunk, so
/// aggregate memory under concurrency stays flat even for large objects (M-7').
type ProxyBody =
    http_body_util::combinators::UnsyncBoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

/// A fully-buffered [`ProxyBody`] for small in-memory responses.
fn full_body(body: impl Into<Bytes>) -> ProxyBody {
    Full::new(body.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

/// Shared context for the forward-proxy listener.
/// Absolute ceiling applied to a buffered request body / upstream response when no
/// `max_body` is configured. The forward proxy buffers each body to re-send it, so an
/// unset limit used to mean "buffer without bound" — a memory-exhaustion DoS on a large
/// upload or a large fetched object. This bounds it even unconfigured; operators set
/// `max_body_bytes` for a tighter cap. 512 MiB is well above any real request/response.
const DEFAULT_MAX_BODY_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone)]
pub(crate) struct ForwardCtx {
    pub db: Db,
    pub client: ForwardClient,
    pub log_access: bool,
    /// Cap on a forwarded request body / upstream response (bytes). `None` falls back to
    /// [`DEFAULT_MAX_BODY_BYTES`] — never unbounded. Mirrors the reverse proxy's
    /// `max_body_bytes` so a single config guards both paths against a memory DoS.
    pub max_body: Option<u64>,
}

impl ForwardCtx {
    pub(crate) fn new(db: Db, log_access: bool, max_body: Option<u64>) -> Self {
        Self {
            db,
            client: Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>(),
            log_access,
            max_body,
        }
    }

    /// The effective body cap: the configured `max_body`, or [`DEFAULT_MAX_BODY_BYTES`]
    /// when unset — so a body is always bounded, never buffered without limit.
    fn body_cap(&self) -> usize {
        self.max_body.unwrap_or(DEFAULT_MAX_BODY_BYTES) as usize
    }
}

fn status_response(code: StatusCode, message: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(code)
        .header("content-type", "text/plain; charset=utf-8")
        .body(full_body(message.to_string()))
        .unwrap_or_else(|_| Response::new(full_body(Bytes::from_static(b"error"))))
}

/// `407 Proxy Authentication Required` with the `Proxy-Authenticate` challenge.
fn proxy_auth_required() -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header("proxy-authenticate", "Basic realm=\"magnetite\"")
        .header("content-type", "text/plain; charset=utf-8")
        .body(full_body(Bytes::from_static(
            "プロキシ認証が必要です。".as_bytes(),
        )))
        .unwrap_or_else(|_| Response::new(full_body(Bytes::from_static(b"auth required"))))
}

/// Parse a `Proxy-Authorization: Basic <base64(user:pass)>` header into `(user, pass)`.
fn parse_proxy_auth(headers: &hyper::HeaderMap) -> Option<(String, String)> {
    let raw = headers.get("proxy-authorization")?.to_str().ok()?;
    let b64 = raw
        .strip_prefix("Basic ")
        .or_else(|| raw.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (user, pass) = text.split_once(':')?;
    Some((user.to_string(), pass.to_string()))
}

/// Whether `name` is a hop-by-hop / proxy-only header that must not be forwarded.
fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "proxy-authorization"
            | "proxy-connection"
            | "connection"
            | "keep-alive"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

async fn access_log(ctx: &ForwardCtx, line: &str, status: u16) {
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
            message: format!("forward {line} {status}"),
            at: Utc::now(),
            meta: None,
        })
        .await;
}

/// Handle one forward-proxy request: source gate, auth gate, destination gate, then
/// either tunnel (`CONNECT`) or fetch (absolute-URI HTTP).
async fn forward_handle(
    req: Request<Incoming>,
    peer_ip: IpAddr,
    ctx: &ForwardCtx,
) -> Result<Response<ProxyBody>, Infallible> {
    // 1. Source rules.
    let rules = match ctx.db.list_forward_rules().await {
        Ok(r) => r,
        Err(_) => {
            return Ok(status_response(
                StatusCode::BAD_GATEWAY,
                "設定の読み込みに失敗しました。",
            ))
        }
    };
    if forward_source_decision(&rules, peer_ip) == AclAction::Deny {
        access_log(ctx, &format!("{peer_ip} source-deny"), 403).await;
        return Ok(status_response(
            StatusCode::FORBIDDEN,
            "アクセスが拒否されました。",
        ));
    }

    // 2. Authentication (only when at least one enabled forward user exists).
    match ctx.db.has_enabled_forward_users().await {
        Ok(true) => {
            let ok = match parse_proxy_auth(req.headers()) {
                Some((user, pass)) => ctx
                    .db
                    .verify_forward_user(&user, &pass)
                    .await
                    .unwrap_or(false),
                None => false,
            };
            if !ok {
                access_log(ctx, &format!("{peer_ip} auth-required"), 407).await;
                return Ok(proxy_auth_required());
            }
        }
        Ok(false) => {}
        Err(_) => {
            return Ok(status_response(
                StatusCode::BAD_GATEWAY,
                "認証情報の確認に失敗しました。",
            ))
        }
    }

    // 3. CONNECT tunnel vs absolute-URI fetch.
    if req.method() == Method::CONNECT {
        forward_connect(req, peer_ip, ctx, &rules).await
    } else {
        forward_http(req, peer_ip, ctx, &rules).await
    }
}

/// `CONNECT host:port` — destination gate, then splice the upgraded client stream to
/// a fresh TCP connection to the target.
async fn forward_connect(
    req: Request<Incoming>,
    peer_ip: IpAddr,
    ctx: &ForwardCtx,
    rules: &[magnetite_core::domains::proxy::model::ForwardRule],
) -> Result<Response<ProxyBody>, Infallible> {
    let Some(authority) = req.uri().authority().cloned() else {
        return Ok(status_response(
            StatusCode::BAD_REQUEST,
            "CONNECT の宛先が不正です。",
        ));
    };
    let host = authority.host().to_string();
    let port = authority.port_u16().unwrap_or(443);
    if forward_dest_decision(rules, &host) == AclAction::Deny {
        access_log(
            ctx,
            &format!("{peer_ip} CONNECT {host}:{port} dest-deny"),
            403,
        )
        .await;
        return Ok(status_response(
            StatusCode::FORBIDDEN,
            "宛先が拒否されました。",
        ));
    }
    let target = format!("{host}:{port}");
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let mut client_io = TokioIo::new(upgraded);
                match TcpStream::connect(&target).await {
                    Ok(mut server) => {
                        let _ = copy_bidirectional(&mut client_io, &mut server).await;
                    }
                    Err(e) => tracing::debug!("forward CONNECT dial {target} failed: {e}"),
                }
            }
            Err(e) => tracing::debug!("forward CONNECT upgrade failed: {e}"),
        }
    });
    access_log(ctx, &format!("{peer_ip} CONNECT {host}:{port}"), 200).await;
    // 200 with an empty body triggers the upgrade.
    Ok(Response::new(full_body(Bytes::new())))
}

/// Absolute-URI HTTP (`GET http://host/path`) — destination gate, then fetch via the
/// forward client and relay the response.
async fn forward_http(
    req: Request<Incoming>,
    peer_ip: IpAddr,
    ctx: &ForwardCtx,
    rules: &[magnetite_core::domains::proxy::model::ForwardRule],
) -> Result<Response<ProxyBody>, Infallible> {
    let host = req.uri().host().unwrap_or_default().to_string();
    if host.is_empty() {
        return Ok(status_response(
            StatusCode::BAD_REQUEST,
            "絶対URIのリクエストのみ転送できます。",
        ));
    }
    let port = req.uri().port_u16().unwrap_or(80);
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_string();
    if forward_dest_decision(rules, &host) == AclAction::Deny {
        access_log(ctx, &format!("{peer_ip} {host} dest-deny"), 403).await;
        return Ok(status_response(
            StatusCode::FORBIDDEN,
            "宛先が拒否されました。",
        ));
    }

    let (parts, body) = req.into_parts();
    // Buffer the request body to re-send it, always under a bounded cap (the configured
    // `max_body` or the default ceiling) so a client can't exhaust memory by streaming an
    // unbounded body through the forward proxy — even when no limit is configured.
    let collected = match Limited::new(body, ctx.body_cap()).collect().await {
        Ok(b) => b.to_bytes(),
        Err(_) => {
            access_log(ctx, &format!("{peer_ip} {host} body-too-large"), 413).await;
            return Ok(status_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "リクエストボディが大きすぎます。",
            ));
        }
    };
    let mut builder = Request::builder()
        .method(parts.method.clone())
        .uri(parts.uri.clone());
    for (name, value) in parts.headers.iter() {
        if !is_hop_by_hop(name.as_str()) {
            builder = builder.header(name, value);
        }
    }
    let upstream_req = match builder.body(Full::new(collected)) {
        Ok(r) => r,
        Err(_) => {
            return Ok(status_response(
                StatusCode::BAD_GATEWAY,
                "リクエストの再構築に失敗しました。",
            ))
        }
    };

    match ctx.client.request(upstream_req).await {
        Ok(resp) => {
            let status = resp.status();
            let (rparts, rbody) = resp.into_parts();
            access_log(
                ctx,
                &format!("{peer_ip} {} {host}:{port}{path}", parts.method),
                status.as_u16(),
            )
            .await;
            // STREAM the upstream response to the client rather than buffering it whole:
            // `Limited` still bounds it (the configured `max_body` or the default ceiling),
            // but the body flows through a chunk at a time, so per-connection memory stays
            // ~one chunk and aggregate memory under concurrency does not blow up. A body
            // that exceeds the cap errors mid-stream (the client sees a truncated response)
            // — headers are already sent, so a 502 is no longer possible, the inherent
            // trade-off of streaming (M-7').
            let body = Limited::new(rbody, ctx.body_cap()).boxed_unsync();
            let mut out = Response::new(body);
            *out.status_mut() = status;
            *out.headers_mut() = rparts.headers;
            Ok(out)
        }
        Err(e) => {
            tracing::debug!("forward fetch {host}:{port} failed: {e}");
            access_log(
                ctx,
                &format!("{peer_ip} {} {host}:{port}{path}", parts.method),
                502,
            )
            .await;
            Ok(status_response(
                StatusCode::BAD_GATEWAY,
                "上流への接続に失敗しました。",
            ))
        }
    }
}

/// The forward-proxy accept loop: bind `addr`, serve each connection with CONNECT
/// upgrades enabled, until `shutdown` flips.
pub(crate) async fn run_forward(
    addr: SocketAddr,
    ctx: ForwardCtx,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("proxy server listening on {addr} (forward)");

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
                        async move { forward_handle(req, peer_ip, &ctx).await }
                    });
                    if let Err(e) = http1::Builder::new()
                        .serve_connection(io, service)
                        .with_upgrades()
                        .await
                    {
                        tracing::debug!("forward proxy connection error: {e}");
                    }
                });
            }
        }
    }
    Ok(())
}
