//! Certificate-export API (`GET /export/certificate/<name>`). Lets an application
//! behind the proxy fetch a managed certificate's PEM + private key, so it can run
//! its own TLS from the same certificate the proxy serves (and re-fetch after an ACME
//! renewal) — a pull-based equivalent of certbot's `--deploy-hook`.
//!
//! This hands out a **private key**, so it is hardened accordingly:
//!   - **TLS required.** The main server terminates plain HTTP (TLS is fronted by the
//!     proxy/ingress), so a request must carry `X-Forwarded-Proto: https` set by that
//!     front; otherwise it is refused. `allow_insecure` bypasses this for a trusted
//!     direct-TLS / test setup only.
//!   - **Per-token authorization.** Each `[cert_export]` token may export only the
//!     certificates in its `certs` list — a leaked token exposes only its own certs,
//!     not the whole `certificate` table.
//!   - **Failure auditing + rate limiting.** A bad token, an unauthorized cert, or a
//!     miss is audited with the peer IP, and repeated failures from one IP lock it out.

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use magnetite_core::authz::Role;
use magnetite_core::config::{CertExportConfig, CertExportToken};
use magnetite_core::domain::DomainKey;
use magnetite_core::models::common::{ActionKind, OpResult};
use magnetite_core::models::NewAuditEntry;
use magnetite_db::Db;
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Failures from one IP within [`LOCKOUT_WINDOW`] before it is locked out.
const MAX_FAILURES: u32 = 10;
/// Sliding window over which failures are counted (also the lockout duration).
const LOCKOUT_WINDOW: Duration = Duration::from_secs(300);
/// Minimum length of a configured export token. Short tokens are brute-forceable and an
/// empty one would be presentable as a bare `Authorization: Bearer `; both are rejected
/// at startup (fail-closed) rather than mounted.
const MIN_TOKEN_LEN: usize = 16;

/// Validate a `[cert_export]` block at startup, fail-closed: the mount is refused (and
/// the daemon does not start) if any of these hold, since each would make a private-key
/// API unsafe or useless.
///
/// # Errors
/// Returns a human-readable reason when: no trusted proxy is configured while
/// `allow_insecure` is off (the API would refuse every request); a token is
/// empty/blank or shorter than [`MIN_TOKEN_LEN`]; a token authorizes no certificates; or
/// a `trusted_proxies` entry is not a valid IP/CIDR.
pub fn validate_cert_export(cfg: &CertExportConfig) -> Result<(), String> {
    if !cfg.allow_insecure && cfg.trusted_proxies.is_empty() {
        return Err(
            "no trusted_proxies set and allow_insecure is false — the API would \
                    refuse every request; list your TLS front(s) in trusted_proxies"
                .into(),
        );
    }
    for p in &cfg.trusted_proxies {
        let net = p.split_once('/').map(|(n, _)| n).unwrap_or(p);
        if net.trim().parse::<IpAddr>().is_err() {
            return Err(format!(
                "trusted_proxies entry '{p}' is not a valid IP or CIDR"
            ));
        }
    }
    for (i, t) in cfg.tokens.iter().enumerate() {
        let n = i + 1;
        if t.token.trim().is_empty() {
            return Err(format!("token #{n} is empty/blank"));
        }
        if t.token.len() < MIN_TOKEN_LEN {
            return Err(format!(
                "token #{n} is shorter than {MIN_TOKEN_LEN} characters"
            ));
        }
        if t.certs.is_empty() {
            return Err(format!("token #{n} authorizes no certificates"));
        }
    }
    Ok(())
}

#[derive(Clone)]
struct CertExportState {
    db: Db,
    /// Bypass the TLS-required check (trusted direct-TLS / test only).
    allow_insecure: bool,
    /// IPs/CIDRs of the TLS-terminating fronts whose `X-Forwarded-*` headers are trusted.
    trusted_proxies: Arc<Vec<String>>,
    tokens: Arc<Vec<CertExportToken>>,
    limiter: RateLimiter,
}

/// Per-IP failure tracker: locks an IP out after too many recent failures.
#[derive(Clone, Default)]
struct RateLimiter {
    failures: Arc<Mutex<HashMap<IpAddr, Attempts>>>,
}

/// Failure bookkeeping for one client IP.
struct Attempts {
    count: u32,
    window_start: Instant,
}

impl RateLimiter {
    /// Whether `ip` is currently locked out (too many recent failures).
    fn is_locked_out(&self, ip: IpAddr) -> bool {
        let mut map = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        match map.get(&ip) {
            Some(a) if a.window_start.elapsed() < LOCKOUT_WINDOW => a.count >= MAX_FAILURES,
            Some(_) => {
                map.remove(&ip); // window elapsed — forget it
                false
            }
            None => false,
        }
    }

    /// Count a failure for `ip`, starting a fresh window if the last one elapsed.
    fn record_failure(&self, ip: IpAddr) {
        let mut map = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        let entry = map.entry(ip).or_insert(Attempts {
            count: 0,
            window_start: Instant::now(),
        });
        if entry.window_start.elapsed() >= LOCKOUT_WINDOW {
            entry.count = 0;
            entry.window_start = Instant::now();
        }
        entry.count = entry.count.saturating_add(1);
    }

    /// Clear an IP's failure record after a successful, authorized request.
    fn clear(&self, ip: IpAddr) {
        self.failures
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&ip);
    }
}

/// The router exposing the certificate-export API. Mounted only when `[cert_export]`
/// is enabled with at least one token.
pub fn cert_export_router(db: Db, cfg: &CertExportConfig) -> Router {
    Router::new()
        .route("/export/certificate/{name}", get(serve_export))
        .with_state(CertExportState {
            db,
            allow_insecure: cfg.allow_insecure,
            trusted_proxies: Arc::new(cfg.trusted_proxies.clone()),
            tokens: Arc::new(cfg.tokens.clone()),
            limiter: RateLimiter::default(),
        })
}

/// Whether `ip` falls within `cidr`. A bare IP literal (no `/prefix`) matches only
/// itself. Malformed entries never match. Self-contained so the server crate needs no
/// dependency on the proxy's router for this small check.
fn ip_in_cidr(cidr: &str, ip: IpAddr) -> bool {
    let (net_s, prefix_s) = cidr.split_once('/').unwrap_or((cidr, ""));
    match (net_s.trim().parse::<IpAddr>(), ip) {
        (Ok(IpAddr::V4(net)), IpAddr::V4(addr)) => {
            let prefix: u32 = prefix_s.parse().unwrap_or(32).min(32);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(net) & mask) == (u32::from(addr) & mask)
        }
        (Ok(IpAddr::V6(net)), IpAddr::V6(addr)) => {
            let prefix: u32 = prefix_s.parse().unwrap_or(128).min(128);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            (u128::from(net) & mask) == (u128::from(addr) & mask)
        }
        _ => false,
    }
}

/// Whether the immediate TCP peer is one of the configured trusted fronts.
fn peer_is_trusted(peer: IpAddr, trusted: &[String]) -> bool {
    trusted.iter().any(|c| ip_in_cidr(c, peer))
}

/// The real client IP for audit + rate limiting. When the peer is a trusted proxy, take
/// the RIGHTMOST `X-Forwarded-For` entry — the address that proxy actually saw and
/// appended — so a client cannot shift blame by prepending forged entries. `X-Forwarded-For`
/// from a NON-trusted peer is ignored (an attacker could forge it), falling back to the
/// direct peer.
fn client_ip(peer: IpAddr, headers: &HeaderMap, trusted: &[String]) -> IpAddr {
    if peer_is_trusted(peer, trusted) {
        if let Some(last) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|xff| xff.rsplit(',').next())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
        {
            return last;
        }
    }
    peer
}

/// Length-checked constant-time token comparison.
fn bearer_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The presented `Authorization: Bearer <token>`, if any.
fn presented_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

/// The token entry matching the presented bearer, if any. Compares (constant-time)
/// against every configured token without short-circuiting, so a miss cannot be told
/// apart from a hit by timing.
fn match_token<'a>(
    tokens: &'a [CertExportToken],
    headers: &HeaderMap,
) -> Option<&'a CertExportToken> {
    let presented = presented_token(headers)?;
    let mut found = None;
    for t in tokens {
        if bearer_eq(presented, &t.token) {
            found = Some(t);
        }
    }
    found
}

/// Whether the request reached us over TLS. `X-Forwarded-Proto: https` is trusted ONLY
/// when set by a trusted proxy peer — a direct connection to the plaintext port cannot
/// assert TLS by forging the header, so it is refused (unless `allow_insecure`).
fn arrived_over_tls(peer: IpAddr, headers: &HeaderMap, trusted: &[String]) -> bool {
    peer_is_trusted(peer, trusted)
        && headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("https"))
            .unwrap_or(false)
}

/// Audit one export attempt (success or failure) with the peer IP.
async fn audit(db: &Db, name: &str, ip: String, result: OpResult) {
    let _ = db
        .append_audit(NewAuditEntry {
            actor: "cert-export".to_string(),
            actor_role: Role::Operator,
            domain: DomainKey::Proxy,
            action: ActionKind::Control,
            target_kind: "certificate".to_string(),
            target_id: name.to_string(),
            result,
            ip,
            detail: None,
        })
        .await;
}

/// `GET /export/certificate/<name>` — return the certificate's PEM chain + private
/// key as JSON, for a token authorized for that certificate. `429` when the IP is
/// locked out, `403` when not over TLS or the token lacks this cert, `401` for a
/// bad/absent token, `404` when the cert has no key material.
async fn serve_export(
    State(state): State<CertExportState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> axum::response::Response {
    // The real client IP (via a trusted proxy's XFF, else the direct peer): keys the
    // audit + rate limit so one client's failures cannot lock out everyone behind a
    // shared proxy IP, and the audit trail names the actual client.
    let ip = client_ip(peer.ip(), &headers, &state.trusted_proxies);
    let ip_s = ip.to_string();

    // 1. Rate-limit gate.
    if state.limiter.is_locked_out(ip) {
        tracing::warn!(target: "auth", proto = "cert-export", ip = %ip_s, "cert-export locked out (too many recent failures)");
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "too many failed attempts; try again later" })),
        )
            .into_response();
    }

    // 2. TLS required (the response carries a private key). Trusted only from a
    // configured proxy peer, so a direct hit on the plaintext port cannot forge it.
    if !state.allow_insecure && !arrived_over_tls(peer.ip(), &headers, &state.trusted_proxies) {
        tracing::warn!(target: "auth", proto = "cert-export", ip = %ip_s, "cert-export refused: request not over TLS (untrusted peer or X-Forwarded-Proto != https)");
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "must be requested over TLS" })),
        )
            .into_response();
    }

    // 3. Authenticate the bearer token.
    let Some(scope) = match_token(&state.tokens, &headers) else {
        state.limiter.record_failure(ip);
        audit(&state.db, &name, ip_s.clone(), OpResult::Failure).await;
        tracing::warn!(target: "auth", proto = "cert-export", ip = %ip_s, cert = %name, "cert-export 401: absent or invalid token");
        return StatusCode::UNAUTHORIZED.into_response();
    };

    // 4. Authorize this token for the requested certificate.
    if !scope.certs.iter().any(|c| c == &name) {
        state.limiter.record_failure(ip);
        audit(&state.db, &name, ip_s.clone(), OpResult::Failure).await;
        tracing::warn!(target: "auth", proto = "cert-export", ip = %ip_s, cert = %name, "cert-export 403: token not authorized for this certificate");
        return StatusCode::FORBIDDEN.into_response();
    }

    // 5. Serve the material.
    match state.db.get_certificate_material(&name).await {
        Ok(Some(material)) => {
            state.limiter.clear(ip);
            audit(&state.db, &name, ip_s.clone(), OpResult::Success).await;
            tracing::info!(target: "auth", proto = "cert-export", ip = %ip_s, cert = %name, "cert-export ok");
            Json(json!({
                "name": name,
                "certificate": material.cert_chain_pem,
                "private_key": material.key_pem,
            }))
            .into_response()
        }
        Ok(None) => {
            audit(&state.db, &name, ip_s, OpResult::Failure).await;
            (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": format!("no certificate '{name}' with key material") })),
            )
                .into_response()
        }
        Err(e) => {
            audit(&state.db, &name, ip_s, OpResult::Failure).await;
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdr(auth: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(a) = auth {
            h.insert(
                header::AUTHORIZATION,
                format!("Bearer {a}").parse().unwrap(),
            );
        }
        h
    }

    #[test]
    fn bearer_eq_matches_only_the_exact_token() {
        assert!(bearer_eq("s3cret-token", "s3cret-token"));
        assert!(!bearer_eq("s3cret-token", "s3cret-toke"));
        assert!(!bearer_eq("s3cret-token", "S3cret-token"));
        assert!(!bearer_eq("", "x"));
        assert!(bearer_eq("", ""));
    }

    #[test]
    fn match_token_selects_the_right_scope() {
        let toks = vec![
            CertExportToken {
                token: "app-a".into(),
                certs: vec!["a.example".into()],
            },
            CertExportToken {
                token: "app-b".into(),
                certs: vec!["b.example".into()],
            },
        ];
        assert!(match_token(&toks, &hdr(None)).is_none());
        assert!(match_token(&toks, &hdr(Some("nope"))).is_none());
        let a = match_token(&toks, &hdr(Some("app-a"))).unwrap();
        assert_eq!(a.certs, vec!["a.example".to_string()]);
        let b = match_token(&toks, &hdr(Some("app-b"))).unwrap();
        assert_eq!(b.certs, vec!["b.example".to_string()]);
    }

    const PROXY: [&str; 1] = ["10.0.0.0/8"];

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn tls_trusted_only_from_a_proxy_peer() {
        let trusted = PROXY.map(String::from);
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        // From a trusted proxy peer, X-Forwarded-Proto: https is honoured.
        assert!(arrived_over_tls(ip("10.1.2.3"), &h, &trusted));
        // The SAME header from a non-trusted (direct) peer is NOT trusted — an attacker
        // hitting the plaintext port cannot forge TLS.
        assert!(!arrived_over_tls(ip("203.0.113.9"), &h, &trusted));
        // A trusted peer without the header is not TLS either.
        assert!(!arrived_over_tls(
            ip("10.1.2.3"),
            &HeaderMap::new(),
            &trusted
        ));
    }

    #[test]
    fn client_ip_uses_xff_only_from_a_trusted_proxy() {
        let trusted = PROXY.map(String::from);
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "198.51.100.7".parse().unwrap());
        // Behind a trusted proxy, the client IP comes from XFF (the real client).
        assert_eq!(client_ip(ip("10.1.2.3"), &h, &trusted), ip("198.51.100.7"));
        // From a non-trusted peer, XFF is ignored (forgeable) → the direct peer.
        assert_eq!(
            client_ip(ip("203.0.113.9"), &h, &trusted),
            ip("203.0.113.9")
        );
        // Multiple hops: the RIGHTMOST entry (appended by our trusted proxy) wins, so a
        // client prepending a forged entry cannot shift the recorded IP.
        let mut multi = HeaderMap::new();
        multi.insert("x-forwarded-for", "1.1.1.1, 198.51.100.7".parse().unwrap());
        assert_eq!(
            client_ip(ip("10.1.2.3"), &multi, &trusted),
            ip("198.51.100.7")
        );
    }

    #[test]
    fn ip_in_cidr_matches_v4_and_v6() {
        assert!(ip_in_cidr("10.0.0.0/8", ip("10.9.9.9")));
        assert!(!ip_in_cidr("10.0.0.0/8", ip("11.0.0.1")));
        assert!(ip_in_cidr("192.168.1.5", ip("192.168.1.5"))); // bare IP = /32
        assert!(!ip_in_cidr("192.168.1.5", ip("192.168.1.6")));
        assert!(ip_in_cidr("2001:db8::/32", ip("2001:db8::1")));
        assert!(!ip_in_cidr("2001:db8::/32", ip("2001:dead::1")));
    }

    #[test]
    fn validate_rejects_unsafe_configs() {
        use magnetite_core::config::CertExportConfig;
        let tok = |t: &str| CertExportToken {
            token: t.into(),
            certs: vec!["a.example".into()],
        };
        // No trusted proxy + not allow_insecure ⇒ refuse-all ⇒ rejected.
        let mut c = CertExportConfig {
            enabled: true,
            allow_insecure: false,
            trusted_proxies: vec![],
            tokens: vec![tok("a-sufficiently-long-token")],
        };
        assert!(validate_cert_export(&c).is_err());
        // Add a trusted proxy: now valid.
        c.trusted_proxies = vec!["10.0.0.0/8".into()];
        assert!(validate_cert_export(&c).is_ok());
        // An empty token is rejected.
        c.tokens = vec![tok("")];
        assert!(validate_cert_export(&c).is_err());
        // A short token is rejected.
        c.tokens = vec![tok("short")];
        assert!(validate_cert_export(&c).is_err());
        // A token with no certs is rejected.
        c.tokens = vec![CertExportToken {
            token: "a-sufficiently-long-token".into(),
            certs: vec![],
        }];
        assert!(validate_cert_export(&c).is_err());
        // A malformed trusted_proxies entry is rejected.
        c.tokens = vec![tok("a-sufficiently-long-token")];
        c.trusted_proxies = vec!["not-an-ip".into()];
        assert!(validate_cert_export(&c).is_err());
    }

    #[test]
    fn rate_limiter_locks_out_after_threshold_and_clears() {
        let rl = RateLimiter::default();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert!(!rl.is_locked_out(ip));
        for _ in 0..MAX_FAILURES {
            rl.record_failure(ip);
        }
        assert!(rl.is_locked_out(ip), "locked out at the threshold");
        rl.clear(ip);
        assert!(!rl.is_locked_out(ip), "cleared after a success");
    }
}
