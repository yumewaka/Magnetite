//! Dynamic-DNS **client**: push Magnetite's current public IP to an external DDNS provider
//! (No-IP / DynDNS / DuckDNS …). Settings are DB-backed and hot-reloaded; a scheduler runs
//! one update per day at the configured local time, and the Web UI can trigger one on demand.
//!
//! Unlike the internal replication feeds, this talks to public providers over the internet,
//! so it verifies TLS certificates against the bundled webpki roots.

use base64::Engine;
use bytes::Bytes;
use chrono::{Local, NaiveTime, Timelike};
use http_body_util::{BodyExt, Empty};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use magnetite_core::domains::dns::model::{DdnsConfig, DdnsMode, DdnsStatus};
use magnetite_db::Db;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// How often the scheduler wakes to check whether it is time for the daily update. Small so
/// a Web-UI schedule/settings change is honoured promptly; the check is a cheap DB read.
const POLL_INTERVAL: Duration = Duration::from_secs(60);

/// Total update attempts before giving up (retries only transport/non-2xx failures — see
/// `perform_update`). Kept low to avoid hammering a provider (spam-ban risk).
const MAX_ATTEMPTS: u32 = 3;
/// Delay between retry attempts.
const RETRY_DELAY: Duration = Duration::from_secs(3);

/// A real-cert-verifying rustls client config (bundled webpki roots + explicit ring provider,
/// so it never depends on a process-default CryptoProvider being installed).
fn client_config() -> rustls::ClientConfig {
    use hyper_rustls::ConfigBuilderExt;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default protocol versions")
        .with_webpki_roots()
        .with_no_client_auth()
}

/// `GET url` with an optional Basic-auth credential; returns `(status, body)`.
async fn http_get(url: &str, basic: Option<(&str, &str)>) -> anyhow::Result<(u16, String)> {
    let uri: hyper::Uri = url.parse()?;
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(client_config())
        .https_or_http()
        .enable_http1()
        .build();
    let client = Client::builder(TokioExecutor::new()).build(https);
    let mut req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(uri)
        // Some providers reject a request without a User-Agent (per the DynDNS spec).
        .header("user-agent", "magnetite-ddns/1.0");
    if let Some((user, pass)) = basic {
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        req = req.header("authorization", format!("Basic {token}"));
    }
    let resp = client.request(req.body(Empty::<Bytes>::new())?).await?;
    let status = resp.status().as_u16();
    let body = resp.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8_lossy(&body).trim().to_string()))
}

/// Fetch the public IP from `source` (a URL returning the bare IP as text), best-effort.
async fn detect_public_ip(source: &str) -> Option<String> {
    match http_get(source, None).await {
        Ok((200, body)) => {
            let ip = body.trim();
            // Accept only something that parses as an IP address.
            ip.parse::<std::net::IpAddr>().ok().map(|_| ip.to_string())
        }
        _ => None,
    }
}

/// Perform one dynamic-DNS update per `config`, returning the outcome (never panics; every
/// failure is captured as a non-ok status). Callable from the scheduler and the Web UI.
pub async fn perform_update(config: &DdnsConfig) -> DdnsStatus {
    let now = chrono::Utc::now().to_rfc3339();
    let mut status = DdnsStatus {
        last_run: Some(now),
        ..Default::default()
    };
    if !config.enabled {
        status.last_message = "無効化されています。".to_string();
        return status;
    }

    // Resolve the IP to advertise (empty ⇒ let the provider detect it from the request).
    let ip = match config.public_ip_source.as_deref().map(str::trim) {
        Some(src) if !src.is_empty() => match detect_public_ip(src).await {
            Some(ip) => Some(ip),
            None => {
                status.last_message = format!("公開IPの取得に失敗しました（{src}）。");
                return status;
            }
        },
        _ => None,
    };
    status.last_ip = ip.clone();

    // Owned Basic-auth credentials (borrowed into `http_get` below).
    let (url, basic): (String, Option<(String, String)>) = match config.mode {
        DdnsMode::Dyndns => {
            if config.server.trim().is_empty() || config.hostname.trim().is_empty() {
                status.last_message = "サーバとホスト名は必須です。".to_string();
                return status;
            }
            // Accept a full URL or a bare host (defaulted to the standard /nic/update path).
            let base =
                if config.server.starts_with("http://") || config.server.starts_with("https://") {
                    config.server.trim().to_string()
                } else {
                    format!("https://{}/nic/update", config.server.trim())
                };
            let sep = if base.contains('?') { '&' } else { '?' };
            let mut url = format!("{base}{sep}hostname={}", config.hostname.trim());
            if let Some(ip) = &ip {
                url.push_str(&format!("&myip={ip}"));
            }
            (
                url,
                Some((config.username.trim().to_string(), config.password.clone())),
            )
        }
        DdnsMode::Template => {
            if config.url_template.trim().is_empty() {
                status.last_message = "URLテンプレートが未設定です。".to_string();
                return status;
            }
            let url = config
                .url_template
                .trim()
                .replace("{host}", config.hostname.trim())
                .replace("{ip}", ip.as_deref().unwrap_or(""))
                .replace("{user}", config.username.trim())
                .replace("{pass}", config.password.as_str());
            // Basic auth for generic providers (e.g. MyDNS): prefer `user:pass@` userinfo in
            // the URL (stripped, since it must go in the header, not the request-target), else
            // the configured username/password if a username is set.
            let (url, userinfo) = split_userinfo(&url);
            let basic = userinfo.or_else(|| {
                let u = config.username.trim();
                (!u.is_empty()).then(|| (u.to_string(), config.password.clone()))
            });
            (url, basic)
        }
    };

    let basic_ref = basic.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
    // Retry on transport/non-2xx failures only — a provider like MyDNS.JP round-robins
    // `www.mydns.jp` across many IPs, so one attempt may hit a node that is down (connect
    // error / 5xx) while another works. A 2xx with a definitive negative body (bad creds →
    // `login_status = 0`) is NOT retried: it is a real answer from a working node, and
    // hammering the provider risks a spam ban.
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let transient = match http_get(&url, basic_ref).await {
            Ok((code, body)) => {
                let ok = update_succeeded(config.mode, code, &body);
                status.last_ok = ok;
                // DynDNS `good <ip>` / `nochg <ip>` echoes the accepted IP.
                if status.last_ip.is_none() {
                    if let Some(echoed) = body.split_whitespace().nth(1) {
                        if echoed.parse::<std::net::IpAddr>().is_ok() {
                            status.last_ip = Some(echoed.to_string());
                        }
                    }
                }
                status.last_message = summarize_response(code, &body);
                // Only a non-2xx is transient (worth another node); a 2xx answer is final.
                !(200..300).contains(&code)
            }
            Err(e) => {
                status.last_ok = false;
                status.last_message = format!("送信に失敗しました: {e}");
                true
            }
        };
        if status.last_ok || !transient || attempt >= MAX_ATTEMPTS {
            break;
        }
        tokio::time::sleep(RETRY_DELAY).await;
    }
    status
}

/// A compact, non-truncated-where-it-matters result summary. Providers like MyDNS.JP answer
/// with a whole HTML page whose `login_status` / `notify OK|NG` line is the real outcome, so
/// surface that up front (it used to be cut off by a 200-char slice), then include a
/// whitespace-collapsed snippet of the body.
fn summarize_response(code: u16, body: &str) -> String {
    let low = body.to_ascii_lowercase();
    let note = if let Some(ok) = extract_login_status(&low) {
        format!(" [login_status={}]", u8::from(ok))
    } else if low.contains("notify ok") {
        " [notify OK]".to_string()
    } else if low.contains("notify ng") {
        " [notify NG]".to_string()
    } else {
        String::new()
    };
    let snippet: String = body
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(500)
        .collect();
    format!("HTTP {code}{note}: {snippet}")
}

/// Extract MyDNS's `login_status = 1|0` (flexible whitespace / `=`) from a lowercased body:
/// `Some(true)` = notify OK, `Some(false)` = notify NG, `None` = not a MyDNS status body.
fn extract_login_status(body_lower: &str) -> Option<bool> {
    let idx = body_lower.find("login_status")?;
    let rest = body_lower[idx + "login_status".len()..]
        .trim_start()
        .trim_start_matches('=')
        .trim_start();
    match rest.chars().next()? {
        '1' => Some(true),
        '0' => Some(false),
        _ => None,
    }
}

/// Split a `scheme://user:pass@host/…` URL into `(url_without_userinfo, Some((user, pass)))`,
/// or `(url, None)` when there is no userinfo. Basic-auth credentials belong in the
/// `Authorization` header, not the request-target, so they are extracted here.
fn split_userinfo(url: &str) -> (String, Option<(String, String)>) {
    let Some(scheme_end) = url.find("://") else {
        return (url.to_string(), None);
    };
    let after = &url[scheme_end + 3..];
    // Userinfo, if any, precedes the first '@' and cannot contain '/'.
    let Some(at) = after.find('@') else {
        return (url.to_string(), None);
    };
    if after[..at].contains('/') {
        return (url.to_string(), None);
    }
    let (user, pass) = match after[..at].split_once(':') {
        Some((u, p)) => (u.to_string(), p.to_string()),
        None => (after[..at].to_string(), String::new()),
    };
    let clean = format!("{}{}", &url[..scheme_end + 3], &after[at + 1..]);
    (clean, Some((user, pass)))
}

/// Whether a provider response indicates success.
fn update_succeeded(mode: DdnsMode, code: u16, body: &str) -> bool {
    if !(200..300).contains(&code) {
        return false;
    }
    let b = body.trim().to_ascii_lowercase();
    match mode {
        // DynDNS v2: `good`/`nochg` = success; `nohost`/`badauth`/`abuse`/`911`/… = failure.
        DdnsMode::Dyndns => b.starts_with("good") || b.starts_with("nochg"),
        // Generic providers judged by BODY (many, incl. MyDNS.JP, return 200 even on auth
        // failure — a 2xx alone must NOT be treated as success):
        //   - MyDNS: `login_status = 1` (notify OK) succeeds, `= 0` (notify NG) fails.
        //   - `notify ok` / `notify ng` markers.
        //   - DuckDNS `KO` / `err…` fail.
        //   - otherwise a 2xx with no explicit failure token is success (DuckDNS `OK`, empty).
        DdnsMode::Template => {
            if let Some(ok) = extract_login_status(&b) {
                return ok;
            }
            if b.contains("notify ng") {
                return false;
            }
            if b.contains("notify ok") {
                return true;
            }
            b != "ko" && !b.starts_with("err")
        }
    }
}

/// Parse `HH:MM` into a time-of-day, defaulting to 03:00 on garbage.
fn parse_hhmm(s: &str) -> NaiveTime {
    let mut parts = s.trim().splitn(2, ':');
    let h = parts
        .next()
        .and_then(|p| p.trim().parse::<u32>().ok())
        .unwrap_or(3);
    let m = parts
        .next()
        .and_then(|p| p.trim().parse::<u32>().ok())
        .unwrap_or(0);
    NaiveTime::from_hms_opt(h.min(23), m.min(59), 0).unwrap_or_default()
}

/// Whether the daily update is due now: enabled, the local time has reached the configured
/// `HH:MM`, and it has not already run today (from `last_run`, an RFC3339 UTC timestamp).
fn is_due(config: &DdnsConfig, last_run: Option<&str>) -> bool {
    if !config.enabled {
        return false;
    }
    let now = Local::now();
    let target = parse_hhmm(&config.update_time);
    let now_minutes = now.hour() * 60 + now.minute();
    let target_minutes = target.hour() * 60 + target.minute();
    if now_minutes < target_minutes {
        return false;
    }
    // Already ran today? Compare the last-run date (converted to local) to today's date.
    match last_run.and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok()) {
        Some(dt) => dt.with_timezone(&Local).date_naive() < now.date_naive(),
        None => true,
    }
}

/// Run the DDNS scheduler until shutdown: seed the settings from `seed` on first run, then
/// every [`POLL_INTERVAL`] re-read the DB settings and, when the daily update is due, perform
/// it and record the result. Runtime settings/schedule edits (Web UI) take effect next poll.
pub async fn run_scheduler(db: Db, seed: Option<DdnsConfig>, mut shutdown: watch::Receiver<bool>) {
    if let Err(e) = db.ensure_ddns_config(seed).await {
        tracing::warn!("ddns: could not seed settings: {e}");
    }
    tracing::info!("ddns: scheduler started (settings DB-backed / hot-reloaded)");
    loop {
        tokio::select! {
            _ = tokio::time::sleep(POLL_INTERVAL) => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
        }
        let config = match db.get_ddns_config().await {
            Ok(Some(c)) => c,
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!("ddns: could not read settings ({e})");
                continue;
            }
        };
        let last_run = db.get_ddns_status().await.ok().and_then(|s| s.last_run);
        if is_due(&config, last_run.as_deref()) {
            tracing::info!("ddns: daily update due for '{}' — sending", config.hostname);
            let status = perform_update(&config).await;
            if status.last_ok {
                tracing::info!("ddns: update ok ({})", status.last_message);
            } else {
                tracing::warn!("ddns: update failed ({})", status.last_message);
            }
            if let Err(e) = db.record_ddns_status(&status).await {
                tracing::warn!("ddns: could not record status: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(mode: DdnsMode) -> DdnsConfig {
        DdnsConfig {
            enabled: true,
            mode,
            server: "dynupdate.no-ip.com".into(),
            hostname: "home.example.com".into(),
            username: "u".into(),
            password: "p".into(),
            url_template: "https://www.duckdns.org/update?domains={host}&token={pass}&ip={ip}"
                .into(),
            public_ip_source: None,
            update_time: "03:00".into(),
        }
    }

    #[test]
    fn dyndns_success_codes() {
        assert!(update_succeeded(DdnsMode::Dyndns, 200, "good 203.0.113.5"));
        assert!(update_succeeded(DdnsMode::Dyndns, 200, "nochg 203.0.113.5"));
        assert!(!update_succeeded(DdnsMode::Dyndns, 200, "badauth"));
        assert!(!update_succeeded(DdnsMode::Dyndns, 401, "good"));
        // Generic/template mode: any 2xx is success (empty body, DuckDNS OK) except an
        // explicit failure token; non-2xx always fails.
        assert!(update_succeeded(DdnsMode::Template, 200, "OK"));
        assert!(update_succeeded(DdnsMode::Template, 200, ""));
        assert!(!update_succeeded(DdnsMode::Template, 200, "KO"));
        assert!(!update_succeeded(DdnsMode::Template, 401, "OK"));
        // MyDNS.JP judged by BODY — 200 with login_status=0 is a FAILURE (auth NG), not a
        // false success; login_status=1 / notify OK is success.
        assert!(update_succeeded(
            DdnsMode::Template,
            200,
            "<html>login_status = 1\nLogin and IP address notify OK.</html>"
        ));
        assert!(!update_succeeded(
            DdnsMode::Template,
            200,
            "<html>login_status = 0\nnotify NG</html>"
        ));
    }

    #[test]
    fn extract_login_status_parses_flexible() {
        assert_eq!(extract_login_status("login_status = 1"), Some(true));
        assert_eq!(extract_login_status("x login_status=0 y"), Some(false));
        assert_eq!(extract_login_status("login_status  =  1 rest"), Some(true));
        assert_eq!(extract_login_status("no such field"), None);
    }

    #[test]
    fn split_userinfo_extracts_and_strips() {
        assert_eq!(
            split_userinfo("https://mid:pw@ipv4.mydns.jp/login.html"),
            (
                "https://ipv4.mydns.jp/login.html".to_string(),
                Some(("mid".to_string(), "pw".to_string()))
            )
        );
        // No userinfo.
        assert_eq!(
            split_userinfo("https://ipv4.mydns.jp/login.html"),
            ("https://ipv4.mydns.jp/login.html".to_string(), None)
        );
        // An '@' in the path (not userinfo) is left alone.
        assert_eq!(
            split_userinfo("https://host/a@b"),
            ("https://host/a@b".to_string(), None)
        );
        // Username only.
        assert_eq!(
            split_userinfo("https://user@host/p"),
            (
                "https://host/p".to_string(),
                Some(("user".to_string(), String::new()))
            )
        );
    }

    #[test]
    fn parse_time_and_due() {
        assert_eq!(
            parse_hhmm("07:30"),
            NaiveTime::from_hms_opt(7, 30, 0).unwrap()
        );
        assert_eq!(parse_hhmm("bad"), NaiveTime::from_hms_opt(3, 0, 0).unwrap());
        // Disabled never fires.
        let mut c = cfg(DdnsMode::Dyndns);
        c.enabled = false;
        assert!(!is_due(&c, None));
    }

    /// A one-shot mock DynDNS provider: capture the first request, then answer with `body`.
    async fn mock_provider(
        body: &'static str,
    ) -> (std::net::SocketAddr, tokio::sync::oneshot::Receiver<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                // Read until the end of the request headers (a single read can return just
                // the request line, missing the Authorization header we assert on).
                let mut acc = Vec::new();
                let mut tmp = [0u8; 1024];
                loop {
                    match stream.read(&mut tmp).await {
                        Ok(0) => break,
                        Ok(n) => {
                            acc.extend_from_slice(&tmp[..n]);
                            if acc.windows(4).any(|w| w == b"\r\n\r\n") || acc.len() > 8192 {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let req = String::from_utf8_lossy(&acc).to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = tx.send(req);
            }
        });
        (addr, rx)
    }

    #[tokio::test]
    async fn perform_update_dyndns_over_http_sends_auth_and_parses_good() {
        let (addr, rx) = mock_provider("good 203.0.113.7").await;
        let mut c = cfg(DdnsMode::Dyndns);
        // A full http:// URL is used verbatim (plain HTTP → no TLS provider needed in tests).
        c.server = format!("http://{addr}/nic/update");
        c.hostname = "home.example.com".into();
        c.username = "alice".into();
        c.password = "s3cret".into();

        let status = perform_update(&c).await;
        assert!(status.last_ok, "good ⇒ ok: {}", status.last_message);
        assert_eq!(status.last_ip.as_deref(), Some("203.0.113.7"));

        // The provider saw the hostname query and a Basic-auth header.
        let req = rx.await.unwrap().to_lowercase();
        assert!(
            req.contains("/nic/update?hostname=home.example.com"),
            "req: {req}"
        );
        // base64("alice:s3cret") = YWxpY2U6czNjcmV0
        assert!(
            req.contains("authorization: basic ywxpy2u6cznjcmv0"),
            "auth: {req}"
        );
    }

    #[tokio::test]
    async fn perform_update_reports_provider_error() {
        let (addr, _rx) = mock_provider("badauth").await;
        let mut c = cfg(DdnsMode::Dyndns);
        c.server = format!("http://{addr}/nic/update");
        let status = perform_update(&c).await;
        assert!(!status.last_ok, "badauth ⇒ failure");
        assert!(status.last_message.contains("badauth"));
    }

    #[tokio::test]
    async fn template_mode_sends_basic_auth_and_2xx_is_success() {
        // MyDNS-like: template URL + Basic auth from the username/password, HTML 2xx = ok.
        let (addr, rx) = mock_provider("<html>login ok, ip updated</html>").await;
        let mut c = cfg(DdnsMode::Template);
        c.url_template = format!("http://{addr}/login.html");
        c.username = "master01".into();
        c.password = "pw".into();

        let status = perform_update(&c).await;
        assert!(status.last_ok, "2xx template ⇒ ok: {}", status.last_message);

        let req = rx.await.unwrap().to_lowercase();
        // base64("master01:pw") = bWFzdGVyMDE6cHc=
        assert!(
            req.contains("authorization: basic bwfzdgvymde6chc"),
            "template Basic auth: {req}"
        );
    }

    #[tokio::test]
    async fn template_mode_uses_url_userinfo_for_basic_auth() {
        let (addr, rx) = mock_provider("OK").await;
        let mut c = cfg(DdnsMode::Template);
        // Credentials embedded in the URL userinfo (stripped → Authorization header).
        c.url_template = format!("http://alice:s3cret@{addr}/update");
        c.username = String::new();
        c.password = String::new();

        let status = perform_update(&c).await;
        assert!(status.last_ok);
        let req = rx.await.unwrap().to_lowercase();
        // The userinfo must NOT appear in the request-target, only as a header.
        assert!(req.contains("get /update"), "clean target: {req}");
        // base64("alice:s3cret") = YWxpY2U6czNjcmV0
        assert!(
            req.contains("authorization: basic ywxpy2u6cznjcmv0"),
            "userinfo→Basic: {req}"
        );
    }

    #[tokio::test]
    async fn mydns_200_with_login_status_0_is_a_failure() {
        // MyDNS returns HTTP 200 even when the password is wrong (login_status = 0). This
        // must be reported as a FAILURE, and the status must surface login_status.
        let (addr, _rx) =
            mock_provider("<html>login_status = 0\nUnauthorized (notify NG)</html>").await;
        let mut c = cfg(DdnsMode::Template);
        c.url_template = format!("http://{addr}/login.html");
        c.username = "mydns19545".into();
        c.password = "wrong".into();

        let s = perform_update(&c).await;
        assert!(!s.last_ok, "200 login_status=0 is not success");
        assert!(
            s.last_message.contains("login_status=0"),
            "status surfaced: {}",
            s.last_message
        );
    }

    #[tokio::test]
    async fn mydns_200_with_login_status_1_is_success() {
        let (addr, _rx) =
            mock_provider("<html>login_status = 1\nLogin and IP address notify OK.</html>").await;
        let mut c = cfg(DdnsMode::Template);
        c.url_template = format!("http://{addr}/login.html");
        c.username = "mydns19545".into();
        c.password = "right".into();

        let s = perform_update(&c).await;
        assert!(s.last_ok, "login_status=1 ⇒ ok: {}", s.last_message);
        assert!(s.last_message.contains("login_status=1"));
    }

    /// A provider that answers `fail_times` requests with 503, then 200 `ok_body` — models a
    /// round-robin backend with a down node.
    async fn mock_flaky(fail_times: usize, ok_body: &'static str) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut n = 0usize;
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    continue;
                };
                let (code, body): (u16, &str) = if n < fail_times {
                    (503, "busy")
                } else {
                    (200, ok_body)
                };
                n += 1;
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf).await;
                    let resp = format!(
                        "HTTP/1.1 {code} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn retries_transient_5xx_then_succeeds() {
        // First node returns 503 (transient) → retry hits the healthy node and succeeds.
        let addr = mock_flaky(1, "good 203.0.113.9").await;
        let mut c = cfg(DdnsMode::Dyndns);
        c.server = format!("http://{addr}/nic/update");
        let s = perform_update(&c).await;
        assert!(
            s.last_ok,
            "retry after 503 should succeed: {}",
            s.last_message
        );
    }
}
