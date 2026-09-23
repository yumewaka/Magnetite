//! Shared client for magnetite's bearer-authenticated replication feeds
//! (mail / DHCP / SYSVOL / proxy / SSO). A feed is an HTTPS `GET` carrying
//! `Authorization: Bearer <secret>` and an [`SINCE_HEADER`] cursor, returning a
//! JSON body the caller deserializes into the feed type.
//!
//! One [`fetch_feed`] serves every feed so the HTTP/TLS plumbing lives in exactly
//! one place; [`post_command`] is its `POST` counterpart for the management plane
//! forwarding a control command (e.g. promote/demote) to a server's `/mgmt/*`.
//!
//! **Transport security.** These feeds carry secrets (mailbox contents, directory
//! data, SSO signing keys, proxy private keys) and the bearer token itself, so:
//! - **TLS is required** — a plaintext `http://` feed URL is rejected, and the
//!   connector refuses to downgrade, so the token/data are never sent in the clear.
//! - **Certificate verification** is opt-in via [`FEED_PIN_ENV`]: set it to the
//!   SHA-256 fingerprint(s) of the peer's leaf certificate and only a matching cert
//!   is accepted (real verification of the self-signed feed cert). Left unset, the
//!   peer cert is not verified — matching the trusted-network self-signed default —
//!   and a warning is logged once so the posture is visible.

#![forbid(unsafe_code)]

use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Request header carrying the pull cursor (the last position the peer holds).
pub const SINCE_HEADER: &str = "x-repl-since";

/// Environment variable holding comma-separated lowercase-hex SHA-256 fingerprints
/// of the replication peers' leaf (end-entity) certificates. When set, a feed TLS
/// connection is accepted only if the server's leaf cert SHA-256 matches one of them.
/// Compute one with `openssl x509 -in feed.crt -outform der | sha256sum`.
pub const FEED_PIN_ENV: &str = "MAGNETITE_FEED_PIN_SHA256";

/// `GET url` with a bearer secret and the `since` cursor, deserializing the JSON
/// body into `T`. `url` is the full feed URL (e.g. `https://primary/repl/sysvol`).
///
/// # Errors
/// Returns an error if the URL is invalid, the request fails, the response status
/// is not `200 OK`, or the body does not deserialize into `T`.
pub async fn fetch_feed<T: serde::de::DeserializeOwned>(
    url: &str,
    secret: &str,
    since: &str,
) -> anyhow::Result<T> {
    use http_body_util::{BodyExt, Empty};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let uri: hyper::Uri = url.parse()?;
    require_https(&uri)?;
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(feed_client_config())
        .https_only()
        .enable_http1()
        .build();
    let client = Client::builder(TokioExecutor::new()).build(https);
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(uri)
        .header("authorization", format!("Bearer {secret}"))
        .header(SINCE_HEADER, since)
        .body(Empty::<bytes::Bytes>::new())?;
    let resp = client.request(req).await?;
    if resp.status() != hyper::StatusCode::OK {
        anyhow::bail!("replication feed {url} returned status {}", resp.status());
    }
    let body = resp.into_body().collect().await?.to_bytes();
    Ok(serde_json::from_slice(&body)?)
}

/// `POST url` with a bearer secret and a JSON body, returning the response status code and
/// its JSON body (or `Value::Null` when the body is empty/not JSON). Unlike [`fetch_feed`],
/// a non-2xx status is **not** an error here: the caller (e.g. the control plane forwarding
/// a command to a managed server) usually wants to relay the status and message verbatim.
/// The same self-signed-tolerant TLS as the feeds is used.
///
/// # Errors
/// Returns an error only for a bad URL or a transport failure (never for an HTTP status).
pub async fn post_command(
    url: &str,
    secret: &str,
    body: &serde_json::Value,
) -> anyhow::Result<(u16, serde_json::Value)> {
    use http_body_util::{BodyExt, Full};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let uri: hyper::Uri = url.parse()?;
    require_https(&uri)?;
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(feed_client_config())
        .https_only()
        .enable_http1()
        .build();
    let client: Client<_, Full<bytes::Bytes>> = Client::builder(TokioExecutor::new()).build(https);
    let payload = serde_json::to_vec(body)?;
    let req = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(uri)
        .header("authorization", format!("Bearer {secret}"))
        .header("content-type", "application/json")
        .body(Full::new(bytes::Bytes::from(payload)))?;
    let resp = client.request(req).await?;
    let status = resp.status().as_u16();
    let bytes = resp.into_body().collect().await?.to_bytes();
    let value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    Ok((status, value))
}

/// Reject a non-HTTPS feed URL: these feeds carry secrets and the bearer token, so
/// they must never traverse a plaintext connection.
///
/// # Errors
/// Returns an error when the URL scheme is anything other than `https`.
fn require_https(uri: &hyper::Uri) -> anyhow::Result<()> {
    match uri.scheme_str() {
        Some("https") => Ok(()),
        other => anyhow::bail!(
            "replication feed URL must be https (it carries secrets); got scheme {:?}",
            other.unwrap_or("(none)")
        ),
    }
}

/// Parse a 32-byte (SHA-256) fingerprint from lowercase/uppercase hex.
fn parse_fingerprint(s: &str) -> Option<[u8; 32]> {
    let s = s.trim().replace([':', ' '], "");
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// The configured leaf-certificate fingerprints to pin to, from [`FEED_PIN_ENV`].
/// Empty when the variable is unset (self-signed, unverified default).
fn pinned_fingerprints() -> Vec<[u8; 32]> {
    std::env::var(FEED_PIN_ENV)
        .ok()
        .map(|v| v.split(',').filter_map(parse_fingerprint).collect())
        .unwrap_or_default()
}

/// Environment variable that EXPLICITLY opts out of feed peer-certificate verification
/// (accept any cert). Set it (`1`/`true`/`yes`) only for a trusted network where the
/// peer cert is self-signed and un-pinned; otherwise an un-pinned feed is refused.
pub const FEED_INSECURE_ENV: &str = "MAGNETITE_FEED_INSECURE_TLS";

/// Whether the operator has explicitly opted out of feed cert verification.
fn insecure_tls_opt_out() -> bool {
    std::env::var(FEED_INSECURE_ENV)
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// The rustls client config for feed connections. Verification is required by
/// default: pin the peer's leaf cert via [`FEED_PIN_ENV`], or explicitly opt out with
/// [`FEED_INSECURE_ENV`]. With neither, an un-pinned peer cert is REFUSED (a MITM is
/// no longer accepted silently). TLS signature checks always run.
fn feed_client_config() -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(FeedVerifier {
            provider,
            pins: pinned_fingerprints(),
            insecure: insecure_tls_opt_out(),
        }))
        .with_no_client_auth()
}

/// Set once the "peer cert not verified" warning has been logged, so it appears
/// once rather than on every feed poll.
static UNVERIFIED_WARNED: AtomicBool = AtomicBool::new(false);

/// Verifies the feed peer's leaf certificate. Pins to the configured SHA-256
/// fingerprints when set; else, only when [`FEED_INSECURE_ENV`] is set, accepts any
/// cert (one-time warning); otherwise REFUSES an un-pinned cert. TLS signature checks
/// run in every accept case.
#[derive(Debug)]
struct FeedVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
    pins: Vec<[u8; 32]>,
    /// Explicit opt-out: accept any cert (self-signed trusted network).
    insecure: bool,
}

impl rustls::client::danger::ServerCertVerifier for FeedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if self.pins.is_empty() {
            if self.insecure {
                if !UNVERIFIED_WARNED.swap(true, Ordering::Relaxed) {
                    tracing::warn!(
                        "replication feed peer certificate is NOT verified ({}=1); set {} to pin it instead",
                        FEED_INSECURE_ENV, FEED_PIN_ENV
                    );
                }
                return Ok(rustls::client::danger::ServerCertVerified::assertion());
            }
            return Err(rustls::Error::General(format!(
                "feed peer certificate is not pinned and verification is required; \
                 set {FEED_PIN_ENV} to the peer's leaf-cert SHA-256, or {FEED_INSECURE_ENV}=1 to opt out"
            )));
        }
        let fp: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if self.pins.contains(&fp) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "feed peer certificate SHA-256 {} does not match any pinned fingerprint",
                fp.iter().map(|b| format!("{b:02x}")).collect::<String>()
            )))
        }
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
            &self.provider.signature_verification_algorithms,
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
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_is_required() {
        assert!(require_https(&"https://primary/repl/mail".parse().unwrap()).is_ok());
        assert!(require_https(&"http://primary/repl/mail".parse().unwrap()).is_err());
        // A bare host with no scheme is also rejected (no plaintext leak).
        assert!(require_https(&"primary:8443".parse().unwrap()).is_err());
    }

    #[test]
    fn fingerprint_parsing() {
        let hex = "a".repeat(64);
        assert_eq!(parse_fingerprint(&hex), Some([0xaa; 32]));
        // Colon/space separators and uppercase are tolerated.
        let colons = (0..32).map(|_| "AA").collect::<Vec<_>>().join(":");
        assert_eq!(parse_fingerprint(&colons), Some([0xaa; 32]));
        // Wrong length or non-hex is rejected.
        assert_eq!(parse_fingerprint("abcd"), None);
        assert_eq!(parse_fingerprint(&"z".repeat(64)), None);
    }
}
