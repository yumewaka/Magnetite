//! Outbound OAuth/OIDC calls to the upstream provider: PKCE, the code→token
//! exchange, and the userinfo fetch. Built on the same hyper + rustls plumbing as
//! the rest of magnetite's outbound clients.

use std::sync::Arc;

use base64::Engine;
use bytes::Bytes;
use chrono::{Duration, Utc};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use magnetite_core::models::OidcTokenResponse;
use sha2::{Digest, Sha256};

type StdErr = Box<dyn std::error::Error + Send + Sync>;

/// The identity read from a provider's userinfo endpoint (fields are best-effort;
/// providers vary, so all are optional).
#[derive(Debug, Default, serde::Deserialize)]
pub(crate) struct Identity {
    /// OIDC subject; GitHub's numeric `id` maps here.
    #[serde(default, alias = "id")]
    pub sub: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    /// OIDC `preferred_username`; GitHub's `login` maps here.
    #[serde(default, alias = "login", alias = "upn")]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

/// The PKCE S256 challenge for a verifier: base64url(sha256(verifier)), no padding.
pub(crate) fn pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// A hyper client over rustls that accepts the presented certificate (see the crate
/// doc: consistent with magnetite's other outbound clients).
fn https_client() -> Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
> {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(danger_client_config())
        .https_or_http()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(https)
}

/// Form field for `application/x-www-form-urlencoded`.
fn form_encode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", pct(k), pct(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Raw token endpoint response (providers return `expires_in` seconds).
#[derive(Debug, serde::Deserialize)]
struct TokenResp {
    access_token: String,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
}

/// Exchange an authorization `code` for tokens at the provider's token endpoint,
/// authenticating the client with its id + secret and proving PKCE.
///
/// # Errors
/// An invalid URL, a transport failure, a non-2xx status, or an undecodable body.
pub(crate) async fn exchange_code(
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<OidcTokenResponse, StdErr> {
    let body = form_encode(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("code_verifier", code_verifier),
    ]);
    let uri: hyper::Uri = token_url.parse()?;
    let req = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json")
        .header("user-agent", "magnetite")
        .body(Full::new(Bytes::from(body)))?;
    let resp = https_client().request(req).await?;
    let status = resp.status();
    let bytes = resp.into_body().collect().await?.to_bytes();
    if !status.is_success() {
        return Err(format!(
            "token endpoint {status}: {}",
            String::from_utf8_lossy(&bytes).trim()
        )
        .into());
    }
    let raw: TokenResp = serde_json::from_slice(&bytes)?;
    Ok(OidcTokenResponse {
        access_token: raw.access_token,
        token_type: raw.token_type.unwrap_or_else(|| "Bearer".to_string()),
        refresh_token: raw.refresh_token,
        id_token: raw.id_token,
        expires_at: raw.expires_in.map(|s| Utc::now() + Duration::seconds(s)),
    })
}

/// Fetch the identity from the provider's userinfo endpoint with the access token.
///
/// # Errors
/// An invalid URL, a transport failure, a non-2xx status, or an undecodable body.
pub(crate) async fn fetch_userinfo(
    userinfo_url: &str,
    access_token: &str,
) -> Result<Identity, StdErr> {
    let uri: hyper::Uri = userinfo_url.parse()?;
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri(uri)
        .header("authorization", format!("Bearer {access_token}"))
        .header("accept", "application/json")
        .header("user-agent", "magnetite")
        .body(Full::new(Bytes::new()))?;
    let resp = https_client().request(req).await?;
    let status = resp.status();
    let bytes = resp.into_body().collect().await?.to_bytes();
    if !status.is_success() {
        return Err(format!(
            "userinfo endpoint {status}: {}",
            String::from_utf8_lossy(&bytes).trim()
        )
        .into());
    }
    // `sub`/`id` may be a string or number; coerce via a Value pass first.
    let mut value: serde_json::Value = serde_json::from_slice(&bytes)?;
    if let Some(obj) = value.as_object_mut() {
        for key in ["sub", "id"] {
            if let Some(serde_json::Value::Number(n)) = obj.get(key).cloned() {
                obj.insert(key.to_string(), serde_json::Value::String(n.to_string()));
            }
        }
    }
    Ok(serde_json::from_value(value)?)
}

fn danger_client_config() -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth()
}

#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
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
