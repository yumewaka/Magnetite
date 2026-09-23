//! Webhook / audit-sink delivery: `POST` the alert as JSON, optionally signing the
//! body with `X-Magnetite-Signature: sha256=<hmac>` when the target has a secret.

use std::sync::Arc;

use hmac::{Hmac, Mac};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use magnetite_core::models::Alert;
use sha2::Sha256;

type StdErr = Box<dyn std::error::Error + Send + Sync>;

/// The JSON body a webhook target receives.
fn payload(alert: &Alert) -> serde_json::Value {
    serde_json::json!({
        "id": alert.meta.id,
        "domain": alert.domain.as_str(),
        "severity": format!("{:?}", alert.severity).to_lowercase(),
        "summary": alert.summary,
        "source_ref": alert.source_ref,
        "rule_ref": alert.rule_ref,
        "created_at": alert.meta.created_at.to_rfc3339(),
    })
}

/// Hex HMAC-SHA256 of `body` under `secret`.
fn sign(secret: &str, body: &[u8]) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(body);
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `POST` the alert JSON to `url`, adding the signature header when `secret` is set.
///
/// # Errors
/// An invalid URL, a transport error, or a non-2xx response status.
pub(crate) async fn post(url: &str, secret: Option<&str>, alert: &Alert) -> Result<(), StdErr> {
    let body = serde_json::to_vec(&payload(alert))?;
    let uri: hyper::Uri = url.parse()?;
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(danger_client_config())
        .https_or_http()
        .enable_http1()
        .build();
    let client = Client::builder(TokioExecutor::new()).build(https);

    let mut builder = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(secret) = secret {
        builder = builder.header(
            "x-magnetite-signature",
            format!("sha256={}", sign(secret, &body)),
        );
    }
    let req = builder.body(Full::new(bytes::Bytes::from(body)))?;

    let resp = client.request(req).await?;
    let status = resp.status();
    let _ = resp.into_body().collect().await;
    if !status.is_success() {
        return Err(format!("endpoint returned {status}").into());
    }
    Ok(())
}

/// A rustls client config that accepts any server certificate (webhook endpoints
/// are operator-configured and often behind self-signed TLS; matches the posture of
/// `magnetite-feed`).
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
