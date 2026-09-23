//! Client-side TLS for the LDAP replication consumers (RFC 4533 syncrepl and the
//! AD DirSync / USN pullers). When an upstream is configured as `ldaps://`, the
//! bind (which carries `bind_password`) and the replicated data must travel over
//! TLS, never plaintext.
//!
//! The upstream feed cert is typically self-signed on a trusted network, so
//! verification is opt-in: set [`LDAP_TLS_PIN_ENV`] to the SHA-256 fingerprint(s)
//! of the upstream's leaf certificate and only a matching cert is accepted;
//! otherwise the cert is accepted (self-signed default) with a one-time warning.
//! TLS signature checks always run.

use magnetite_core::LdapConsumerConfig;
use sha2::{Digest, Sha256};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

/// An upstream LDAP connection that is either plaintext (`ldap://`) or TLS
/// (`ldaps://`). Presenting one concrete stream type lets every replication puller
/// (syncrepl consumer, AD DirSync/USN) run its dialog unchanged over either.
pub(crate) enum MaybeTlsStream {
    Plain(TcpStream),
    Tls(Box<TlsStream<TcpStream>>),
}

impl AsyncRead for MaybeTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_flush(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Connect to the upstream LDAP provider, upgrading to TLS when the `provider_url`
/// is `ldaps://` so the bind (which carries `bind_password`) and the replicated data
/// never traverse plaintext.
///
/// # Errors
/// Returns an error if the TCP connect fails, the TLS server name is invalid, or the
/// TLS handshake fails.
pub(crate) async fn connect(config: &LdapConsumerConfig) -> anyhow::Result<MaybeTlsStream> {
    // Refuse a CREDENTIALED bind over plaintext ldap:// — the bind password would go in
    // the clear. Anonymous plaintext (no password) is allowed; an explicit opt-out
    // (MAGNETITE_LDAP_ALLOW_PLAINTEXT) permits a credentialed plaintext bind on a
    // trusted network.
    if !config.is_ldaps() && !config.bind_password.is_empty() && !allow_plaintext_bind() {
        anyhow::bail!(
            "refusing a credentialed LDAP bind over plaintext {} — use ldaps:// (recommended) \
             or set {}=1 to allow it on a trusted network",
            config.provider_url,
            LDAP_ALLOW_PLAINTEXT_ENV
        );
    }
    let tcp = TcpStream::connect(config.host_port()).await?;
    if config.is_ldaps() {
        let server_name = rustls::pki_types::ServerName::try_from(config.host())
            .map_err(|_| anyhow::anyhow!("invalid TLS server name '{}'", config.host()))?;
        let tls = ldaps_connector().connect(server_name, tcp).await?;
        Ok(MaybeTlsStream::Tls(Box::new(tls)))
    } else {
        Ok(MaybeTlsStream::Plain(tcp))
    }
}

/// Environment variable that allows a CREDENTIALED bind over plaintext `ldap://`
/// (bind password sent in the clear). Set (`1`/`true`/`yes`/`on`) only on a trusted
/// network; otherwise such a bind is refused in favour of `ldaps://`.
pub(crate) const LDAP_ALLOW_PLAINTEXT_ENV: &str = "MAGNETITE_LDAP_ALLOW_PLAINTEXT";

/// Environment variable that EXPLICITLY opts out of upstream cert verification
/// (accept any `ldaps://` cert). Set only for a trusted, self-signed, un-pinned peer.
pub(crate) const LDAP_INSECURE_ENV: &str = "MAGNETITE_LDAP_INSECURE_TLS";

fn env_flag(key: &str) -> bool {
    std::env::var(key)
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn allow_plaintext_bind() -> bool {
    env_flag(LDAP_ALLOW_PLAINTEXT_ENV)
}

/// Environment variable holding comma-separated lowercase-hex SHA-256 fingerprints
/// of the upstream LDAP provider's leaf certificate(s). Compute one with
/// `openssl x509 -in upstream.crt -outform der | sha256sum`.
pub(crate) const LDAP_TLS_PIN_ENV: &str = "MAGNETITE_LDAP_TLS_PIN_SHA256";

/// Parse a 32-byte (SHA-256) fingerprint from hex (`:`/space separators tolerated).
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

/// The configured leaf-certificate fingerprints to pin to, from [`LDAP_TLS_PIN_ENV`].
fn pinned_fingerprints() -> Vec<[u8; 32]> {
    std::env::var(LDAP_TLS_PIN_ENV)
        .ok()
        .map(|v| v.split(',').filter_map(parse_fingerprint).collect())
        .unwrap_or_default()
}

/// A [`TlsConnector`] for connecting to an upstream `ldaps://` provider.
pub(crate) fn ldaps_connector() -> TlsConnector {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(UpstreamVerifier {
            provider,
            pins: pinned_fingerprints(),
            insecure: env_flag(LDAP_INSECURE_ENV),
        }))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

/// Set once the "upstream cert not verified" warning has been logged.
static UNVERIFIED_WARNED: AtomicBool = AtomicBool::new(false);

/// Verifies the upstream's leaf certificate against the configured SHA-256 pins;
/// with none configured it accepts any cert (self-signed default) but logs a
/// one-time warning. TLS signature checks run in every case.
#[derive(Debug)]
struct UpstreamVerifier {
    provider: Arc<rustls::crypto::CryptoProvider>,
    pins: Vec<[u8; 32]>,
    /// Explicit opt-out: accept any cert (self-signed trusted upstream).
    insecure: bool,
}

impl rustls::client::danger::ServerCertVerifier for UpstreamVerifier {
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
                        "LDAP syncrepl upstream certificate is NOT verified ({}=1); set {} to pin it instead",
                        LDAP_INSECURE_ENV, LDAP_TLS_PIN_ENV
                    );
                }
                return Ok(rustls::client::danger::ServerCertVerified::assertion());
            }
            return Err(rustls::Error::General(format!(
                "upstream LDAP certificate is not pinned and verification is required; \
                 set {LDAP_TLS_PIN_ENV} to the peer's leaf-cert SHA-256, or {LDAP_INSECURE_ENV}=1 to opt out"
            )));
        }
        let fp: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if self.pins.contains(&fp) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "upstream LDAP certificate SHA-256 {} does not match any pinned fingerprint",
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
    fn fingerprint_parsing() {
        assert_eq!(parse_fingerprint(&"a".repeat(64)), Some([0xaa; 32]));
        assert_eq!(parse_fingerprint("abcd"), None);
    }

    #[test]
    fn connector_builds() {
        // Building the connector must not panic (installs the ring provider config).
        let _ = ldaps_connector();
    }
}
