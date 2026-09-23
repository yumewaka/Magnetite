//! Implicit TLS for the mail servers (T3). Builds a single-certificate rustls
//! `ServerConfig` — the mail host presents one certificate (referenced by name
//! from the mail config's `tls_cert_name`) on the SMTPS/IMAPS/POP3S ports — and
//! provides a shared accept loop that wraps each connection in TLS before
//! handing the stream to the plaintext protocol handler.
//!
//! Certificates are loaded once at startup — restart to pick up cert changes
//! (R5, restart-scoped). STARTTLS (in-dialog upgrade) is deferred; the S-ports
//! offer implicit TLS from the first byte.

use magnetite_db::{CertMaterial, Db};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

/// Outcome of one plaintext protocol dialog: either the client finished, or it
/// issued STARTTLS/STLS and the caller must upgrade the connection to TLS and
/// resume the dialog on the encrypted stream.
pub(crate) enum Flow {
    Done,
    StartTls,
}

/// Build a [`TlsAcceptor`] for the mail host from the mail config's
/// `tls_cert_name`, or `None` when no usable certificate is configured (in which
/// case STARTTLS is not offered and the implicit-TLS ports do not start).
pub(crate) async fn mail_tls_acceptor(db: &Db) -> Option<TlsAcceptor> {
    let config = db.get_mail_config().await.ok()?;
    let name = config.tls_cert_name.as_deref()?;
    let server_config = build_server_config(db, name).await?;
    Some(TlsAcceptor::from(server_config))
}

/// Build a single-certificate TLS server config from the certificate named
/// `cert_name`, or `None` if it has no private key or its PEM is unusable (in
/// which case the implicit-TLS listeners are skipped).
pub(crate) async fn build_server_config(db: &Db, cert_name: &str) -> Option<Arc<ServerConfig>> {
    let material = db
        .get_certificate_material(cert_name)
        .await
        .ok()
        .flatten()?;
    let (certs, key) = parse_material(&material)?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .ok()?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .ok()?;
    Some(Arc::new(config))
}

/// Parse cert-chain + key PEM into rustls types.
fn parse_material(
    material: &CertMaterial,
) -> Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut material.cert_chain_pem.as_bytes())
            .collect::<Result<_, _>>()
            .ok()?;
    if certs.is_empty() {
        return None;
    }
    let key = rustls_pemfile::private_key(&mut material.key_pem.as_bytes())
        .ok()
        .flatten()?;
    Some((certs, key))
}

/// Bind `addr`, perform the TLS handshake on each accepted connection, and run
/// `handle` over the resulting TLS stream until `shutdown` fires.
pub(crate) async fn accept_loop<F, Fut>(
    addr: SocketAddr,
    acceptor: TlsAcceptor,
    mut shutdown: watch::Receiver<bool>,
    handle: F,
) -> std::io::Result<()>
where
    F: Fn(TlsStream<TcpStream>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = std::io::Result<()>> + Send + 'static,
{
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("implicit-TLS mail server listening on {addr}");
    let handle = Arc::new(handle);
    let conns = crate::conn::limiter();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted { Ok(v) => v, Err(_) => continue };
                let Ok(permit) = conns.clone().try_acquire_owned() else {
                    tracing::warn!(target: "conn", %peer, "mail TLS conn limit reached; dropping");
                    continue;
                };
                tracing::debug!(target: "conn", %peer, "implicit-TLS mail connection");
                let acceptor = acceptor.clone();
                let handle = handle.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    // Bound the TLS handshake: a client that connects but never completes
                    // the handshake would otherwise hold a connection slot indefinitely.
                    let hs = acceptor.accept(stream);
                    match tokio::time::timeout(crate::line::IO_TIMEOUT, hs).await {
                        Ok(Ok(tls)) => {
                            if let Err(e) = handle(tls).await {
                                tracing::debug!("mail TLS connection error: {e}");
                            }
                        }
                        Ok(Err(e)) => tracing::debug!("mail TLS handshake failed: {e}"),
                        Err(_) => {
                            tracing::debug!(target: "conn", %peer, "mail TLS handshake timed out");
                        }
                    }
                });
            }
        }
    }
    Ok(())
}

/// Test-only TLS client helpers shared by the STARTTLS integration tests.
#[cfg(test)]
pub(crate) mod testutil {
    use std::sync::Arc;
    use tokio_rustls::TlsConnector;

    /// A rustls verifier that accepts any server certificate (test client only).
    #[derive(Debug)]
    struct NoVerify(Arc<rustls::crypto::CryptoProvider>);
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

    /// A `TlsConnector` that trusts any certificate (for self-signed test certs).
    pub(crate) fn danger_connector() -> TlsConnector {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth();
        TlsConnector::from(Arc::new(config))
    }
}
