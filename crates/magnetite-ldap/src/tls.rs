//! StartTLS support for the LDAP server. Builds a single-certificate rustls
//! `ServerConfig` from the certificate named in `[domains.ldap.server]
//! .tls_cert_name` (loaded from the shared cert store via
//! `get_certificate_material`). Loaded once at startup — restart to pick up cert
//! changes (R5, restart-scoped).

use magnetite_db::{CertMaterial, Db};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

/// Build a StartTLS acceptor from the named certificate, or `None` when unset or
/// the certificate has no usable key (StartTLS is then unavailable).
pub(crate) async fn build_acceptor(db: &Db, cert_name: Option<&str>) -> Option<TlsAcceptor> {
    let name = cert_name?;
    let material = db.get_certificate_material(name).await.ok().flatten()?;
    let (certs, key) = parse_material(&material)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .ok()?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .ok()?;
    Some(TlsAcceptor::from(Arc::new(config)))
}

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
