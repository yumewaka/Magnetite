//! TLS termination for the reverse proxy (T2). Builds a rustls `ServerConfig` whose SNI
//! resolver maps each TLS-enabled virtual host's hostname to its certificate + private key
//! (from the shared DB via `get_certificate_material`). The resolver reads a shared cert
//! map that a background task refreshes from the DB, so adding/rotating/removing a
//! certificate or TLS vhost takes effect WITHOUT a restart (FR-8, hot reload).

use magnetite_core::domains::proxy::model::VirtualHost;
use magnetite_db::{CertMaterial, Db};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// The live SNI → certificate map, keyed by lowercased hostname.
pub(crate) type CertMap = HashMap<String, Arc<CertifiedKey>>;

/// Parse cert-chain + key PEM into a rustls [`CertifiedKey`].
fn certified_key(material: &CertMaterial) -> Option<CertifiedKey> {
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut material.cert_chain_pem.as_bytes())
            .collect::<Result<_, _>>()
            .ok()?;
    if certs.is_empty() {
        return None;
    }
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut material.key_pem.as_bytes())
        .ok()
        .flatten()?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key).ok()?;
    Some(CertifiedKey::new(certs, signing_key))
}

/// Load the current SNI cert map from the DB: one entry per enabled, TLS-enabled host with
/// a usable certificate. Bad/missing certs are logged and skipped.
///
/// A hostname can now back SEVERAL vhosts (path-routed, e.g. `/` and `/export`), but TLS
/// terminates ONCE per SNI — a host presents ONE certificate. So the cert is chosen
/// DETERMINISTICALLY (a stable sort, first entry wins) rather than by `HashMap` insertion
/// order (last-wins, nondeterministic across restarts); if a host's vhosts name different
/// `certificate_ref`s, that is a misconfiguration and is warned. A TLS vhost with no
/// `certificate_ref` (a path sub-vhost inheriting the host's cert) is simply skipped.
pub(crate) async fn load_sni_map(db: &Db) -> CertMap {
    let mut map = CertMap::new();
    let Ok(vhosts) = db.list_vhosts().await else {
        return map;
    };
    let tls_vhosts: Vec<&VirtualHost> = vhosts
        .iter()
        .filter(|v| v.enabled && v.tls_enabled)
        .collect();
    for (host, cert_name) in choose_host_certs(&tls_vhosts) {
        let Some(material) = db.get_certificate_material(&cert_name).await.ok().flatten() else {
            tracing::warn!("proxy TLS: host {host} cert '{cert_name}' has no key; skipped");
            continue;
        };
        match certified_key(&material) {
            Some(ck) => {
                map.insert(host, Arc::new(ck));
            }
            None => tracing::warn!("proxy TLS: cert '{cert_name}' PEM is invalid; skipped"),
        }
    }
    map
}

/// Choose ONE certificate name per TLS-enabled host, deterministically. A hostname can
/// back several path-routed vhosts, but TLS terminates once per SNI, so a host presents a
/// single certificate. Vhosts are stable-sorted (hostname, path_prefix, certificate_ref)
/// and the first with a `certificate_ref` wins per host — independent of DB row order,
/// unlike the previous last-write-wins `insert`. A host whose vhosts name DIFFERENT certs
/// is a misconfiguration and is warned (the first is used). Vhosts with no
/// `certificate_ref` (a path sub-vhost inheriting the host's cert) contribute nothing.
/// Pure (logging aside) so the selection is unit-testable without loading certs.
fn choose_host_certs(vhosts: &[&VirtualHost]) -> Vec<(String, String)> {
    let mut sorted: Vec<&&VirtualHost> = vhosts.iter().collect();
    sorted.sort_by(|a, b| {
        a.hostname
            .cmp(&b.hostname)
            .then_with(|| a.path_prefix.cmp(&b.path_prefix))
            .then_with(|| a.certificate_ref.cmp(&b.certificate_ref))
    });
    let mut chosen: Vec<(String, String)> = Vec::new();
    for vhost in sorted {
        let Some(cert_name) = vhost.certificate_ref.as_deref() else {
            continue;
        };
        let host = vhost.hostname.to_ascii_lowercase();
        match chosen.iter().find(|(h, _)| h == &host) {
            Some((_, existing)) if existing != cert_name => tracing::warn!(
                "proxy TLS: host {host} has vhosts with different certificate_ref \
                 ('{existing}' vs '{cert_name}'); using '{existing}' — align the host's \
                 vhosts to one certificate"
            ),
            Some(_) => {} // same cert named again — nothing to do
            None => chosen.push((host, cert_name.to_string())),
        }
    }
    chosen
}

/// A rustls cert resolver that looks up the SNI hostname in a shared, hot-swappable map.
struct DynamicSniResolver {
    certs: Arc<RwLock<CertMap>>,
}

impl std::fmt::Debug for DynamicSniResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DynamicSniResolver")
    }
}

impl ResolvesServerCert for DynamicSniResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let name = client_hello.server_name()?.to_ascii_lowercase();
        self.certs.read().ok()?.get(&name).cloned()
    }
}

/// Build a hot-reloadable TLS server config. The SNI resolver reads a shared cert map
/// (seeded here, refreshed by a background task via the returned handle), so certificate /
/// TLS-vhost changes apply without a restart. `None` only on crypto-provider init failure —
/// the listener still starts with an empty map (a cert added later resolves on refresh).
pub(crate) async fn build_dynamic_config(
    db: &Db,
) -> Option<(Arc<ServerConfig>, Arc<RwLock<CertMap>>)> {
    let certs = Arc::new(RwLock::new(load_sni_map(db).await));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .ok()?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(DynamicSniResolver {
            certs: certs.clone(),
        }));
    // Advertise HTTP/2 then HTTP/1.1 via ALPN — a client that supports h2 negotiates it;
    // others fall back to h1 (and h1 is what a WebSocket upgrade handshake uses).
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Some((Arc::new(config), certs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetite_core::domains::proxy::model::{LbStrategy, ProxyMode};

    fn vhost(hostname: &str, path: Option<&str>, cert: Option<&str>) -> VirtualHost {
        VirtualHost {
            id: String::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            created_by: "admin".into(),
            hostname: hostname.into(),
            path_prefix: path.map(str::to_string),
            listen_port: 443,
            upstream: vec![],
            tls_enabled: true,
            certificate_ref: cert.map(str::to_string),
            force_https: false,
            proxy_mode: ProxyMode::Http,
            lb_strategy: LbStrategy::RoundRobin,
            enabled: true,
        }
    }

    #[test]
    fn one_cert_per_host_even_with_path_routed_vhosts() {
        // The host cert comes from the vhost that names one; a path sub-vhost with no
        // certificate_ref inherits it and contributes nothing to the map.
        let root = vhost("mag.example.com", None, Some("mag-cert"));
        let export = vhost("mag.example.com", Some("/export"), None);
        let refs: Vec<&VirtualHost> = vec![&root, &export];
        assert_eq!(
            choose_host_certs(&refs),
            vec![("mag.example.com".to_string(), "mag-cert".to_string())]
        );
    }

    #[test]
    fn choice_is_deterministic_regardless_of_input_order() {
        // Same host, two vhosts naming the SAME cert on different paths: one entry, and
        // the result does not depend on the order the vhosts arrive in.
        let a = vhost("mag.example.com", None, Some("mag-cert"));
        let b = vhost("mag.example.com", Some("/export"), Some("mag-cert"));
        let forward: Vec<&VirtualHost> = vec![&a, &b];
        let reverse: Vec<&VirtualHost> = vec![&b, &a];
        assert_eq!(choose_host_certs(&forward), choose_host_certs(&reverse));
        assert_eq!(choose_host_certs(&forward).len(), 1);
    }

    #[test]
    fn conflicting_certs_pick_the_stable_first_not_the_last_written() {
        // Two vhosts for one host name DIFFERENT certs (a misconfiguration). The choice is
        // deterministic by the stable sort (hostname, path_prefix, cert): the None-path
        // (root) vhost sorts before the /export one, so the ROOT vhost's cert wins —
        // regardless of the order the vhosts arrive in, unlike last-write-wins.
        let root = vhost("mag.example.com", None, Some("root-cert"));
        let export = vhost("mag.example.com", Some("/export"), Some("other-cert"));
        let forward: Vec<&VirtualHost> = vec![&root, &export];
        let reverse: Vec<&VirtualHost> = vec![&export, &root];
        let expected = vec![("mag.example.com".to_string(), "root-cert".to_string())];
        assert_eq!(choose_host_certs(&forward), expected);
        assert_eq!(
            choose_host_certs(&reverse),
            expected,
            "the winner does not depend on input order"
        );
    }

    #[test]
    fn distinct_hosts_each_get_their_cert() {
        let a = vhost("a.example.com", None, Some("a-cert"));
        let b = vhost("b.example.com", None, Some("b-cert"));
        let refs: Vec<&VirtualHost> = vec![&b, &a];
        let mut got = choose_host_certs(&refs);
        got.sort();
        assert_eq!(
            got,
            vec![
                ("a.example.com".to_string(), "a-cert".to_string()),
                ("b.example.com".to_string(), "b-cert".to_string()),
            ]
        );
    }
}
