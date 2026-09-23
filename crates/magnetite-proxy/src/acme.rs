//! ACME (RFC 8555) automatic TLS via the HTTP-01 challenge (FR-9).
//!
//! When `[domains.proxy.acme]` is enabled, a background task obtains and renews a
//! certificate from an ACME CA (Let's Encrypt by default) for the configured domains.
//! The HTTP-01 challenge token is served on the proxy's plain HTTP listener (port 80
//! must be reachable from the CA); the issued certificate is stored in the shared DB
//! cert store under `certificate_name`, where the hot-reload SNI resolver (FR-8) picks
//! it up without a restart. A TLS virtual host references it by that name.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use magnetite_core::config::AcmeConfig;
use magnetite_db::Db;
use tokio::sync::watch;

/// Shared HTTP-01 challenge responses: challenge token → key authorization. The HTTP
/// handler serves these at `/.well-known/acme-challenge/<token>`; the ACME task fills an
/// entry before asking the CA to validate and clears it once the order completes.
pub(crate) type ChallengeStore = Arc<Mutex<HashMap<String, String>>>;

/// Proxy-KV key under which the ACME account credentials are persisted.
const KV_ACCOUNT: &str = "acme_account_credentials";
/// Let's Encrypt production directory URL.
const LE_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
/// Let's Encrypt staging directory URL (untrusted certs, generous rate limits).
const LE_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
/// Default certificate name in the cert store when not configured.
const DEFAULT_CERT_NAME: &str = "acme";
/// Default renew-before window (days of remaining validity).
const DEFAULT_RENEW_BEFORE_DAYS: i64 = 30;
/// Assumed validity window when recording the issued cert (LE issues 90-day certs; the
/// stored `not_after` only drives renewal timing — the cert PEM itself is authoritative).
const ASSUMED_VALIDITY_DAYS: i64 = 89;
/// How often the manager re-reads its (DB-backed) settings and re-checks the certificate.
/// Short so a Web-UI domain change is picked up and re-issued within ~a minute; the check
/// itself is a cheap local DB read (LE is only contacted when issuance is actually needed).
const RELOAD_INTERVAL: Duration = Duration::from_secs(60);
/// Backoff before retrying after a failed issuance attempt (don't hammer the CA).
const RETRY_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// Resolved ACME settings (from [`AcmeConfig`]). `None` when ACME is disabled or the
/// configuration is unusable (no domains).
#[derive(Clone, Debug)]
pub(crate) struct AcmeSettings {
    directory_url: String,
    contact_email: Option<String>,
    domains: Vec<String>,
    certificate_name: String,
    renew_before_days: i64,
}

impl AcmeSettings {
    /// Build settings from config, or `None` when ACME is disabled / has no domains.
    pub(crate) fn from_config(cfg: &AcmeConfig) -> Option<Self> {
        if !cfg.enabled {
            return None;
        }
        let domains: Vec<String> = cfg
            .domains
            .iter()
            .map(|d| d.trim().to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
        if domains.is_empty() {
            tracing::warn!("proxy ACME: enabled but no domains configured; disabled");
            return None;
        }
        let directory_url = cfg.directory_url.clone().unwrap_or_else(|| {
            if cfg.staging {
                LE_STAGING.to_string()
            } else {
                LE_PRODUCTION.to_string()
            }
        });
        Some(Self {
            directory_url,
            contact_email: cfg
                .contact_email
                .as_ref()
                .map(|e| e.trim().to_string())
                .filter(|e| !e.is_empty()),
            domains,
            certificate_name: cfg
                .certificate_name
                .clone()
                .filter(|n| !n.trim().is_empty())
                .unwrap_or_else(|| DEFAULT_CERT_NAME.to_string()),
            renew_before_days: cfg
                .renew_before_days
                .unwrap_or(DEFAULT_RENEW_BEFORE_DAYS)
                .max(1),
        })
    }
}

/// Run the ACME manager: seed the DB settings from `seed` on first run, then poll the
/// DB-backed settings, obtaining/renewing the certificate as needed, until shutdown. Runs
/// as a background task spawned by the proxy. Because the settings live in the DB (edited
/// from the Web UI), a domain added at runtime is picked up on the next poll and — via the
/// SAN-drift check in `needs_renewal` — re-issued onto the shared certificate WITHOUT a
/// restart.
pub(crate) async fn run_acme_manager(
    db: Db,
    seed: Option<AcmeConfig>,
    challenges: ChallengeStore,
    mut shutdown: watch::Receiver<bool>,
) {
    // Seed from the file config once; an operator-edited DB row wins thereafter.
    if let Err(e) = db.ensure_acme_config(seed).await {
        tracing::warn!("proxy ACME: could not seed settings: {e}");
    }
    tracing::info!("proxy ACME: manager started (settings are DB-backed / hot-reloaded)");

    let mut last_desc: Option<String> = None;
    loop {
        let mut wait = RELOAD_INTERVAL;
        match current_settings(&db).await {
            Some(settings) => {
                // Log when the effective settings change (enable / domain add / etc.).
                let desc = format!(
                    "cert '{}' for {:?} via {}",
                    settings.certificate_name, settings.domains, settings.directory_url
                );
                if last_desc.as_deref() != Some(desc.as_str()) {
                    tracing::info!("proxy ACME: managing {desc}");
                    last_desc = Some(desc);
                }
                if needs_renewal(&db, &settings).await {
                    match obtain_certificate(&db, &settings, &challenges).await {
                        Ok(()) => tracing::info!(
                            "proxy ACME: certificate '{}' issued/renewed successfully",
                            settings.certificate_name
                        ),
                        Err(e) => {
                            tracing::error!(
                                "proxy ACME: issuance for {:?} failed: {e}",
                                settings.domains
                            );
                            wait = RETRY_INTERVAL;
                        }
                    }
                }
            }
            None => {
                // ACME disabled or no domains: idle and re-check (it may be enabled later).
                if last_desc.take().is_some() {
                    tracing::info!("proxy ACME: now disabled / no domains; idle");
                }
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
        }
    }
}

/// Load the current effective ACME settings from the DB, or `None` when disabled / unusable.
async fn current_settings(db: &Db) -> Option<AcmeSettings> {
    match db.get_acme_config().await {
        Ok(Some(cfg)) => AcmeSettings::from_config(&cfg),
        Ok(None) => None,
        Err(e) => {
            tracing::warn!("proxy ACME: could not read settings ({e})");
            None
        }
    }
}

/// Whether the managed certificate is missing, within its renew-before window, or no longer
/// covers every configured domain (SAN drift — a host was added to `acme.domains`). The last
/// case matters because the single shared SAN certificate must be re-issued to add a host;
/// checking only expiry meant a newly-added domain was never actually put on the cert.
async fn needs_renewal(db: &Db, settings: &AcmeSettings) -> bool {
    match db.list_certificates().await {
        Ok(certs) => match certs
            .into_iter()
            .find(|c| c.name == settings.certificate_name)
        {
            Some(cert) => {
                let remaining = cert.not_after.signed_duration_since(Utc::now()).num_days();
                if remaining <= settings.renew_before_days {
                    tracing::info!(
                        "proxy ACME: certificate '{}' has {remaining} day(s) left; renewing",
                        settings.certificate_name
                    );
                    return true;
                }
                if let Some(missing) = uncovered_domain(&cert.san, &settings.domains) {
                    tracing::info!(
                        "proxy ACME: certificate '{}' does not yet cover '{missing}'; re-issuing \
                         to add it",
                        settings.certificate_name
                    );
                    return true;
                }
                false
            }
            None => true,
        },
        Err(e) => {
            tracing::warn!("proxy ACME: cannot list certificates ({e}); attempting issuance");
            true
        }
    }
}

/// The first configured domain not present in the certificate's SAN list (case-insensitive),
/// or `None` when the cert already covers every configured domain.
fn uncovered_domain(cert_san: &[String], domains: &[String]) -> Option<String> {
    let covered: std::collections::HashSet<String> = cert_san
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .collect();
    domains
        .iter()
        .find(|d| !covered.contains(&d.trim().to_ascii_lowercase()))
        .cloned()
}

/// Run one ACME order end-to-end: register/restore the account, answer the HTTP-01
/// challenges, finalize with a fresh key + CSR, and store the issued certificate.
async fn obtain_certificate(
    db: &Db,
    settings: &AcmeSettings,
    challenges: &ChallengeStore,
) -> Result<(), String> {
    let account = load_or_create_account(db, settings).await?;

    let identifiers: Vec<Identifier> = settings
        .domains
        .iter()
        .map(|d| Identifier::Dns(d.clone()))
        .collect();
    let mut order = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(|e| format!("new order: {e}"))?;

    // Provision the HTTP-01 response for each pending authorization, then signal ready.
    // On any error mid-loop, clear the tokens we already inserted so stale challenge
    // responses don't linger in the shared map.
    let mut tokens: Vec<String> = Vec::new();
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut authz = match result {
            Ok(authz) => authz,
            Err(e) => {
                clear_tokens(challenges, &tokens);
                return Err(format!("authorization: {e}"));
            }
        };
        if authz.status == AuthorizationStatus::Valid {
            continue;
        }
        let mut challenge = match authz.challenge(ChallengeType::Http01) {
            Some(c) => c,
            None => {
                clear_tokens(challenges, &tokens);
                return Err("no HTTP-01 challenge offered".to_string());
            }
        };
        let token = challenge.token.clone();
        let key_auth = challenge.key_authorization().as_str().to_string();
        if let Ok(mut map) = challenges.lock() {
            map.insert(token.clone(), key_auth);
        }
        tokens.push(token);
        if let Err(e) = challenge.set_ready().await {
            clear_tokens(challenges, &tokens);
            return Err(format!("set challenge ready: {e}"));
        }
    }

    // Wait for the CA to validate the challenges and move the order to `Ready`.
    let policy = RetryPolicy::default();
    let status = order.poll_ready(&policy).await.map_err(|e| {
        clear_tokens(challenges, &tokens);
        format!("poll order ready: {e}")
    })?;
    if status != OrderStatus::Ready {
        clear_tokens(challenges, &tokens);
        return Err(format!("order did not become ready: {status:?}"));
    }

    // Generate a fresh key pair + CSR for the domains and request finalization.
    let key_pem = match finalize(&mut order, &settings.domains).await {
        Ok(pem) => pem,
        Err(e) => {
            clear_tokens(challenges, &tokens);
            return Err(e);
        }
    };

    let cert_chain_pem = order.poll_certificate(&policy).await.map_err(|e| {
        clear_tokens(challenges, &tokens);
        format!("poll certificate: {e}")
    })?;
    clear_tokens(challenges, &tokens);

    // Store into the shared cert store; the FR-8 hot-reload resolver serves it next refresh.
    let (leaf_pem, chain_pem) = split_leaf_chain(&cert_chain_pem);
    let now = Utc::now();
    // Record the certificate's REAL validity window (parsed from the issued leaf), so
    // renewal timing follows the certificate rather than an assumed 89-day guess.
    let (not_before, not_after) = leaf_validity(&leaf_pem).unwrap_or_else(|| {
        tracing::warn!(
            "proxy ACME: could not parse issued certificate validity; \
             assuming now + {ASSUMED_VALIDITY_DAYS} day(s) for renewal timing"
        );
        (now, now + chrono::Duration::days(ASSUMED_VALIDITY_DAYS))
    });
    let subject = format!("CN={}", settings.domains[0]);
    db.upsert_certificate(
        &settings.certificate_name,
        &subject,
        "ACME",
        &settings.domains,
        not_before,
        not_after,
        &leaf_pem,
        chain_pem.as_deref(),
        Some(&key_pem),
        "acme",
    )
    .await
    .map_err(|e| format!("store certificate: {e}"))?;
    Ok(())
}

/// Restore the ACME account from persisted credentials, or register a new one and persist
/// its credentials so later renewals reuse the same account.
async fn load_or_create_account(db: &Db, settings: &AcmeSettings) -> Result<Account, String> {
    if let Ok(Some(json)) = db.get_proxy_kv(KV_ACCOUNT).await {
        match serde_json::from_str::<AccountCredentials>(&json) {
            Ok(creds) => {
                match Account::builder()
                    .map_err(|e| format!("ACME client: {e}"))?
                    .from_credentials(creds)
                    .await
                {
                    Ok(account) => return Ok(account),
                    Err(e) => tracing::warn!(
                        "proxy ACME: stored account credentials rejected ({e}); registering anew"
                    ),
                }
            }
            Err(e) => tracing::warn!("proxy ACME: stored account credentials corrupt ({e})"),
        }
    }

    let contact_string = settings
        .contact_email
        .as_ref()
        .map(|e| format!("mailto:{e}"));
    let contact: Vec<&str> = contact_string.as_deref().into_iter().collect();
    let new_account = NewAccount {
        contact: &contact,
        terms_of_service_agreed: true,
        only_return_existing: false,
    };
    let (account, credentials) = Account::builder()
        .map_err(|e| format!("ACME client: {e}"))?
        .create(&new_account, settings.directory_url.clone(), None)
        .await
        .map_err(|e| format!("register account: {e}"))?;
    match serde_json::to_string(&credentials) {
        Ok(json) => {
            if let Err(e) = db.set_proxy_kv(KV_ACCOUNT, &json).await {
                tracing::warn!("proxy ACME: could not persist account credentials: {e}");
            }
        }
        Err(e) => tracing::warn!("proxy ACME: could not serialize account credentials: {e}"),
    }
    Ok(account)
}

/// Generate an ECDSA key pair and CSR (SANs = the order's domains) and finalize the order.
/// Returns the private key as PEM (to store alongside the issued certificate).
async fn finalize(order: &mut instant_acme::Order, domains: &[String]) -> Result<String, String> {
    let mut params =
        rcgen::CertificateParams::new(domains.to_vec()).map_err(|e| format!("CSR params: {e}"))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let key_pair = rcgen::KeyPair::generate().map_err(|e| format!("key generation: {e}"))?;
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| format!("CSR: {e}"))?;
    order
        .finalize_csr(csr.der().as_ref())
        .await
        .map_err(|e| format!("finalize order: {e}"))?;
    Ok(key_pair.serialize_pem())
}

/// Split a PEM certificate chain into the leaf certificate and the remaining chain.
fn split_leaf_chain(pem: &str) -> (String, Option<String>) {
    const MARK: &str = "-----END CERTIFICATE-----";
    match pem.find(MARK) {
        Some(idx) => {
            let end = idx + MARK.len();
            let leaf = pem[..end].trim_start().to_string();
            let rest = pem[end..].trim();
            let chain = (!rest.is_empty()).then(|| rest.to_string());
            (leaf, chain)
        }
        None => (pem.trim().to_string(), None),
    }
}

/// Parse the leaf certificate's validity window `(notBefore, notAfter)` from its PEM,
/// so the stored record — which drives renewal timing — reflects the certificate the
/// CA actually issued rather than an assumed 89-day window. Returns `None` if the PEM
/// cannot be parsed or its dates are out of `DateTime` range (the caller then falls
/// back to the assumed window); the PEM itself always remains authoritative for serving.
fn leaf_validity(leaf_pem: &str) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    use x509_parser::prelude::*;
    let (_, pem) = parse_x509_pem(leaf_pem.as_bytes()).ok()?;
    let cert = pem.parse_x509().ok()?;
    let validity = cert.validity();
    let not_before = DateTime::from_timestamp(validity.not_before.timestamp(), 0)?;
    let not_after = DateTime::from_timestamp(validity.not_after.timestamp(), 0)?;
    Some((not_before, not_after))
}

/// Remove served challenge responses once an order completes (or fails).
fn clear_tokens(challenges: &ChallengeStore, tokens: &[String]) {
    if let Ok(mut map) = challenges.lock() {
        for token in tokens {
            map.remove(token);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_validity_parses_the_real_window() {
        // A self-signed cert with a known validity window; leaf_validity must read
        // exactly those dates (not an assumed 89-day guess).
        let mut params = rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2025, 3, 1);
        params.not_after = rcgen::date_time_ymd(2025, 5, 30);
        let key = rcgen::KeyPair::generate().unwrap();
        let pem = params.self_signed(&key).unwrap().pem();

        let (nb, na) = leaf_validity(&pem).expect("parse the issued validity");
        assert_eq!(
            nb,
            DateTime::parse_from_rfc3339("2025-03-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
        assert_eq!(
            na,
            DateTime::parse_from_rfc3339("2025-05-30T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
        // Non-cert input yields None, so the caller falls back to the assumed window.
        assert!(
            leaf_validity("-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----").is_none()
        );
        assert!(leaf_validity("not a pem at all").is_none());
    }

    #[test]
    fn settings_disabled_when_not_enabled() {
        let cfg = AcmeConfig {
            enabled: false,
            domains: vec!["example.com".into()],
            ..Default::default()
        };
        assert!(AcmeSettings::from_config(&cfg).is_none());
    }

    #[test]
    fn settings_require_domains() {
        let cfg = AcmeConfig {
            enabled: true,
            domains: vec!["  ".into()],
            ..Default::default()
        };
        assert!(AcmeSettings::from_config(&cfg).is_none());
    }

    #[test]
    fn settings_defaults_and_staging_url() {
        let cfg = AcmeConfig {
            enabled: true,
            staging: true,
            domains: vec!["Example.COM".into(), "www.example.com".into()],
            ..Default::default()
        };
        let s = AcmeSettings::from_config(&cfg).expect("settings");
        assert_eq!(s.directory_url, LE_STAGING);
        assert_eq!(s.certificate_name, "acme");
        assert_eq!(s.renew_before_days, 30);
        // domains are lowercased.
        assert_eq!(s.domains, vec!["example.com", "www.example.com"]);
    }

    #[test]
    fn explicit_directory_overrides_staging() {
        let cfg = AcmeConfig {
            enabled: true,
            staging: true,
            directory_url: Some("https://ca.internal/dir".into()),
            domains: vec!["example.com".into()],
            certificate_name: Some("wildcard".into()),
            renew_before_days: Some(45),
            ..Default::default()
        };
        let s = AcmeSettings::from_config(&cfg).expect("settings");
        assert_eq!(s.directory_url, "https://ca.internal/dir");
        assert_eq!(s.certificate_name, "wildcard");
        assert_eq!(s.renew_before_days, 45);
    }

    #[test]
    fn split_leaf_chain_separates_leaf_and_rest() {
        let leaf = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----";
        let inter = "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----";
        let full = format!("{leaf}\n{inter}\n");
        let (got_leaf, got_chain) = split_leaf_chain(&full);
        assert_eq!(got_leaf, leaf);
        assert_eq!(got_chain.as_deref(), Some(inter));
    }

    #[test]
    fn split_leaf_chain_single_cert_has_no_chain() {
        let leaf = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        let (got_leaf, got_chain) = split_leaf_chain(leaf);
        assert_eq!(got_leaf, leaf.trim());
        assert!(got_chain.is_none());
    }

    #[test]
    fn uncovered_domain_detects_san_drift() {
        // Cert already covers both configured domains → nothing to re-issue for.
        assert_eq!(
            uncovered_domain(
                &["a.example.com".into(), "b.example.com".into()],
                &["a.example.com".into(), "b.example.com".into()],
            ),
            None
        );
        // A newly-added domain not on the cert → returned (triggers re-issue).
        assert_eq!(
            uncovered_domain(
                &["a.example.com".into()],
                &["a.example.com".into(), "b.example.com".into()],
            )
            .as_deref(),
            Some("b.example.com")
        );
        // Case-insensitive coverage.
        assert_eq!(
            uncovered_domain(&["A.Example.COM".into()], &["a.example.com".into()],),
            None
        );
    }

    /// Regression: instant-acme builds its HTTPS client from the process-level rustls
    /// `CryptoProvider`; with none installed it panics on the first ACME call, so issuance
    /// never even started. The binary installs `ring` at startup — do the same here, then
    /// drive the exact `Account::builder().create()` path against an unreachable directory
    /// and assert we get a NETWORK error, not a provider panic. Without the install this
    /// test panics instead of returning `Err`.
    #[tokio::test]
    async fn acme_client_setup_uses_installed_crypto_provider_without_panicking() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let contact: Vec<&str> = Vec::new();
        let new_account = NewAccount {
            contact: &contact,
            terms_of_service_agreed: true,
            only_return_existing: false,
        };
        let result = Account::builder()
            .expect("ACME client builder should not panic once a provider is installed")
            .create(
                &new_account,
                // Unreachable directory: the call must fail on the network, having already
                // safely constructed the TLS client.
                "https://127.0.0.1:1/directory".to_string(),
                None,
            )
            .await;
        assert!(
            result.is_err(),
            "unreachable ACME directory must return an error, not succeed"
        );
    }
}
