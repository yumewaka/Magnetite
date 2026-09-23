//! `magnetite-server` — the single binary that boots the integrated platform
//! (09 §2): load config, open the one embedded DB, wire the Leptos SSR app and
//! server functions, start background tasks, and serve with graceful shutdown.

// The composed shell view resolves through a deeply nested future whose layout
// computation exceeds rustc's default query-depth limit (128) when the SSR app
// is linked here. Raise it (mirrors magnetite-app's own limit).
#![recursion_limit = "256"]

use axum::routing::any;
use axum::Router;
use leptos::prelude::*;
use leptos_axum::{generate_route_list, LeptosRoutes};
use magnetite_app::state::AppState;
use magnetite_app::App;
use magnetite_core::AppConfig;
use magnetite_db::{Db, EmbeddedService, ServiceRegistry};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tower_cookies::CookieManagerLayer;
use tracing::info;

mod cert_export;
mod health;
mod mgmt;
mod repl;
mod role;

fn main() -> anyhow::Result<()> {
    install_panic_hook();

    // Run the whole runtime on a thread with a large stack: the SSR render and
    // SurrealDB can be stack-hungry (mirrors the source deployment).
    let handle = std::thread::Builder::new()
        .name("magnetite-main".into())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(8 * 1024 * 1024)
                .build()
                .expect("failed to build tokio runtime")
                .block_on(async_main())
        })
        .expect("failed to spawn main thread");

    match handle.join() {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!("main thread panicked")),
    }
}

async fn async_main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,magnetite=debug".into()),
        )
        .init();

    // Install the process-level rustls CryptoProvider once. The embedded mail/proxy TLS
    // paths pass a `ring` provider explicitly, but instant-acme (the proxy's ACME/Let's
    // Encrypt client) reads the process *default* provider — which is unset here and would
    // panic on the first HTTP-01 issuance. `.ok()` tolerates a provider already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "magnetite.toml".to_string());
    let config = AppConfig::load(&config_path)
        .map_err(|e| anyhow::anyhow!("failed to load config from '{config_path}': {e}"))?;
    enforce_production_hardening(&config, &config_path)?;
    info!(
        "Starting Magnetite on {}:{}",
        config.server.host, config.server.port
    );

    // Open the database. By default an embedded RocksDB store under the config
    // directory; when `MAGNETITE_DB_URL` is set, connect to that SurrealDB URL
    // instead (e.g. `ws://dbhost:8000` — a networked server several DC front-ends
    // share, Tier B multi-DC). The `any` engine dispatches on the URL scheme.
    let db = match std::env::var("MAGNETITE_DB_URL") {
        Ok(url) if !url.trim().is_empty() => {
            info!("Opening shared database at {url}");
            Db::connect_url(url.trim())
                .await
                .map_err(|e| anyhow::anyhow!("failed to open database at {url}: {e}"))?
        }
        _ => {
            // Resolve the data directory relative to the config file.
            let config_dir = std::path::Path::new(&config_path)
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| std::path::Path::new("."));
            let db_path = config_dir.join("data").join("magnetite-db");
            info!("Opening embedded database at {}", db_path.display());
            Db::connect(&db_path)
                .await
                .map_err(|e| anyhow::anyhow!("failed to open database: {e}"))?
        }
    };

    // Prove the store actually persists a write before serving. A full disk or a lost
    // writable mount otherwise stays invisible until the first user write fails (silent
    // data loss). Fatal: a store that cannot commit is not safe to run.
    db.probe_writable()
        .await
        .map_err(|e| anyhow::anyhow!("database is not writable — refusing to start: {e}"))?;

    log_db_durability();

    // Base directory for on-disk DB backups: alongside the embedded store's data dir
    // (resolved from the config path), overridable via `MAGNETITE_BACKUP_DIR`. Used
    // even with a networked store, so a backup always has a local landing place.
    let backup_base = Path::new(&config_path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .join("data");

    let config = Arc::new(config);

    // Embedded protocol servers (09b §-1). Each domain's server is configured
    // under `[domains.<d>.server]` in AppConfig (R5, restart-scoped); a domain
    // with no `server` block serves no protocol and reports Disabled. Domains
    // are ported one at a time (Phase E1+ = DNS).
    let embedded = build_embedded_services(&config, &db);
    let services = ServiceRegistry::new(embedded);
    let state = AppState::new(db.clone(), config.clone(), services.clone());

    // Runtime replication-role control for the config-replication domains. Each secondary
    // registers below and hands its pull loop a pause flag; the management plane flips it
    // to promote/demote the node without a restart (P2 manual failover).
    let roles = role::RoleController::new();

    // Seed the domain SID (the single source of truth shared with the AD DC over the
    // same magnetite-db) from config on first run; once seeded the persisted value wins,
    // so the LDAP objectSid, the KDC/SAMR PAC and web-created group SIDs all agree.
    if let Err(e) = db
        .ensure_domain_sid(&config.domain_sid_subauth(), "system")
        .await
    {
        tracing::warn!("failed to seed domain SID: {e}");
    }

    // Background tasks with graceful shutdown (09 §1).
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    services.start_all(&db, &shutdown_tx.subscribe());
    spawn_session_cleanup(
        db.clone(),
        config.policy.retention_days,
        shutdown_tx.subscribe(),
    );
    // Periodic off-store DB backup (disaster recovery). Env-tunable; on by default.
    spawn_backup_task(db.clone(), backup_base, shutdown_tx.subscribe())?;

    // Dynamic-DNS client scheduler: pushes the current public IP to an external DDNS
    // provider daily at the configured time. Settings are DB-backed and edited from the
    // Web UI (DNS → ダイナミックDNS), so the task always runs and idles until enabled.
    {
        let ddns_db = db.clone();
        let ddns_shutdown = shutdown_tx.subscribe();
        magnetite_db::spawn_supervised("ddns-scheduler", async move {
            magnetite_dns::ddns::run_scheduler(ddns_db, None, ddns_shutdown).await;
        });
    }

    // Alert notification dispatcher: fans newly-raised alerts out to the configured
    // notification targets (webhook / audit-sink / email). Email uses the mail
    // server's relay; the From address is derived from the directory base DN.
    {
        let relay = config
            .domains
            .get(&magnetite_core::domain::DomainKey::Mail)
            .and_then(|d| d.server.as_ref())
            .and_then(|s| s.relay.clone());
        let domain = config
            .ldap_base_dn()
            .split(',')
            .filter_map(|p| p.trim().strip_prefix("dc="))
            .collect::<Vec<_>>()
            .join(".");
        let from_address = if domain.is_empty() {
            "magnetite-alerts@localhost".to_string()
        } else {
            format!("magnetite-alerts@{domain}")
        };
        magnetite_notify::spawn_dispatcher(
            db.clone(),
            magnetite_notify::NotifyConfig {
                relay,
                from_address,
            },
            shutdown_tx.subscribe(),
        );
    }

    // LDAP syncrepl consumer (RFC 4533): when configured, replicate an upstream
    // LDAP directory into this instance's store.
    if let Some(consumer_cfg) = config
        .domains
        .get(&magnetite_core::domain::DomainKey::Ldap)
        .and_then(|d| d.server.as_ref())
        .and_then(|s| s.consumer.as_ref())
        .filter(|c| c.enabled && !c.provider_url.trim().is_empty())
    {
        info!(
            "LDAP syncrepl consumer: replicating from {} every {}s",
            consumer_cfg.provider_url,
            consumer_cfg.interval()
        );
        magnetite_ldap::spawn_consumer(
            db.clone(),
            consumer_cfg.clone(),
            config.ldap_base_dn().to_string(),
            shutdown_tx.subscribe(),
        );
    }

    // Inbound AD DRS replication (DCSync) from the Web-UI server: when configured, pull
    // directory changes from the upstream DC(s) into the shared DB on an interval — the
    // same agent the standalone magnetite-addc daemon runs, so a server-only deployment
    // stays in sync without it. Applies to the DB only (no in-process KDC/directory here).
    spawn_addc_replication(&config, &db, &shutdown_tx);

    magnetite_app::register_server_functions();

    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port)
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid server address: {e}"))?;
    // The compiled site assets (WASM/JS bundle, CSS) live under `site_root`.
    // `cargo leptos` writes them to `target/site` in development; a packaged
    // deployment sets `LEPTOS_SITE_ROOT` to the bundled `site/` directory.
    let site_root = std::env::var("LEPTOS_SITE_ROOT").unwrap_or_else(|_| "target/site".to_string());
    let leptos_options = LeptosOptions::builder()
        .output_name("magnetite")
        .site_root(site_root)
        .site_pkg_dir("pkg")
        .site_addr(addr)
        .build();

    let routes = generate_route_list(App);

    let context_state = state.clone();
    let provide = move || provide_context(context_state.clone());

    let leptos_options_fallback = leptos_options.clone();
    let mut app = Router::new()
        .route(
            "/api/{*fn_name}",
            any({
                let provide = provide.clone();
                move |req: axum::extract::Request| {
                    leptos_axum::handle_server_fns_with_context(provide.clone(), req)
                }
            }),
        )
        .leptos_routes_with_context(&leptos_options, routes, provide, {
            let options = leptos_options.clone();
            move || magnetite_app::shell(options.clone())
        })
        .fallback(leptos_axum::file_and_error_handler(magnetite_app::shell))
        .with_state(leptos_options_fallback);

    // Embedded OIDC issuer (Phase E8): mount the IdP endpoints on the main
    // server at `issuer = server.base_url` when the SSO domain is enabled.
    if config.is_domain_enabled(magnetite_core::domain::DomainKey::Sso) {
        match magnetite_sso::SsoState::new(db.clone(), config.server.base_url.clone()).await {
            Ok(sso_state) => {
                info!("Embedded OIDC issuer at {}/oidc", config.server.base_url);
                app = app.merge(magnetite_sso::oidc_router(sso_state));
            }
            Err(e) => tracing::warn!("OIDC issuer disabled: signing key init failed: {e}"),
        }

        // Upstream SSO federation (relying-party side): let users log into magnetite
        // through an external provider. Mounts /auth/sso/{provider}/start + callback.
        info!(
            "Upstream SSO federation at {}/auth/sso",
            config.server.base_url
        );
        app = app.merge(magnetite_federation::federation_router(
            magnetite_federation::FederationState::new(db.clone(), config.server.base_url.clone()),
        ));
    }

    // Mailbox replication (Phase E4 / Step 2 HA). When mail replication is
    // configured with a secret, serve the change feed at `/repl/mail`; when this
    // instance is a secondary (a `primary_url` is set), also poll the primary.
    if let Some(repl_cfg) = config
        .domains
        .get(&magnetite_core::domain::DomainKey::Mail)
        .and_then(|d| d.server.as_ref())
        .and_then(|s| s.replication.as_ref())
        .filter(|r| r.enabled && !r.secret.trim().is_empty())
    {
        info!("Mailbox replication feed at /repl/mail");
        app = app.merge(repl::mail_repl_router(db.clone(), repl_cfg.secret.clone()));
        if repl_cfg.is_secondary() {
            let primary_url = repl_cfg.primary_url.clone().unwrap_or_default();
            info!(
                "Mailbox replication: pulling from primary {primary_url} every {}s",
                repl_cfg.interval()
            );
            repl::spawn_mail_pull(
                db.clone(),
                primary_url,
                repl_cfg.secret.clone(),
                repl_cfg.interval(),
                roles.register_secondary(magnetite_core::domain::DomainKey::Mail),
                shutdown_tx.subscribe(),
            );
        }
    }

    // DHCP lease replication (failover continuity for split-scope servers): the same
    // primary/secondary shape as mail — serve the lease feed, and if this is a peer,
    // poll the primary and apply its leases.
    if let Some(repl_cfg) = config
        .domains
        .get(&magnetite_core::domain::DomainKey::Dhcp)
        .and_then(|d| d.server.as_ref())
        .and_then(|s| s.replication.as_ref())
        .filter(|r| r.enabled && !r.secret.trim().is_empty())
    {
        info!("DHCP lease replication feed at /repl/dhcp");
        app = app.merge(repl::dhcp_repl_router(db.clone(), repl_cfg.secret.clone()));
        if repl_cfg.is_secondary() {
            let primary_url = repl_cfg.primary_url.clone().unwrap_or_default();
            info!(
                "DHCP lease replication: pulling from primary {primary_url} every {}s",
                repl_cfg.interval()
            );
            repl::spawn_dhcp_pull(
                db.clone(),
                primary_url,
                repl_cfg.secret.clone(),
                repl_cfg.interval(),
                roles.register_secondary(magnetite_core::domain::DomainKey::Dhcp),
                shutdown_tx.subscribe(),
            );
        }
    }

    // SYSVOL (Group Policy) replication — a DFS-R-equivalent keeping the SysVol
    // share consistent across DCs. Gated on the AD DC domain's replication
    // config; a peer pulls the versioned file feed into its store (the SMB DC
    // then builds its served tree from that store).
    if let Some(repl_cfg) = config
        .domains
        .get(&magnetite_core::domain::DomainKey::Addc)
        .and_then(|d| d.server.as_ref())
        .and_then(|s| s.replication.as_ref())
        .filter(|r| r.enabled && !r.secret.trim().is_empty())
    {
        info!("SYSVOL (Group Policy) replication feed at /repl/sysvol");
        app = app.merge(repl::sysvol_repl_router(
            db.clone(),
            repl_cfg.secret.clone(),
        ));
        if repl_cfg.is_secondary() {
            let primary_url = repl_cfg.primary_url.clone().unwrap_or_default();
            info!(
                "SYSVOL replication: pulling from primary {primary_url} every {}s",
                repl_cfg.interval()
            );
            repl::spawn_sysvol_pull(
                db.clone(),
                primary_url,
                repl_cfg.secret.clone(),
                repl_cfg.interval(),
                shutdown_tx.subscribe(),
            );
        }
    }

    // Reverse-proxy configuration replication (Tier C): serve a full config snapshot at
    // `/repl/proxy`, and if this instance is a secondary, poll the primary and replace
    // the local proxy config. A secondary receives ACME-issued certs via this feed, so
    // it does not run its own ACME issuance (handled where the proxy service is built).
    if let Some(repl_cfg) = config
        .domains
        .get(&magnetite_core::domain::DomainKey::Proxy)
        .and_then(|d| d.server.as_ref())
        .and_then(|s| s.replication.as_ref())
        .filter(|r| r.enabled && !r.secret.trim().is_empty())
    {
        info!("Proxy config replication feed at /repl/proxy");
        app = app.merge(repl::proxy_repl_router(db.clone(), repl_cfg.secret.clone()));
        if repl_cfg.is_secondary() {
            let primary_url = repl_cfg.primary_url.clone().unwrap_or_default();
            info!(
                "Proxy config replication: pulling from primary {primary_url} every {}s",
                repl_cfg.interval()
            );
            repl::spawn_proxy_pull(
                db.clone(),
                primary_url,
                repl_cfg.secret.clone(),
                repl_cfg.interval(),
                roles.register_secondary(magnetite_core::domain::DomainKey::Proxy),
                shutdown_tx.subscribe(),
            );
        }
    }

    // SSO config replication (Tier C): serve a full snapshot of providers / OIDC clients /
    // signing keys at `/repl/sso`, and if this instance is a secondary, poll the primary and
    // replace the local SSO config. Sessions are not replicated (they re-establish on
    // failover). Replicating signing keys keeps the JWKS consistent across nodes.
    if let Some(repl_cfg) = config
        .domains
        .get(&magnetite_core::domain::DomainKey::Sso)
        .and_then(|d| d.server.as_ref())
        .and_then(|s| s.replication.as_ref())
        .filter(|r| r.enabled && !r.secret.trim().is_empty())
    {
        info!("SSO config replication feed at /repl/sso");
        app = app.merge(repl::sso_repl_router(db.clone(), repl_cfg.secret.clone()));
        if repl_cfg.is_secondary() {
            let primary_url = repl_cfg.primary_url.clone().unwrap_or_default();
            info!(
                "SSO config replication: pulling from primary {primary_url} every {}s",
                repl_cfg.interval()
            );
            repl::spawn_sso_pull(
                db.clone(),
                primary_url,
                repl_cfg.secret.clone(),
                repl_cfg.interval(),
                roles.register_secondary(magnetite_core::domain::DomainKey::Sso),
                shutdown_tx.subscribe(),
            );
        }
    }

    // Unauthenticated liveness/readiness/metrics probes (09 §3): `/healthz`,
    // `/readyz`, `/metrics`. Always mounted — a load balancer or Kubernetes must
    // be able to probe the node regardless of which domains are configured. They
    // expose only operational state, never config or secrets (unlike `/mgmt/*`).
    app = app.merge(health::health_router(db.clone(), services.clone()));

    // Management-plane agent API (`/mgmt/*`): expose this server's identity + per-domain
    // health/role for a magnetite-center control plane to poll. Gated by the [mgmt] token.
    if let Some(mgmt_cfg) = config
        .mgmt
        .as_ref()
        .filter(|m| m.enabled && !m.token.trim().is_empty())
    {
        info!("Management agent API at /mgmt/*");
        app = app.merge(mgmt::mgmt_router(
            db.clone(),
            config.clone(),
            services.clone(),
            roles.clone(),
            mgmt_cfg.token.clone(),
        ));
    }

    // Certificate-export API (`/export/certificate/<name>`): hand a managed cert's
    // PEM + private key to an app behind the proxy (deploy-hook-style distribution).
    // Per-token cert authorization + TLS-required + failure audit/rate-limit (H-1).
    if let Some(cx) = config.cert_export.as_ref().filter(|c| c.enabled) {
        if cx.tokens.is_empty() {
            info!("cert-export enabled but no tokens configured; API not mounted");
        } else {
            // Fail-closed: a private-key API must not start with an unsafe/useless config
            // (spoofable trust, empty/short tokens, unscoped tokens).
            cert_export::validate_cert_export(cx)
                .map_err(|e| anyhow::anyhow!("invalid [cert_export] config: {e}"))?;
            info!("Certificate-export API at /export/certificate/* (per-token authz; TLS required via trusted proxy)");
            app = app.merge(cert_export::cert_export_router(db.clone(), cx));
        }
    }

    let app = app.layer(CookieManagerLayer::new());

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("Magnetite listening on http://{}", addr);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    let _ = shutdown_tx.send(true);
    info!("Magnetite shut down gracefully");
    Ok(())
}

/// The AD DC realm when the `addc` domain is enabled — used to cross-wire the KDC's
/// service key into the embedded LDAP (GSS-SPNEGO SASL). `None` if no AD DC.
fn addc_realm(config: &AppConfig) -> Option<String> {
    let addc = config
        .domains
        .get(&magnetite_core::domain::DomainKey::Addc)
        .and_then(|d| d.server.as_ref())
        .and_then(|s| s.addc.as_ref())?;
    Some(
        addc.realm
            .clone()
            .unwrap_or_else(|| magnetite_addc::DEFAULT_REALM.to_string()),
    )
}

/// Start the inbound AD DRS replication agent(s) from `[domains.addc.server.addc.replication]`
/// when enabled: one background agent per upstream DC, pulling changes into the shared DB
/// on the configured interval. Runs the same agent the standalone daemon uses, minus the
/// in-process KDC/directory (server-side has none — it applies to the DB, which the
/// embedded LDAP then serves). A bad address is logged and skipped.
fn spawn_addc_replication(
    config: &AppConfig,
    db: &Db,
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
) {
    let Some(repl) = config
        .domains
        .get(&magnetite_core::domain::DomainKey::Addc)
        .and_then(|d| d.server.as_ref())
        .and_then(|s| s.addc.as_ref())
        .and_then(|a| a.replication.as_ref())
        .filter(|r| r.enabled && !r.upstreams.is_empty())
    else {
        return;
    };
    let realm = repl
        .realm
        .clone()
        .or_else(|| addc_realm(config))
        .unwrap_or_else(|| magnetite_addc::DEFAULT_REALM.to_string());
    let kdc: SocketAddr = match repl.kdc.trim().parse() {
        Ok(a) => a,
        Err(e) => {
            tracing::error!("AD DC replication: invalid kdc {:?}: {e}", repl.kdc);
            return;
        }
    };
    let nc_dn = repl
        .nc_dn
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("dc={}", realm.to_lowercase().replace('.', ",dc=")));
    let interval = Duration::from_secs(repl.interval_secs.unwrap_or(300).max(1));
    let user = repl
        .user
        .clone()
        .unwrap_or_else(|| "Administrator".to_string());
    for up in &repl.upstreams {
        let drs: SocketAddr = match up.drs.trim().parse() {
            Ok(a) => a,
            Err(e) => {
                tracing::error!("AD DC replication: invalid upstream drs {:?}: {e}", up.drs);
                continue;
            }
        };
        let cfg = magnetite_addc::ReplicationConfig {
            kdc,
            drs,
            realm: realm.clone(),
            user: user.clone(),
            password: repl.password.clone().unwrap_or_default(),
            keytab: repl.keytab.clone().map(std::path::PathBuf::from),
            spn: up.spn.clone(),
            nc_dn: nc_dn.clone(),
            extra_ncs: repl.extra_ncs.clone(),
            interval,
        };
        info!(
            "AD DC replication: pulling from DRS {} (NC {}) every {}s",
            drs,
            nc_dn,
            interval.as_secs()
        );
        // Own thread + LocalSet (the DRS client uses !Send futures); applies to the DB
        // only — no live KDC/directory in the server process.
        magnetite_addc::spawn_replication_thread(
            cfg,
            db.clone(),
            shutdown_tx.subscribe(),
            None,
            None,
            None,
        );
    }
}

/// Construct the embedded protocol servers from `[domains.<d>.server]` config
/// (09b §-1 / R5). Domains without a `server` block serve no protocol.
fn build_embedded_services(config: &AppConfig, db: &Db) -> Vec<Arc<dyn EmbeddedService>> {
    use magnetite_core::domain::DomainKey;
    let mut services: Vec<Arc<dyn EmbeddedService>> = Vec::new();

    // Build the AD DC service first (when configured) so the embedded LDAP server —
    // constructed below — can share its live KDC store: a domain join's `computer`
    // Add over LDAP then registers the machine account with the running KDC.
    let addc_service: Option<Arc<magnetite_addc::AddcService>> = config
        .domains
        .get(&DomainKey::Addc)
        .and_then(|d| d.server.as_ref())
        .and_then(|s| s.addc.as_ref())
        .map(|addc| Arc::new(magnetite_addc::AddcService::new(addc)));

    // DNS (Phase E1).
    if let Some(server) = config
        .domains
        .get(&DomainKey::Dns)
        .and_then(|d| d.server.as_ref())
    {
        match server.socket() {
            Some(addr) => {
                let forwarders: Vec<SocketAddr> = server
                    .forwarders
                    .iter()
                    .filter_map(|s| s.parse().ok())
                    .collect();
                info!(
                    "Embedded DNS server on {addr} (UDP/TCP), {} forwarder(s), query_log={}",
                    forwarders.len(),
                    server.query_log
                );
                let mut dns = magnetite_dns::DnsService::new(addr, forwarders, server.query_log);
                // When the AD DC is enabled, accept GSS-TSIG dynamic updates
                // (RFC 3645): a domain member secures its DNS registration with a
                // `DNS/<dc-fqdn>` Kerberos ticket — the same key the KDC issues it.
                if let Some(realm) = addc_realm(config) {
                    if let Ok(key) = magnetite_addc::dns_service_key(&realm) {
                        info!("Embedded DNS: GSS-TSIG dynamic updates enabled (realm {realm})");
                        dns = dns.with_gss_key(key);
                    }
                }
                services.push(Arc::new(dns));
            }
            None => tracing::warn!("domains.dns.server.listen is missing or not a valid host:port"),
        }
    }

    // DHCP (Phase E2).
    if let Some(server) = config
        .domains
        .get(&DomainKey::Dhcp)
        .and_then(|d| d.server.as_ref())
    {
        match server.socket() {
            Some(addr) => {
                info!(
                    "Embedded DHCPv4 server on {addr} (UDP), log_events={}",
                    server.query_log
                );
                // Split-scope redundancy: with NODE_INDEX + DHCP_NODES set, this server
                // allocates from a disjoint slice of each pool so N independent DHCP
                // servers never hand the same address to two clients (no coordination).
                let mut dhcp = magnetite_dhcp::DhcpService::new(addr, server.query_log);
                if let (Some(idx), Some(count)) = (
                    std::env::var("NODE_INDEX")
                        .ok()
                        .and_then(|s| s.trim().parse::<u32>().ok()),
                    std::env::var("DHCP_NODES")
                        .ok()
                        .and_then(|s| s.trim().parse::<u32>().ok()),
                ) {
                    if count > 1 {
                        info!("DHCP split-scope: node {idx} of {count} (disjoint pool slice)");
                        dhcp = dhcp.with_partition(idx, count);
                    }
                }
                services.push(Arc::new(dhcp));
            }
            None => {
                tracing::warn!("domains.dhcp.server.listen is missing or not a valid host:port")
            }
        }
    }

    // LDAP (Phase E6).
    if let Some(server) = config
        .domains
        .get(&DomainKey::Ldap)
        .and_then(|d| d.server.as_ref())
    {
        match server.socket() {
            Some(addr) => {
                info!(
                    "Embedded LDAP server on {addr}, log_events={}, StartTLS={}",
                    server.query_log,
                    server.tls_cert_name.as_deref().unwrap_or("off")
                );
                let mut ldap = magnetite_ldap::LdapService::new(
                    addr,
                    server.query_log,
                    server.tls_cert_name.clone(),
                    config.ldap_base_dn().to_string(),
                );
                // When the AD DC is enabled, let LDAP accept GSS-SPNEGO Kerberos binds
                // (a domain-join client authenticates with a `ldap/<dc-fqdn>` ticket) —
                // the same service key the KDC issues those tickets against.
                if let Some(realm) = addc_realm(config) {
                    if let Ok(key) = magnetite_addc::ldap_service_key(&realm) {
                        info!("Embedded LDAP: GSS-SPNEGO SASL bind enabled (realm {realm})");
                        ldap = ldap.with_gss_key(key);
                    }
                }
                // When the AD DC is enabled, a `computer` Add over LDAP registers the
                // machine account with the DC's live KDC (and persists it).
                if let Some(addc) = &addc_service {
                    info!("Embedded LDAP: machine accounts register with the AD DC KDC");
                    ldap = ldap.with_machine_registrar(addc.machine_registrar(db.clone()));
                    // Accept an NTLM GSS-SPNEGO SASL bind (a Windows join with no
                    // Kerberos ticket) verified against the DC directory's NT hashes.
                    info!("Embedded LDAP: NTLM SASL bind enabled (directory NT hashes)");
                    ldap = ldap.with_nt_hash_lookup(addc.nt_hash_lookup());
                    // Match the RootDSE serverName/dsServiceName to the DC's configured
                    // computer label (its CLDAP/DNS identity).
                    ldap = ldap.with_dc_label(addc.dc_label().to_string());
                }
                services.push(Arc::new(ldap));
            }
            None => {
                tracing::warn!("domains.ldap.server.listen is missing or not a valid host:port")
            }
        }
    }

    // Proxy (Phase E3).
    if let Some(server) = config
        .domains
        .get(&DomainKey::Proxy)
        .and_then(|d| d.server.as_ref())
    {
        match server.socket() {
            Some(addr) => {
                let tls_addr = server
                    .tls_listen
                    .as_deref()
                    .and_then(|s| s.parse::<SocketAddr>().ok());
                let forward_addr = server
                    .forward_listen
                    .as_deref()
                    .and_then(|s| s.parse::<SocketAddr>().ok());
                // Comma-separated L4/TCP stream listen sockets (RDP/PostgreSQL/…).
                let tcp_addrs: Vec<SocketAddr> = server
                    .tcp_listen
                    .as_deref()
                    .unwrap_or("")
                    .split(',')
                    .filter_map(|s| s.trim().parse::<SocketAddr>().ok())
                    .collect();
                info!(
                    "Embedded reverse proxy on {addr}{}{}{}, log_access={}",
                    tls_addr
                        .map(|t| format!(" (+HTTPS {t})"))
                        .unwrap_or_default(),
                    forward_addr
                        .map(|f| format!(" (+forward {f})"))
                        .unwrap_or_default(),
                    if tcp_addrs.is_empty() {
                        String::new()
                    } else {
                        format!(" (+TCP {tcp_addrs:?})")
                    },
                    server.query_log
                );
                // A proxy replication secondary receives certs (incl. ACME-issued ones)
                // via /repl/proxy, so it must NOT run its own ACME issuance — that would
                // double-issue and be overwritten on the next pull.
                let is_repl_secondary = server
                    .replication
                    .as_ref()
                    .filter(|r| r.enabled && !r.secret.trim().is_empty())
                    .is_some_and(|r| r.is_secondary());
                let acme_cfg = if is_repl_secondary {
                    None
                } else {
                    server.acme.clone()
                };
                if is_repl_secondary && server.acme.as_ref().is_some_and(|a| a.enabled) {
                    info!(
                        "Embedded reverse proxy: ACME disabled (this node is a proxy replication secondary; certs arrive via /repl/proxy)"
                    );
                } else if let Some(acme) = &acme_cfg {
                    if acme.enabled {
                        info!(
                            "Embedded reverse proxy: ACME auto-TLS enabled for {:?} (cert '{}')",
                            acme.domains,
                            acme.certificate_name.as_deref().unwrap_or("acme")
                        );
                    }
                }
                services.push(Arc::new(
                    magnetite_proxy::ProxyService::new(
                        addr,
                        tls_addr,
                        forward_addr,
                        tcp_addrs,
                        server.max_body_bytes,
                        server.query_log,
                    )
                    .with_acme(acme_cfg),
                ));
            }
            None => {
                tracing::warn!("domains.proxy.server.listen is missing or not a valid host:port")
            }
        }
    }

    // Mail / SMTP (Phase E4).
    if let Some(server) = config
        .domains
        .get(&DomainKey::Mail)
        .and_then(|d| d.server.as_ref())
    {
        match server.socket() {
            Some(addr) => {
                info!(
                    "Embedded SMTP server on {addr}, log_events={}, relay={}",
                    server.query_log,
                    server
                        .relay
                        .as_ref()
                        .map(|r| r.host.as_str())
                        .unwrap_or("direct")
                );
                services.push(Arc::new(magnetite_mail::MailService::new(
                    addr,
                    server.query_log,
                    server.relay.clone(),
                )));
            }
            None => {
                tracing::warn!("domains.mail.server.listen is missing or not a valid host:port")
            }
        }
    }

    // Watch collector (Phase E7). No listen socket — it polls monitored hosts.
    if let Some(server) = config
        .domains
        .get(&DomainKey::Watch)
        .and_then(|d| d.server.as_ref())
    {
        let interval_secs = server.interval_secs.unwrap_or(60);
        let probe_port = server.probe_port.unwrap_or(22);
        info!(
            "Embedded Watch collector: interval={interval_secs}s, probe_port={probe_port}, log_events={}",
            server.query_log
        );
        services.push(Arc::new(magnetite_watch::WatchService::new(
            interval_secs,
            probe_port,
            server.query_log,
        )));
    }

    // AD DC — KDC + SMB/SYSVOL + RPC (SAMR/LSA/DRSUAPI). Built at the top of this
    // function (so LDAP can share its KDC store); here we just log and register it.
    if let Some(server) = config
        .domains
        .get(&DomainKey::Addc)
        .and_then(|d| d.server.as_ref())
    {
        match (server.addc.as_ref(), &addc_service) {
            (Some(_), Some(service)) => {
                let a = service.addrs();
                info!(
                    "Embedded AD DC: realm={} KDC={} SMB={} RPC/SAMR={} DRSUAPI={}",
                    service.realm(),
                    a.kdc,
                    a.smb,
                    a.rpc,
                    a.drs
                );
                services.push(service.clone());
            }
            _ => tracing::warn!("domains.addc.server is present but has no [addc] block"),
        }
    }

    services
}

/// Periodically purge expired/revoked sessions (09 §1 / §6.5).
/// Periodic maintenance: expire sessions and enforce the retention window on the
/// append-only observability tables (logs / audit / metrics) so they don't grow unbounded.
fn spawn_session_cleanup(
    db: Db,
    retention_days: u32,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    magnetite_db::spawn_supervised("session-cleanup", async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(300)) => {
                    if let Err(e) = db.cleanup_expired_sessions().await {
                        tracing::warn!("session cleanup failed: {e}");
                    }
                    match db.run_retention(retention_days).await {
                        Ok(n) if n > 0 => info!("retention: pruned {n} expired log/audit/metric row(s)"),
                        Ok(_) => {}
                        Err(e) => tracing::warn!("retention prune failed: {e}"),
                    }
                }
                _ = shutdown.changed() => break,
            }
        }
    });
}

/// The config file's mode (masked to `0o777`) when it is group/other-accessible, i.e.
/// unsafe for a secret-bearing file (should be `0600`). `None` if it is adequately
/// restricted, cannot be stat'd, or POSIX modes don't apply.
#[cfg(unix)]
fn config_world_readable_mode(path: &str) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    let m = std::fs::metadata(path).ok()?;
    let mode = m.permissions().mode() & 0o777;
    (mode & 0o077 != 0).then_some(mode)
}

#[cfg(not(unix))]
fn config_world_readable_mode(_path: &str) -> Option<u32> {
    None
}

/// Warn if the config file (which may hold secrets — tokens, bind/relay passwords) is
/// group- or world-accessible. It should be mode 0600; a loud startup warning nudges the
/// operator to `chmod` it. (In `PRODUCTION` this is escalated to a hard failure by
/// [`enforce_production_hardening`].)
fn warn_if_config_world_readable(path: &str) {
    if let Some(mode) = config_world_readable_mode(path) {
        tracing::warn!(
            "config file {path} is mode {mode:o} (group/other-accessible) and may contain \
             secrets — restrict it with `chmod 0600 {path}`"
        );
    }
}

/// Whether `PRODUCTION` is set to a truthy value. Enables the fail-closed startup guards:
/// a sole production deployment must not run with dev-default secrets or a world-readable
/// secret config (mirrors the domain-secret guard in `magnetite-addc`).
fn production_mode() -> bool {
    std::env::var("PRODUCTION")
        .map(|v| {
            matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// The built-in dev fallback for the SSO client secret (`${SSO_CLIENT_SECRET:-…}` in
/// magnetite.toml). Running production with this means the OIDC client secret is public.
const DEV_SSO_CLIENT_SECRET: &str = "changeme-dev-only";

/// Whether an SSO client secret is unsafe for production: empty/blank or the dev default.
fn sso_secret_is_weak(secret: &str) -> bool {
    let s = secret.trim();
    s.is_empty() || s == DEV_SSO_CLIENT_SECRET
}

/// Fail-closed production guard. In `PRODUCTION` mode, refuse to start when a secret is
/// left at its dev default or when the (secret-bearing) config is group/other-readable;
/// outside production these are only warnings. Keeps a sole production IdP from silently
/// serving with a public client secret or a leaky config (M-3).
fn enforce_production_hardening(config: &AppConfig, config_path: &str) -> anyhow::Result<()> {
    if !production_mode() {
        warn_if_config_world_readable(config_path);
        return Ok(());
    }
    if let Some(sso) = &config.sso {
        if sso_secret_is_weak(&sso.client_secret) {
            anyhow::bail!(
                "PRODUCTION is set but [sso] client_secret is empty or the dev default \
                 ('{DEV_SSO_CLIENT_SECRET}') — set SSO_CLIENT_SECRET to a strong value \
                 (e.g. in secrets.env at mode 0600) and restart"
            );
        }
    }
    if let Some(mode) = config_world_readable_mode(config_path) {
        anyhow::bail!(
            "PRODUCTION is set but config {config_path} is mode {mode:o} (group/other-accessible) \
             and may hold secrets — `chmod 0600 {config_path}` (or move secrets to secrets.env) \
             and restart"
        );
    }
    Ok(())
}

/// Log the store's write-durability posture at startup. Embedded RocksDB stores are
/// opened with an explicit `?sync=every` (per-commit fsync — see `Db::connect` /
/// `ensure_rocksdb_sync`), so a committed write survives a crash regardless of the engine
/// default; a networked store's durability is the remote server's concern. If a
/// `SURREAL_*SYNC*` env var requests a relaxed mode, surface that it does NOT win (the URL
/// parameter takes precedence) so the mismatch is not mistaken for a durability change.
fn log_db_durability() {
    let relaxed = std::env::vars().find(|(k, v)| {
        k.starts_with("SURREAL_")
            && k.contains("SYNC")
            && matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "never" | "false" | "off" | "0"
            )
    });
    match relaxed {
        Some((k, v)) => tracing::warn!(
            "DB durability: {k}={v} requests relaxed sync, but the embedded store is opened with \
             explicit sync=every (per-commit fsync), which takes precedence"
        ),
        None => info!(
            "DB durability: embedded RocksDB opened with sync=every (per-commit fsync) — a \
             committed write survives a crash"
        ),
    }
}

/// Spawn the periodic off-store DB backup task: write a full SurrealQL dump (a
/// disaster-recovery snapshot that survives loss of the live store) to the backup
/// directory and prune older ones. A **baseline dump is written once at startup** so a
/// fresh node — or one that keeps crashing before the first interval elapses — always has
/// a recent snapshot, then repeats on the interval. Tunable via env:
/// `MAGNETITE_BACKUP_INTERVAL_HOURS` (default 24; `0` disables), `MAGNETITE_BACKUP_KEEP`
/// (default 7), `MAGNETITE_BACKUP_DIR` (default `<data>/backups`).
///
/// For real disaster recovery point `MAGNETITE_BACKUP_DIR` at an **off-host** location (a
/// mounted network share or a separate volume): a backup that shares the live store's
/// disk is lost with it. This warns when the resolved directory sits under the data
/// directory, i.e. on the same host.
fn spawn_backup_task(
    db: Db,
    data_dir: PathBuf,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let interval_hours: u64 = std::env::var("MAGNETITE_BACKUP_INTERVAL_HOURS")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(24);
    if interval_hours == 0 {
        info!("periodic DB backup disabled (MAGNETITE_BACKUP_INTERVAL_HOURS=0)");
        return Ok(());
    }
    let keep: usize = std::env::var("MAGNETITE_BACKUP_KEEP")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(7);
    let dir = std::env::var("MAGNETITE_BACKUP_DIR")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir.join("backups"));
    // Create it now so the filesystem check below can stat it (and so the first backup
    // doesn't race to create it).
    let _ = std::fs::create_dir_all(&dir);
    // A backup that shares the live store's filesystem is lost with it. In PRODUCTION this
    // is fail-closed (a DR backup MUST be off-store); otherwise it is a loud warning.
    if backup_shares_data_filesystem(&dir, &data_dir) {
        if production_mode() {
            anyhow::bail!(
                "PRODUCTION is set but the DB backup dir {} shares the live store's filesystem \
                 — a disk loss would take both; point MAGNETITE_BACKUP_DIR at an off-host \
                 share/volume and restart",
                dir.display()
            );
        }
        tracing::warn!(
            "DB backup dir {} is on the same filesystem as the live store — a disk loss takes \
             both; set MAGNETITE_BACKUP_DIR to an off-host share/volume for disaster recovery",
            dir.display()
        );
    }
    let interval = Duration::from_secs(interval_hours * 3600);
    info!(
        "periodic DB backup: baseline now, then every {interval_hours}h to {} (keep {keep})",
        dir.display()
    );
    magnetite_db::spawn_supervised("db-backup", async move {
        // Baseline snapshot at startup so there is always a recent backup, even if the
        // node restarts before an interval elapses.
        run_db_backup(&db, &dir, keep).await;
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => run_db_backup(&db, &dir, keep).await,
                _ = shutdown.changed() => break,
            }
        }
    });
    Ok(())
}

/// Whether the backup dir and the live store's data dir sit on the SAME filesystem
/// (Unix: identical `st_dev`) — so losing that filesystem loses both, defeating disaster
/// recovery. Falls back to the path-tree check ([`backup_is_on_data_host`]) where device
/// ids aren't available (non-Unix, or a directory that can't be stat'd).
#[cfg(unix)]
fn backup_shares_data_filesystem(backup_dir: &Path, data_dir: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let device = |p: &Path| {
        p.ancestors()
            .find_map(|a| std::fs::metadata(a).ok())
            .map(|m| m.dev())
    };
    match (device(backup_dir), device(data_dir)) {
        (Some(a), Some(b)) => a == b,
        _ => backup_is_on_data_host(backup_dir, data_dir),
    }
}

#[cfg(not(unix))]
fn backup_shares_data_filesystem(backup_dir: &Path, data_dir: &Path) -> bool {
    backup_is_on_data_host(backup_dir, data_dir)
}

/// Whether `backup_dir` resolves to a location under `data_dir` (or its parent tree),
/// i.e. the backup would share the live store's host/volume — defeating disaster
/// recovery. Compares canonical paths where possible, falling back to the raw paths.
/// Used as the portable fallback for [`backup_shares_data_filesystem`].
fn backup_is_on_data_host(backup_dir: &Path, data_dir: &Path) -> bool {
    // The data dir usually exists; the backup dir may not yet, so compare the data dir's
    // canonical path against the backup dir's nearest existing ancestor.
    let data = data_dir.canonicalize();
    let backup = backup_dir.ancestors().find_map(|a| a.canonicalize().ok());
    match (data, backup) {
        (Ok(d), Some(b)) => b.starts_with(&d) || d.starts_with(&b),
        // Can't resolve (e.g. backup dir on an unmounted share): assume ops chose an
        // off-host target and stay quiet rather than warn spuriously.
        _ => backup_dir.starts_with(data_dir),
    }
}

/// Write one timestamped backup and prune older ones beyond `keep`.
async fn run_db_backup(db: &Db, dir: &Path, keep: usize) {
    if let Err(e) = std::fs::create_dir_all(dir) {
        tracing::warn!("DB backup: cannot create {}: {e}", dir.display());
        return;
    }
    let file = dir.join(format!(
        "magnetite-{}.surql",
        chrono::Utc::now().format("%Y%m%d-%H%M%S")
    ));
    match db.export_backup(&file).await {
        Ok(()) => {
            info!("DB backup written: {}", file.display());
            prune_backups(dir, keep);
        }
        Err(e) => tracing::warn!("DB backup failed: {e}"),
    }
}

/// Keep only the newest `keep` `magnetite-*.surql` backups in `dir` (timestamped names
/// sort chronologically), deleting the rest.
fn prune_backups(dir: &Path, keep: usize) {
    let mut backups: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("magnetite-") && n.ends_with(".surql"))
            })
            .collect(),
        Err(_) => return,
    };
    if backups.len() <= keep {
        return;
    }
    backups.sort(); // ascending by name = oldest first
    for old in backups.iter().rev().skip(keep) {
        if let Err(e) = std::fs::remove_file(old) {
            tracing::warn!("DB backup prune: cannot remove {}: {e}", old.display());
        }
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    info!("Shutdown signal received");
}

/// Capture panics to the tracing log (ERROR) AND a log file, with the panicking thread and
/// a backtrace, so a crash leaves actionable diagnostics (05 §4). The file is best-effort
/// (it is volatile in a container); the tracing line is what a log aggregator captures.
fn install_panic_hook() {
    let _ = std::fs::remove_file("magnetite-panic.log");
    std::panic::set_hook(Box::new(|info| {
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "unknown panic".to_string());
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_default();
        let thread = std::thread::current()
            .name()
            .unwrap_or("unnamed")
            .to_string();
        // Force-capture regardless of RUST_BACKTRACE so a production crash is diagnosable.
        let backtrace = std::backtrace::Backtrace::force_capture();
        // ERROR to tracing (what journald / a log sink actually sees).
        tracing::error!(target: "panic", %thread, location, "panic: {msg}\n{backtrace}");
        let output =
            format!("=== PANIC ===\nThread: {thread}\nLocation: {location}\nMessage: {msg}\n{backtrace}\n\n");
        eprintln!("{output}");
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("magnetite-panic.log")
        {
            let _ = f.write_all(output.as_bytes());
        }
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_under_data_dir_is_flagged_as_on_host() {
        let data = tempfile::tempdir().unwrap();
        let backup = data.path().join("backups");
        std::fs::create_dir_all(&backup).unwrap();
        assert!(
            backup_is_on_data_host(&backup, data.path()),
            "a backup dir inside the data dir shares the store's disk"
        );
    }

    #[test]
    fn backup_in_a_separate_tree_is_not_flagged() {
        let data = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        assert!(
            !backup_is_on_data_host(elsewhere.path(), data.path()),
            "a backup dir in a separate tree is assumed off-host"
        );
    }

    #[test]
    fn weak_sso_secrets_are_detected() {
        assert!(sso_secret_is_weak(""));
        assert!(sso_secret_is_weak("   "));
        assert!(sso_secret_is_weak(DEV_SSO_CLIENT_SECRET));
        assert!(sso_secret_is_weak("  changeme-dev-only  ")); // trimmed
        assert!(!sso_secret_is_weak("a-real-strong-random-secret"));
    }
}
