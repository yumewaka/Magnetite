//! `magnetite-addc` — the standalone integrated AD domain-controller daemon.
//!
//! A thin wrapper over the [`magnetite_addc`] library: it resolves the realm and
//! listen sockets from environment variables, builds the directory (from
//! `magnetite-db` when `MAGNETITE_DB_PATH` is set, otherwise a fixed in-memory
//! set), and runs the KDC/SMB/RPC/DRSUAPI servers until one exits. The same
//! servers run in-process inside `magnetite-server` via `magnetite_addc::AddcService`.

use magnetite_addc::{
    build_directory_from_db, default_directory, rid_pool_seed, spawn_rid_allocator, spawn_servers,
    AddcAddrs,
};
use magnetite_core::config::AddcConfig;
use magnetite_rpc::Directory;
use std::sync::Arc;

type AccountStoreRef = std::sync::Arc<dyn magnetite_rpc::AccountStore>;

/// Build the directory from `magnetite-db` (when `MAGNETITE_DB_PATH` is set) or the
/// default in-memory set. In database mode also returns an [`AccountStore`] (so
/// SAMR-created accounts are persisted) and the `Db` handle (so the caller can run
/// the LDAP directory server on the same database).
async fn build_directory(
    realm: &str,
) -> anyhow::Result<(Directory, Option<AccountStoreRef>, Option<magnetite_db::Db>)> {
    // `MAGNETITE_DB_URL` (a shared networked SurrealDB, e.g. `ws://host:8000`, for
    // Tier B multi-DC) takes precedence over `MAGNETITE_DB_PATH` (an embedded store);
    // neither set ⇒ the fixed in-memory directory.
    let db = match (env_opt("MAGNETITE_DB_URL"), env_opt("MAGNETITE_DB_PATH")) {
        (Some(url), _) if !url.trim().is_empty() => {
            let db = magnetite_db::Db::connect_url(url.trim()).await?;
            println!("magnetite-addc: directory sourced from shared magnetite-db at {url}");
            db
        }
        (_, Some(path)) if !path.trim().is_empty() => {
            let db = magnetite_db::Db::connect(&path).await?;
            println!("magnetite-addc: directory sourced from magnetite-db at {path}");
            db
        }
        _ => return Ok((default_directory()?, None, None)),
    };
    let dir = build_directory_from_db(&db, realm).await?;
    let store = magnetite_addc::db_account_store(db.clone(), realm);
    Ok((dir, Some(store), Some(db)))
}

/// Read an environment override, or `None` to fall back to the well-known default.
fn env_opt(var: &str) -> Option<String> {
    std::env::var(var).ok()
}

/// Whether an env value is an affirmative flag (`1`/`true`/`yes`/`on`, case-insensitive).
/// `None` or any other value is treated as false.
fn is_truthy(v: Option<&str>) -> bool {
    matches!(
        v.map(|s| s.trim().to_ascii_lowercase()).as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

/// Decode an even-length hex string into bytes (`None` on malformed input). Used for
/// the `DRS_KEY` AES256 override.
fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// Build the inbound-replication config from `REPL_*` env vars, letting this DC also
/// act as a replication consumer of an upstream AD DC. Returns `None` when no upstream
/// is configured (`REPL_DRS` unset). `REPL_KDC`/`REPL_REALM`/`REPL_USER`/`REPL_PASS`/
/// `REPL_SPN`/`REPL_NC`/`REPL_INTERVAL_SECS` fill in the rest (with defaults).
/// `REPL_KEYTAB` (a keytab file for `REPL_USER`) is the production alternative to
/// `REPL_PASS` — when set, the agent loads the AES256 key from it, so no cleartext
/// replication password lives in the environment.
fn replication_config_from_env(realm: &str) -> Option<magnetite_addc::ReplicationConfig> {
    let drs = env_opt("REPL_DRS")?.parse().ok()?;
    let kdc = env_opt("REPL_KDC")
        .unwrap_or_else(|| "127.0.0.1:88".into())
        .parse()
        .ok()?;
    let interval_secs = env_opt("REPL_INTERVAL_SECS")
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);
    let default_nc = format!("dc={}", realm.to_lowercase().replace('.', ",dc="));
    Some(magnetite_addc::ReplicationConfig {
        kdc,
        drs,
        realm: env_opt("REPL_REALM").unwrap_or_else(|| realm.to_string()),
        user: env_opt("REPL_USER").unwrap_or_else(|| "Administrator".into()),
        password: env_opt("REPL_PASS").unwrap_or_default(),
        keytab: env_opt("REPL_KEYTAB").map(std::path::PathBuf::from),
        spn: env_opt("REPL_SPN").unwrap_or_else(|| "ldap/dc1".into()),
        nc_dn: env_opt("REPL_NC").unwrap_or(default_nc),
        extra_ncs: extra_ncs_from_env(),
        interval: std::time::Duration::from_secs(interval_secs),
    })
}

/// The extra read-only partitions to seed once — `REPL_EXTRA_NCS`, a `;`-separated list
/// of NC DNs (typically the Config + Schema NCs). Empty when unset.
fn extra_ncs_from_env() -> Vec<String> {
    env_opt("REPL_EXTRA_NCS")
        .map(|s| {
            s.split(';')
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Build the inbound-replication configs — one per upstream. `REPL_PEERS` (a
/// comma-separated list of `drs_addr=spn` entries, e.g.
/// `10.69.134.30:135=ldap/kether.example.com,10.69.134.31:135=ldap/binar.example.com`)
/// makes this DC a MULTI-upstream consumer that pulls from EVERY listed peer — for
/// redundancy (pull from both old DCs during migration) or a magnetite mesh — sharing
/// `REPL_KDC`/`REPL_REALM`/`REPL_USER`/`REPL_PASS`/`REPL_NC`/`REPL_INTERVAL_SECS`. When
/// `REPL_PEERS` is unset it falls back to the single `REPL_DRS`/`REPL_SPN` config.
fn replication_configs_from_env(realm: &str) -> Vec<magnetite_addc::ReplicationConfig> {
    // Computed-topology mode wins when configured: deploy the SAME `REPL_TOPOLOGY`
    // (the whole DC set) to every node and each self-selects its ring partners.
    if let Some(cfgs) = topology_configs_from_env(realm) {
        return cfgs;
    }
    let Some(peers) = env_opt("REPL_PEERS") else {
        return replication_config_from_env(realm).into_iter().collect();
    };
    let Ok(kdc) = env_opt("REPL_KDC")
        .unwrap_or_else(|| "127.0.0.1:88".into())
        .parse()
    else {
        return Vec::new();
    };
    let interval = std::time::Duration::from_secs(
        env_opt("REPL_INTERVAL_SECS")
            .and_then(|s| s.parse().ok())
            .unwrap_or(300),
    );
    let default_nc = format!("dc={}", realm.to_lowercase().replace('.', ",dc="));
    let repl_realm = env_opt("REPL_REALM").unwrap_or_else(|| realm.to_string());
    let user = env_opt("REPL_USER").unwrap_or_else(|| "Administrator".into());
    let password = env_opt("REPL_PASS").unwrap_or_default();
    let keytab = env_opt("REPL_KEYTAB").map(std::path::PathBuf::from);
    let nc_dn = env_opt("REPL_NC").unwrap_or(default_nc);
    peers
        .split(',')
        .filter_map(parse_peer_entry)
        .map(|(drs, spn)| magnetite_addc::ReplicationConfig {
            kdc,
            drs,
            realm: repl_realm.clone(),
            user: user.clone(),
            password: password.clone(),
            keytab: keytab.clone(),
            spn,
            nc_dn: nc_dn.clone(),
            extra_ncs: extra_ncs_from_env(),
            interval,
        })
        .collect()
}

/// Build inbound-replication configs from a *computed* intra-site topology. `REPL_TOPOLOGY`
/// is a comma-separated list describing the WHOLE domain-controller set — one
/// `id@host:port=spn` entry per DC (`id` is the DC's stable DSA-GUID hex or name) — and
/// `NODE_DSA_ID` names THIS node within it. Every node runs the same `REPL_TOPOLOGY`;
/// each computes its own ring neighbours (see [`magnetite_addc::topology`]) so no
/// per-node peer list is needed. Shared `REPL_KDC`/`REPL_REALM`/`REPL_USER`/`REPL_PASS`/
/// `REPL_NC`/`REPL_INTERVAL_SECS` fill in the rest. `None` when `REPL_TOPOLOGY` is unset;
/// an empty vec when this node has no live partners (e.g. it is the only DC).
fn topology_configs_from_env(realm: &str) -> Option<Vec<magnetite_addc::ReplicationConfig>> {
    let (dcs, self_id, common) = topology_parts_from_env(realm)?;
    // Static wiring: this node's ring partners with no dead-node knowledge. The dynamic
    // manager (REPL_RECONCILE_SECS) reroutes around failures at runtime instead.
    Some(magnetite_addc::topology::inbound_configs(
        &dcs,
        &self_id,
        &std::collections::HashSet::new(),
        &common,
    ))
}

/// Parse `REPL_TOPOLOGY` (the whole DC set) into `(dcs, self_id, common)` — the raw parts
/// the static [`topology_configs_from_env`] and the dynamic topology manager both build
/// on. `None` when `REPL_TOPOLOGY` is unset or `REPL_KDC` is unparseable.
fn topology_parts_from_env(
    realm: &str,
) -> Option<(
    Vec<magnetite_addc::topology::TopologyDc>,
    String,
    magnetite_addc::topology::ReplicationCommon,
)> {
    let topo = env_opt("REPL_TOPOLOGY")?;
    let self_id = env_opt("NODE_DSA_ID").unwrap_or_default();
    let kdc = env_opt("REPL_KDC")
        .unwrap_or_else(|| "127.0.0.1:88".into())
        .parse()
        .ok()?;
    let dcs: Vec<magnetite_addc::topology::TopologyDc> = topo
        .split(',')
        .filter_map(|e| parse_topology_entry(e, kdc))
        .collect();
    let default_nc = format!("dc={}", realm.to_lowercase().replace('.', ",dc="));
    let common = magnetite_addc::topology::ReplicationCommon {
        realm: env_opt("REPL_REALM").unwrap_or_else(|| realm.to_string()),
        user: env_opt("REPL_USER").unwrap_or_else(|| "Administrator".into()),
        password: env_opt("REPL_PASS").unwrap_or_default(),
        keytab: env_opt("REPL_KEYTAB").map(std::path::PathBuf::from),
        nc_dn: env_opt("REPL_NC").unwrap_or(default_nc),
        interval: std::time::Duration::from_secs(
            env_opt("REPL_INTERVAL_SECS")
                .and_then(|s| s.parse().ok())
                .unwrap_or(300),
        ),
    };
    Some((dcs, self_id, common))
}

/// Build this domain's FSMO role ownership. It starts with every role held by
/// `self_dsa` (a single-node domain) and applies `FSMO_OWNERS` overrides — a
/// comma-separated list of `role=owner_dsa` (role keys: `schema`/`naming`/`rid`/`pdc`/
/// `infra`, see [`FsmoRole::from_key`]) — so a multi-node domain records which peer
/// holds each role it does not own. Unknown role keys are skipped.
fn fsmo_ownership_from_env(self_dsa: &str) -> magnetite_addc::fsmo::FsmoOwnership {
    fsmo_ownership_from_spec(self_dsa, env_opt("FSMO_OWNERS").as_deref())
}

/// The pure core of [`fsmo_ownership_from_env`]: `self_dsa` holds every role, then each
/// `role=owner` in `spec` (comma-separated) reassigns that role. Empty owners and
/// unknown role keys are skipped.
fn fsmo_ownership_from_spec(
    self_dsa: &str,
    spec: Option<&str>,
) -> magnetite_addc::fsmo::FsmoOwnership {
    use magnetite_addc::fsmo::{FsmoOwnership, FsmoRole};
    let mut owners = FsmoOwnership::all_held_by(self_dsa);
    for entry in spec.unwrap_or("").split(',') {
        if let Some((role, owner)) = entry.split_once('=') {
            let owner = owner.trim();
            if let (Some(role), false) = (FsmoRole::from_key(role), owner.is_empty()) {
                owners.transfer(role, owner);
            }
        }
    }
    owners
}

/// Parse one `REPL_TOPOLOGY` entry `"id@host:port=spn"` into a [`TopologyDc`] with the
/// shared `kdc`. `None` for a missing `@`/`=`, a malformed address, or an empty id/spn.
fn parse_topology_entry(
    entry: &str,
    kdc: std::net::SocketAddr,
) -> Option<magnetite_addc::topology::TopologyDc> {
    let (id, rest) = entry.split_once('@')?;
    let (drs_s, spn) = rest.split_once('=')?;
    let id = id.trim();
    let drs = drs_s.trim().parse().ok()?;
    let spn = spn.trim();
    (!id.is_empty() && !spn.is_empty()).then(|| magnetite_addc::topology::TopologyDc {
        id: id.to_string(),
        drs,
        kdc,
        spn: spn.to_string(),
    })
}

/// Parse one `REPL_PEERS` entry `"host:port=spn"` into its DRS address and SPN. `None`
/// for a malformed address, a missing `=`, or an empty SPN (that entry is skipped).
fn parse_peer_entry(entry: &str) -> Option<(std::net::SocketAddr, String)> {
    let (drs_s, spn) = entry.split_once('=')?;
    let drs = drs_s.trim().parse().ok()?;
    let spn = spn.trim();
    (!spn.is_empty()).then(|| (drs, spn.to_string()))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Log at INFO by default (RUST_LOG overrides) so operational events — including the
    // inbound-replication agent's per-cycle summary — are visible.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    // Production guard (B3): when `PRODUCTION` is truthy, refuse to start if any domain
    // secret is still unset/empty or at the built-in PoC default. Left at the defaults,
    // the domain's krbtgt/service keys are public (golden-ticket forgery = full domain
    // compromise), so a sole-IdP deployment must hard-fail rather than serve them.
    if is_truthy(env_opt("PRODUCTION").as_deref()) {
        let missing = magnetite_addc::missing_production_secrets();
        if !missing.is_empty() {
            anyhow::bail!(
                "PRODUCTION set but these domain secrets are unset or at the PoC default: {}. \
                 Set each to a strong random value, IDENTICAL on every DC, and restart.",
                missing.join(", ")
            );
        }
        println!("magnetite-addc: production secrets check passed (all domain secrets overridden)");
    }

    let realm =
        std::env::var("REALM").unwrap_or_else(|_| magnetite_addc::DEFAULT_REALM.to_string());

    // This DC's computer label (DNS host label / NetBIOS), default `magnetite`.
    let dc_label = magnetite_addc::dc_label(env_opt("DC_NAME").as_deref());

    // Env vars override the well-known listen sockets (host:port).
    let addrs = AddcAddrs::from_config(&AddcConfig {
        realm: Some(realm.clone()),
        dc_name: env_opt("DC_NAME"),
        kdc_listen: env_opt("KDC_ADDR"),
        smb_listen: env_opt("SMB_ADDR"),
        rpc_listen: env_opt("RPC_ADDR"),
        drs_listen: env_opt("DRS_ADDR"),
        dc_ipv4: env_opt("DC_IPV4"),
        cldap_listen: env_opt("CLDAP_ADDR"),
        kpasswd_listen: env_opt("KPASSWD_ADDR"),
        epm_listen: env_opt("EPM_ADDR"),
        sntp_listen: env_opt("SNTP_ADDR"),
        // The standalone binary does not configure DRS replication through this env
        // path; it is driven separately when used. (Field added to AddcConfig later.)
        replication: None,
    });

    // The DC's IPv4 address the Endpoint Mapper returns in its towers.
    let dc_ipv4 = env_opt("DC_IPV4")
        .as_deref()
        .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
        .map(|a| a.octets())
        .unwrap_or([127, 0, 0, 1]);

    let (mut dir, account_store, db) = build_directory(&realm).await?;
    // When magnetite serves outbound DRS replication into a FOREIGN domain (e.g. a
    // Samba domain during migration), replicated objects must carry that domain's real
    // SID. `DOMAIN_SID` (space/dash-separated sub-authorities after S-1-5, e.g.
    // "21 2171852460 1012688135 3873131180") overrides the directory's default.
    if let Some(sid) = env_opt("DOMAIN_SID") {
        let sub: Vec<u32> = sid
            .split([' ', '-'])
            .filter_map(|p| p.parse().ok())
            .collect();
        if !sub.is_empty() {
            let shown = sub.iter().map(u32::to_string).collect::<Vec<_>>().join("-");
            println!("magnetite-addc: domain SID overridden to S-1-5-{shown}");
            // Persist to the shared DB so the LDAP objectSid and netlogon paths (served
            // over the same magnetite-db) honour the override too — not just this
            // in-process directory (the KDC/SAMR/LSA/DRSUAPI). The override wins over any
            // previously seeded value. (No-op for the in-memory directory, which has no DB.)
            if let Some(db) = db.as_ref() {
                // A group's objectSid is computed and stored at creation, so CHANGING the
                // domain SID after groups exist leaves those groups on the old prefix
                // (users keep only a RID, so they are unaffected). Warn loudly — the domain
                // SID must be finalised before any object is created.
                let changing = db
                    .get_domain_sid()
                    .await
                    .ok()
                    .flatten()
                    .is_some_and(|prev| prev != sub);
                if changing {
                    let existing_groups = db.list_ad_groups().await.map(|g| g.len()).unwrap_or(0);
                    if existing_groups > 0 {
                        tracing::warn!(
                            "DOMAIN_SID changed with {existing_groups} existing group(s): their \
                             stored objectSids keep the OLD prefix and are NOT rewritten. Set the \
                             domain SID before creating objects."
                        );
                    }
                }
                if let Err(e) = db.set_domain_sid(&sub, "system").await {
                    tracing::warn!("failed to persist DOMAIN_SID override: {e}");
                }
            }
            dir.set_domain_sid(sub);
        }
    }
    let directory = Arc::new(dir);
    // The DRSUAPI acceptor key a foreign domain's KDC encrypts magnetite's DRS tickets
    // with (the machine-account key that domain holds for magnetite, recovered by
    // DCSyncing MAGNETITE$). `DRS_KEY` = 64 hex chars (AES256); unset ⇒ the local
    // host/magnetite key (self-domain mode).
    let drs_key = env_opt("DRS_KEY").and_then(|s| hex_to_bytes(s.trim()));
    // A shared handle for the replication agent to push inbound changes into (the
    // runtime sets are shared across the directory's clones, incl. the interfaces').
    let directory_for_repl = Arc::clone(&directory);

    // DB-atomic RID allocation (only in database mode; the in-memory default has no
    // store to persist a pool). A join then gets a RID that survives a restart. When
    // this is an INDEPENDENT node in a magnetite multi-master cluster (Tier C), set
    // `NODE_INDEX` to a distinct value per node so each draws RIDs from a disjoint range
    // (`rid_pool_base`) and object SIDs never collide across nodes; unset ⇒ the single-
    // node seed above the existing accounts.
    let rid_allocator = match &db {
        Some(db) => {
            let seed = match env_opt("NODE_INDEX").and_then(|s| s.trim().parse::<u32>().ok()) {
                Some(idx) => {
                    let base = magnetite_addc::rid_pool_base(idx);
                    println!("magnetite-addc: NODE_INDEX={idx} → RID range starts at {base}");
                    base
                }
                None => rid_pool_seed(&directory),
            };
            Some(spawn_rid_allocator(db.clone(), seed).await)
        }
        None => None,
    };
    // FSMO role ownership. A single magnetite domain holds every role on this node; a
    // multi-node domain overrides individual owners via `FSMO_OWNERS`. `NODE_DSA_ID`
    // (shared with REPL_TOPOLOGY) names this node; it defaults to the DC label.
    let self_dsa = env_opt("NODE_DSA_ID").unwrap_or_else(|| dc_label.clone());
    let fsmo = fsmo_ownership_from_env(&self_dsa);
    let held: Vec<&str> = fsmo
        .roles_held_by(&self_dsa)
        .iter()
        .map(|r| r.as_str())
        .collect();
    println!("magnetite-addc: FSMO owner (dsa={self_dsa}); roles held here: {held:?}");
    for role in magnetite_addc::fsmo::FsmoRole::all() {
        if let Some(owner) = fsmo.owner(role) {
            if owner != self_dsa {
                println!("magnetite-addc: FSMO {} owned by {owner}", role.as_str());
            }
        }
    }

    // This DC's persistent DRS replication identity (database mode only; the in-memory
    // default falls back to the fixed PoC invocation ID).
    let drs_invocation_id = match &db {
        Some(db) => db.dsa_invocation_id().await.ok(),
        None => None,
    };

    println!(
        "magnetite-addc up: realm={realm}  KDC={}  SMB={} (SYSVOL + IPC$ pipes: samr, lsarpc, netlogon)  RPC/SAMR={}  DRSUAPI={}  CLDAP={} (UDP)  kpasswd={} (UDP+TCP)  EPM={}  SNTP={} (UDP)",
        addrs.kdc, addrs.smb, addrs.rpc, addrs.drs, addrs.cldap, addrs.kpasswd, addrs.epm, addrs.sntp
    );

    // The CLDAP netlogon-ping responder answers Windows DC-discovery pings.
    let cldap_info = magnetite_addc::cldap::domain_info(&directory, &dc_label);
    // Only the RID master grants RID pools over DRS; a node that doesn't hold the role
    // refuses the request so pools never overlap across DCs.
    let is_rid_master = fsmo.is_owner(magnetite_addc::fsmo::FsmoRole::RidMaster, &self_dsa);
    let (mut servers, kdc) = spawn_servers(
        directory,
        &realm,
        &dc_label,
        addrs,
        account_store,
        rid_allocator,
        drs_invocation_id,
        dc_ipv4,
        drs_key,
        is_rid_master,
    )?;
    let cldap_addr = addrs.cldap;
    servers.spawn(async move {
        magnetite_addc::cldap::serve_cldap(cldap_addr, cldap_info).await?;
        anyhow::Ok(())
    });

    // Optional inbound replication (database mode only): pull from EVERY configured
    // upstream AD DC on an interval and apply into our store — one agent per peer, so a
    // node can consume from several DCs at once (both old DCs during migration, or a
    // magnetite mesh). Each agent runs on its own thread (the agent is !Send). The
    // shutdown channel is shared; the receiver clones per agent.
    // Dynamic KCC mode (opt-in): with REPL_TOPOLOGY set and REPL_RECONCILE_SECS given,
    // run the health-driven topology manager instead of static agents — it reroutes the
    // ring around a failed peer and reverts on recovery. It owns the health registry and
    // the agent lifecycle for the process's lifetime.
    let reconcile_secs = env_opt("REPL_RECONCILE_SECS").and_then(|s| s.trim().parse::<u64>().ok());
    if let (Some(db), Some(secs), Some((dcs, self_id, common))) =
        (db.as_ref(), reconcile_secs, topology_parts_from_env(&realm))
    {
        println!(
            "magnetite-addc: dynamic KCC topology manager ({} DCs, self={self_id}, reconcile {secs}s)",
            dcs.len()
        );
        let (_tx, rx) = tokio::sync::watch::channel(false);
        std::mem::forget(_tx); // run for the process lifetime
        let health: magnetite_addc::ReplHealthRegistry =
            std::sync::Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
        let db = db.clone();
        let dir = directory_for_repl.clone();
        tokio::spawn(magnetite_addc::topology::run_topology_manager(
            dcs,
            self_id,
            common,
            db,
            Some(dir),
            Some(kdc.clone()),
            health,
            magnetite_addc::topology::DEFAULT_FAILURE_THRESHOLD,
            std::time::Duration::from_secs(secs.max(1)),
            rx,
        ));
        // Run until any server exits (the dynamic manager owns replication from here).
        if let Some(result) = servers.join_next().await {
            result??;
        }
        return Ok(());
    }

    let repl_configs = replication_configs_from_env(&realm);
    if let Some(db) = db.as_ref() {
        if !repl_configs.is_empty() {
            println!(
                "magnetite-addc: inbound replication from {} upstream(s)",
                repl_configs.len()
            );
            let (repl_tx, repl_rx) = tokio::sync::watch::channel(false);
            let health: magnetite_addc::ReplHealthRegistry =
                std::sync::Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
            for repl in repl_configs {
                println!(
                    "  ↳ upstream DRS {} (NC {}) every {}s",
                    repl.drs,
                    repl.nc_dn,
                    repl.interval.as_secs()
                );
                let _ = magnetite_addc::spawn_replication_thread(
                    repl,
                    db.clone(),
                    repl_rx.clone(),
                    Some(directory_for_repl.clone()),
                    Some(kdc.clone()),
                    Some(health.clone()),
                );
            }
            std::mem::forget(repl_tx); // keep replicating for the process lifetime

            // Periodic per-upstream replication-health summary, for operator visibility.
            let health_log = health.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    if let Ok(m) = health_log.lock() {
                        for (addr, h) in m.iter() {
                            if h.is_healthy() {
                                println!(
                                    "magnetite-addc: replication {addr} healthy (cycles={})",
                                    h.total_cycles
                                );
                            } else {
                                println!(
                                    "magnetite-addc: replication {addr} UNHEALTHY (failures={}, last_error={:?})",
                                    h.consecutive_failures, h.last_error
                                );
                            }
                        }
                    }
                }
            });
        }
    }

    // Optional self-contained SYSVOL (Group Policy) replication pull (database mode):
    // a Tier C DC pulls Group Policy files from a peer's `/repl/sysvol` feed straight
    // into its own store, and its live re-serve then serves them over SMB — no shared
    // database or separate puller. `REPL_SYSVOL_URL` (the peer base URL) +
    // `REPL_SYSVOL_SECRET` enable it; `REPL_SYSVOL_INTERVAL_SECS` (default 60) paces it.
    if let (Some(db), Some(url), Some(secret)) = (
        db.as_ref(),
        env_opt("REPL_SYSVOL_URL"),
        env_opt("REPL_SYSVOL_SECRET"),
    ) {
        let interval_secs = env_opt("REPL_SYSVOL_INTERVAL_SECS")
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(60)
            .max(1);
        println!("magnetite-addc: SYSVOL replication pull from {url} every {interval_secs}s");
        let (tx, rx) = tokio::sync::watch::channel(false);
        std::mem::forget(tx); // keep pulling for the process lifetime
        magnetite_addc::sysvol_pull::spawn_sysvol_pull(
            magnetite_addc::sysvol_pull::SysvolPullConfig {
                primary_url: url,
                secret,
                interval: std::time::Duration::from_secs(interval_secs),
            },
            db.clone(),
            rx,
        );
    }

    // In database mode, also run the LDAP directory server on the SAME database, so
    // a SAMR-created machine account's `computer` object is served over LDAP too
    // (as it is inside magnetite-server). LDAP is TCP; CLDAP above is UDP.
    if let Some(db) = db {
        use magnetite_db::EmbeddedService;
        let ldap_addr: std::net::SocketAddr = env_opt("LDAP_ADDR")
            .unwrap_or_else(|| "0.0.0.0:389".to_string())
            .parse()
            .expect("LDAP_ADDR host:port");
        let base_dn = format!("dc={}", realm.to_lowercase().replace('.', ",dc="));
        println!("magnetite-addc: LDAP directory on {ldap_addr} (base {base_dn})");
        // The `ldap/<dc-fqdn>` service key enables GSS-SPNEGO SASL binds (domain join).
        let ldap_key = magnetite_addc::ldap_service_key(&realm)?;
        // A `computer` Add over LDAP registers the machine with the live KDC (and
        // persists it), so the joined machine can immediately obtain a TGT.
        let registrar = magnetite_addc::machine_key_registrar(kdc, Some(db.clone()), &realm);
        let ldap = magnetite_ldap::LdapService::new(ldap_addr, true, None, base_dn)
            .with_gss_key(ldap_key)
            .with_machine_registrar(registrar);
        let (ldap_tx, ldap_rx) = tokio::sync::watch::channel(false);
        ldap.start(db, ldap_rx);
        std::mem::forget(ldap_tx); // keep the service running for the process lifetime
    }

    // Run until a server exits (propagating its error) or a shutdown signal arrives.
    // On SIGTERM / Ctrl-C the process returns cleanly so the Tokio runtime and the
    // embedded RocksDB store drop and flush, instead of hanging until systemd SIGKILLs
    // it (which risks the on-disk store).
    tokio::select! {
        joined = servers.join_next() => {
            if let Some(result) = joined {
                result??;
            }
        }
        _ = shutdown_signal() => {
            println!("magnetite-addc: shutdown signal received, stopping");
        }
    }
    Ok(())
}

/// Resolve on Ctrl-C or (on Unix) SIGTERM — the signal systemd sends on stop.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::{fsmo_ownership_from_spec, parse_peer_entry, parse_topology_entry};
    use magnetite_addc::fsmo::FsmoRole;

    #[test]
    fn parse_peer_entry_splits_drs_and_spn() {
        let (drs, spn) = parse_peer_entry("10.69.134.30:135=ldap/kether.example.com").unwrap();
        assert_eq!(drs.to_string(), "10.69.134.30:135");
        assert_eq!(spn, "ldap/kether.example.com");
        // Surrounding whitespace is tolerated.
        let (drs2, spn2) = parse_peer_entry(" 127.0.0.1:1027 = ldap/dc1 ").unwrap();
        assert_eq!(drs2.port(), 1027);
        assert_eq!(spn2, "ldap/dc1");
        // Malformed entries are skipped (None), never a panic.
        assert!(parse_peer_entry("no-equals").is_none());
        assert!(parse_peer_entry("not-an-addr=ldap/x").is_none());
        assert!(
            parse_peer_entry("127.0.0.1:88=").is_none(),
            "empty SPN rejected"
        );
    }

    #[test]
    fn parse_topology_entry_splits_id_addr_and_spn() {
        let kdc = "127.0.0.1:88".parse().unwrap();
        let dc = parse_topology_entry("nodeA@10.0.0.1:1025=ldap/nodea.example.com", kdc).unwrap();
        assert_eq!(dc.id, "nodeA");
        assert_eq!(dc.drs, "10.0.0.1:1025".parse().unwrap());
        assert_eq!(dc.spn, "ldap/nodea.example.com");
        assert_eq!(dc.kdc, kdc);
        // Whitespace is trimmed around each field.
        let dc2 = parse_topology_entry(" b @ 127.0.0.1:1027 = ldap/b ", kdc).unwrap();
        assert_eq!(dc2.id, "b");
        assert_eq!(dc2.spn, "ldap/b");
    }

    #[test]
    fn fsmo_ownership_defaults_to_self_then_applies_overrides() {
        // No spec: this node holds all five roles.
        let o = fsmo_ownership_from_spec("dc1", None);
        assert_eq!(o.roles_held_by("dc1").len(), 5);
        // Overrides move named roles to peers; the rest stay local. Unknown keys and
        // empty owners are ignored.
        let o = fsmo_ownership_from_spec("dc1", Some("pdc=dc2, rid = dc3 ,bogus=dc4,schema="));
        assert_eq!(o.owner(FsmoRole::PdcEmulator), Some("dc2"));
        assert_eq!(o.owner(FsmoRole::RidMaster), Some("dc3"));
        assert_eq!(o.owner(FsmoRole::SchemaMaster), Some("dc1")); // empty owner skipped
        assert!(o.is_owner(FsmoRole::InfrastructureMaster, "dc1"));
    }

    #[test]
    fn parse_topology_entry_rejects_malformed() {
        let kdc = "127.0.0.1:88".parse().unwrap();
        assert!(parse_topology_entry("no-at-or-eq", kdc).is_none());
        assert!(parse_topology_entry("id@not-an-addr=ldap/x", kdc).is_none());
        assert!(
            parse_topology_entry("@127.0.0.1:88=ldap/x", kdc).is_none(),
            "empty id"
        );
        assert!(
            parse_topology_entry("id@127.0.0.1:88=", kdc).is_none(),
            "empty spn"
        );
    }
}
