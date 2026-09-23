//! `magnetite-addc` — the integrated Active Directory domain-controller.
//!
//! Composes the tracer-bullet AD protocol servers so a domain member performs the
//! real flow against a single host:
//!
//! * **KDC** ([`magnetite_krb5`]) — `kinit`, TGS for `cifs/magnetite` + `host/magnetite`.
//! * **SMB** ([`magnetite_smb`]) — Kerberos-authenticated SYSVOL (Group Policy) plus
//!   `IPC$` with the `ncacn_np` pipes `\pipe\samr`, `\pipe\lsarpc`, `\pipe\netlogon`.
//! * **RPC** ([`magnetite_rpc`]) — SAMR over `ncacn_ip_tcp`, and a
//!   Kerberos-authenticated DRSUAPI endpoint (DCSync replication).
//!
//! All servers answer from one shared [`Directory`], seeded from `magnetite-db`.
//! The crate is consumed two ways: the standalone `magnetite-addc` binary (env-var
//! configured), and [`AddcService`] — an [`EmbeddedService`] that runs the whole
//! stack in-process inside `magnetite-server`, sourcing principals from the shared
//! database.

pub mod cldap;
pub mod demote;
pub mod fsmo;
pub mod promote;
pub mod sntp;
pub mod sysvol_pull;
pub mod topology;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};

use magnetite_core::config::AddcConfig;
use magnetite_core::domain::DomainKey;
use magnetite_db::{Db, EmbeddedService, NewLogEntry, ServiceHealth};
use magnetite_krb5::keys::{default_salt, derive_aes256_key, PrincipalStore};
use magnetite_krb5::obtain_service_ticket;
use magnetite_krb5::server::KdcServer;
use magnetite_rpc::{
    AccountStore, Directory, DrsClient, DrsuapiInterface, LsaInterface, NetlogonInterface,
    RidAllocator, RpcInterface, SamrInterface, User,
};
use magnetite_smb::{PipeFactory, PipeRegistry};
use std::collections::VecDeque;
use std::sync::Mutex;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;

/// The built-in (PoC) machine-account password backing the Netlogon secure channel.
/// Overridden by the `MACHINE_PASSWORD` env var for any real deployment.
const MACHINE_PASSWORD: &str = "Machine123";

/// This DC's machine-account password: the `MACHINE_PASSWORD` env var when set,
/// otherwise the built-in PoC default (with a warning, so the "no default credential"
/// gate is visible rather than silent).
fn machine_password() -> String {
    match std::env::var("MACHINE_PASSWORD") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            tracing::warn!(
                "MACHINE_PASSWORD not set — using the built-in PoC default; set it for any real deployment"
            );
            MACHINE_PASSWORD.to_string()
        }
    }
}

/// The default DC computer label when `dc_name` is unset — the lowercase DNS host
/// label under the domain and (uppercased) the DC's NetBIOS computer name.
pub const DEFAULT_DC_LABEL: &str = "magnetite";

/// Resolve this DC's computer label (lowercase DNS host label) from the optional
/// configured `dc_name`, falling back to [`DEFAULT_DC_LABEL`]. Blank/whitespace
/// names fall back too. The value drives the FQDN service SPNs, the DC-locator DNS
/// A/SRV targets, the CLDAP response and the LDAP RootDSE identity.
pub fn dc_label(dc_name: Option<&str>) -> String {
    dc_name
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_DC_LABEL)
        .to_lowercase()
}

/// The first RID a runtime-created account may receive (above the seeded users).
/// `pub` so the Web layer allocates local-account RIDs from the same disjoint floor.
pub const RID_POOL_FIRST: u32 = 1100;
/// How many RIDs a front-end reserves from the shared store per DB round-trip.
const RID_BLOCK: u32 = 256;
/// When the locally-held RIDs fall to this many, refill in the background.
const RID_WATERMARK: u32 = 64;
/// The block size reserved for RID-POOL grants (`EXOP_FSMO_RID_ALLOC`). Larger than a
/// single grant so one reservation serves several pools; a per-block remainder smaller
/// than a grant is discarded (negligible against the RID space).
const RID_POOL_BLOCK: u32 = 4096;
/// Refill the pool region in the background when it falls below this many RIDs.
const RID_POOL_WATERMARK: u32 = 1024;

/// Which reserved region the background refiller should top up.
#[derive(Clone, Copy)]
enum RefillKind {
    /// The single-RID region SAMR mints from.
    Single,
    /// The pool region the DRSUAPI RID master grants from.
    Pool,
}

/// A [`RidAllocator`] backed by the shared database. It hands out single RIDs (SAMR
/// account mint) AND contiguous pools (the DRSUAPI RID master) from locally-reserved
/// blocks (`reserve_rid_block`) and refills both in the background, so the synchronous
/// SAMR / DRSUAPI paths never block on the DB, yet everything draws from the ONE durable
/// `rid_pool:main` counter — single RIDs and served pools never overlap and both persist
/// across restarts.
struct DbRidAllocator {
    /// Reserved-but-unspent single-RID ranges as `(next, end)`; shared with the refiller.
    ranges: Arc<Mutex<VecDeque<(u32, u32)>>>,
    /// Reserved-but-unspent pool-grant ranges as `(next, end)`; shared with the refiller.
    pool_ranges: Arc<Mutex<VecDeque<(u32, u32)>>>,
    /// Signals the background task to reserve another block of the given kind.
    refill: mpsc::UnboundedSender<RefillKind>,
}

impl RidAllocator for DbRidAllocator {
    fn allocate(&self) -> Option<u32> {
        let mut q = self.ranges.lock().expect("rid ranges");
        // Drop any exhausted ranges at the front.
        while matches!(q.front(), Some(&(n, e)) if n >= e) {
            q.pop_front();
        }
        let remaining: u32 = q.iter().map(|(n, e)| e.saturating_sub(*n)).sum();
        if remaining <= RID_WATERMARK {
            let _ = self.refill.send(RefillKind::Single); // best-effort
        }
        match q.front_mut() {
            Some((n, _)) => {
                let rid = *n;
                *n += 1;
                Some(rid)
            }
            None => {
                let _ = self.refill.send(RefillKind::Single);
                None
            }
        }
    }

    fn allocate_pool(&self, size: u32) -> Option<(u32, u32)> {
        let size = size.max(1);
        let mut q = self.pool_ranges.lock().expect("rid pool ranges");
        // Drop front ranges that cannot fit a whole `size` pool (discard the remainder).
        while matches!(q.front(), Some(&(n, e)) if e.saturating_sub(n) < size) {
            q.pop_front();
        }
        let remaining: u32 = q.iter().map(|(n, e)| e.saturating_sub(*n)).sum();
        if remaining <= RID_POOL_WATERMARK {
            let _ = self.refill.send(RefillKind::Pool);
        }
        match q.front_mut() {
            Some((n, _)) => {
                let base = *n;
                *n += size;
                Some((base, size))
            }
            None => {
                let _ = self.refill.send(RefillKind::Pool);
                None
            }
        }
    }
}

/// Build a DB-backed RID allocator: reserve the first single-RID and pool blocks up
/// front (so the first mint / grant does not wait) and spawn the background refiller.
/// `first` seeds the pool on its very first use (place it above any pre-existing RID).
/// The RID to seed the shared pool with for `directory`: one above every
/// pre-existing account's RID, and never below the well-known floor
/// ([`RID_POOL_FIRST`]). Placing it above the seeded users guarantees a
/// runtime-created account never re-uses a live RID.
pub fn rid_pool_seed(directory: &Directory) -> u32 {
    directory
        .users()
        .iter()
        .map(|u| u.rid)
        .max()
        .map_or(RID_POOL_FIRST, |m| (m + 1).max(RID_POOL_FIRST))
}

/// The RID range each Tier C node owns, so independent stores never hand out the same
/// RID (a real AD dynamically leases 500-RID pools from the RID master; this is a
/// simpler static partition by node index). ~1M RIDs per node → ~1000 nodes fit in the
/// usable RID space.
const RID_RANGE_PER_NODE: u32 = 1 << 20;

/// The base RID of node `node_index`'s disjoint range: `[base, base + RID_RANGE_PER_NODE)`.
/// Independent magnetite DCs (Tier C, each its own store) MUST be assigned distinct
/// indices (via `NODE_INDEX`), so RIDs — and therefore object SIDs — never collide
/// across nodes. Node 0 starts at [`RID_POOL_FIRST`], above the well-known RIDs.
pub fn rid_pool_base(node_index: u32) -> u32 {
    RID_POOL_FIRST.saturating_add(node_index.saturating_mul(RID_RANGE_PER_NODE))
}

pub async fn spawn_rid_allocator(db: Db, first: u32) -> Arc<dyn RidAllocator> {
    let ranges: Arc<Mutex<VecDeque<(u32, u32)>>> = Arc::new(Mutex::new(VecDeque::new()));
    let pool_ranges: Arc<Mutex<VecDeque<(u32, u32)>>> = Arc::new(Mutex::new(VecDeque::new()));
    // Pre-reserve one single-RID block and one pool block up front. Both draw from the
    // same durable `rid_pool:main` counter, so the two regions are disjoint.
    match db.reserve_rid_block(first, RID_BLOCK).await {
        Ok(base) => ranges
            .lock()
            .expect("rid ranges")
            .push_back((base, base + RID_BLOCK)),
        Err(e) => tracing::warn!("initial RID block reservation failed: {e}"),
    }
    match db.reserve_rid_block(first, RID_POOL_BLOCK).await {
        Ok(base) => pool_ranges
            .lock()
            .expect("rid pool ranges")
            .push_back((base, base + RID_POOL_BLOCK)),
        Err(e) => tracing::warn!("initial RID pool block reservation failed: {e}"),
    }
    let (tx, mut rx) = mpsc::unbounded_channel::<RefillKind>();
    let db2 = db.clone();
    let ranges2 = ranges.clone();
    let pool_ranges2 = pool_ranges.clone();
    tokio::spawn(async move {
        while let Some(kind) = rx.recv().await {
            match kind {
                RefillKind::Single => match db2.reserve_rid_block(first, RID_BLOCK).await {
                    Ok(base) => ranges2
                        .lock()
                        .expect("rid ranges")
                        .push_back((base, base + RID_BLOCK)),
                    Err(e) => tracing::warn!("RID block refill failed: {e}"),
                },
                RefillKind::Pool => match db2.reserve_rid_block(first, RID_POOL_BLOCK).await {
                    Ok(base) => pool_ranges2
                        .lock()
                        .expect("rid pool ranges")
                        .push_back((base, base + RID_POOL_BLOCK)),
                    Err(e) => tracing::warn!("RID pool block refill failed: {e}"),
                },
            }
        }
    });
    Arc::new(DbRidAllocator {
        ranges,
        pool_ranges,
        refill: tx,
    })
}

/// The default realm when none is configured.
pub const DEFAULT_REALM: &str = "EXAMPLE.COM";

// Built-in (PoC) defaults for the domain's krbtgt + service secrets. Each is
// overridable by the matching env var below. These derive the **krbtgt and service
// Kerberos keys — the root of the domain's trust** — so for a production domain set a
// strong, secret value, and the IDENTICAL value on every DC (else the domain splits).
/// Default for `CIFS_SECRET` (the `cifs`/`ldap` service keys).
const DEFAULT_CIFS_SECRET: &str = "cifs-secret";
/// Default for `KADMIN_SECRET` (the `kadmin/changepw` / kpasswd service).
const DEFAULT_KADMIN_SECRET: &str = "kadmin-changepw-secret";
/// Default for `DNS_SECRET` (the `DNS/<dc-fqdn>` GSS-TSIG service).
const DEFAULT_DNS_SECRET: &str = "dns-secret";
/// Default for `KRBTGT_SECRET` (the krbtgt account — the Kerberos root key).
const DEFAULT_KRBTGT_SECRET: &str = "krbtgt-secret";
/// Default for `HOST_SECRET` (the `host/<dc-fqdn>` service, backing DRSUAPI DCSync).
const DEFAULT_HOST_SECRET: &str = "host-secret";

/// Resolve a domain secret from `var` (memoized). Falls back to the built-in PoC
/// `default` with a one-time warning, so a default-credential deployment is visible
/// rather than silent.
fn domain_secret(
    var: &'static str,
    default: &'static str,
    cell: &'static OnceLock<String>,
) -> &'static str {
    cell.get_or_init(|| match std::env::var(var) {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            tracing::warn!(
                "{var} not set — using the built-in PoC default; set a strong secret (identical on every DC) for a production domain"
            );
            default.to_string()
        }
    })
}

/// The `cifs`/`ldap` service secret (`CIFS_SECRET` env, else the PoC default).
fn cifs_secret() -> &'static str {
    static CELL: OnceLock<String> = OnceLock::new();
    domain_secret("CIFS_SECRET", DEFAULT_CIFS_SECRET, &CELL)
}
/// The `kadmin/changepw` service secret (`KADMIN_SECRET` env, else the PoC default).
fn kadmin_secret() -> &'static str {
    static CELL: OnceLock<String> = OnceLock::new();
    domain_secret("KADMIN_SECRET", DEFAULT_KADMIN_SECRET, &CELL)
}
/// The `DNS/<fqdn>` service secret (`DNS_SECRET` env, else the PoC default).
fn dns_secret() -> &'static str {
    static CELL: OnceLock<String> = OnceLock::new();
    domain_secret("DNS_SECRET", DEFAULT_DNS_SECRET, &CELL)
}
/// The krbtgt secret — the Kerberos root key (`KRBTGT_SECRET` env, else the PoC default).
fn krbtgt_secret() -> &'static str {
    static CELL: OnceLock<String> = OnceLock::new();
    domain_secret("KRBTGT_SECRET", DEFAULT_KRBTGT_SECRET, &CELL)
}
/// The `host/<fqdn>` service secret (`HOST_SECRET` env, else the PoC default).
fn host_secret() -> &'static str {
    static CELL: OnceLock<String> = OnceLock::new();
    domain_secret("HOST_SECRET", DEFAULT_HOST_SECRET, &CELL)
}

/// Every domain secret whose env var must carry a strong, non-default value before
/// magnetite is the *sole* IdP: `(env var, built-in PoC default)`. Leaving any at its
/// default publishes the domain's Kerberos root/service keys to anyone who reads the
/// source (krbtgt at the default ⇒ golden-ticket forgery ⇒ full domain compromise), so
/// [`missing_production_secrets`] refuses to start production with any still unset.
const PRODUCTION_SECRETS: &[(&str, &str)] = &[
    ("KRBTGT_SECRET", DEFAULT_KRBTGT_SECRET),
    ("CIFS_SECRET", DEFAULT_CIFS_SECRET),
    ("HOST_SECRET", DEFAULT_HOST_SECRET),
    ("KADMIN_SECRET", DEFAULT_KADMIN_SECRET),
    ("DNS_SECRET", DEFAULT_DNS_SECRET),
    ("MACHINE_PASSWORD", MACHINE_PASSWORD),
];

/// The names of the domain secrets still unset, empty, or left at the built-in PoC
/// default — the ones that must be given strong values (identical on every DC) before
/// production. An empty result means every secret is overridden. Used by the startup
/// production guard (see `PRODUCTION` env in the daemon) to hard-fail rather than
/// silently serve a domain whose Kerberos root key is public.
pub fn missing_production_secrets() -> Vec<&'static str> {
    PRODUCTION_SECRETS
        .iter()
        .filter(|(var, default)| match std::env::var(var) {
            Ok(v) => v.trim().is_empty() || v == *default,
            Err(_) => true,
        })
        .map(|(var, _)| *var)
        .collect()
}

/// The DRSUAPI interface UUID (`E3514235-4B06-11D1-AB04-00C04FC2DCD2`) as the
/// 16 GUID bytes an endpoint-mapper tower carries (for EPM registration).
const DRSUAPI_UUID: [u8; 16] = [
    0x35, 0x42, 0x51, 0xe3, 0x06, 0x4b, 0xd1, 0x11, 0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2,
];
/// The SAMR interface UUID (`12345778-1234-ABCD-EF00-0123456789AC`) as tower bytes.
const SAMR_UUID: [u8; 16] = [
    0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xac,
];

/// The AES256 key the `ldap/<dc-fqdn>` (and `cifs/…`) SPN is issued against —
/// hand it to [`magnetite_ldap::LdapService::with_gss_key`] so the embedded LDAP
/// server accepts GSS-SPNEGO SASL binds from a domain-join client.
///
/// # Errors
/// Propagates a Kerberos key-derivation failure.
pub fn ldap_service_key(realm: &str) -> anyhow::Result<Vec<u8>> {
    let service = ["cifs".to_string(), "magnetite".to_string()];
    Ok(derive_aes256_key(
        cifs_secret(),
        &default_salt(realm, &service),
    )?)
}

/// The AES256 key the `DNS/<dc-fqdn>` SPN is issued against — hand it to
/// [`magnetite_dns::DnsService::with_gss_key`] so the embedded DNS server accepts
/// GSS-TSIG (RFC 3645) TKEY negotiations and secured dynamic updates.
///
/// # Errors
/// Propagates a Kerberos key-derivation failure.
pub fn dns_service_key(realm: &str) -> anyhow::Result<Vec<u8>> {
    let service = ["dns".to_string(), "magnetite".to_string()];
    Ok(derive_aes256_key(
        dns_secret(),
        &default_salt(realm, &service),
    )?)
}

/// The well-known domain groups the directory seeds (name, RID). These are the
/// standard AD groups SAMR/LSA resolve; the single source used by both the
/// directory builder and the control-plane UI.
pub const WELL_KNOWN_GROUPS: &[(&str, u32)] = &[("Domain Admins", 512), ("Domain Users", 513)];

/// The service principal names (SPNs) the KDC issues tickets for: the TGS
/// (`krbtgt/REALM`), the SMB service (`cifs/magnetite`) and the RPC/DRSUAPI
/// service (`host/magnetite`). Mirrors what [`spawn_servers`] registers.
pub fn service_principals(realm: &str) -> Vec<String> {
    vec![
        format!("krbtgt/{realm}"),
        "cifs/magnetite".to_string(),
        "host/magnetite".to_string(),
    ]
}

/// The four listen sockets the AD DC binds. Each has a well-known default.
#[derive(Debug, Clone, Copy)]
pub struct AddcAddrs {
    /// Kerberos KDC (`:88`).
    pub kdc: SocketAddr,
    /// SMB — SYSVOL + `ncacn_np` pipes (`:445`).
    pub smb: SocketAddr,
    /// RPC/SAMR over `ncacn_ip_tcp` (`:1025`).
    pub rpc: SocketAddr,
    /// DRSUAPI, Kerberos-authenticated DCSync (`:1027`).
    pub drs: SocketAddr,
    /// CLDAP netlogon ping, UDP (`:389`) — the DC-discovery responder.
    pub cldap: SocketAddr,
    /// Kerberos Change/Set Password (`kpasswd`, UDP+TCP `:464`).
    pub kpasswd: SocketAddr,
    /// RPC Endpoint Mapper (`ept`, `:135`) — resolves RPC services' dynamic ports.
    pub epm: SocketAddr,
    /// SNTP time service (UDP `:123`) — keeps members within the Kerberos skew.
    pub sntp: SocketAddr,
}

impl AddcAddrs {
    /// Resolve the sockets from an [`AddcConfig`], applying the well-known defaults
    /// for any that are unset or unparseable.
    pub fn from_config(cfg: &AddcConfig) -> Self {
        fn socket(value: &Option<String>, default: &str) -> SocketAddr {
            value
                .as_deref()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| default.parse().expect("valid default socket"))
        }
        Self {
            kdc: socket(&cfg.kdc_listen, "0.0.0.0:88"),
            smb: socket(&cfg.smb_listen, "0.0.0.0:445"),
            rpc: socket(&cfg.rpc_listen, "0.0.0.0:1025"),
            drs: socket(&cfg.drs_listen, "0.0.0.0:1027"),
            cldap: socket(&cfg.cldap_listen, "0.0.0.0:389"),
            kpasswd: socket(&cfg.kpasswd_listen, "0.0.0.0:464"),
            epm: socket(&cfg.epm_listen, "0.0.0.0:135"),
            sntp: socket(&cfg.sntp_listen, "0.0.0.0:123"),
        }
    }
}

/// Build the `ncacn_np` pipe registry: one interface per well-known pipe, all
/// answering from the shared `directory`.
fn pipe_registry(
    directory: Arc<Directory>,
    kdc: Arc<PrincipalStore>,
    account_store: Option<Arc<dyn AccountStore>>,
    rid_allocator: Option<Arc<dyn RidAllocator>>,
) -> PipeRegistry {
    let mut pipes = PipeRegistry::new();
    // SAMR over the pipe gets the same KDC + account store as the TCP endpoint, so a
    // machine account created over the Kerberos-authenticated SMB pipe registers with
    // the KDC and is persisted (the real domain-join transport).
    let d = directory.clone();
    let k = kdc.clone();
    let acct = account_store.clone();
    let alloc = rid_allocator.clone();
    let samr: PipeFactory = Arc::new(move || {
        let mut samr = SamrInterface::new_with_kdc(d.clone(), k.clone());
        if let Some(store) = &acct {
            samr = samr.with_account_store(store.clone());
        }
        if let Some(a) = &alloc {
            samr = samr.with_rid_allocator(a.clone());
        }
        Arc::new(samr) as Arc<dyn RpcInterface>
    });
    let d = directory.clone();
    let lsa: PipeFactory =
        Arc::new(move || Arc::new(LsaInterface::new(d.clone())) as Arc<dyn RpcInterface>);
    let k = kdc.clone();
    let acct = account_store.clone();
    let d = directory.clone();
    let netlogon: PipeFactory = Arc::new(move || {
        // The secure channel gets the same KDC + account store as SAMR, so a
        // `NetrServerPasswordSet2` rotation re-registers the machine account with
        // the KDC and persists it — closing the domain-join credential loop. The
        // shared directory lets `Authenticate3` resolve the caller's real machine NT
        // hash by AccountName (rather than the placeholder constructor password).
        let mut nl = NetlogonInterface::new(&machine_password())
            .with_kdc(k.clone())
            .with_directory(d.clone());
        if let Some(store) = &acct {
            nl = nl.with_account_store(store.clone());
        }
        Arc::new(nl) as Arc<dyn RpcInterface>
    });
    pipes.insert("samr".to_string(), samr);
    pipes.insert("lsarpc".to_string(), lsa);
    pipes.insert("netlogon".to_string(), netlogon);
    pipes
}

/// The default in-memory directory (`alice` from [`Directory::default`] plus a
/// second user `bob` to demonstrate consistency across interfaces).
///
/// # Errors
/// Propagates a Kerberos key-derivation failure while adding `bob`.
/// Parse a dotted IPv4 string to four octets, falling back to loopback — used to
/// fill the Endpoint Mapper's tower host floor.
fn parse_ipv4(s: &str) -> [u8; 4] {
    s.parse::<std::net::Ipv4Addr>()
        .map(|a| a.octets())
        .unwrap_or([127, 0, 0, 1])
}

pub fn default_directory() -> anyhow::Result<Directory> {
    let mut dir = Directory::default();
    dir.add_user("bob", 1001, "bobpass123")?;
    Ok(dir)
}

/// An [`AccountStore`] backed by `magnetite-db`: SAMR-created (and repassworded)
/// accounts are persisted to `ad_principal`, so they survive a restart. Persistence
/// is fire-and-forget (spawned) since [`AccountStore::persist_account`] is sync.
struct DbAccountStore {
    db: magnetite_db::Db,
    realm: String,
}

impl AccountStore for DbAccountStore {
    fn persist_account(
        &self,
        sam_account_name: &str,
        rid: u32,
        password: &str,
        nt_hash: [u8; 16],
        kerberos_key: &[u8],
    ) {
        let db = self.db.clone();
        let realm = self.realm.clone();
        let sam = sam_account_name.to_string();
        let password = password.to_string();
        let kerberos_key = kerberos_key.to_vec();
        tokio::spawn(async move {
            let key = (!kerberos_key.is_empty()).then_some(kerberos_key.as_slice());
            // A locally originated write (SAMR create / password reset): persist the
            // object AND its bumped replication stamp atomically (Tier C item 2), so the
            // change replicates out with a climbing version and wins over a peer's prior
            // value — and a crash can't leave the object un-stamped.
            if let Err(e) = db
                .upsert_local_principal(&sam, rid, &password, &nt_hash, key, &realm)
                .await
            {
                tracing::warn!("persisting AD account {sam} failed: {e}");
                addc_log(
                    &db,
                    magnetite_core::models::common::LogLevel::Warn,
                    format!("AD アカウント {sam} の保存に失敗しました: {e}"),
                )
                .await;
            } else {
                let what = if sam.ends_with('$') {
                    format!("マシンアカウント {sam} を登録 (RID {rid})")
                } else {
                    format!("アカウント {sam} を保存 (RID {rid})")
                };
                addc_log(&db, magnetite_core::models::common::LogLevel::Info, what).await;
            }
            // Unify with the LDAP directory: a machine account (name ending in `$`)
            // also gets a `computer` object, so it's consistent across both stores.
            if sam.ends_with('$') {
                let dns_domain = realm.to_lowercase();
                let base_dn = format!("dc={}", dns_domain.replace('.', ",dc="));
                let host = format!(
                    "{}.{}",
                    sam.trim_end_matches('$').to_lowercase(),
                    dns_domain
                );
                if let Err(e) = db
                    .ensure_computer_entry(&base_dn, &sam, &host, 0x1002, "magnetite-addc")
                    .await
                {
                    tracing::warn!("LDAP computer object for {sam} failed: {e}");
                }
            }
        });
    }
}

/// Append an AD DC operational event to the shared DB log sink (S-Logs), so security
/// events surface in the Web logs view rather than only in the process trace.
/// Best-effort — a failure to log never disrupts serving.
async fn addc_log(db: &Db, level: magnetite_core::models::common::LogLevel, message: String) {
    let _ = db
        .append_log(NewLogEntry {
            domain: DomainKey::Addc,
            log_kind: magnetite_core::models::common::LogKind::Operation,
            level,
            message,
            at: chrono::Utc::now(),
            meta: None,
        })
        .await;
}

/// A database-backed [`AccountStore`] for the AD DC (persists SAMR-created accounts).
pub fn db_account_store(db: magnetite_db::Db, realm: &str) -> Arc<dyn AccountStore> {
    Arc::new(DbAccountStore {
        db,
        realm: realm.to_string(),
    })
}

/// Build the DC's directory from `magnetite-db`'s AD principals. Seeds `alice`/`bob`
/// on an empty database (PoC), then sources every user (with its stored NT hash and
/// Kerberos key) from the store — so the database is the single source of truth.
///
/// # Errors
/// Propagates database and key-derivation failures.
/// Whether the PoC demo users (alice/bob) may be auto-seeded into an empty store —
/// `SEED_POC_USERS` set to an affirmative value (`1`/`true`/`yes`/`on`). Off by default
/// so a production/replica DC never resurrects known-credential accounts.
fn seed_poc_users_enabled() -> bool {
    matches!(
        std::env::var("SEED_POC_USERS")
            .ok()
            .map(|s| s.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

/// Well-known RID of the `Domain Users` group — every account's default primary group.
const DOMAIN_USERS_RID: u32 = 513;

/// The group RIDs a user belongs to, for the KDC's PAC: always `Domain Users` (513),
/// plus every AD group in `groups` whose members include the user's RID. This is the
/// per-user group SID set Windows puts in the access token.
fn user_group_rids(groups: &[magnetite_rpc::Group], user_rid: u32) -> Vec<u32> {
    let mut rids = vec![DOMAIN_USERS_RID];
    for g in groups {
        if g.rid != DOMAIN_USERS_RID && g.members.contains(&user_rid) {
            rids.push(g.rid);
        }
    }
    rids
}

pub async fn build_directory_from_db(db: &Db, realm: &str) -> anyhow::Result<Directory> {
    // PoC demo users (alice/bob) are seeded into an empty store ONLY when explicitly
    // opted in via `SEED_POC_USERS`. They have publicly-known passwords, so seeding them
    // by default was a foot-gun: a production or replica DC whose `ad_principal` is empty
    // (before the first replication cycle, or after every real user is deleted) would
    // resurrect two authenticatable accounts with known credentials. Default off.
    if seed_poc_users_enabled() && db.list_ad_principals().await?.is_empty() {
        db.create_ad_principal("alice", 1000, "password12", realm)
            .await?;
        db.create_ad_principal("bob", 1001, "bobpass123", realm)
            .await?;
    }
    // Derive the domain identity from the realm so CLDAP/SAMR/LSA advertise the
    // configured domain (a Windows join's CLDAP netlogon ping rejects the DC if the
    // response's DnsDomainName doesn't match the queried domain). DNS domain = the
    // lowercased realm; NetBIOS = the first label uppercased, ≤15 chars (RFC 1001).
    let dns_domain = realm.to_lowercase();
    let netbios: String = dns_domain
        .split('.')
        .next()
        .unwrap_or(&dns_domain)
        .to_uppercase()
        .chars()
        .take(15)
        .collect();
    // Domain SID sub-authorities: the DB-persisted single source of truth (seeded by the
    // web/config or the `DOMAIN_SID` override) so the KDC/SAMR/LSA/DRSUAPI, the LDAP
    // objectSid and netlogon all present one domain identity. Default when unseeded.
    let domain_sub = db
        .get_domain_sid()
        .await?
        .unwrap_or_else(|| vec![21, 1, 2, 3]);
    let mut dir = Directory::new(&netbios, &dns_domain, realm, domain_sub);
    for p in db.list_ad_principals().await? {
        let mut nt_hash = [0u8; 16];
        if p.nt_hash.len() == 16 {
            nt_hash.copy_from_slice(&p.nt_hash);
        }
        dir.add_user_with_keys(
            &p.sam_account_name,
            p.rid,
            nt_hash,
            p.kerberos_key,
            p.disabled,
        );
        // Attach the change's REAL replication origin (from the store) so outbound DRS
        // preserves it instead of re-stamping every object as locally originated — the
        // prerequisite for magnetite↔magnetite multi-master convergence.
        if let Some(s) = db.repl_stamp(&p.sam_account_name).await? {
            dir.set_user_repl_meta(
                &p.sam_account_name,
                magnetite_rpc::ReplMeta {
                    version: s.version,
                    originating_time: s.originating_time + DSTIME_EPOCH_OFFSET,
                    originating_dsa: s.originating_dsa,
                    originating_usn: s.originating_usn,
                },
            );
        }
    }
    // Groups: prefer the ones replicated from an upstream DC (the real domain groups,
    // including any custom ones); fall back to the minimal well-known set when nothing
    // has been replicated (a fresh or in-memory directory).
    let replicated_groups = db.list_ad_groups().await?;
    if replicated_groups.is_empty() {
        for (name, rid) in WELL_KNOWN_GROUPS {
            dir.add_group(name, *rid);
        }
    } else {
        // A member's RID is the last sub-authority of its (little-endian) objectSid hex.
        let rid_of = |sid_hex: &str| -> Option<u32> {
            let bytes: Vec<u8> = (0..sid_hex.len() / 2)
                .map(|i| u8::from_str_radix(&sid_hex[i * 2..i * 2 + 2], 16).unwrap_or(0))
                .collect();
            (bytes.len() >= 4)
                .then(|| u32::from_le_bytes(bytes[bytes.len() - 4..].try_into().unwrap()))
        };
        for g in &replicated_groups {
            let member_rids: Vec<u32> = g.member_sids.iter().filter_map(|s| rid_of(s)).collect();
            dir.add_group_with_members(&g.sam_account_name, g.rid, member_rids);
            // Attach the group's real replication origin (stored keyed by its SID hex) so
            // outbound DRS preserves it and the group dampens/converges (Tier C item 5c).
            if let Some(s) = db.repl_stamp(&g.sid).await? {
                dir.set_group_repl_meta(
                    &g.sam_account_name,
                    magnetite_rpc::ReplMeta {
                        version: s.version,
                        originating_time: s.originating_time + DSTIME_EPOCH_OFFSET,
                        originating_dsa: s.originating_dsa,
                        originating_usn: s.originating_usn,
                    },
                );
            }
            // The FULL per-link membership state (present + absent tombstones) with each
            // link's stamp, so outbound serves removals and a peer conflict-resolves per
            // link (Tier C item 5d).
            let links: Vec<magnetite_rpc::GroupLink> = g
                .member_links
                .iter()
                .filter_map(|l| {
                    rid_of(&l.member_sid).map(|member_rid| {
                        let mut dsa = [0u8; 16];
                        let n = l.originating_dsa.len().min(16);
                        dsa[..n].copy_from_slice(&l.originating_dsa[..n]);
                        magnetite_rpc::GroupLink {
                            member_rid,
                            present: l.present,
                            repl_meta: Some(magnetite_rpc::ReplMeta {
                                version: l.version,
                                originating_time: l.originating_time + DSTIME_EPOCH_OFFSET,
                                originating_dsa: dsa,
                                originating_usn: l.originating_usn,
                            }),
                        }
                    })
                })
                .collect();
            dir.set_group_member_links(&g.sam_account_name, links);
        }
    }
    Ok(dir)
}

/// Unix-epoch → 1601-epoch (`DSTIME`) offset in seconds. The DRS wire stamps time as a
/// `DSTIME` (seconds since 1601-01-01); the store keeps Unix seconds. Convert on the way
/// in (consumer) and back out (outbound `repl_meta`) so both wire directions agree and
/// internal `wins_over` time comparisons stay consistent.
const DSTIME_EPOCH_OFFSET: i64 = 11_644_473_600;

/// Apply a decoded `GetNCChanges` reply to the local store (Tier C C1): upsert every
/// replicated principal — recovering its NT hash from the encrypted `unicodePwd` and
/// its Kerberos AES256 key from `supplementalCredentials`, both under `session_key` —
/// and advance the source DSA's up-to-dateness cursor. This is the orchestration a
/// replication consumer runs each cycle after decoding a source DC's reply. Returns
/// the number of principals applied.
///
/// The origin stamp uses the source DSA's identity + the reply's high-water USN;
/// proper per-attribute version-based conflict resolution (Tier C C3) is a later
/// refinement.
///
/// # Errors
/// A database error while applying an object or advancing the cursor.
pub async fn apply_replicated_changes(
    db: &Db,
    changes: &magnetite_rpc::ReplicatedChanges,
    session_key: &[u8],
    realm: &str,
) -> anyhow::Result<usize> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut applied = 0usize;
    // The LDAP naming context, so replicated objects are also projected into the `entry`
    // tree the directory server reads (B1) — e.g. EXAMPLE.COM -> dc=example,dc=com.
    let base_dn = format!("dc={}", realm.to_lowercase().replace('.', ",dc="));
    // First, apply tombstones: a deleted object replicates `isDeleted=TRUE` with most
    // attributes stripped but its retained objectSid, so match by RID (principal) or SID
    // (group) and remove it from the store. Its class (groupType) may be stripped too, so
    // try both — whichever table held it is cleared. The live directory + KDC are purged
    // by the caller's refresh, which reconciles them against the now-smaller DB (B4b).
    for obj in &changes.objects {
        if !obj.is_deleted() {
            continue;
        }
        if let Some(rid) = obj.object_rid() {
            if let Some(sam) = db.delete_replicated_principal(rid).await? {
                db.delete_projected_entry(&base_dn, &sam).await?;
                tracing::info!(%sam, rid, "replication: applied tombstone (principal deleted)");
            }
        }
        if let Some(sid) = obj.object_sid() {
            let sid_hex: String = sid.iter().map(|x| format!("{x:02x}")).collect();
            if let Some(sam) = db.delete_replicated_group(&sid_hex).await? {
                db.delete_projected_entry(&base_dn, &sam).await?;
                tracing::info!(%sam, "replication: applied tombstone (group deleted)");
            }
        }
    }
    for obj in &changes.objects {
        if obj.is_deleted() {
            continue; // handled above
        }
        let (Some(sam), Some(rid), Some(nt)) = (
            obj.sam_account_name(),
            obj.object_rid(),
            obj.nt_hash(session_key),
        ) else {
            continue; // skip objects lacking the fields a principal needs
        };
        // Stamp the change with the source's real version/origin (the newest of the
        // object's per-attribute metadata), so version-based conflict resolution is
        // meaningful; fall back to the reply cursor when no metadata was sent. The wire
        // `originating_time` is a DSTIME (secs since 1601); store it internally in Unix
        // seconds so it is consistent with locally stamped changes and the `wins_over`
        // tiebreak (the outbound path converts back to DSTIME).
        // The OBJECT stamp (newest across the object's attributes) governs the identity;
        // the SECRET (unicodePwd) converges on its OWN per-attribute stamp so a newer
        // local password is not clobbered when only the name is newer upstream (Tier C
        // item 4, per-attribute merge). When the source sends no per-attribute metadata
        // (uniform magnetite outbound), the secret stamp falls back to the object stamp,
        // so behaviour matches object-level resolution. The wire `originating_time` is a
        // DSTIME (secs since 1601); stored internally in Unix seconds.
        let obj_meta = obj.newest_metadata();
        let object_stamp = magnetite_db::ReplStamp {
            version: obj_meta.map_or(1, |m| m.version),
            originating_time: obj_meta.map_or(now, |m| m.originating_time - DSTIME_EPOCH_OFFSET),
            originating_dsa: obj_meta.map_or(changes.source_invocation_id, |m| m.originating_dsa),
            originating_usn: obj_meta.map_or(changes.usn_to, |m| m.originating_usn),
            local_usn: 0, // assigned locally by the store
        };
        let sec_meta = obj.secret_metadata();
        let secret_stamp = magnetite_db::ReplStamp {
            version: sec_meta.map_or(object_stamp.version, |m| m.version),
            originating_time: sec_meta.map_or(object_stamp.originating_time, |m| {
                m.originating_time - DSTIME_EPOCH_OFFSET
            }),
            originating_dsa: sec_meta.map_or(object_stamp.originating_dsa, |m| m.originating_dsa),
            originating_usn: sec_meta.map_or(object_stamp.originating_usn, |m| m.originating_usn),
            local_usn: 0,
        };
        // The replicated AES256 key (from supplementalCredentials) lets the applied
        // principal authenticate via AES Kerberos, not just NTLM. Empty if absent.
        let aes256 = obj
            .kerberos_keys(session_key)
            .into_iter()
            .find(|k| k.key_type == magnetite_rpc::KERB_ETYPE_AES256)
            .map(|k| k.key)
            .unwrap_or_default();
        // Per-attribute conflict resolution + no-regress happen inside the store.
        if db
            .apply_replicated_principal_merged(
                &sam,
                rid,
                &nt,
                &aes256,
                obj.is_disabled(),
                realm,
                &object_stamp,
                &secret_stamp,
            )
            .await?
        {
            applied += 1;
        }
        // Project the user into the LDAP `entry` tree so the directory server serves it
        // (B1). userAccountControl: prefer the replicated value, else synthesize
        // NORMAL_ACCOUNT (with ACCOUNTDISABLE when disabled).
        if let Some(sid) = obj.object_sid() {
            let uac = obj.user_account_control().unwrap_or(if obj.is_disabled() {
                0x0202
            } else {
                0x0200
            });
            db.ensure_user_entry(&base_dn, &sam, sid, uac, "replication")
                .await?;
        }
    }

    // Groups replicate without secrets; their membership arrives as separate linked
    // values (REPLVALINF) rather than a `member` attribute. Map each group object by
    // its objectGUID, gather its members' SIDs from the links (which reference the
    // group by that GUID), and upsert the group with its membership.
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    type GroupEntry = (String, u32, String, magnetite_db::ReplStamp);
    let mut group_by_guid: std::collections::HashMap<[u8; 16], GroupEntry> =
        std::collections::HashMap::new();
    for obj in &changes.objects {
        if obj.is_group() {
            if let (Some(sam), Some(rid), Some(sid)) =
                (obj.sam_account_name(), obj.object_rid(), obj.object_sid())
            {
                // Stamp the group with its real origin (Tier C item 5c), like a principal,
                // so it dampens/converges instead of ping-ponging.
                let meta = obj.newest_metadata();
                let stamp = magnetite_db::ReplStamp {
                    version: meta.map_or(1, |m| m.version),
                    originating_time: meta
                        .map_or(now, |m| m.originating_time - DSTIME_EPOCH_OFFSET),
                    originating_dsa: meta
                        .map_or(changes.source_invocation_id, |m| m.originating_dsa),
                    originating_usn: meta.map_or(changes.usn_to, |m| m.originating_usn),
                    local_usn: 0, // assigned locally by apply_replicated_group
                };
                group_by_guid.insert(obj.guid, (sam, rid, hex(sid), stamp));
            }
        }
    }
    // Collect ALL membership links (present AND absent tombstones) with their per-link
    // metadata, converting the wire DSTIME to internal Unix seconds — the store merges
    // them per link so removals and concurrent add/remove converge (item 5d).
    let mut links_by_group: std::collections::HashMap<[u8; 16], Vec<magnetite_db::IncomingLink>> =
        std::collections::HashMap::new();
    for link in &changes.links {
        if link.attr_id == magnetite_rpc::LINK_ATTR_MEMBER && !link.target_sid.is_empty() {
            links_by_group
                .entry(link.source_guid)
                .or_default()
                .push(magnetite_db::IncomingLink {
                    member_sid: hex(&link.target_sid),
                    present: link.present,
                    version: link.version,
                    originating_dsa: link.originating_dsa,
                    originating_usn: link.originating_usn,
                    originating_time: link.originating_time - DSTIME_EPOCH_OFFSET,
                });
        }
    }
    // Apply ALL groups to the store first, THEN project their LDAP entries — a group's
    // `member` DNs are resolved against the ad_group/ad_principal stores, so a member that
    // is itself a group must already be applied or its DN would be missed. Splitting the
    // passes makes member resolution complete and order-independent (a HashMap-iteration
    // race otherwise dropped members like Domain Admins from Administrators).
    for (guid, (sam, rid, sid_hex, stamp)) in &group_by_guid {
        // apply_replicated_group merges the links per-link and keeps the winning OBJECT
        // stamp internally, so we never skip a link-only membership change here.
        let incoming = links_by_group.get(guid).cloned().unwrap_or_default();
        db.apply_replicated_group(sam, *rid, sid_hex, &incoming, stamp)
            .await?;
    }
    for (guid, (sam, _rid, sid_hex, _stamp)) in &group_by_guid {
        // Project the group into the LDAP `entry` tree with its present members' DNs (B1).
        let sid_bytes: Vec<u8> = (0..sid_hex.len() / 2)
            .map(|i| u8::from_str_radix(&sid_hex[i * 2..i * 2 + 2], 16).unwrap_or(0))
            .collect();
        let present_members: Vec<String> = links_by_group
            .get(guid)
            .map(|links| {
                links
                    .iter()
                    .filter(|l| l.present)
                    .map(|l| l.member_sid.clone())
                    .collect()
            })
            .unwrap_or_default();
        db.ensure_group_entry(&base_dn, sam, &sid_bytes, &present_members, "replication")
            .await?;
    }

    // Generic object projection (Config/Schema NC + OUs): any LIVE object that is neither
    // a group nor a stored principal is projected into the LDAP `entry` tree if it can be
    // classified — see [`project_generic_objects`].
    project_generic_objects(db, &changes.objects, session_key, realm).await?;

    db.record_cursor(changes.source_invocation_id, changes.usn_to)
        .await?;
    Ok(applied)
}

/// Project every LIVE, classifiable, non-principal, non-group object into the LDAP
/// `entry` tree (an organizationalUnit, an attributeSchema / classSchema, a crossRef).
/// Users/groups/computers are handled by their own paths; an unclassifiable object
/// (`projected_object_classes` → `None`) or one with no recognized attributes is left
/// untouched, so this never mis-projects. `session_key` distinguishes a stored principal
/// (which has a recoverable secret) from a generic object; pass an empty slice for a NC
/// with no secrets (Config/Schema). Returns the number of objects projected.
///
/// # Errors
/// A store error while projecting.
async fn project_generic_objects(
    db: &Db,
    objects: &[magnetite_rpc::ReplicatedObject],
    session_key: &[u8],
    realm: &str,
) -> anyhow::Result<usize> {
    let base_dn = format!("dc={}", realm.to_lowercase().replace('.', ",dc="));
    let mut projected = 0usize;
    for obj in objects {
        if obj.is_deleted() || obj.is_group() {
            continue;
        }
        let is_principal = obj.sam_account_name().is_some()
            && obj.object_rid().is_some()
            && obj.nt_hash(session_key).is_some();
        if is_principal {
            continue; // already applied + projected as a user entry
        }
        let Some(classes) = obj.projected_object_classes() else {
            continue;
        };
        let dn = obj.dn();
        let attrs = obj.ldap_attributes();
        if dn.is_empty() || attrs.is_empty() {
            continue;
        }
        db.upsert_projected_entry(dn, classes, attrs, "replication")
            .await?;
        projected += 1;
    }
    let _ = base_dn; // objects carry absolute DNs; base kept for future relative projection
    Ok(projected)
}

/// Seed the read-only partitions (Config + Schema NCs) into the LDAP `entry` tree: page
/// each NC fully over the existing Kerberos-sealed `client` and project its objects
/// generically ([`project_generic_objects`]). These partitions carry no secrets, so no
/// session key is needed. Idempotent (projection is upsert), so it is safe to re-run.
/// Returns the total objects projected across all NCs.
///
/// # Errors
/// A DRS transport failure or a store error.
pub async fn seed_projected_ncs(
    client: &mut DrsClient,
    db: &Db,
    ncs: &[String],
    realm: &str,
) -> anyhow::Result<usize> {
    // DRS_INIT_SYNC | DRS_WRIT_REP | DRS_NEVER_SYNCED, paged (schema is ~1600 objects).
    const FLAGS: u32 = 0x0000_0020 | 0x0000_0010 | 0x0020_0000;
    let mut total = 0usize;
    for nc in ncs {
        let objects = client
            .replicate_nc(nc, FLAGS, 1000, 8)
            .await
            .map_err(|e| anyhow::anyhow!("replicate_nc({nc}): {e}"))?;
        let n = project_generic_objects(db, &objects, &[], realm).await?;
        tracing::info!(nc = %nc, pulled = objects.len(), projected = n, "seeded partition NC");
        total += n;
    }
    Ok(total)
}

/// The outcome of one [`replicate_cycle`].
#[derive(Debug, Clone, Copy)]
pub struct ReplCycleOutcome {
    /// Objects the source returned this cycle — near zero on a delta cycle with no
    /// source changes, since our `pUpToDateVecDest` lets the source skip them.
    pub pulled: usize,
    /// Principals actually applied to the local store this cycle.
    pub applied: usize,
    /// The source DSA's invocation ID — feed it back as `source_dsa` next cycle.
    pub source_dsa: [u8; 16],
}

/// Run one **incremental** replication cycle against a source DC: pull its changes
/// newer than the up-to-dateness cursors we hold, apply them, and advance the cursor.
/// The first cycle (`source_dsa == None`, no cursor) is a from-scratch full sync; a
/// later cycle sends our cursors as `pUpToDateVecDest`, so the source ships only the
/// true delta (an unchanged source returns no objects). Feed the returned `source_dsa`
/// back in as `source_dsa` next cycle.
///
/// This is the loop body a running replication consumer schedules periodically, and it
/// is safely re-runnable: [`apply_replicated_changes`] applies MS-DRSR conflict
/// resolution, so any object we already hold with a winning stamp is skipped.
///
/// # Errors
/// A transport failure, a FAULT, an undecodable reply, or a database error.
pub async fn replicate_cycle(
    db: &Db,
    client: &mut DrsClient,
    nc_dn: &str,
    session_key: &[u8],
    realm: &str,
    source_dsa: Option<[u8; 16]>,
) -> anyhow::Result<ReplCycleOutcome> {
    const DRS_WRIT_REP: u32 = 0x0000_0010;
    const DRS_INIT_SYNC: u32 = 0x0000_0020;
    const DRS_NEVER_SYNCED: u32 = 0x0020_0000;

    // Our up-to-dateness cursors: the USN we hold for the source picks the low-water
    // mark, and (on a delta cycle) the whole vector goes in the request as
    // pUpToDateVecDest so the source returns only the objects newer than them.
    let utdv = db.up_to_date_vector().await?;
    let from = match source_dsa {
        Some(dsa) => utdv.iter().find(|c| c.dsa == dsa).map_or(0, |c| c.high_usn),
        None => 0,
    };
    // A from-scratch sync asks for a full writeable copy (and carries no cursors); a
    // delta cycle sends our cursors so the source ships only the changes past them.
    let (flags, cursors): (u32, Vec<([u8; 16], i64)>) = if from == 0 {
        (DRS_INIT_SYNC | DRS_WRIT_REP | DRS_NEVER_SYNCED, Vec::new())
    } else {
        (
            DRS_WRIT_REP,
            utdv.iter().map(|c| (c.dsa, c.high_usn)).collect(),
        )
    };
    let changes = client
        .get_nc_changes_delta(nc_dn, [0u8; 16], [0u8; 16], from, flags, 400, &cursors)
        .await
        .map_err(|e| anyhow::anyhow!("get_nc_changes_delta: {e}"))?;
    let pulled = changes.objects.len();
    let source_dsa = changes.source_invocation_id;
    let applied = apply_replicated_changes(db, &changes, session_key, realm).await?;
    Ok(ReplCycleOutcome {
        pulled,
        applied,
        source_dsa,
    })
}

/// Configuration for the periodic [`run_replication_agent`].
#[derive(Debug, Clone)]
pub struct ReplicationConfig {
    /// The source KDC (`host:88`) to obtain a service ticket from.
    pub kdc: SocketAddr,
    /// The source DC's DRSUAPI endpoint (`host:port`, `ncacn_ip_tcp`).
    pub drs: SocketAddr,
    /// The Kerberos realm (e.g. `MAGTEST.LOCAL`).
    pub realm: String,
    /// The account to replicate as — it must hold replication rights (a DC account or
    /// a replication admin).
    pub user: String,
    /// That account's password. Used to derive the Kerberos key when `keytab` is `None`
    /// (a PoC / dev convenience). Production should prefer a keytab so no cleartext
    /// password lives in the config/env.
    pub password: String,
    /// Optional keytab file holding `user`'s Kerberos key. When set, the replication
    /// agent loads the AES256 key from it instead of deriving one from `password` — the
    /// production path (no cleartext credential). The keytab must contain an
    /// AES256-CTS-HMAC-SHA1-96 key for `user@realm`.
    pub keytab: Option<std::path::PathBuf>,
    /// The DRS service SPN to request a ticket for (e.g. `ldap/dc1.magtest.local`).
    pub spn: String,
    /// The naming-context DN to replicate (e.g. `DC=magtest,DC=local`).
    pub nc_dn: String,
    /// Extra read-only partitions to SEED ONCE into the LDAP tree — typically the Config
    /// and Schema NCs (`CN=Configuration,…` / `CN=Schema,CN=Configuration,…`). They carry
    /// no secrets and change rarely, so they are paged + projected on the first successful
    /// cycle only (see [`seed_projected_ncs`]), not swept every interval. Empty = none.
    pub extra_ncs: Vec<String>,
    /// How long to wait between replication cycles.
    pub interval: std::time::Duration,
}

/// One connect-and-replicate cycle: obtain a fresh service ticket, Kerberos-bind the
/// source's DRSUAPI, and run [`replicate_cycle`]. A fresh ticket + bind each cycle
/// keeps the agent robust to ticket expiry and dropped connections.
async fn replicate_connected(
    cfg: &ReplicationConfig,
    db: &Db,
    source_dsa: Option<[u8; 16]>,
    seed_extra_ncs: bool,
) -> anyhow::Result<ReplCycleOutcome> {
    // Prefer a keytab (production: no cleartext password); fall back to deriving the key
    // from the configured password (dev/PoC).
    let key = match &cfg.keytab {
        Some(path) => magnetite_krb5::load_keytab_key(
            path,
            &cfg.realm,
            &[cfg.user.as_str()],
            magnetite_krb5::keys::AES256_CTS_HMAC_SHA1_96,
        )
        .map_err(|e| anyhow::anyhow!("load keytab: {e}"))?,
        None => derive_aes256_key(
            &cfg.password,
            &default_salt(&cfg.realm, std::slice::from_ref(&cfg.user)),
        )
        .map_err(|e| anyhow::anyhow!("derive key: {e}"))?,
    };
    let spn: Vec<&str> = cfg.spn.split('/').collect();
    let ticket = obtain_service_ticket(cfg.kdc, &cfg.realm, &[cfg.user.as_str()], &key, &spn)
        .await
        .map_err(|e| anyhow::anyhow!("obtain_service_ticket: {e}"))?;
    let mut client = DrsClient::connect_kerberos_ticket(
        cfg.drs,
        &ticket.ticket_der,
        &ticket.session_key,
        &cfg.realm,
        &[cfg.user.as_str()],
    )
    .await
    .map_err(|e| anyhow::anyhow!("connect_kerberos_ticket: {e}"))?;
    let session_key = client
        .session_key()
        .ok_or_else(|| anyhow::anyhow!("no GSS session key"))?
        .to_vec();
    // Seed the read-only Config/Schema partitions once (first cycle), reusing this
    // Kerberos-sealed connection, before the domain-NC cycle.
    if seed_extra_ncs && !cfg.extra_ncs.is_empty() {
        if let Err(e) = seed_projected_ncs(&mut client, db, &cfg.extra_ncs, &cfg.realm).await {
            tracing::warn!(error = %e, "seeding Config/Schema partitions failed (continuing)");
        }
    }
    replicate_cycle(
        db,
        &mut client,
        &cfg.nc_dn,
        &session_key,
        &cfg.realm,
        source_dsa,
    )
    .await
}

/// Per-upstream inbound-replication health, updated each cycle by [`run_replication_agent`].
/// A peer is healthy once it has synced at least once and is not in a failure streak.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplPeerHealth {
    /// Unix time (secs) of the last successful cycle, or `None` if it has never synced.
    pub last_success_unix: Option<i64>,
    /// Consecutive failed cycles since the last success (0 when healthy).
    pub consecutive_failures: u32,
    /// Total cycles run (success + failure).
    pub total_cycles: u64,
    /// The most recent failure's error text, cleared on the next success.
    pub last_error: Option<String>,
}

impl ReplPeerHealth {
    /// Record a successful cycle at `at_unix` (clears the failure streak and error).
    pub fn record_success(&mut self, at_unix: i64) {
        self.last_success_unix = Some(at_unix);
        self.consecutive_failures = 0;
        self.total_cycles += 1;
        self.last_error = None;
    }

    /// Record a failed cycle (bumps the failure streak, keeps the last success time).
    pub fn record_failure(&mut self, error: impl Into<String>) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.total_cycles += 1;
        self.last_error = Some(error.into());
    }

    /// Whether this peer is currently healthy: it has synced and is not failing.
    pub fn is_healthy(&self) -> bool {
        self.last_success_unix.is_some() && self.consecutive_failures == 0
    }
}

/// A shared registry of per-upstream replication health, keyed by the peer's DRS
/// address — the agents populate it, the daemon reads it (health surface / logs).
pub type ReplHealthRegistry =
    Arc<std::sync::Mutex<std::collections::BTreeMap<std::net::SocketAddr, ReplPeerHealth>>>;

/// Run the periodic replication agent until `shutdown` flips to `true`: every
/// `cfg.interval` it pulls the source DC's changes — a full sync on the first cycle,
/// then deltas via the up-to-dateness cursor — and applies them to `db`. A transient
/// failure (network, ticket) is logged and retried on the next tick; the source DSA is
/// remembered across cycles so the cursor is used. This is the packaged loop a server
/// spawns as a background task to keep the local directory in sync with an upstream AD.
///
/// The returned future is **not `Send`** (the Kerberos ticket path holds a non-`Send`
/// cipher across an await), so run it on a `LocalSet` / a dedicated single-thread
/// runtime rather than a plain multi-thread `tokio::spawn`.
pub async fn run_replication_agent(
    cfg: ReplicationConfig,
    db: Db,
    mut shutdown: watch::Receiver<bool>,
    live_directory: Option<Arc<Directory>>,
    kdc: Option<Arc<PrincipalStore>>,
    health: Option<ReplHealthRegistry>,
) {
    const BACKOFF_BASE: std::time::Duration = std::time::Duration::from_secs(2);
    const BACKOFF_MAX: std::time::Duration = std::time::Duration::from_secs(300);
    let mut source_dsa: Option<[u8; 16]> = None;
    let mut failures: u32 = 0;
    // The Config/Schema partitions are seeded once, on the first cycle that connects.
    let mut extra_ncs_seeded = false;
    loop {
        // On success wait the configured interval; on repeated failure back off
        // exponentially so a down/unreachable upstream is not hammered.
        let seed_now = !extra_ncs_seeded && !cfg.extra_ncs.is_empty();
        let wait = match replicate_connected(&cfg, &db, source_dsa, seed_now).await {
            Ok(out) => {
                failures = 0;
                source_dsa = Some(out.source_dsa);
                if seed_now {
                    extra_ncs_seeded = true;
                }
                if let Some(reg) = &health {
                    if let Ok(mut m) = reg.lock() {
                        m.entry(cfg.drs).or_default().record_success(
                            std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .map(|d| d.as_secs() as i64)
                                .unwrap_or(0),
                        );
                    }
                }
                tracing::info!(
                    pulled = out.pulled,
                    applied = out.applied,
                    "replication cycle complete"
                );
                // Push the newly-applied users/groups into the live directory so the
                // running DC's SAMR/LSA reflect them without a restart.
                if out.applied > 0 {
                    if let Some(dir) = &live_directory {
                        if let Err(e) =
                            refresh_live_directory(dir, &db, &cfg.realm, kdc.as_ref()).await
                        {
                            tracing::warn!(error = %e, "live directory refresh failed");
                        }
                    }
                }
                cfg.interval
            }
            Err(e) => {
                failures += 1;
                if let Some(reg) = &health {
                    if let Ok(mut m) = reg.lock() {
                        m.entry(cfg.drs).or_default().record_failure(e.to_string());
                    }
                }
                let backoff = failure_backoff(failures, BACKOFF_BASE, BACKOFF_MAX);
                tracing::warn!(
                    error = %e,
                    consecutive_failures = failures,
                    retry_in_secs = backoff.as_secs(),
                    "replication cycle failed; backing off"
                );
                backoff
            }
        };
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = shutdown.changed() => break,
        }
    }
}

/// Register a directory's users into the KDC's runtime store so they can obtain a
/// TGT: machine accounts under their SPN aliases, users under their `sAMAccountName`.
/// Used both at startup (static seed) and by the replication refresh (dynamic), so a
/// replicated user or password change authenticates without a restart. A user with no
/// stored Kerberos key (e.g. NTLM-only) is skipped for Kerberos.
fn seed_kdc_from_users<'a>(
    store: &PrincipalStore,
    users: impl IntoIterator<Item = &'a User>,
    groups: &[magnetite_rpc::Group],
    dynamic: bool,
) {
    for user in users {
        let sam = user.sam_account_name.as_str();
        // A disabled account (userAccountControl ACCOUNTDISABLE) must not authenticate:
        // revoke any runtime key it previously held (a disable replicated in after the
        // account was already registered) and never (re)register it (B4a).
        if user.disabled {
            if dynamic {
                store.remove_dynamic_principal(sam);
            }
            continue;
        }
        if user.kerberos_key.is_empty() {
            continue;
        }
        if sam.ends_with('$') {
            store.register_machine_key(sam, user.kerberos_key.clone());
        } else if dynamic {
            // Register with the real PAC identity (RID + group SIDs) so a refreshed
            // user's logon ticket names the actual user, not a fixed identity.
            store.register_user_identity(
                sam,
                user.kerberos_key.clone(),
                user.rid,
                DOMAIN_USERS_RID,
                user_group_rids(groups, user.rid),
            );
        }
    }
}

/// Rebuild the directory from the DB and upsert its users + groups into the live
/// `directory`'s runtime sets **and**, when `kdc` is given, the KDC's runtime key
/// store — so a running DC's SAMR/LSA/**Kerberos login** reflect freshly replicated
/// data without a restart (B2). The runtime sets are shared across the directory's
/// clones, so this reaches the copies the interfaces hold; the KDC store's dynamic
/// map is likewise `&self`-updatable and shadows the startup seed.
async fn refresh_live_directory(
    directory: &Directory,
    db: &Db,
    realm: &str,
    kdc: Option<&Arc<PrincipalStore>>,
) -> anyhow::Result<()> {
    let fresh = build_directory_from_db(db, realm).await?;
    let users = fresh.all_users();
    let fresh_groups = fresh.all_groups();
    if let Some(store) = kdc {
        seed_kdc_from_users(store, users.iter(), &fresh_groups, true);
    }
    // Reconcile deletions (B4b): the DB is the truth after apply removed any tombstoned
    // object, so drop from the live directory any runtime user/group the DB no longer
    // holds, and revoke each removed user from the KDC so it can no longer get a TGT.
    let keep_users: std::collections::HashSet<String> =
        users.iter().map(|u| u.sam_account_name.clone()).collect();
    for removed in directory.retain_runtime_users(&keep_users) {
        if let Some(store) = kdc {
            store.remove_dynamic_principal(&removed);
        }
    }
    let keep_groups: std::collections::HashSet<u32> =
        fresh.all_groups().iter().map(|g| g.rid).collect();
    directory.retain_runtime_groups(&keep_groups);

    for user in users {
        directory.upsert_runtime_user(user);
    }
    for group in fresh.all_groups() {
        directory.upsert_runtime_group(group);
    }
    Ok(())
}

/// A cheap change signature over the served SYSVOL files (paths + bytes): any
/// add, delete or content change moves it, so a DC can tell whether the store
/// changed without diffing trees.
fn sysvol_signature(files: &[(String, Vec<u8>)]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    files.len().hash(&mut hasher);
    for (path, content) in files {
        path.hash(&mut hasher);
        content.hash(&mut hasher);
    }
    hasher.finish()
}

/// Rebuild the served SYSVOL tree from the store and swap it in (via
/// [`magnetite_smb::set_sysvol`]) only when its contents changed since `last_sig`.
/// Called on a timer so a peer's replicated SYSVOL changes (pulled into the
/// shared store) are served without a restart — the live half of the
/// DFS-R-equivalent. Returns the current signature.
async fn refresh_served_sysvol(
    db: &Db,
    base_dn: &str,
    last_sig: Option<u64>,
) -> anyhow::Result<u64> {
    let files = db.list_sysvol_files().await?;
    let sig = sysvol_signature(&files);
    if last_sig != Some(sig) {
        let count = files.len();
        magnetite_smb::set_sysvol(magnetite_smb::Vfs::from_files(files));
        // The NETLOGON share (logon scripts) is the `scripts` subtree of SYSVOL, so a
        // script change bumps the same signature — re-serve both together.
        let netlogon = db.netlogon_files(base_dn).await.unwrap_or_default();
        let scripts = netlogon.len();
        magnetite_smb::set_netlogon(magnetite_smb::Vfs::from_files(netlogon));
        tracing::info!(
            "SYSVOL served from replicated store ({count} file(s), {scripts} logon script(s))"
        );
    }
    Ok(sig)
}

/// Exponential backoff for the `failures`-th consecutive failure (1-based): `base`
/// doubled each time, capped at `max`. `failures == 0` yields `base` (unused — callers
/// only back off after a failure).
fn failure_backoff(
    failures: u32,
    base: std::time::Duration,
    max: std::time::Duration,
) -> std::time::Duration {
    let shift = failures.saturating_sub(1).min(16);
    base.saturating_mul(1u32 << shift).min(max)
}

/// Launch [`run_replication_agent`] as a background OS thread — the way a multi-thread
/// server hosts it despite the agent future being `!Send`. The thread runs its own
/// current-thread Tokio runtime and a [`LocalSet`](tokio::task::LocalSet), so the
/// non-`Send` Kerberos ticket path is legal there. Signal `shutdown` and `.join()` the
/// returned handle to stop it.
///
/// `db` and `cfg` are `Send`, so moving them into the thread is fine; only the *future*
/// is `!Send`, which the dedicated current-thread runtime accommodates.
pub fn spawn_replication_thread(
    cfg: ReplicationConfig,
    db: Db,
    shutdown: watch::Receiver<bool>,
    live_directory: Option<Arc<Directory>>,
    kdc: Option<Arc<PrincipalStore>>,
    health: Option<ReplHealthRegistry>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("repl-agent".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!(error = %e, "replication agent: failed to build runtime");
                    return;
                }
            };
            let local = tokio::task::LocalSet::new();
            local.block_on(
                &rt,
                run_replication_agent(cfg, db, shutdown, live_directory, kdc, health),
            );
        })
        .expect("spawn replication agent thread")
}

/// Seed the KDC from `directory` and spawn the KDC, SMB, RPC/SAMR and DRSUAPI
/// servers, returning the [`JoinSet`] of their tasks. The `cifs`/`host` service
/// keys are derived from the SAME secrets the KDC holds, so tickets it issues
/// verify at the SMB and DRSUAPI endpoints.
///
/// `drs_key` overrides the DRSUAPI acceptor key: when magnetite serves outbound
/// replication as a replica INSIDE a foreign domain, a peer (e.g. Samba) obtains a
/// DRS ticket from *that* domain's KDC, encrypted with the machine-account key the
/// domain holds for magnetite — so the endpoint must verify with that key, not the
/// locally derived `host` key. `None` keeps the self-domain `host/magnetite` key.
///
/// # Errors
/// Propagates principal-registration and key-derivation failures.
#[allow(clippy::too_many_arguments)]
pub fn spawn_servers(
    directory: Arc<Directory>,
    realm: &str,
    dc_label: &str,
    addrs: AddcAddrs,
    account_store: Option<Arc<dyn AccountStore>>,
    rid_allocator: Option<Arc<dyn RidAllocator>>,
    drs_invocation_id: Option<[u8; 16]>,
    dc_ipv4: [u8; 4],
    drs_key: Option<Vec<u8>>,
    is_rid_master: bool,
) -> anyhow::Result<(JoinSet<anyhow::Result<()>>, Arc<PrincipalStore>)> {
    // Wire the durable RID allocator into the directory so the DRSUAPI RID master serves
    // pools (EXOP_FSMO_RID_ALLOC) from the SAME persistent counter that mints local
    // accounts — served pools and local RIDs never overlap and both survive restarts.
    if let Some(a) = &rid_allocator {
        directory.set_rid_source(a.clone());
    }
    // Seed the KDC: the directory users' long-term keys + the service principals. A
    // machine account (`HOST$`) is registered under its `host/`/`cifs/` SPN aliases too
    // (all sharing its stored AD-computer-account key), so a joined member's logon
    // TGS-REQ for `host/<fqdn>` resolves after a restart WITHOUT a re-join.
    let mut store = PrincipalStore::new(realm);
    // The real domain SID + per-user group memberships feed the KDC's PAC so a logon
    // ticket carries the user's own SID and group SIDs (not a fixed identity).
    store.set_domain_sid(directory.domain_sid().to_vec());
    let groups_snapshot = directory.all_groups();
    for user in directory.users() {
        // A disabled account (userAccountControl ACCOUNTDISABLE) must not authenticate,
        // so its key is never seeded into the KDC (B4a).
        if user.disabled {
            continue;
        }
        let sam = user.sam_account_name.as_str();
        if sam.ends_with('$') {
            store.register_machine_key(sam, user.kerberos_key.clone());
        } else {
            store.add_user_principal(
                sam,
                user.kerberos_key.clone(),
                user.rid,
                DOMAIN_USERS_RID,
                user_group_rids(&groups_snapshot, user.rid),
            );
        }
    }
    store.add_password_principal(&["krbtgt", realm], krbtgt_secret())?;
    store.add_password_principal(&["cifs", "magnetite"], cifs_secret())?;
    // The `host/magnetite` SPN backs Kerberos-authenticated RPC (DRSUAPI DCSync).
    store.add_password_principal(&["host", "magnetite"], host_secret())?;
    // The `kadmin/changepw` SPN backs the kpasswd (RFC 3244) password-change service.
    store.add_password_principal(&["kadmin", "changepw"], kadmin_secret())?;
    // Constrained delegation (MS-SFU): `host/magnetite` may S4U2Proxy to
    // `cifs/magnetite` on a user's behalf.
    store.allow_delegation(&["host", "magnetite"], &["cifs", "magnetite"]);
    // Optional S4U delegation demo principal — seeded ONLY when `WEBSERVICE_SECRET`
    // is set, so a production domain carries no known-password service account. The
    // impacket S4U demo sets it: `getST.py -impersonate <user> -spn cifs/magnetite
    // '<realm>/webservice:<WEBSERVICE_SECRET>'`.
    if let Ok(ws) = std::env::var("WEBSERVICE_SECRET") {
        if !ws.trim().is_empty() {
            store.add_password_principal(&["webservice"], &ws)?;
            store.allow_delegation(&["webservice"], &["cifs", "magnetite"]);
        }
    }

    // The SMB `cifs` service key = the SAME principal key the KDC issues against.
    let cifs_service = ["cifs".to_string(), "magnetite".to_string()];
    let cifs_vec = derive_aes256_key(cifs_secret(), &default_salt(realm, &cifs_service))?;
    let mut cifs_key = [0u8; 32];
    cifs_key.copy_from_slice(&cifs_vec);

    // The `host` service key for the Kerberos-authenticated DRSUAPI endpoint.
    let host_service = ["host".to_string(), "magnetite".to_string()];
    let host_key = derive_aes256_key(host_secret(), &default_salt(realm, &host_service))?;

    // The `kadmin/changepw` service key the kpasswd server verifies AP-REQs with —
    // the same key the KDC issues that service's tickets against.
    let changepw_service = ["kadmin".to_string(), "changepw".to_string()];
    let changepw_key = derive_aes256_key(kadmin_secret(), &default_salt(realm, &changepw_service))?;

    // FQDN-based SPN aliases (`cifs`/`ldap`/`host` per the DC's DNS name), keyed
    // with the SAME service key as the single-label SPN so a real domain-join
    // client — which derives SPNs from the DC's FQDN, e.g. `cifs/<dc>.<dom>` — gets
    // a ticket the corresponding service (SMB, LDAP GSSAPI, RPC) can verify. The host
    // label is `dc_label` (per-DC); the single-label `cifs/magnetite` alias above
    // stays a fixed realm-wide PoC alias shared by every DC.
    let dc_fqdn = format!("{dc_label}.{}", realm.to_lowercase());
    store.add_key_principal(&["cifs", dc_fqdn.as_str()], cifs_vec.clone());
    store.add_key_principal(&["ldap", dc_fqdn.as_str()], cifs_vec.clone());
    store.add_key_principal(&["host", dc_fqdn.as_str()], host_key.clone());
    // `DNS/<fqdn>` backs GSS-TSIG dynamic DNS updates (RFC 3645) — a domain member
    // gets a ticket for it, negotiates a TKEY context, then updates its records.
    let dns_service = ["dns".to_string(), "magnetite".to_string()];
    let dns_key = derive_aes256_key(dns_secret(), &default_salt(realm, &dns_service))?;
    store.add_key_principal(&["dns", dc_fqdn.as_str()], dns_key);

    let mut set = JoinSet::new();

    // The principal store is shared (Arc) between the KDC and the SAMR interface, so
    // a machine account SAMR creates is registered with the KDC and can authenticate.
    let store = Arc::new(store);
    let kdc = KdcServer::new(store.clone());
    let kdc_addr = addrs.kdc;
    set.spawn(async move {
        kdc.run(kdc_addr).await?;
        anyhow::Ok(())
    });

    let smb_pipes = pipe_registry(
        directory.clone(),
        store.clone(),
        account_store.clone(),
        rid_allocator.clone(),
    );
    let smb_addr = addrs.smb;
    // NT-hash lookup so the SMB server can verify a Windows client's NTLMv2
    // session-setup (it falls back to NTLM when it can't get a Kerberos ticket for
    // the new realm), keying + signing the session the client then requires.
    let nt_hash_lookup: magnetite_smb::NtHashLookup = {
        let dir = directory.clone();
        Arc::new(move |user: &str| {
            dir.users()
                .iter()
                .find(|u| u.sam_account_name.eq_ignore_ascii_case(user))
                .map(|u| u.nt_hash)
        })
    };
    set.spawn(async move {
        magnetite_smb::serve_with_kerberos_and_pipes(
            smb_addr,
            cifs_key,
            smb_pipes,
            Some(nt_hash_lookup),
        )
        .await?;
        anyhow::Ok(())
    });

    // SAMR accepts NTLM-authenticated binds so a join client can set a machine
    // password (SamrSetInformationUser2 needs the session key); unauthenticated
    // reads (enumeration) still work. The bind authenticates as `alice`.
    let samr_dir = directory.clone();
    let samr_store = store.clone();
    let admin_nt_hash = directory
        .users()
        .iter()
        .find(|u| u.sam_account_name == "alice")
        .map(|u| u.nt_hash)
        .unwrap_or_default();
    let rpc_addr = addrs.rpc;
    set.spawn(async move {
        let mut samr = SamrInterface::new_with_kdc(samr_dir, samr_store);
        if let Some(store) = account_store {
            samr = samr.with_account_store(store);
        }
        if let Some(a) = rid_allocator {
            samr = samr.with_rid_allocator(a);
        }
        magnetite_rpc::server::serve_with_ntlm(rpc_addr, Arc::new(samr), admin_nt_hash).await?;
        anyhow::Ok(())
    });

    // DRSUAPI accepts Kerberos (SPNEGO/GSS) binds: the acceptor subkey signs the
    // PDUs (GSS MIC) and encrypts the DCSync secret. In self-domain mode the acceptor
    // key is the local `host/magnetite` key; when replicating as a replica inside a
    // foreign domain, `drs_key` supplies the machine-account key that domain holds.
    let drs_dir = directory;
    let drs_addr = addrs.drs;
    let drs_acceptor_key = drs_key.unwrap_or(host_key);
    set.spawn(async move {
        let mut drs = DrsuapiInterface::new(drs_dir).with_rid_master(is_rid_master);
        if let Some(id) = drs_invocation_id {
            drs = drs.with_invocation_id(id);
        }
        magnetite_rpc::server::serve_with_kerberos(drs_addr, Arc::new(drs), drs_acceptor_key)
            .await?;
        anyhow::Ok(())
    });

    // kpasswd (RFC 3244) on :464 — a client (or joined machine) changes its own
    // password; the new key lands in the shared store and the KDC issues from it.
    let kpasswd_store = store.clone();
    let kpasswd_addr = addrs.kpasswd;
    set.spawn(async move {
        magnetite_krb5::serve_kpasswd(kpasswd_addr, kpasswd_store, changepw_key).await?;
        anyhow::Ok(())
    });

    // Endpoint Mapper on :135 — a Windows client resolves the RPC services' dynamic
    // ports here before connecting (SAMR/DRSUAPI over ncacn_ip_tcp).
    let epm = magnetite_rpc::EpmInterface::new(
        vec![
            magnetite_rpc::Registration {
                uuid: DRSUAPI_UUID,
                major_version: 4,
                port: addrs.drs.port(),
            },
            magnetite_rpc::Registration {
                uuid: SAMR_UUID,
                major_version: 1,
                port: addrs.rpc.port(),
            },
        ],
        dc_ipv4,
    );
    let epm_addr = addrs.epm;
    set.spawn(async move {
        magnetite_rpc::server::serve(epm_addr, Arc::new(epm)).await?;
        anyhow::Ok(())
    });

    // SNTP on :123 — the DC serves time so members stay within the Kerberos skew.
    let sntp_addr = addrs.sntp;
    set.spawn(async move {
        sntp::serve_sntp(sntp_addr).await?;
        anyhow::Ok(())
    });

    // Hand the shared KDC store back so the caller can register machine accounts
    // created over LDAP (a domain join's `computer` Add) with the live KDC.
    Ok((set, store))
}

/// A handle to the KDC principal store that becomes available once the AD DC
/// servers start. Shared (via `Arc<OnceLock>`) between [`AddcService`] — which
/// fills it in on start — and a [`KdcMachineRegistrar`] that reads it, so the
/// separately-constructed embedded LDAP server can register machine accounts with
/// the live KDC even though it is built before the DC starts.
type KdcHandle = Arc<OnceLock<Arc<PrincipalStore>>>;

/// A handle to the DC's [`Directory`], published once the DC starts. Lets the
/// separately-built embedded LDAP server verify an NTLM SASL bind against a user's
/// NT hash (a Windows join with no Kerberos ticket) even though the LDAP server is
/// constructed before the directory is loaded.
type DirectoryHandle = Arc<OnceLock<Arc<Directory>>>;

/// Registers a machine account with the live KDC (and persists it to the database)
/// when a `computer` object is added over LDAP — the write half of a domain join.
/// Encode an account/group `objectSid` (hex, little-endian) from the domain
/// sub-authorities + `rid` — `S-1-5-<sub…>-<rid>`, the RID last so it is recovered as the
/// last LE u32 (matching [`build_directory_from_db`]).
fn object_sid_hex(domain_sub: &[u32], rid: u32) -> String {
    let count = u8::try_from(domain_sub.len() + 1).unwrap_or(5);
    let mut sid: Vec<u8> = vec![0x01, count, 0, 0, 0, 0, 0, 0x05]; // rev, count, NT authority(5)
    for s in domain_sub {
        sid.extend_from_slice(&s.to_le_bytes());
    }
    sid.extend_from_slice(&rid.to_le_bytes());
    sid.iter().map(|b| format!("{b:02x}")).collect()
}

/// Implements [`magnetite_ldap::MachineKeyRegistrar`] so the embedded LDAP server
/// can register machines without depending on the KDC crate directly.
struct KdcMachineRegistrar {
    kdc: KdcHandle,
    db: Option<Db>,
    realm: String,
}

impl magnetite_ldap::MachineKeyRegistrar for KdcMachineRegistrar {
    fn register_machine(&self, sam_account_name: &str, password: &str) {
        // Live registration (derive the machine's Kerberos key so it can `kinit`)
        // when the KDC is up. Before it starts, fall through to DB persistence — the
        // KDC rebuilds its store from the database at startup, so the account is
        // still recovered (just not until the next start).
        match self.kdc.get() {
            Some(kdc) => {
                if let Err(e) = kdc.register_machine(&[sam_account_name], password) {
                    tracing::warn!(
                        "addc: KDC machine registration failed for {sam_account_name}: {e}"
                    );
                    return;
                }
            }
            None => tracing::warn!(
                "addc: KDC not started yet; machine {sam_account_name} persisted to DB only"
            ),
        }
        // Persist the key material so the account survives a restart. The trait
        // method is synchronous; hop onto the runtime to run the async upsert.
        if let Some(db) = &self.db {
            let db = db.clone();
            let realm = self.realm.clone();
            let sam = sam_account_name.to_string();
            let pw = password.to_string();
            tokio::spawn(async move {
                if let Err(e) = db.upsert_ad_principal(&sam, 0, &pw, &realm).await {
                    tracing::warn!("addc: persisting machine account {sam} failed: {e}");
                }
            });
        }
    }

    fn register_user<'a>(
        &'a self,
        sam_account_name: &'a str,
        password: &'a str,
        rid: Option<u32>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let Some(db) = &self.db else { return };
            // Resolve the RID: explicit (inherit an old domain's SID) → existing → fresh.
            let rid = match rid {
                Some(r) => r,
                None => match db.get_ad_principal(sam_account_name).await {
                    Ok(Some(existing)) => existing.rid,
                    _ => match db.reserve_rid_block(RID_POOL_FIRST, 1).await {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!("addc: RID reserve for user {sam_account_name}: {e}");
                            return;
                        }
                    },
                },
            };
            // No password supplied (e.g. an `ldapsearch` migration LDIF, which cannot
            // carry the cleartext): do NOT derive a credential from the empty password —
            // that would leave a logon-able account with a well-known key. Create it
            // disabled (RID preserved for group membership + later activation) unless it
            // already exists, so an already-provisioned account is never clobbered.
            if password.is_empty() {
                match db.get_ad_principal(sam_account_name).await {
                    Ok(Some(_)) => {}
                    _ => {
                        if let Err(e) = db.create_disabled_ad_principal(sam_account_name, rid).await
                        {
                            tracing::warn!(
                                "addc: creating disabled LDAP user {sam_account_name}: {e}"
                            );
                        }
                    }
                }
                return;
            }
            // Derive the NT hash + Kerberos key from the password (the standard LDAP path;
            // verbatim hash/key import is offered by the Web API). The 20s live refresh
            // then makes the account authenticatable — no restart.
            if let Err(e) = db
                .upsert_ad_principal(sam_account_name, rid, password, &self.realm)
                .await
            {
                tracing::warn!("addc: provisioning LDAP user {sam_account_name} failed: {e}");
            }
        })
    }

    fn register_group<'a>(
        &'a self,
        sam_account_name: &'a str,
        member_sams: &'a [String],
        rid: Option<u32>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let Some(db) = &self.db else { return };
            let domain_sub = db
                .get_domain_sid()
                .await
                .ok()
                .flatten()
                .unwrap_or_else(|| vec![21, 1, 2, 3]);
            let rid = match rid {
                Some(r) => r,
                None => match db.get_ad_group(sam_account_name).await {
                    Ok(Some(existing)) => existing.rid,
                    _ => match db.reserve_rid_block(RID_POOL_FIRST, 1).await {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!("addc: RID reserve for group {sam_account_name}: {e}");
                            return;
                        }
                    },
                },
            };
            let group_sid = object_sid_hex(&domain_sub, rid);
            if let Err(e) = db
                .upsert_ad_group(sam_account_name, rid, &group_sid, &[])
                .await
            {
                tracing::warn!("addc: provisioning LDAP group {sam_account_name} failed: {e}");
                return;
            }
            // Link each member (user via ad_principal, nested group via ad_group). A
            // member with no provisioned AD identity is skipped (the PAC would drop it).
            for m in member_sams {
                let member_sid = match db.get_ad_principal(m).await {
                    Ok(Some(u)) => Some(object_sid_hex(&domain_sub, u.rid)),
                    _ => match db.get_ad_group(m).await {
                        Ok(Some(g)) => Some(g.sid),
                        _ => None,
                    },
                };
                if let Some(msid) = member_sid {
                    if let Err(e) = db.set_group_member_local(&group_sid, &msid, true).await {
                        tracing::warn!("addc: linking {m} into group {sam_account_name}: {e}");
                    }
                }
            }
        })
    }
}

/// Build a [`MachineKeyRegistrar`](magnetite_ldap::MachineKeyRegistrar) bound to an
/// already-running `kdc` store (the standalone `magnetite-addc` binary, where the
/// store is in hand). Attach it via
/// [`LdapService::with_machine_registrar`](magnetite_ldap::LdapService::with_machine_registrar).
#[must_use]
pub fn machine_key_registrar(
    kdc: Arc<PrincipalStore>,
    db: Option<Db>,
    realm: &str,
) -> Arc<dyn magnetite_ldap::MachineKeyRegistrar> {
    let handle: KdcHandle = Arc::new(OnceLock::new());
    let _ = handle.set(kdc);
    Arc::new(KdcMachineRegistrar {
        kdc: handle,
        db,
        realm: realm.to_string(),
    })
}

// Health states, stored in an `AtomicU8` (mirrors the other embedded services).
const H_STARTING: u8 = 0;
const H_HEALTHY: u8 = 1;
const H_ERROR: u8 = 2;

/// The embedded AD domain controller: an [`EmbeddedService`] that runs the KDC,
/// SMB, RPC/SAMR and DRSUAPI servers in-process, sourcing principals from the
/// shared database.
pub struct AddcService {
    realm: String,
    /// This DC's computer label (lowercase DNS host label); see [`dc_label`].
    dc_label: String,
    addrs: AddcAddrs,
    dc_ipv4: String,
    health: Arc<AtomicU8>,
    /// The KDC store, published once the DC servers start. Lets the separately
    /// built embedded LDAP server register machine accounts with the live KDC.
    kdc: KdcHandle,
    /// The directory, published once the DC starts — the source for the embedded
    /// LDAP server's NTLM-SASL NT-hash lookup.
    directory: DirectoryHandle,
}

impl AddcService {
    /// A [`MachineKeyRegistrar`](magnetite_ldap::MachineKeyRegistrar) that registers
    /// LDAP-created machine accounts with this service's KDC (available once it has
    /// started) and persists them to `db`. Attach it to the embedded LDAP server so
    /// a domain join's `computer` Add reaches the live KDC.
    #[must_use]
    pub fn machine_registrar(&self, db: Db) -> Arc<dyn magnetite_ldap::MachineKeyRegistrar> {
        Arc::new(KdcMachineRegistrar {
            kdc: self.kdc.clone(),
            db: Some(db),
            realm: self.realm.clone(),
        })
    }

    /// Construct the service from its [`AddcConfig`] (realm + listen sockets +
    /// DC-locator IP, each falling back to its well-known default).
    pub fn new(cfg: &AddcConfig) -> Self {
        Self {
            realm: cfg
                .realm
                .clone()
                .unwrap_or_else(|| DEFAULT_REALM.to_string()),
            dc_label: dc_label(cfg.dc_name.as_deref()),
            addrs: AddcAddrs::from_config(cfg),
            dc_ipv4: cfg
                .dc_ipv4
                .clone()
                .unwrap_or_else(|| "127.0.0.1".to_string()),
            health: Arc::new(AtomicU8::new(H_STARTING)),
            kdc: Arc::new(OnceLock::new()),
            directory: Arc::new(OnceLock::new()),
        }
    }

    /// An [`NtHashLookup`](magnetite_smb::NtHashLookup) that resolves a user's NT
    /// hash from this service's directory (published once the DC starts) so the
    /// embedded LDAP server can verify an NTLM GSS-SPNEGO SASL bind — a Windows join
    /// that couldn't obtain a Kerberos ticket. Returns `None` before the directory
    /// is loaded or for an unknown account.
    #[must_use]
    pub fn nt_hash_lookup(&self) -> magnetite_smb::NtHashLookup {
        let directory = self.directory.clone();
        Arc::new(move |user: &str| {
            directory.get().and_then(|dir| {
                dir.users()
                    .iter()
                    .find(|u| u.sam_account_name.eq_ignore_ascii_case(user))
                    .map(|u| u.nt_hash)
            })
        })
    }

    /// The resolved listen sockets.
    pub fn addrs(&self) -> AddcAddrs {
        self.addrs
    }

    /// The Kerberos realm.
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// This DC's computer label (lowercase DNS host label). Pass it to the embedded
    /// LDAP server ([`with_dc_label`](magnetite_ldap::LdapService::with_dc_label)) so
    /// its RootDSE `serverName`/`dsServiceName` match this DC's CLDAP/DNS identity.
    pub fn dc_label(&self) -> &str {
        &self.dc_label
    }
}

impl EmbeddedService for AddcService {
    fn domain(&self) -> DomainKey {
        DomainKey::Addc
    }

    fn health(&self) -> ServiceHealth {
        match self.health.load(Ordering::Relaxed) {
            H_HEALTHY => ServiceHealth::Healthy,
            H_ERROR => ServiceHealth::Error,
            _ => ServiceHealth::Unknown,
        }
    }

    fn start(&self, db: Db, mut shutdown: watch::Receiver<bool>) {
        let realm = self.realm.clone();
        let dc_label = self.dc_label.clone();
        let addrs = self.addrs;
        let dc_ipv4 = self.dc_ipv4.clone();
        let health = self.health.clone();
        let kdc_handle = self.kdc.clone();
        let directory_handle = self.directory.clone();
        magnetite_db::spawn_health_guarded("addc", health.clone(), H_ERROR, async move {
            // Source the directory from the shared database (seed on first run).
            let directory = match build_directory_from_db(&db, &realm).await {
                Ok(dir) => Arc::new(dir),
                Err(e) => {
                    tracing::error!("AD DC directory build failed: {e}");
                    health.store(H_ERROR, Ordering::Relaxed);
                    return;
                }
            };
            // Publish the directory so the embedded LDAP server's NTLM-SASL NT-hash
            // lookup can resolve accounts (a join binds LDAP with NTLM when it has no
            // Kerberos ticket).
            tracing::info!(
                "AD DC directory loaded {} account(s): {}",
                directory.users().len(),
                directory
                    .users()
                    .iter()
                    .map(|u| u.sam_account_name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let _ = directory_handle.set(directory.clone());
            addc_log(
                &db,
                magnetite_core::models::common::LogLevel::Info,
                format!(
                    "AD DC 起動: realm {realm}, {} アカウント (KDC {}, SMB {}, RPC {}, DRS {})",
                    directory.users().len(),
                    addrs.kdc,
                    addrs.smb,
                    addrs.rpc,
                    addrs.drs
                ),
            )
            .await;

            // Publish the DC-locator DNS records (SRV/A) so a Windows client can
            // find the DC via magnetite-dns. The DNS domain is the lowercased realm.
            let dns_domain = realm.to_lowercase();
            if let Err(e) = db.seed_dc_locator(&dns_domain, &dc_label, &dc_ipv4).await {
                tracing::warn!("AD DC DNS locator seeding failed: {e}");
            }
            // The CLDAP netlogon-ping responder answers Windows DC-discovery pings.
            let cldap_info = cldap::domain_info(&directory, &dc_label);
            // Persist SAMR-created accounts to the shared database.
            let account_store = Some(db_account_store(db.clone(), &realm));
            // DB-atomic RID allocation: seed the pool above every pre-existing
            // account's RID, so a runtime join gets a RID that persists across restarts
            // and never collides across DC front-ends sharing one store.
            let rid_allocator =
                Some(spawn_rid_allocator(db.clone(), rid_pool_seed(&directory)).await);
            // This DC's persistent DRS replication identity (stable across restarts),
            // so a replication partner never sees a USN rollback (Tier C C0).
            let drs_invocation_id = match db.dsa_invocation_id().await {
                Ok(id) => Some(id),
                Err(e) => {
                    tracing::warn!("AD DC DSA invocation-id resolution failed: {e}");
                    None
                }
            };
            // SYSVOL (Group Policy) serving from the replicated store: seed the
            // baseline Default Domain Policy on first run, then serve the tree the
            // store holds — which SYSVOL replication (the DFS-R-equivalent feed)
            // keeps in sync across DCs. Re-checked on a timer below so a peer's
            // pulled changes are served without a restart.
            if let Err(e) = db
                .seed_sysvol_files(&magnetite_smb::default_sysvol_files())
                .await
            {
                tracing::warn!("SYSVOL store seeding failed: {e}");
            }
            let sysvol_base_dn = format!("dc={}", realm.to_lowercase().replace('.', ",dc="));
            let mut sysvol_sig = match refresh_served_sysvol(&db, &sysvol_base_dn, None).await {
                Ok(sig) => Some(sig),
                Err(e) => {
                    tracing::warn!("SYSVOL store read failed, serving default: {e}");
                    None
                }
            };

            // Keep an Arc to the directory for the periodic live refresh below (the
            // runtime sets are shared across clones, so refreshing this copy reaches
            // the interfaces' copies too).
            let directory_for_refresh = directory.clone();
            // Publish the KDC store so the separately-built embedded LDAP server's
            // machine registrar can register domain-join `computer` adds with the
            // live KDC (see `AddcService::machine_registrar`).
            let (mut servers, kdc) = match spawn_servers(
                directory,
                &realm,
                &dc_label,
                addrs,
                account_store,
                rid_allocator,
                drs_invocation_id,
                parse_ipv4(&dc_ipv4),
                None, // self-domain: DRSUAPI verifies with the local host/magnetite key
                true, // embedded single-DC: this node is the RID master
            ) {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::error!("AD DC server startup failed: {e}");
                    health.store(H_ERROR, Ordering::Relaxed);
                    return;
                }
            };
            // Keep an Arc to the KDC store for the periodic live refresh below.
            let kdc_for_refresh = kdc.clone();
            // Publish the live KDC store to any waiting machine registrar.
            let _ = kdc_handle.set(kdc);
            let cldap_addr = addrs.cldap;
            servers.spawn(async move {
                cldap::serve_cldap(cldap_addr, cldap_info).await?;
                anyhow::Ok(())
            });
            health.store(H_HEALTHY, Ordering::Relaxed);
            tracing::info!(
                "Embedded AD DC up: realm={realm} KDC={} SMB={} RPC/SAMR={} DRSUAPI={}",
                addrs.kdc,
                addrs.smb,
                addrs.rpc,
                addrs.drs
            );

            // Poll the SYSVOL store so replicated Group Policy changes are re-served
            // live (delay the first tick so it doesn't fire right after the startup
            // load above).
            const SYSVOL_REFRESH_SECS: u64 = 30;
            let refresh_period = std::time::Duration::from_secs(SYSVOL_REFRESH_SECS);
            let mut sysvol_tick = tokio::time::interval_at(
                tokio::time::Instant::now() + refresh_period,
                refresh_period,
            );

            // Periodically rebuild the directory + KDC store from the DB so accounts
            // provisioned out-of-band (a Web CreateUser writing `ad_principal`, not just
            // a replication apply) become authenticatable without a DC restart.
            const DIR_REFRESH_SECS: u64 = 20;
            let dir_period = std::time::Duration::from_secs(DIR_REFRESH_SECS);
            let mut dir_tick =
                tokio::time::interval_at(tokio::time::Instant::now() + dir_period, dir_period);

            // Serve until shutdown. An individual server task may exit — most often
            // a bind failure on a port another process on the host already holds
            // (e.g. Windows W32Time on 123, or SMB on 445). Log it and keep the rest
            // of the DC running; a single contended port must not take down the whole
            // domain controller. Only when *every* server has exited is the DC down.
            loop {
                tokio::select! {
                    _ = shutdown.changed() => {
                        tracing::info!("AD DC shutting down");
                        break;
                    }
                    _ = sysvol_tick.tick() => {
                        match refresh_served_sysvol(&db, &sysvol_base_dn, sysvol_sig).await {
                            Ok(sig) => sysvol_sig = Some(sig),
                            Err(e) => tracing::debug!("SYSVOL refresh check failed: {e}"),
                        }
                    }
                    _ = dir_tick.tick() => {
                        if let Err(e) = refresh_live_directory(
                            &directory_for_refresh, &db, &realm, Some(&kdc_for_refresh),
                        ).await {
                            tracing::debug!("AD DC directory refresh failed: {e}");
                        }
                    }
                    joined = servers.join_next() => {
                        match joined {
                            Some(Ok(Ok(()))) => {
                                tracing::warn!("an AD DC server exited unexpectedly (continuing)");
                            }
                            Some(Ok(Err(e))) => {
                                tracing::error!("an AD DC server failed (continuing): {e}");
                            }
                            Some(Err(e)) => {
                                tracing::error!("an AD DC server task panicked (continuing): {e}");
                            }
                            None => {
                                tracing::error!("all AD DC servers have exited — DC is down");
                                health.store(H_ERROR, Ordering::Relaxed);
                                break;
                            }
                        }
                    }
                }
            }
            servers.shutdown().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repl_peer_health_tracks_success_and_failure() {
        let mut h = ReplPeerHealth::default();
        assert!(!h.is_healthy(), "a never-synced peer is not healthy");
        h.record_success(1000);
        assert!(h.is_healthy());
        assert_eq!(h.last_success_unix, Some(1000));
        assert_eq!(h.total_cycles, 1);

        // A failure marks it unhealthy but keeps the last success time + error.
        h.record_failure("timeout");
        assert!(!h.is_healthy());
        assert_eq!(h.consecutive_failures, 1);
        assert_eq!(h.last_success_unix, Some(1000));
        assert_eq!(h.last_error.as_deref(), Some("timeout"));
        h.record_failure("refused");
        assert_eq!(h.consecutive_failures, 2);
        assert_eq!(h.total_cycles, 3);

        // A later success clears the failure streak and error.
        h.record_success(2000);
        assert!(h.is_healthy());
        assert_eq!(h.consecutive_failures, 0);
        assert_eq!(h.last_error, None);
        assert_eq!(h.last_success_unix, Some(2000));
    }

    #[test]
    fn failure_backoff_doubles_then_caps() {
        let base = std::time::Duration::from_secs(2);
        let max = std::time::Duration::from_secs(300);
        // 1st..Nth consecutive failure doubles the base until it saturates at `max`.
        assert_eq!(
            failure_backoff(1, base, max),
            std::time::Duration::from_secs(2)
        );
        assert_eq!(
            failure_backoff(2, base, max),
            std::time::Duration::from_secs(4)
        );
        assert_eq!(
            failure_backoff(3, base, max),
            std::time::Duration::from_secs(8)
        );
        assert_eq!(
            failure_backoff(8, base, max),
            std::time::Duration::from_secs(256)
        );
        assert_eq!(
            failure_backoff(9, base, max),
            max,
            "caps at max (512 > 300)"
        );
        // A very large failure count stays capped (no overflow/panic in the shift).
        assert_eq!(failure_backoff(1000, base, max), max);
    }

    #[tokio::test]
    async fn sysvol_refresh_detects_store_changes() {
        // The live half of SYSVOL replication: the DC's timer re-serves only when
        // the store changed. Signature moves on content change and on delete.
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        db.upsert_sysvol_file("dom\\GPT.INI", b"v1").await.unwrap();

        let sig1 = refresh_served_sysvol(&db, "dc=dom", None).await.unwrap();
        // Unchanged store → stable signature (no re-serve).
        assert_eq!(
            refresh_served_sysvol(&db, "dc=dom", Some(sig1))
                .await
                .unwrap(),
            sig1
        );
        // A replicated content change moves it → triggers a live re-serve.
        db.upsert_sysvol_file("dom\\GPT.INI", b"v2").await.unwrap();
        let sig2 = refresh_served_sysvol(&db, "dc=dom", Some(sig1))
            .await
            .unwrap();
        assert_ne!(sig1, sig2);
        // A tombstone (drops the file from the served set) also moves it.
        db.delete_sysvol_file("dom\\GPT.INI").await.unwrap();
        let sig3 = refresh_served_sysvol(&db, "dc=dom", Some(sig2))
            .await
            .unwrap();
        assert_ne!(sig2, sig3);
    }

    #[test]
    fn machine_registrar_registers_the_kerberos_key_with_the_kdc() {
        let realm = "EXAMPLE.COM";
        let kdc = Arc::new(PrincipalStore::new(realm));
        // No database: exercise the live-KDC path in isolation (the DB upsert is
        // covered by magnetite-db's `upsert_replaces_key_material_for_an_existing_name`).
        let registrar = machine_key_registrar(kdc.clone(), None, realm);

        let sam = "WIN11PC$";
        let password = "M@chineSecret1";
        registrar.register_machine(sam, password);

        // The KDC now holds the machine's AES256 long-term key, derived exactly as
        // the KDC itself would — so a machine created over LDAP can obtain a TGT.
        let principal = kdc
            .get(&[sam.to_string()])
            .expect("machine account registered with the KDC");
        let expected =
            derive_aes256_key(password, &default_salt(realm, &[sam.to_string()])).unwrap();
        assert_eq!(principal.key.key, expected);
    }

    #[tokio::test]
    async fn ldap_user_without_password_is_provisioned_disabled_not_logon_able() {
        let realm = "EXAMPLE.COM";
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        let kdc = Arc::new(PrincipalStore::new(realm));
        let registrar = machine_key_registrar(kdc, Some(db.clone()), realm);

        // A password-less LDAP add (an `ldapsearch` migration LDIF carries no cleartext)
        // must NOT become a logon-able account with an empty-password-derived key: it is
        // provisioned DISABLED, with its RID preserved for later activation.
        registrar.register_user("bob", "", Some(1234)).await;
        let bob = db
            .get_ad_principal("bob")
            .await
            .unwrap()
            .expect("bob present");
        assert!(bob.disabled, "a password-less LDAP user must be disabled");
        assert!(
            bob.kerberos_key.is_empty(),
            "and carry no usable Kerberos key"
        );
        assert_eq!(bob.rid, 1234, "the supplied objectSid RID is preserved");

        // A user WITH a password is provisioned enabled and log-on-able.
        registrar.register_user("carol", "RealPass123", None).await;
        let carol = db
            .get_ad_principal("carol")
            .await
            .unwrap()
            .expect("carol present");
        assert!(
            !carol.disabled && !carol.kerberos_key.is_empty(),
            "a supplied password provisions a real, enabled credential"
        );
    }

    /// Allocate one RID, tolerating a momentary `None` while a background refill is in
    /// flight (the block boundary case). Fails the test if no RID appears in time.
    async fn alloc_one(allocator: &Arc<dyn RidAllocator>) -> u32 {
        for _ in 0..1000 {
            if let Some(rid) = allocator.allocate() {
                return rid;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        panic!("allocator produced no RID (refill never completed)");
    }

    #[tokio::test]
    async fn replicated_changes_apply_to_the_local_store() {
        use magnetite_rpc::{Directory, DrsuapiInterface, RpcInterface};
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();

        // A source DC with two users (no groups, so the high-water is exactly the two
        // principals); encrypt its secrets under a known session key (as a negotiated RPC
        // bind would), then generate its GetNCChanges reply.
        let mut src = Directory::new("EXAMPLE", "example.com", "EXAMPLE.COM", vec![21, 1, 2, 3]);
        src.add_user("alice", 1000, "password12").unwrap();
        src.add_user("bob", 1001, "bobpass123").unwrap();
        let key = [3u8; 16];
        let reply = DrsuapiInterface::new(Arc::new(src))
            .call_with_session(3, &[], Some(&key)) // 3 = OP_GET_NC_CHANGES
            .unwrap();
        let changes = magnetite_rpc::parse_get_nc_changes_reply(&reply).expect("decode reply");

        // Apply the whole reply to a fresh local store.
        let n = apply_replicated_changes(&db, &changes, &key, "EXAMPLE.COM")
            .await
            .unwrap();
        assert_eq!(n, 2, "both principals applied");

        // alice landed with the replicated (decrypted) NT hash of "password12".
        let ps = db.list_ad_principals().await.unwrap();
        let alice = ps
            .iter()
            .find(|p| p.sam_account_name == "alice")
            .expect("alice replicated");
        assert_eq!(alice.rid, 1000);
        let expected: Vec<u8> = (0..16)
            .map(|i| {
                let h = "1b62018f0d05c737d06402294ce24236";
                u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).unwrap()
            })
            .collect();
        assert_eq!(
            alice.nt_hash, expected,
            "decrypted NT hash matches password12"
        );
        assert!(ps
            .iter()
            .any(|p| p.sam_account_name == "bob" && p.rid == 1001));

        // The source DSA's cursor is now in our up-to-dateness vector.
        let utdv = db.up_to_date_vector().await.unwrap();
        assert!(utdv
            .iter()
            .any(|c| c.dsa == changes.source_invocation_id && c.high_usn == 2));
    }

    #[tokio::test]
    async fn build_directory_carries_replicated_origin_into_outbound() {
        // Tier C item 1: a change replicated in from ANOTHER DSA is stored with its real
        // origin stamp; build_directory_from_db must surface that stamp as the user's
        // `repl_meta`, and the outbound DRS reply must then serve THAT origin — not
        // re-stamp the object as locally originated (which would break convergence).
        use magnetite_rpc::{DrsuapiInterface, RpcInterface};
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();

        let origin_dsa = [0xCDu8; 16];
        let nt = [0x11u8; 16];
        let aes256 = vec![0x22u8; 32];
        let remote = magnetite_db::ReplStamp {
            version: 9,
            originating_time: 1_700_000_000, // Unix seconds, as stored internally
            originating_dsa: origin_dsa,
            originating_usn: 555,
            local_usn: 0,
        };
        db.apply_replicated_principal("remoteuser", 1500, &nt, &aes256, "EXAMPLE.COM", &remote)
            .await
            .unwrap();

        let built = build_directory_from_db(&db, "EXAMPLE.COM").await.unwrap();
        let user = built
            .users()
            .iter()
            .find(|u| u.sam_account_name == "remoteuser")
            .expect("replicated user present");
        let meta = user.repl_meta.expect("repl_meta attached from the store");
        assert_eq!(meta.version, 9);
        assert_eq!(meta.originating_dsa, origin_dsa);
        assert_eq!(meta.originating_usn, 555);
        assert_eq!(
            meta.originating_time,
            1_700_000_000 + 11_644_473_600,
            "internal Unix time is converted to the wire DSTIME"
        );

        // The outbound reply serves that origin, not this DC's identity.
        let reply = DrsuapiInterface::new(Arc::new(built))
            .call_with_session(3, &[], Some(&[3u8; 16])) // 3 = OP_GET_NC_CHANGES
            .unwrap();
        let changes = magnetite_rpc::parse_get_nc_changes_reply(&reply).expect("decode reply");
        let obj = changes
            .objects
            .iter()
            .find(|o| o.sam_account_name().as_deref() == Some("remoteuser"))
            .expect("remoteuser served outbound");
        let md = obj.newest_metadata().expect("object metadata");
        assert_eq!(md.version, 9, "real origin version served");
        assert_eq!(md.originating_dsa, origin_dsa, "real origin DSA served");
        assert_ne!(
            md.originating_dsa, changes.source_invocation_id,
            "a replicated-in change is not re-stamped as originated by this DC"
        );
    }

    #[tokio::test]
    async fn local_edit_propagates_as_a_higher_version_outbound() {
        // Tier C item 2 (with item 1): a locally originated edit bumps the version, and
        // build_directory_from_db → outbound serves that climbing version originated by
        // THIS DC — so a peer holding the prior value accepts the update.
        use magnetite_rpc::{DrsuapiInterface, RpcInterface};
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        db.create_ad_principal("carol", 1200, "pw1", "EXAMPLE.COM")
            .await
            .unwrap(); // version 1
        db.upsert_ad_principal("carol", 1200, "N3wPass!", "EXAMPLE.COM")
            .await
            .unwrap(); // local edit → version 2

        let inv = db.dsa_invocation_id().await.unwrap();
        let built = build_directory_from_db(&db, "EXAMPLE.COM").await.unwrap();
        let reply = DrsuapiInterface::new(Arc::new(built))
            .with_invocation_id(inv)
            .call_with_session(3, &[], Some(&[3u8; 16])) // 3 = OP_GET_NC_CHANGES
            .unwrap();
        let changes = magnetite_rpc::parse_get_nc_changes_reply(&reply).expect("decode reply");
        let carol = changes
            .objects
            .iter()
            .find(|o| o.sam_account_name().as_deref() == Some("carol"))
            .expect("carol served outbound");
        let md = carol.newest_metadata().expect("carol metadata");
        assert_eq!(
            md.version, 2,
            "a local edit is served as version 2 outbound"
        );
        assert_eq!(
            md.originating_dsa, inv,
            "the edit is originated by this DC's DSA"
        );
    }

    #[tokio::test]
    async fn outbound_dampens_a_replicated_in_change_the_peer_already_holds() {
        // Tier C item 3 e2e: a change replicated IN from DSA B (its origin preserved by
        // item 1) must NOT be re-served to a peer whose up-to-dateness vector already
        // covers B up to that USN — otherwise A↔B ping-pong. The whole chain: apply →
        // store origin → build_directory → outbound dampening.
        use magnetite_rpc::{DrsuapiInterface, RpcInterface};
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        let origin_dsa = [0xB7u8; 16];
        let remote = magnetite_db::ReplStamp {
            version: 4,
            originating_time: 1_700_000_000,
            originating_dsa: origin_dsa,
            originating_usn: 9,
            local_usn: 0,
        };
        db.apply_replicated_principal(
            "remoteuser",
            1500,
            &[0x11u8; 16],
            &[0x22u8; 32],
            "EXAMPLE.COM",
            &remote,
        )
        .await
        .unwrap();

        let inv = db.dsa_invocation_id().await.unwrap();
        let built = build_directory_from_db(&db, "EXAMPLE.COM").await.unwrap();
        let iface = DrsuapiInterface::new(Arc::new(built)).with_invocation_id(inv);

        // A minimal V8 GetNCChanges request whose UTDV holds DSA B up to USN 9.
        let mut stub = vec![0u8; 120];
        stub[20..24].copy_from_slice(&8u32.to_le_bytes()); // dwInVersion = 8
        stub[28..32].copy_from_slice(&8u32.to_le_bytes()); // union tag = 8
        stub.extend_from_slice(&origin_dsa); // a UTDV cursor: {uuidDsa=B,
        stub.extend_from_slice(&9u64.to_le_bytes()); //          usnHighProp=9}
                                                     // Check remoteuser's presence specifically (build_directory also seeds groups,
                                                     // which are served but not dampened — so assert on the object, not the count).
        let served = |reply: &[u8]| -> bool {
            magnetite_rpc::parse_get_nc_changes_reply(reply)
                .expect("decode reply")
                .objects
                .iter()
                .any(|o| o.sam_account_name().as_deref() == Some("remoteuser"))
        };
        let out = iface
            .call_with_session(3, &stub, Some(&[3u8; 16])) // 3 = OP_GET_NC_CHANGES
            .unwrap();
        assert!(
            !served(&out),
            "the peer already holds this change from B — do not boomerang it"
        );

        // If the peer holds B only up to USN 8 (< 9), the change is genuinely newer → sent.
        stub.truncate(120);
        stub.extend_from_slice(&origin_dsa);
        stub.extend_from_slice(&8u64.to_le_bytes());
        let out2 = iface.call_with_session(3, &stub, Some(&[3u8; 16])).unwrap();
        assert!(
            served(&out2),
            "a change newer than the peer holds from B is served"
        );
    }

    #[tokio::test]
    async fn group_memberships_replicate_end_to_end() {
        // Tier C item 5b e2e: a source group with two members replicates outbound as a
        // group object + present member linked values; applying the reply lands the group
        // AND its memberships in the local store — full magnetite→magnetite group repl.
        use magnetite_rpc::{Directory, DrsuapiInterface, RpcInterface};
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        let mut src = Directory::new("EXAMPLE", "example.com", "EXAMPLE.COM", vec![21, 1, 2, 3]);
        src.add_user("alice", 1000, "password12").unwrap();
        src.add_user("bob", 1001, "bobpass123").unwrap();
        src.add_group_with_members("Engineers", 1200, vec![1000, 1001]);
        let key = [3u8; 16];
        let reply = DrsuapiInterface::new(Arc::new(src))
            .call_with_session(3, &[], Some(&key)) // 3 = OP_GET_NC_CHANGES
            .unwrap();
        let changes = magnetite_rpc::parse_get_nc_changes_reply(&reply).expect("decode reply");
        apply_replicated_changes(&db, &changes, &key, "EXAMPLE.COM")
            .await
            .unwrap();

        let groups = db.list_ad_groups().await.unwrap();
        let eng = groups
            .iter()
            .find(|g| g.sam_account_name == "Engineers")
            .expect("the group replicated");
        // Members are stored as SID hex; recover each member's RID (last sub-authority).
        let member_rids: Vec<u32> = eng
            .member_sids
            .iter()
            .filter_map(|s| {
                let bytes: Vec<u8> = (0..s.len() / 2)
                    .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap_or(0))
                    .collect();
                (bytes.len() >= 4)
                    .then(|| u32::from_le_bytes(bytes[bytes.len() - 4..].try_into().unwrap()))
            })
            .collect();
        assert!(
            member_rids.contains(&1000) && member_rids.contains(&1001),
            "both memberships replicated and applied (got {member_rids:?})"
        );
    }

    #[tokio::test]
    async fn replicated_group_dampens_when_the_peer_already_holds_it() {
        // Tier C item 5c: a group replicated in from DSA B carries B's origin stamp, so
        // outbound it dampens when the peer's UTDV already covers B — no group ping-pong.
        use magnetite_rpc::{DrsuapiInterface, RpcInterface};
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();

        // A source (DSA B) whose group carries a real origin stamp, replicated into us.
        let origin_dsa = [0xC9u8; 16];
        let mut src = Directory::new("EXAMPLE", "example.com", "EXAMPLE.COM", vec![21, 1, 2, 3]);
        src.add_group_with_members("Engineers", 1200, vec![]);
        src.set_group_repl_meta(
            "Engineers",
            magnetite_rpc::ReplMeta {
                version: 3,
                originating_time: 13_350_000_000, // a DSTIME (only DSA/USN matter for dampening)
                originating_dsa: origin_dsa,
                originating_usn: 7,
            },
        );
        let reply = DrsuapiInterface::new(Arc::new(src))
            .with_invocation_id([0x1a; 16])
            .call_with_session(3, &[], Some(&[3u8; 16]))
            .unwrap();
        let changes = magnetite_rpc::parse_get_nc_changes_reply(&reply).expect("decode");
        apply_replicated_changes(&db, &changes, &[3u8; 16], "EXAMPLE.COM")
            .await
            .unwrap();

        // Serve outbound from our store; the group now carries B's origin.
        let inv = db.dsa_invocation_id().await.unwrap();
        let built = build_directory_from_db(&db, "EXAMPLE.COM").await.unwrap();
        let iface = DrsuapiInterface::new(Arc::new(built)).with_invocation_id(inv);

        let served = |reply: &[u8]| -> bool {
            magnetite_rpc::parse_get_nc_changes_reply(reply)
                .unwrap()
                .objects
                .iter()
                .any(|o| o.is_group() && o.sam_account_name().as_deref() == Some("Engineers"))
        };
        // Peer holds B up to USN 7 → the group is dampened.
        let mut stub = vec![0u8; 120];
        stub[20..24].copy_from_slice(&8u32.to_le_bytes());
        stub[28..32].copy_from_slice(&8u32.to_le_bytes());
        stub.extend_from_slice(&origin_dsa);
        stub.extend_from_slice(&7u64.to_le_bytes());
        let out = iface.call_with_session(3, &stub, Some(&[3u8; 16])).unwrap();
        assert!(
            !served(&out),
            "the group is dampened — the peer already holds B's change"
        );

        // Peer holds B only to USN 6 → the group is served.
        stub.truncate(120);
        stub.extend_from_slice(&origin_dsa);
        stub.extend_from_slice(&6u64.to_le_bytes());
        let out2 = iface.call_with_session(3, &stub, Some(&[3u8; 16])).unwrap();
        assert!(served(&out2), "a newer group than the peer holds is served");
    }

    #[tokio::test]
    async fn two_magnetite_nodes_converge_bidirectionally() {
        // Tier C item 7: two magnetite DBs (A, B) with their OWN stores replicate to each
        // other; a change on either side propagates and the two converge — validating
        // items 1-5c together (origin-preserving outbound, version stamps, conflict
        // resolution, group objects + memberships).
        use magnetite_rpc::{DrsuapiInterface, RpcInterface};
        let key = [3u8; 16];
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let a = Db::connect(dir_a.path().join("db")).await.unwrap();
        let b = Db::connect(dir_b.path().join("db")).await.unwrap();

        let sid = |rid: u32| -> String {
            let mut v = vec![1u8, 5, 0, 0, 0, 0, 0, 5];
            for s in [21u32, 1, 2, 3, rid] {
                v.extend_from_slice(&s.to_le_bytes());
            }
            v.iter().map(|x| format!("{x:02x}")).collect()
        };

        // A one-shot full-sync pull: `src` serves its whole directory, `dst` applies it.
        async fn full_sync(src: &Db, dst: &Db, key: &[u8]) {
            let inv = src.dsa_invocation_id().await.unwrap();
            let dir = build_directory_from_db(src, "EXAMPLE.COM").await.unwrap();
            let mut stub = vec![0u8; 120];
            stub[20..24].copy_from_slice(&8u32.to_le_bytes());
            stub[28..32].copy_from_slice(&8u32.to_le_bytes());
            let reply = DrsuapiInterface::new(std::sync::Arc::new(dir))
                .with_invocation_id(inv)
                .call_with_session(3, &stub, Some(key))
                .unwrap();
            let changes = magnetite_rpc::parse_get_nc_changes_reply(&reply).expect("decode");
            apply_replicated_changes(dst, &changes, key, "EXAMPLE.COM")
                .await
                .unwrap();
        }
        async fn names(db: &Db) -> Vec<(String, u32)> {
            let mut n: Vec<(String, u32)> = db
                .list_ad_principals()
                .await
                .unwrap()
                .into_iter()
                .map(|p| (p.sam_account_name, p.rid))
                .collect();
            n.sort();
            n
        }

        // A originates alice + a group Engineers (alice is a member).
        a.create_ad_principal("alice", 1000, "password12", "EXAMPLE.COM")
            .await
            .unwrap();
        a.upsert_ad_group("Engineers", 1200, &sid(1200), &[sid(1000)])
            .await
            .unwrap();

        // A → B: B learns alice, the group, and the membership.
        full_sync(&a, &b, &key).await;
        assert_eq!(
            names(&b).await,
            vec![("alice".to_string(), 1000)],
            "B has A's user"
        );
        let b_groups = b.list_ad_groups().await.unwrap();
        let eng = b_groups
            .iter()
            .find(|g| g.sam_account_name == "Engineers")
            .expect("group replicated");
        assert!(!eng.member_sids.is_empty(), "the membership replicated");

        // B originates bob; B → A propagates it, and A → B is idempotent (no regression).
        b.create_ad_principal("bob", 1001, "bobpass123", "EXAMPLE.COM")
            .await
            .unwrap();
        full_sync(&b, &a, &key).await; // bob → A (alice/group round-trip, conflict-res skips)
        full_sync(&a, &b, &key).await; // back to B (idempotent)

        // Converged: both hold {alice, bob}.
        let expected = vec![("alice".to_string(), 1000), ("bob".to_string(), 1001)];
        assert_eq!(names(&a).await, expected, "A converged to both users");
        assert_eq!(names(&b).await, expected, "B converged to both users");
        // And alice's replicated secret is intact on B (byte-identical NT hash).
        let b_alice = b
            .list_ad_principals()
            .await
            .unwrap()
            .into_iter()
            .find(|p| p.sam_account_name == "alice")
            .unwrap();
        let expected_hash: Vec<u8> = (0..16)
            .map(|i| {
                u8::from_str_radix(&"1b62018f0d05c737d06402294ce24236"[i * 2..i * 2 + 2], 16)
                    .unwrap()
            })
            .collect();
        assert_eq!(
            b_alice.nt_hash, expected_hash,
            "alice's NT hash survived replication"
        );
    }

    #[tokio::test]
    async fn two_nodes_converge_on_member_removal() {
        // Tier C item 5e: a LOCAL member removal on node A (set_group_member_local) turns
        // the link into a stamped tombstone; replicating A→B removes the member on B too —
        // full two-node membership-removal convergence over the wire.
        use magnetite_rpc::{DrsuapiInterface, RpcInterface};
        let key = [3u8; 16];
        let da = tempfile::tempdir().unwrap();
        let dbdir = tempfile::tempdir().unwrap();
        let a = Db::connect(da.path().join("db")).await.unwrap();
        let b = Db::connect(dbdir.path().join("db")).await.unwrap();
        let sid = |rid: u32| -> String {
            let mut v = vec![1u8, 5, 0, 0, 0, 0, 0, 5];
            for s in [21u32, 1, 2, 3, rid] {
                v.extend_from_slice(&s.to_le_bytes());
            }
            v.iter().map(|x| format!("{x:02x}")).collect()
        };
        async fn full_sync(src: &Db, dst: &Db, key: &[u8]) {
            let inv = src.dsa_invocation_id().await.unwrap();
            let dir = build_directory_from_db(src, "EXAMPLE.COM").await.unwrap();
            let mut stub = vec![0u8; 120];
            stub[20..24].copy_from_slice(&8u32.to_le_bytes());
            stub[28..32].copy_from_slice(&8u32.to_le_bytes());
            let reply = DrsuapiInterface::new(std::sync::Arc::new(dir))
                .with_invocation_id(inv)
                .call_with_session(3, &stub, Some(key))
                .unwrap();
            let changes = magnetite_rpc::parse_get_nc_changes_reply(&reply).expect("decode");
            apply_replicated_changes(dst, &changes, key, "EXAMPLE.COM")
                .await
                .unwrap();
        }
        async fn present_members(db: &Db) -> Vec<u32> {
            let g = db
                .list_ad_groups()
                .await
                .unwrap()
                .into_iter()
                .find(|g| g.sam_account_name == "Engineers")
                .unwrap();
            let mut rids: Vec<u32> = g
                .member_sids
                .iter()
                .filter_map(|s| {
                    let by: Vec<u8> = (0..s.len() / 2)
                        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap_or(0))
                        .collect();
                    (by.len() >= 4)
                        .then(|| u32::from_le_bytes(by[by.len() - 4..].try_into().unwrap()))
                })
                .collect();
            rids.sort();
            rids
        }

        a.create_ad_principal("alice", 1000, "password12", "EXAMPLE.COM")
            .await
            .unwrap();
        a.create_ad_principal("bob", 1001, "bobpass123", "EXAMPLE.COM")
            .await
            .unwrap();
        a.upsert_ad_group("Engineers", 1200, &sid(1200), &[sid(1000), sid(1001)])
            .await
            .unwrap();

        full_sync(&a, &b, &key).await;
        assert_eq!(
            present_members(&b).await,
            vec![1000, 1001],
            "B has both members"
        );

        // A removes bob locally; the removal replicates to B.
        a.set_group_member_local(&sid(1200), &sid(1001), false)
            .await
            .unwrap();
        full_sync(&a, &b, &key).await;
        assert_eq!(
            present_members(&b).await,
            vec![1000],
            "bob's removal replicated to B"
        );
        let bg = b
            .list_ad_groups()
            .await
            .unwrap()
            .into_iter()
            .find(|g| g.sam_account_name == "Engineers")
            .unwrap();
        assert!(
            bg.member_links
                .iter()
                .any(|l| l.member_sid == sid(1001) && !l.present),
            "bob remains as an absent tombstone on B"
        );
    }

    #[tokio::test]
    async fn build_directory_serves_replicated_groups_via_samr() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();

        // A group replicated from an upstream DC (as apply_replicated_changes stores it).
        db.upsert_ad_group("Engineering", 1111, "0105deadbeef", &[])
            .await
            .unwrap();
        // A user, so the directory is DB-sourced (not the fixed in-memory fallback).
        db.upsert_ad_principal_with_hash("alice", 1000, "pw", &[0u8; 16], Some(&[]), "EXAMPLE.COM")
            .await
            .unwrap();

        let directory = build_directory_from_db(&db, "EXAMPLE.COM").await.unwrap();
        // SAMR enumerates the replicated group (not just the hardcoded well-known set).
        let g = directory
            .groups()
            .iter()
            .find(|g| g.sam_account_name == "Engineering")
            .expect("replicated group is served");
        assert_eq!(g.rid, 1111);
    }

    #[tokio::test]
    async fn refresh_live_directory_reflects_replicated_data_without_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::connect(tmp.path().join("db")).await.unwrap();
        db.upsert_ad_principal_with_hash(
            "carol",
            1105,
            "pw",
            &[9u8; 16],
            Some(&[7u8; 32]),
            "EXAMPLE.COM",
        )
        .await
        .unwrap();
        db.upsert_ad_group("Eng", 4500, "0105aabbccdd", &[])
            .await
            .unwrap();

        // A live directory a running DC's interfaces would already hold — initially
        // without the just-replicated data.
        let live = Directory::new("EX", "ex.com", "EXAMPLE.COM", vec![21, 1, 2, 3]);
        assert!(live.all_users().is_empty());
        assert!(live.all_groups().is_empty());
        // A running KDC's store — initially it cannot issue carol a ticket (B2).
        let kdc = Arc::new(PrincipalStore::new("EXAMPLE.COM"));
        assert!(kdc.get(&["carol".to_string()]).is_none());

        // The agent's post-cycle refresh pushes the DB's users/groups into the live
        // directory's runtime sets AND registers them in the KDC — visible + able to
        // Kerberos-login without a restart.
        refresh_live_directory(&live, &db, "EXAMPLE.COM", Some(&kdc))
            .await
            .unwrap();
        assert!(live
            .all_users()
            .iter()
            .any(|u| u.sam_account_name == "carol"));
        assert!(live
            .all_groups()
            .iter()
            .any(|g| g.rid == 4500 && g.sam_account_name == "Eng"));
        assert!(matches!(live.resolve_rid(4500), Some((n, _)) if n == "Eng"));
        // B2: carol is now a live KDC principal with her replicated AES256 key.
        let carol = kdc.get(&["carol".to_string()]).expect("carol registered");
        assert_eq!(carol.key.key, vec![7u8; 32]);
    }

    // The only test that mutates the production-secret env vars, so there is no
    // cross-test race on them (env is process-global).
    #[test]
    fn production_secret_guard_flags_defaults_and_passes_when_overridden() {
        // Unset ⇒ every secret is reported missing.
        for (var, _) in PRODUCTION_SECRETS {
            std::env::remove_var(var);
        }
        let missing = missing_production_secrets();
        assert_eq!(missing.len(), PRODUCTION_SECRETS.len());
        assert!(missing.contains(&"KRBTGT_SECRET"));

        // Left at the PoC default ⇒ still reported (not just "set").
        for (var, default) in PRODUCTION_SECRETS {
            std::env::set_var(var, default);
        }
        assert_eq!(missing_production_secrets().len(), PRODUCTION_SECRETS.len());

        // Strong overrides ⇒ none missing.
        for (var, _) in PRODUCTION_SECRETS {
            std::env::set_var(var, "s3cret-Xk92@random-value");
        }
        assert!(missing_production_secrets().is_empty());

        // One still at its default ⇒ exactly that one is reported.
        std::env::set_var("KRBTGT_SECRET", DEFAULT_KRBTGT_SECRET);
        assert_eq!(missing_production_secrets(), vec!["KRBTGT_SECRET"]);

        for (var, _) in PRODUCTION_SECRETS {
            std::env::remove_var(var);
        }
    }

    #[tokio::test]
    async fn disabled_replicated_account_is_not_kdc_registered_and_is_revoked() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::connect(tmp.path().join("db")).await.unwrap();

        // dave arrives ENABLED and is registered in a running KDC (B2).
        let stamp = magnetite_db::ReplStamp {
            version: 1,
            originating_time: 1000,
            originating_dsa: [1u8; 16],
            originating_usn: 10,
            local_usn: 0,
        };
        db.apply_replicated_principal_merged(
            "dave",
            1200,
            &[1u8; 16],
            &[5u8; 32],
            false,
            "EXAMPLE.COM",
            &stamp,
            &stamp,
        )
        .await
        .unwrap();
        let live = Directory::new("EX", "ex.com", "EXAMPLE.COM", vec![21, 1, 2, 3]);
        let kdc = Arc::new(PrincipalStore::new("EXAMPLE.COM"));
        refresh_live_directory(&live, &db, "EXAMPLE.COM", Some(&kdc))
            .await
            .unwrap();
        assert!(
            kdc.get(&["dave".to_string()]).is_some(),
            "enabled dave should be KDC-registered"
        );

        // A later replication disables dave (higher version ⇒ object stamp wins).
        let disable = magnetite_db::ReplStamp {
            version: 2,
            originating_time: 2000,
            originating_dsa: [1u8; 16],
            originating_usn: 20,
            local_usn: 0,
        };
        db.apply_replicated_principal_merged(
            "dave",
            1200,
            &[1u8; 16],
            &[5u8; 32],
            true,
            "EXAMPLE.COM",
            &disable,
            &disable,
        )
        .await
        .unwrap();
        refresh_live_directory(&live, &db, "EXAMPLE.COM", Some(&kdc))
            .await
            .unwrap();
        // B4a: a disabled account must no longer be able to obtain a TGT.
        assert!(
            kdc.get(&["dave".to_string()]).is_none(),
            "disabled dave must be revoked from the KDC"
        );
        // He remains visible in the directory, marked disabled.
        assert!(live
            .all_users()
            .iter()
            .any(|u| u.sam_account_name == "dave" && u.disabled));
    }

    #[tokio::test]
    async fn tombstoned_account_is_reconciled_out_of_directory_and_kdc() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Db::connect(tmp.path().join("db")).await.unwrap();
        let stamp = magnetite_db::ReplStamp {
            version: 1,
            originating_time: 1000,
            originating_dsa: [1u8; 16],
            originating_usn: 10,
            local_usn: 0,
        };
        db.apply_replicated_principal_merged(
            "erin",
            1300,
            &[1u8; 16],
            &[5u8; 32],
            false,
            "EXAMPLE.COM",
            &stamp,
            &stamp,
        )
        .await
        .unwrap();
        let live = Directory::new("EX", "ex.com", "EXAMPLE.COM", vec![21, 1, 2, 3]);
        let kdc = Arc::new(PrincipalStore::new("EXAMPLE.COM"));
        refresh_live_directory(&live, &db, "EXAMPLE.COM", Some(&kdc))
            .await
            .unwrap();
        assert!(live
            .all_users()
            .iter()
            .any(|u| u.sam_account_name == "erin"));
        assert!(kdc.get(&["erin".to_string()]).is_some());

        // A tombstone deletes erin from the store (as apply_replicated_changes does for
        // an isDeleted object, matched by RID). The next refresh must reconcile her out
        // of the live directory AND revoke her from the KDC (B4b).
        assert_eq!(
            db.delete_replicated_principal(1300)
                .await
                .unwrap()
                .as_deref(),
            Some("erin")
        );
        refresh_live_directory(&live, &db, "EXAMPLE.COM", Some(&kdc))
            .await
            .unwrap();
        assert!(
            !live
                .all_users()
                .iter()
                .any(|u| u.sam_account_name == "erin"),
            "a deleted account must vanish from the live directory"
        );
        assert!(
            kdc.get(&["erin".to_string()]).is_none(),
            "a deleted account must be revoked from the KDC"
        );
    }

    #[tokio::test]
    async fn rid_survives_allocator_restart() {
        // A DC "restart" at the allocator layer: a fresh allocator on the SAME store
        // must continue from the persisted pool, never resetting to the floor (the old
        // in-memory counter reset to 1100 every boot — exactly the bug Phase 2 fixes).
        // Cross-*process* file persistence is covered by magnetite-db's
        // `reserve_rid_block_hands_out_disjoint_climbing_blocks`; here we hold one store
        // open because RocksDB keeps a file lock a dropped handle only releases
        // asynchronously, which a second in-process connect would race.
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();

        // Phase 1: seed the pool at 1100 and hand out a few climbing RIDs.
        let allocator = spawn_rid_allocator(db.clone(), 1100).await;
        let mut phase1 = Vec::new();
        for _ in 0..5 {
            phase1.push(alloc_one(&allocator).await);
        }
        assert_eq!(phase1[0], 1100, "pool seeds at the floor");
        assert!(
            phase1.windows(2).all(|w| w[1] == w[0] + 1),
            "climbing: {phase1:?}"
        );
        drop(allocator); // the DC stops.

        // Phase 2: a fresh allocator boots on the same persisted store. Its RID is above
        // every RID phase 1 handed out — the pool did not reset (collision-free).
        let allocator = spawn_rid_allocator(db.clone(), 1100).await;
        let after_restart = alloc_one(&allocator).await;
        let max_phase1 = *phase1.iter().max().unwrap();
        assert!(
            after_restart > max_phase1,
            "RID pool reset across restart: {after_restart} !> {max_phase1}"
        );
    }

    #[tokio::test]
    async fn rid_pools_and_single_rids_share_the_durable_counter() {
        // The durability bridge: a Directory injected with the DB-backed allocator serves
        // RID pools (EXOP_FSMO_RID_ALLOC) from the SAME persistent counter that mints
        // single RIDs, so a served pool and a locally minted RID never overlap.
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        let allocator = spawn_rid_allocator(db.clone(), 1100).await;

        let directory = Directory::default();
        directory.set_rid_source(allocator.clone());

        let mut used: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
        let (b1, c1) = directory.allocate_rid_pool(500).expect("pool 1 granted");
        assert_eq!(c1, 500, "pool is the requested contiguous size");
        for r in b1..b1 + c1 {
            assert!(used.insert(r), "pool 1 RID {r} reused");
        }
        // Interleave single-RID mint (the SAMR path).
        for _ in 0..10 {
            let r = alloc_one(&allocator).await;
            assert!(used.insert(r), "single RID {r} overlaps a served pool");
        }
        let (b2, c2) = directory.allocate_rid_pool(500).expect("pool 2 granted");
        for r in b2..b2 + c2 {
            assert!(used.insert(r), "pool 2 RID {r} reused / overlaps");
        }
        assert_ne!(b1, b2, "successive pools are disjoint");

        // A fresh allocator on the same store (a "restart") keeps climbing — a re-granted
        // pool sits above everything handed out before.
        drop(allocator);
        let allocator2 = spawn_rid_allocator(db.clone(), 1100).await;
        let directory2 = Directory::default();
        directory2.set_rid_source(allocator2);
        let (b3, _) = directory2.allocate_rid_pool(500).expect("pool 3 granted");
        assert!(
            b3 > *used.iter().max().unwrap(),
            "post-restart pool {b3} overlaps earlier RIDs"
        );
    }

    #[tokio::test]
    async fn independent_nodes_get_disjoint_rid_ranges() {
        // Tier C RID safety: distinct NODE_INDEX values give disjoint RID ranges, so two
        // independent stores never mint the same object SID.
        assert_eq!(
            rid_pool_base(0),
            1100,
            "node 0 starts above the well-known RIDs"
        );
        for i in 0..8u32 {
            assert!(
                rid_pool_base(i + 1) > rid_pool_base(i),
                "ranges climb per index"
            );
            assert!(
                rid_pool_base(i + 1) - rid_pool_base(i) >= 1_000_000,
                "each node owns a large ({}) RID range",
                rid_pool_base(i + 1) - rid_pool_base(i)
            );
        }

        // Each node reserving from its own base yields non-overlapping RID blocks.
        let d0 = tempfile::tempdir().unwrap();
        let d1 = tempfile::tempdir().unwrap();
        let n0 = Db::connect(d0.path().join("db")).await.unwrap();
        let n1 = Db::connect(d1.path().join("db")).await.unwrap();
        let r0 = n0.reserve_rid_block(rid_pool_base(0), 256).await.unwrap();
        let r1 = n1.reserve_rid_block(rid_pool_base(1), 256).await.unwrap();
        assert_eq!(r0, rid_pool_base(0));
        assert_eq!(r1, rid_pool_base(1));
        assert!(
            r0 + 256 <= r1,
            "node 0's RIDs are entirely below node 1's range — no SID collision"
        );
    }

    #[tokio::test]
    async fn rid_allocator_refills_across_block_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        let allocator = spawn_rid_allocator(db, 1100).await;

        // Draw well past one block so the background refiller must reserve more; every
        // RID stays distinct and strictly increasing across the boundary.
        let count = (RID_BLOCK as usize) * 2 + 10;
        let mut rids = Vec::with_capacity(count);
        for _ in 0..count {
            rids.push(alloc_one(&allocator).await);
        }
        assert!(
            rids.windows(2).all(|w| w[1] > w[0]),
            "strictly increasing across refills"
        );
        let distinct: std::collections::HashSet<_> = rids.iter().copied().collect();
        assert_eq!(distinct.len(), rids.len(), "no RID handed out twice");
        assert_eq!(rids[0], 1100);
    }
}
