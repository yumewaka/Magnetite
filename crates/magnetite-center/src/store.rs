//! The control plane's own datastore — clusters and the Magnetite servers registered
//! under them, plus the last polled health of each. This is SEPARATE from the managed
//! servers' databases; the center only records inventory + health, never their data.
//!
//! Each row carries its own UUID (`cid`/`sid`) used as the external id, so callers never
//! need to parse SurrealDB record ids.

use crate::failover::RoleIntent;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use surrealdb::engine::any::{self, Any};
use surrealdb::types::{RecordId, SurrealValue};
use surrealdb::Surreal;

const NS: &str = "magnetite_center";
const DB: &str = "main";

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Handle to the control plane's embedded datastore (cheap to clone).
#[derive(Clone)]
pub struct CenterDb {
    inner: Arc<Surreal<Any>>,
}

// ---- Records (internal) ----------------------------------------------------

/// Default consecutive-failure threshold for auto-failover (missed health polls).
const DEFAULT_THRESHOLD: u32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct ClusterRecord {
    id: Option<RecordId>,
    cid: String,
    name: String,
    created_at: String,
    /// P3 auto-failover policy. `#[serde(default)]` so clusters created before P3 load.
    #[serde(default)]
    auto_failover: bool,
    #[serde(default)]
    failure_threshold: u32,
    /// The sid the center currently regards as this cluster's active primary.
    #[serde(default)]
    active_primary: Option<String>,
    /// P4 DNS-failover policy: the service record steered to the active primary on
    /// failover. `#[serde(default)]` so pre-P4 clusters load.
    #[serde(default)]
    dns_zone: Option<String>,
    #[serde(default)]
    dns_name: Option<String>,
    #[serde(default)]
    dns_ttl: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct ServerRecord {
    id: Option<RecordId>,
    sid: String,
    name: String,
    base_url: String,
    /// Shared bearer token for this server's /mgmt API — a secret, never projected.
    token: String,
    /// The `cid` of the cluster this server belongs to, if any.
    cluster_ref: Option<String>,
    /// The server's own stable id, learned from /mgmt/identity on first successful poll.
    server_id: Option<String>,
    last_ok: bool,
    last_seen: Option<String>,
    /// The last /mgmt/health JSON body (as a string), or None if never polled.
    last_health: Option<String>,
    last_error: Option<String>,
    created_at: String,
    /// P3 failover role/state. `#[serde(default)]` so pre-P3 rows load.
    #[serde(default)]
    intent: String,
    #[serde(default)]
    fenced: bool,
    #[serde(default)]
    consecutive_failures: u32,
    /// P4: the IP the cluster's DNS record should point at when THIS server is the active
    /// primary (the client-routable address, which may differ from base_url's host).
    #[serde(default)]
    dns_target: Option<String>,
}

// ---- Public projections (token scrubbed) -----------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Cluster {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub auto_failover: bool,
    pub failure_threshold: u32,
    pub active_primary: Option<String>,
    pub dns_zone: Option<String>,
    pub dns_name: Option<String>,
    pub dns_ttl: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManagedServer {
    pub id: String,
    pub name: String,
    pub base_url: String,
    pub cluster: Option<String>,
    pub server_id: Option<String>,
    pub last_ok: bool,
    pub last_seen: Option<String>,
    pub last_health: Option<serde_json::Value>,
    pub last_error: Option<String>,
    pub intent: String,
    pub fenced: bool,
    pub consecutive_failures: u32,
    pub dns_target: Option<String>,
}

/// A poll target: what the health loop needs to reach a server's /mgmt API.
pub struct PollTarget {
    pub sid: String,
    pub base_url: String,
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct FailoverEventRecord {
    id: Option<RecordId>,
    eid: String,
    cluster_ref: Option<String>,
    at: String,
    kind: String,
    message: String,
}

/// A recorded failover action (for the center's event log).
#[derive(Debug, Clone, Serialize)]
pub struct FailoverEvent {
    pub id: String,
    pub cluster: Option<String>,
    pub at: String,
    pub kind: String,
    pub message: String,
}

impl FailoverEventRecord {
    fn into_model(self) -> FailoverEvent {
        FailoverEvent {
            id: self.eid,
            cluster: self.cluster_ref,
            at: self.at,
            kind: self.kind,
            message: self.message,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct LeaseRecord {
    id: Option<RecordId>,
    /// Constant discriminator for the singleton row (`"leader"`).
    slot: String,
    /// The center id currently holding the lease (empty when unheld).
    holder: String,
    /// When the lease expires (RFC3339); a candidate may claim it once past.
    expires_at: String,
    /// Bumped each time leadership changes hands (observability).
    term: u64,
}

/// The control plane's leadership state, as seen by one center instance.
#[derive(Debug, Clone, Serialize)]
pub struct LeaderInfo {
    /// The center id holding the lease (empty when unheld/expired).
    pub holder: String,
    /// Whether the querying instance is the holder.
    pub is_self: bool,
    pub term: u64,
    pub expires_at: String,
}

impl ClusterRecord {
    fn threshold(&self) -> u32 {
        if self.failure_threshold == 0 {
            DEFAULT_THRESHOLD
        } else {
            self.failure_threshold
        }
    }

    fn into_model(self) -> Cluster {
        let failure_threshold = self.threshold();
        Cluster {
            id: self.cid,
            name: self.name,
            created_at: self.created_at,
            auto_failover: self.auto_failover,
            failure_threshold,
            active_primary: self.active_primary,
            dns_zone: self.dns_zone,
            dns_name: self.dns_name,
            dns_ttl: if self.dns_ttl == 0 { 60 } else { self.dns_ttl },
        }
    }
}

impl ServerRecord {
    fn into_model(self) -> ManagedServer {
        ManagedServer {
            id: self.sid,
            name: self.name,
            base_url: self.base_url,
            cluster: self.cluster_ref,
            server_id: self.server_id,
            last_ok: self.last_ok,
            last_seen: self.last_seen,
            last_health: self.last_health.and_then(|s| serde_json::from_str(&s).ok()),
            last_error: self.last_error,
            intent: if self.intent.is_empty() {
                "unset".to_string()
            } else {
                self.intent
            },
            fenced: self.fenced,
            consecutive_failures: self.consecutive_failures,
            dns_target: self.dns_target,
        }
    }
}

impl CenterDb {
    /// Open the embedded control-plane store at `path` (a directory) and ensure the schema.
    /// This is the single-node default; for HA use [`CenterDb::connect_url`] against a
    /// shared SurrealDB so several center instances coordinate through it.
    pub async fn connect(path: &str) -> Result<Self> {
        std::fs::create_dir_all(path)?;
        let abs = std::path::Path::new(path);
        let abs = if abs.is_absolute() {
            abs.to_path_buf()
        } else {
            std::env::current_dir()?.join(abs)
        };
        let url = format!("rocksdb://{}", abs.display().to_string().replace('\\', "/"));
        Self::open(&url).await
    }

    /// Open a control-plane store at an explicit SurrealDB URL (e.g. `ws://dbhost:8000`),
    /// so multiple center instances can share one datastore for HA (P5). The leader lease
    /// stored there elects the single instance that runs the failover loop.
    pub async fn connect_url(url: &str) -> Result<Self> {
        Self::open(url).await
    }

    /// Cheap datastore connectivity probe: run a trivial query to confirm the store
    /// still answers. Backs the unauthenticated `/readyz` readiness probe so a load
    /// balancer / Kubernetes can tell whether this instance can actually serve (a
    /// networked SurrealDB that dropped, or an embedded store that failed to reopen,
    /// surfaces here rather than as opaque 500s later).
    ///
    /// # Errors
    /// Returns an error if the datastore is unreachable.
    pub async fn ping(&self) -> Result<()> {
        self.inner.query("RETURN true").await?.check()?;
        Ok(())
    }

    async fn open(url: &str) -> Result<Self> {
        let inner = any::connect(url).await?;
        inner.use_ns(NS).use_db(DB).await?;
        inner
            .query("DEFINE TABLE IF NOT EXISTS cluster")
            .query("DEFINE TABLE IF NOT EXISTS managed_server")
            .query("DEFINE TABLE IF NOT EXISTS failover_event")
            .query("DEFINE TABLE IF NOT EXISTS leader_lease")
            .query("DEFINE INDEX IF NOT EXISTS cluster_cid ON TABLE cluster COLUMNS cid UNIQUE")
            .query(
                "DEFINE INDEX IF NOT EXISTS server_sid ON TABLE managed_server COLUMNS sid UNIQUE",
            )
            // The lease is a singleton: a UNIQUE index makes concurrent sentinel creation
            // safe (the loser's CREATE fails and it falls back to renewing via UPDATE).
            .query("DEFINE INDEX IF NOT EXISTS lease_singleton ON leader_lease COLUMNS slot UNIQUE")
            .await?;
        let db = Self {
            inner: Arc::new(inner),
        };
        db.ensure_lease_sentinel().await?;
        Ok(db)
    }

    /// Ensure the singleton lease row exists (unheld, already expired), so leadership
    /// acquisition is always a conditional UPDATE with no create race.
    async fn ensure_lease_sentinel(&self) -> Result<()> {
        let existing: Vec<LeaseRecord> = self
            .inner
            .query("SELECT * FROM leader_lease WHERE slot = 'leader' LIMIT 1")
            .await?
            .take(0)?;
        if existing.is_empty() {
            let rec = LeaseRecord {
                id: None,
                slot: "leader".to_string(),
                holder: String::new(),
                expires_at: "1970-01-01T00:00:00+00:00".to_string(),
                term: 0,
            };
            // Tolerate a concurrent creator winning the unique index.
            let attempt: std::result::Result<Option<LeaseRecord>, surrealdb::Error> =
                self.inner.create("leader_lease").content(rec).await;
            let _ = attempt;
        }
        Ok(())
    }

    // ---- Clusters ----------------------------------------------------------

    pub async fn create_cluster(&self, name: &str) -> Result<Cluster> {
        let rec = ClusterRecord {
            id: None,
            cid: new_id(),
            name: name.to_string(),
            created_at: now(),
            auto_failover: false,
            failure_threshold: DEFAULT_THRESHOLD,
            active_primary: None,
            dns_zone: None,
            dns_name: None,
            dns_ttl: 60,
        };
        let created: Option<ClusterRecord> = self.inner.create("cluster").content(rec).await?;
        created
            .map(ClusterRecord::into_model)
            .ok_or_else(|| anyhow::anyhow!("cluster creation failed"))
    }

    pub async fn list_clusters(&self) -> Result<Vec<Cluster>> {
        let recs: Vec<ClusterRecord> = self
            .inner
            .query("SELECT * FROM cluster ORDER BY name ASC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(ClusterRecord::into_model).collect())
    }

    async fn cluster_exists(&self, cid: &str) -> Result<bool> {
        let recs: Vec<ClusterRecord> = self
            .inner
            .query("SELECT * FROM cluster WHERE cid = $c LIMIT 1")
            .bind(("c", cid.to_string()))
            .await?
            .take(0)?;
        Ok(!recs.is_empty())
    }

    // ---- Servers -----------------------------------------------------------

    /// Register a managed server. A `cluster` (its cid) may be given; an unknown cluster
    /// is rejected.
    pub async fn register_server(
        &self,
        name: &str,
        base_url: &str,
        token: &str,
        cluster: Option<&str>,
    ) -> Result<ManagedServer> {
        if let Some(c) = cluster {
            if !self.cluster_exists(c).await? {
                anyhow::bail!("unknown cluster '{c}'");
            }
        }
        let rec = ServerRecord {
            id: None,
            sid: new_id(),
            name: name.to_string(),
            base_url: base_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            cluster_ref: cluster.map(|c| c.to_string()),
            server_id: None,
            last_ok: false,
            last_seen: None,
            last_health: None,
            last_error: None,
            created_at: now(),
            intent: String::new(),
            fenced: false,
            consecutive_failures: 0,
            dns_target: None,
        };
        let created: Option<ServerRecord> =
            self.inner.create("managed_server").content(rec).await?;
        created
            .map(ServerRecord::into_model)
            .ok_or_else(|| anyhow::anyhow!("server registration failed"))
    }

    pub async fn list_servers(&self) -> Result<Vec<ManagedServer>> {
        let recs: Vec<ServerRecord> = self
            .inner
            .query("SELECT * FROM managed_server ORDER BY name ASC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(ServerRecord::into_model).collect())
    }

    /// Remove a server by its `sid`. Returns whether a row was deleted.
    pub async fn delete_server(&self, sid: &str) -> Result<bool> {
        let deleted: Vec<ServerRecord> = self
            .inner
            .query("DELETE managed_server WHERE sid = $s RETURN BEFORE")
            .bind(("s", sid.to_string()))
            .await?
            .take(0)?;
        Ok(!deleted.is_empty())
    }

    /// The reachability details (base_url + token) for one registered server, or `None`
    /// if no server holds that `sid`. Used to forward a control command to it.
    pub async fn get_target(&self, sid: &str) -> Result<Option<PollTarget>> {
        let recs: Vec<ServerRecord> = self
            .inner
            .query("SELECT * FROM managed_server WHERE sid = $s LIMIT 1")
            .bind(("s", sid.to_string()))
            .await?
            .take(0)?;
        Ok(recs.into_iter().next().map(|r| PollTarget {
            sid: r.sid,
            base_url: r.base_url,
            token: r.token,
        }))
    }

    /// The reachability details the poll loop needs for every registered server.
    pub async fn poll_targets(&self) -> Result<Vec<PollTarget>> {
        let recs: Vec<ServerRecord> = self
            .inner
            .query("SELECT * FROM managed_server")
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .map(|r| PollTarget {
                sid: r.sid,
                base_url: r.base_url,
                token: r.token,
            })
            .collect())
    }

    /// Record the outcome of one poll: on success store the health JSON + (first time)
    /// the server's own id; on failure store the error. Always stamps `last_seen`.
    pub async fn record_health(
        &self,
        sid: &str,
        server_id: Option<String>,
        health: Option<serde_json::Value>,
        error: Option<String>,
    ) -> Result<()> {
        let ok = error.is_none();
        let health_str = health.map(|h| h.to_string());
        // Only overwrite server_id when we learned one (keep a previously-known value).
        let set_sid = server_id.is_some();
        // Reset the consecutive-failure counter on success, increment it on failure — the
        // auto-failover evaluator compares this to the cluster's threshold.
        self.inner
            .query(
                "UPDATE managed_server SET last_ok = $ok, last_seen = $t, \
                 last_health = $h, last_error = $e, \
                 server_id = IF $set THEN $sid ELSE server_id END, \
                 consecutive_failures = IF $ok THEN 0 ELSE consecutive_failures + 1 END \
                 WHERE sid = $s",
            )
            .bind(("ok", ok))
            .bind(("t", now()))
            .bind(("h", health_str))
            .bind(("e", error))
            .bind(("set", set_sid))
            .bind(("sid", server_id))
            .bind(("s", sid.to_string()))
            .await?;
        Ok(())
    }

    // ---- P3 failover: policy, intent, state, events ------------------------

    /// Set a server's failover role intent (`primary` / `standby` / `unset`).
    pub async fn set_intent(&self, sid: &str, intent: RoleIntent) -> Result<bool> {
        let updated: Vec<ServerRecord> = self
            .inner
            .query("UPDATE managed_server SET intent = $i WHERE sid = $s RETURN AFTER")
            .bind(("i", intent.as_str().to_string()))
            .bind(("s", sid.to_string()))
            .await?
            .take(0)?;
        Ok(!updated.is_empty())
    }

    /// Set a cluster's auto-failover policy (armed + missed-poll threshold, min 1).
    pub async fn set_failover_policy(
        &self,
        cid: &str,
        auto_failover: bool,
        failure_threshold: u32,
    ) -> Result<bool> {
        let updated: Vec<ClusterRecord> = self
            .inner
            .query("UPDATE cluster SET auto_failover = $a, failure_threshold = $t WHERE cid = $c RETURN AFTER")
            .bind(("a", auto_failover))
            .bind(("t", failure_threshold.max(1)))
            .bind(("c", cid.to_string()))
            .await?
            .take(0)?;
        Ok(!updated.is_empty())
    }

    /// Set a cluster's DNS-failover policy: the zone/name of the service record steered to
    /// the active primary, and its TTL. Empty zone/name clears steering for the cluster.
    pub async fn set_dns_policy(
        &self,
        cid: &str,
        zone: Option<&str>,
        name: Option<&str>,
        ttl: u32,
    ) -> Result<bool> {
        let updated: Vec<ClusterRecord> = self
            .inner
            .query(
                "UPDATE cluster SET dns_zone = $z, dns_name = $n, dns_ttl = $t \
                 WHERE cid = $c RETURN AFTER",
            )
            .bind(("z", zone.map(|s| s.to_string())))
            .bind(("n", name.map(|s| s.to_string())))
            .bind(("t", ttl.max(1)))
            .bind(("c", cid.to_string()))
            .await?
            .take(0)?;
        Ok(!updated.is_empty())
    }

    /// Set a server's DNS target (the client-routable IP the steered record points at when
    /// this server is the active primary). `None`/empty clears it.
    pub async fn set_dns_target(&self, sid: &str, ip: Option<&str>) -> Result<bool> {
        let updated: Vec<ServerRecord> = self
            .inner
            .query("UPDATE managed_server SET dns_target = $ip WHERE sid = $s RETURN AFTER")
            .bind(("ip", ip.map(|s| s.to_string())))
            .bind(("s", sid.to_string()))
            .await?
            .take(0)?;
        Ok(!updated.is_empty())
    }

    // ---- P5 leader lease (HA) ----------------------------------------------

    /// Try to acquire or renew the leadership lease for `center_id`, extending it `ttl_secs`
    /// into the future. Succeeds (and returns `is_self = true`) when this instance already
    /// held the lease or the current lease had expired; otherwise reports the live holder.
    /// The single acquirer is the only instance that should run the failover loop.
    pub async fn try_acquire_leadership(
        &self,
        center_id: &str,
        ttl_secs: u64,
    ) -> Result<LeaderInfo> {
        let now = now();
        let expires =
            (chrono::Utc::now() + chrono::Duration::seconds(ttl_secs.max(1) as i64)).to_rfc3339();
        // Conditional CAS: claim only if we already hold it or it has expired. Bump `term`
        // when leadership actually changes hands.
        let updated: Vec<LeaseRecord> = self
            .inner
            .query(
                "UPDATE leader_lease SET \
                 term = IF holder = $me THEN term ELSE term + 1 END, \
                 holder = $me, expires_at = $exp \
                 WHERE slot = 'leader' AND (holder = $me OR expires_at <= $now) RETURN AFTER",
            )
            .bind(("me", center_id.to_string()))
            .bind(("exp", expires))
            .bind(("now", now))
            .await?
            .take(0)?;
        if let Some(rec) = updated.into_iter().next() {
            return Ok(LeaderInfo {
                is_self: rec.holder == center_id,
                holder: rec.holder,
                term: rec.term,
                expires_at: rec.expires_at,
            });
        }
        // Not claimed → another instance holds a live lease. Report who.
        self.current_leader(center_id).await
    }

    /// The current leadership state as seen by `center_id` (no acquisition attempt).
    pub async fn current_leader(&self, center_id: &str) -> Result<LeaderInfo> {
        let recs: Vec<LeaseRecord> = self
            .inner
            .query("SELECT * FROM leader_lease WHERE slot = 'leader' LIMIT 1")
            .await?
            .take(0)?;
        Ok(match recs.into_iter().next() {
            Some(rec) => LeaderInfo {
                is_self: rec.holder == center_id && !rec.holder.is_empty(),
                holder: rec.holder,
                term: rec.term,
                expires_at: rec.expires_at,
            },
            None => LeaderInfo {
                holder: String::new(),
                is_self: false,
                term: 0,
                expires_at: String::new(),
            },
        })
    }

    /// Voluntarily release the lease if held (graceful shutdown → faster failover to a
    /// standby center). Only clears it when this instance is the current holder.
    pub async fn release_leadership(&self, center_id: &str) -> Result<()> {
        self.inner
            .query(
                "UPDATE leader_lease SET holder = '', expires_at = '1970-01-01T00:00:00+00:00' \
                 WHERE slot = 'leader' AND holder = $me",
            )
            .bind(("me", center_id.to_string()))
            .await?;
        Ok(())
    }

    /// One cluster by its `cid`.
    pub async fn get_cluster(&self, cid: &str) -> Result<Option<Cluster>> {
        let recs: Vec<ClusterRecord> = self
            .inner
            .query("SELECT * FROM cluster WHERE cid = $c LIMIT 1")
            .bind(("c", cid.to_string()))
            .await?
            .take(0)?;
        Ok(recs.into_iter().next().map(ClusterRecord::into_model))
    }

    /// The DNS target IP configured for one server (empty string treated as unset).
    pub async fn get_dns_target(&self, sid: &str) -> Result<Option<String>> {
        Ok(self
            .get_target_record(sid)
            .await?
            .and_then(|r| r.dns_target)
            .filter(|s| !s.trim().is_empty()))
    }

    /// The reachability details for every server in one cluster (for broadcasting a DNS
    /// steer to all of them, best-effort).
    pub async fn cluster_targets(&self, cid: &str) -> Result<Vec<PollTarget>> {
        let recs: Vec<ServerRecord> = self
            .inner
            .query("SELECT * FROM managed_server WHERE cluster_ref = $c")
            .bind(("c", cid.to_string()))
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .map(|r| PollTarget {
                sid: r.sid,
                base_url: r.base_url,
                token: r.token,
            })
            .collect())
    }

    /// The cluster a server belongs to (its cid), if any.
    pub async fn server_cluster(&self, sid: &str) -> Result<Option<String>> {
        Ok(self
            .get_target_record(sid)
            .await?
            .and_then(|r| r.cluster_ref))
    }

    async fn get_target_record(&self, sid: &str) -> Result<Option<ServerRecord>> {
        let recs: Vec<ServerRecord> = self
            .inner
            .query("SELECT * FROM managed_server WHERE sid = $s LIMIT 1")
            .bind(("s", sid.to_string()))
            .await?
            .take(0)?;
        Ok(recs.into_iter().next())
    }

    /// Record a cluster's active primary (the sid the center regards as serving).
    pub async fn set_active_primary(&self, cid: &str, sid: Option<&str>) -> Result<()> {
        self.inner
            .query("UPDATE cluster SET active_primary = $p WHERE cid = $c")
            .bind(("p", sid.map(|s| s.to_string())))
            .bind(("c", cid.to_string()))
            .await?;
        Ok(())
    }

    /// Mark or clear a server's fenced flag.
    pub async fn set_fenced(&self, sid: &str, fenced: bool) -> Result<()> {
        self.inner
            .query("UPDATE managed_server SET fenced = $f WHERE sid = $s")
            .bind(("f", fenced))
            .bind(("s", sid.to_string()))
            .await?;
        Ok(())
    }

    /// Append a failover event (audit trail for automatic actions).
    pub async fn record_event(
        &self,
        cluster: Option<&str>,
        kind: &str,
        message: &str,
    ) -> Result<()> {
        let rec = FailoverEventRecord {
            id: None,
            eid: new_id(),
            cluster_ref: cluster.map(|c| c.to_string()),
            at: now(),
            kind: kind.to_string(),
            message: message.to_string(),
        };
        let _: Option<FailoverEventRecord> =
            self.inner.create("failover_event").content(rec).await?;
        Ok(())
    }

    /// The most recent failover events, newest first (capped at `limit`).
    pub async fn list_events(&self, limit: u32) -> Result<Vec<FailoverEvent>> {
        let recs: Vec<FailoverEventRecord> = self
            .inner
            .query("SELECT * FROM failover_event ORDER BY at DESC LIMIT $n")
            .bind(("n", limit.max(1)))
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .map(FailoverEventRecord::into_model)
            .collect())
    }

    /// Build a [`ClusterView`] per cluster for the failover evaluator: each server's
    /// intent / health / failure count / fenced flag plus whether it currently *acts* as a
    /// primary (any managed domain reporting role `primary` in its last health snapshot).
    pub async fn cluster_views(&self) -> Result<Vec<(String, crate::failover::ClusterView)>> {
        let clusters: Vec<ClusterRecord> =
            self.inner.query("SELECT * FROM cluster").await?.take(0)?;
        let servers: Vec<ServerRecord> = self
            .inner
            .query("SELECT * FROM managed_server")
            .await?
            .take(0)?;
        let mut out = Vec::new();
        for c in clusters {
            let views: Vec<crate::failover::ServerView> = servers
                .iter()
                .filter(|s| s.cluster_ref.as_deref() == Some(c.cid.as_str()))
                .map(|s| crate::failover::ServerView {
                    sid: s.sid.clone(),
                    intent: RoleIntent::parse(&s.intent).unwrap_or_default(),
                    healthy: s.last_ok,
                    consecutive_failures: s.consecutive_failures,
                    fenced: s.fenced,
                    acts_primary: acts_primary(s.last_health.as_deref()),
                })
                .collect();
            out.push((
                c.cid.clone(),
                crate::failover::ClusterView {
                    auto_failover: c.auto_failover,
                    failure_threshold: c.threshold(),
                    active_primary: c.active_primary.clone(),
                    servers: views,
                },
            ));
        }
        Ok(out)
    }
}

/// Whether a server's last health snapshot shows it acting as primary for any managed
/// (enabled, non-standalone) domain.
fn acts_primary(last_health: Option<&str>) -> bool {
    let Some(raw) = last_health else { return false };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(raw) else {
        return false;
    };
    value
        .get("domains")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter().any(|d| {
                d.get("role").and_then(|r| r.as_str()) == Some("primary")
                    && d.get("enabled").and_then(|e| e.as_bool()).unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_db() -> (CenterDb, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = CenterDb::connect(dir.path().join("db").to_str().unwrap())
            .await
            .unwrap();
        (db, dir)
    }

    #[tokio::test]
    async fn cluster_and_server_registration_roundtrip() {
        let (db, _d) = test_db().await;
        let c = db.create_cluster("prod").await.unwrap();
        assert_eq!(c.name, "prod");
        assert_eq!(db.list_clusters().await.unwrap().len(), 1);

        // Unknown cluster is rejected.
        assert!(db
            .register_server("s1", "http://a:4000", "tok", Some("nope"))
            .await
            .is_err());

        let s = db
            .register_server("s1", "http://a:4000/", "tok", Some(&c.id))
            .await
            .unwrap();
        assert_eq!(s.base_url, "http://a:4000"); // trailing slash trimmed
        assert_eq!(s.cluster.as_deref(), Some(c.id.as_str()));
        assert!(!s.last_ok);

        // list_servers scrubs the token (projection has no token field at all).
        let listed = db.list_servers().await.unwrap();
        assert_eq!(listed.len(), 1);
        let json = serde_json::to_string(&listed[0]).unwrap();
        assert!(!json.contains("tok"));

        // poll_targets carries the token (server-side only).
        let targets = db.poll_targets().await.unwrap();
        assert_eq!(targets[0].token, "tok");

        // record health, then read it back.
        db.record_health(
            &s.id,
            Some("server-uuid-1".into()),
            Some(serde_json::json!({"domains": []})),
            None,
        )
        .await
        .unwrap();
        let after = db.list_servers().await.unwrap();
        assert!(after[0].last_ok);
        assert_eq!(after[0].server_id.as_deref(), Some("server-uuid-1"));
        assert!(after[0].last_health.is_some());

        // a failure keeps the previously-learned server_id.
        db.record_health(&s.id, None, None, Some("connection refused".into()))
            .await
            .unwrap();
        let after = db.list_servers().await.unwrap();
        assert!(!after[0].last_ok);
        assert_eq!(after[0].server_id.as_deref(), Some("server-uuid-1"));
        assert_eq!(after[0].last_error.as_deref(), Some("connection refused"));

        assert!(db.delete_server(&s.id).await.unwrap());
        assert!(db.list_servers().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn leader_lease_elects_one_and_allows_takeover_on_expiry() {
        let (db, _d) = test_db().await;
        // Two center instances share this store (modelling CENTER_DB_URL).
        let a = "center-a";
        let b = "center-b";

        // A claims the (unheld) lease → leader; B sees A holds it.
        let la = db.try_acquire_leadership(a, 1).await.unwrap();
        assert!(la.is_self, "A becomes leader");
        let lb = db.try_acquire_leadership(b, 1).await.unwrap();
        assert!(!lb.is_self, "B is not leader while A's lease is live");
        assert_eq!(lb.holder, a);

        // A renews without changing the term.
        let la2 = db.try_acquire_leadership(a, 1).await.unwrap();
        assert!(la2.is_self);
        assert_eq!(la2.term, la.term, "renew keeps the same term");

        // Let A's lease expire, then B takes over (term bumps).
        tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
        let lb2 = db.try_acquire_leadership(b, 30).await.unwrap();
        assert!(lb2.is_self, "B takes over the expired lease");
        assert!(lb2.term > la.term, "leadership change bumps the term");

        // A now sees B as leader and steps aside.
        let la3 = db.try_acquire_leadership(a, 30).await.unwrap();
        assert!(!la3.is_self);
        assert_eq!(la3.holder, b);

        // B releases on shutdown → A can immediately reclaim.
        db.release_leadership(b).await.unwrap();
        let la4 = db.try_acquire_leadership(a, 30).await.unwrap();
        assert!(la4.is_self, "A reclaims after B releases");
    }

    #[tokio::test]
    async fn dns_failover_policy_and_target_roundtrip() {
        let (db, _d) = test_db().await;
        let c = db.create_cluster("prod").await.unwrap();
        let s = db
            .register_server("dc1", "http://a:4000", "tok", Some(&c.id))
            .await
            .unwrap();

        // Cluster DNS policy.
        assert!(db
            .set_dns_policy(&c.id, Some("example.com"), Some("app.example.com"), 30)
            .await
            .unwrap());
        let cl = db.get_cluster(&c.id).await.unwrap().unwrap();
        assert_eq!(cl.dns_zone.as_deref(), Some("example.com"));
        assert_eq!(cl.dns_name.as_deref(), Some("app.example.com"));
        assert_eq!(cl.dns_ttl, 30);

        // Server DNS target + lookups used by the steer path.
        assert!(db.set_dns_target(&s.id, Some("10.0.0.5")).await.unwrap());
        assert_eq!(
            db.get_dns_target(&s.id).await.unwrap().as_deref(),
            Some("10.0.0.5")
        );
        assert_eq!(
            db.server_cluster(&s.id).await.unwrap().as_deref(),
            Some(c.id.as_str())
        );
        let targets = db.cluster_targets(&c.id).await.unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].base_url, "http://a:4000");

        // Clearing the target is reflected as unset.
        assert!(db.set_dns_target(&s.id, None).await.unwrap());
        assert!(db.get_dns_target(&s.id).await.unwrap().is_none());
    }
}
