//! DHCP domain repository (07_data_dhcp / 08_dhcp_logic): pools (with AC-14
//! range-overlap), reservations (MAC/IP uniqueness + in-range), leases
//! (list/release) and the singleton config.

use crate::error::{DbError, DbResult};
use crate::records::{parse_rfc3339, record_key, to_rfc3339};
use crate::store::Db;
use chrono::Utc;
use magnetite_core::domains::dhcp::model::{
    DhcpConfig, DhcpLeaseFeed, Lease, LeaseState, Pool, ProtoVer, Reservation,
};
use magnetite_core::domains::dhcp::validate::{intervals_overlap, v4_range, v6_range};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use surrealdb::types::{RecordId, SurrealValue};

const MSG_OVERLAP: &str = "指定範囲は既存プールと重複しています。";
const MSG_MAC_DUP: &str = "この MAC アドレスは既に予約されています。";
const MSG_POOL_IN_USE: &str = "有効なリースまたは予約が存在するため、プールを削除できません。";

// ---- Records --------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct PoolRecord {
    id: Option<RecordId>,
    name: String,
    subnet_v4: Option<String>,
    range_start_v4: Option<String>,
    range_end_v4: Option<String>,
    subnet_v6: Option<String>,
    range_start_v6: Option<String>,
    range_end_v6: Option<String>,
    gateway: Option<String>,
    dns_servers: Vec<String>,
    domain_name: Option<String>,
    lease_duration_secs: Option<u32>,
    enabled: bool,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl PoolRecord {
    fn from_model(p: &Pool, now: &str) -> Self {
        Self {
            id: None,
            name: p.name.clone(),
            subnet_v4: p.subnet_v4.clone(),
            range_start_v4: p.range_start_v4.clone(),
            range_end_v4: p.range_end_v4.clone(),
            subnet_v6: p.subnet_v6.clone(),
            range_start_v6: p.range_start_v6.clone(),
            range_end_v6: p.range_end_v6.clone(),
            gateway: p.gateway.clone(),
            dns_servers: p.dns_servers.clone(),
            domain_name: p.domain_name.clone(),
            lease_duration_secs: p.lease_duration_secs,
            enabled: p.enabled,
            created_at: now.to_string(),
            updated_at: now.to_string(),
            created_by: p.created_by.clone(),
        }
    }

    fn into_model(self) -> Pool {
        Pool {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            name: self.name,
            subnet_v4: self.subnet_v4,
            range_start_v4: self.range_start_v4,
            range_end_v4: self.range_end_v4,
            subnet_v6: self.subnet_v6,
            range_start_v6: self.range_start_v6,
            range_end_v6: self.range_end_v6,
            gateway: self.gateway,
            dns_servers: self.dns_servers,
            domain_name: self.domain_name,
            lease_duration_secs: self.lease_duration_secs,
            enabled: self.enabled,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct ReservationRecord {
    id: Option<RecordId>,
    pool_ref: String,
    mac_address: String,
    ip_address: String,
    hostname: Option<String>,
    description: Option<String>,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl ReservationRecord {
    fn into_model(self) -> Reservation {
        Reservation {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            pool_ref: self.pool_ref,
            mac_address: self.mac_address,
            ip_address: self.ip_address,
            hostname: self.hostname,
            description: self.description,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct LeaseRecord {
    id: Option<RecordId>,
    pool_ref: String,
    ip_address: String,
    mac_address: Option<String>,
    client_id: Option<String>,
    hostname: Option<String>,
    state: String,
    lease_start: String,
    lease_expiry: String,
    last_renewal: Option<String>,
    protocol_version: String,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl LeaseRecord {
    fn from_model(l: &Lease) -> Self {
        LeaseRecord {
            id: None,
            pool_ref: l.pool_ref.clone(),
            ip_address: l.ip_address.clone(),
            mac_address: l.mac_address.clone(),
            client_id: l.client_id.clone(),
            hostname: l.hostname.clone(),
            state: l.state.as_str().to_string(),
            lease_start: to_rfc3339(l.lease_start),
            lease_expiry: to_rfc3339(l.lease_expiry),
            last_renewal: l.last_renewal.map(to_rfc3339),
            protocol_version: match l.protocol_version {
                ProtoVer::V6 => "V6",
                ProtoVer::V4 => "V4",
            }
            .to_string(),
            created_at: to_rfc3339(l.created_at),
            updated_at: to_rfc3339(l.updated_at),
            created_by: l.created_by.clone(),
        }
    }

    fn into_model(self) -> Lease {
        Lease {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            pool_ref: self.pool_ref,
            ip_address: self.ip_address,
            mac_address: self.mac_address,
            client_id: self.client_id,
            hostname: self.hostname,
            state: LeaseState::from_str(&self.state).unwrap_or(LeaseState::Expired),
            lease_start: parse_rfc3339(&self.lease_start),
            lease_expiry: parse_rfc3339(&self.lease_expiry),
            last_renewal: self.last_renewal.as_deref().map(parse_rfc3339),
            protocol_version: if self.protocol_version == "V6" {
                ProtoVer::V6
            } else {
                ProtoVer::V4
            },
        }
    }
}

/// The singleton config row. Mirrors the account/pool record shape (id set to
/// `None` on write, populated on read).
/// Singleton row persisting the DHCP lease-replication pull cursor.
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct DhcpReplStateRecord {
    id: Option<RecordId>,
    cursor: String,
    last_sync: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct ConfigRecord {
    id: Option<RecordId>,
    v4_enabled: bool,
    v6_enabled: bool,
    default_lease_secs: u32,
    max_lease_secs: Option<u32>,
    default_dns_servers: Vec<String>,
    default_domain_name: Option<String>,
    authoritative: bool,
}

impl ConfigRecord {
    fn from_model(c: &DhcpConfig) -> Self {
        Self {
            id: None,
            v4_enabled: c.v4_enabled,
            v6_enabled: c.v6_enabled,
            default_lease_secs: c.default_lease_secs,
            max_lease_secs: c.max_lease_secs,
            default_dns_servers: c.default_dns_servers.clone(),
            default_domain_name: c.default_domain_name.clone(),
            authoritative: c.authoritative,
        }
    }

    fn into_model(self) -> DhcpConfig {
        DhcpConfig {
            v4_enabled: self.v4_enabled,
            v6_enabled: self.v6_enabled,
            default_lease_secs: self.default_lease_secs,
            max_lease_secs: self.max_lease_secs,
            default_dns_servers: self.default_dns_servers,
            default_domain_name: self.default_domain_name,
            authoritative: self.authoritative,
        }
    }
}

fn in_pool_range(pool: &Pool, ip: &str) -> bool {
    if let Ok(v4) = Ipv4Addr::from_str(ip) {
        return v4_range(pool).is_some_and(|(s, e)| {
            let n = u32::from(v4);
            n >= s && n <= e
        });
    }
    if let Ok(v6) = Ipv6Addr::from_str(ip) {
        return v6_range(pool).is_some_and(|(s, e)| {
            let n = u128::from(v6);
            n >= s && n <= e
        });
    }
    false
}

impl Db {
    // ---- Pools ------------------------------------------------------------

    /// List pools ordered by name.
    pub async fn list_pools(&self) -> DbResult<Vec<Pool>> {
        let recs: Vec<PoolRecord> = self
            .inner
            .query("SELECT * FROM pool ORDER BY name ASC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(PoolRecord::into_model).collect())
    }

    /// Fetch a pool by id.
    pub async fn get_pool(&self, id: &str) -> DbResult<Option<Pool>> {
        let rec: Option<PoolRecord> = self.inner.select(("pool", id)).await?;
        Ok(rec.map(PoolRecord::into_model))
    }

    /// Reject an address range that overlaps another pool of the same family
    /// (AC-14 / 08_dhcp_logic §5.1). `exclude_id` skips the pool being updated.
    async fn check_range_overlap(&self, pool: &Pool, exclude_id: Option<&str>) -> DbResult<()> {
        let new_v4 = v4_range(pool);
        let new_v6 = v6_range(pool);
        for other in self.list_pools().await? {
            if exclude_id == Some(other.id.as_str()) {
                continue;
            }
            if let (Some(a), Some(b)) = (new_v4, v4_range(&other)) {
                if intervals_overlap(a, b) {
                    return Err(DbError::Constraint(MSG_OVERLAP.into()));
                }
            }
            if let (Some(a), Some(b)) = (new_v6, v6_range(&other)) {
                if intervals_overlap(a, b) {
                    return Err(DbError::Constraint(MSG_OVERLAP.into()));
                }
            }
        }
        Ok(())
    }

    /// Create a pool (name unique, no range overlap).
    pub async fn create_pool(&self, pool: &Pool) -> DbResult<Pool> {
        self.check_range_overlap(pool, None).await?;
        let now = to_rfc3339(Utc::now());
        let created: Option<PoolRecord> = self
            .inner
            .create("pool")
            .content(PoolRecord::from_model(pool, &now))
            .await?;
        created
            .map(PoolRecord::into_model)
            .ok_or_else(|| DbError::Constraint("pool creation returned nothing".into()))
    }

    /// Update a pool (no range overlap against others).
    pub async fn update_pool(&self, pool: &Pool) -> DbResult<Option<Pool>> {
        self.check_range_overlap(pool, Some(&pool.id)).await?;
        let now = to_rfc3339(Utc::now());
        let mut rec = PoolRecord::from_model(pool, &now);
        rec.id = None;
        let updated: Option<PoolRecord> = self
            .inner
            .update(("pool", pool.id.as_str()))
            .content(rec)
            .await?;
        Ok(updated.map(PoolRecord::into_model))
    }

    /// Number of active leases in a pool (drives the delete confirmation).
    pub async fn count_pool_active_leases(&self, pool_id: &str) -> DbResult<usize> {
        let now = Utc::now();
        Ok(self
            .list_leases(Some(pool_id))
            .await?
            .into_iter()
            .filter(|l| l.is_active_at(now))
            .count())
    }

    /// Delete a pool. Rejects when reservations exist; cascades leases (which
    /// are runtime state). 08_dhcp_logic §5.3.
    pub async fn delete_pool(&self, pool_id: &str) -> DbResult<()> {
        if !self.list_reservations(pool_id).await?.is_empty() {
            return Err(DbError::Constraint(MSG_POOL_IN_USE.into()));
        }
        self.inner
            .query("DELETE lease WHERE pool_ref = $p")
            .bind(("p", pool_id.to_string()))
            .await?;
        let _: Option<PoolRecord> = self.inner.delete(("pool", pool_id)).await?;
        Ok(())
    }

    // ---- Reservations -----------------------------------------------------

    /// List reservations for a pool.
    pub async fn list_reservations(&self, pool_id: &str) -> DbResult<Vec<Reservation>> {
        let recs: Vec<ReservationRecord> = self
            .inner
            .query("SELECT * FROM reservation WHERE pool_ref = $p ORDER BY ip_address ASC")
            .bind(("p", pool_id.to_string()))
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .map(ReservationRecord::into_model)
            .collect())
    }

    /// Create a reservation: MAC and IP unique within the pool, IP in range.
    pub async fn create_reservation(&self, res: &Reservation) -> DbResult<Reservation> {
        let pool = self
            .get_pool(&res.pool_ref)
            .await?
            .ok_or(DbError::NotFound)?;
        if !in_pool_range(&pool, &res.ip_address) {
            return Err(DbError::Constraint(MSG_OVERLAP.into()));
        }
        let existing = self.list_reservations(&res.pool_ref).await?;
        if existing.iter().any(|r| r.mac_address == res.mac_address) {
            return Err(DbError::Constraint(MSG_MAC_DUP.into()));
        }
        if existing.iter().any(|r| r.ip_address == res.ip_address) {
            return Err(DbError::Constraint(MSG_OVERLAP.into()));
        }
        let now = to_rfc3339(Utc::now());
        let rec = ReservationRecord {
            id: None,
            pool_ref: res.pool_ref.clone(),
            mac_address: res.mac_address.clone(),
            ip_address: res.ip_address.clone(),
            hostname: res.hostname.clone(),
            description: res.description.clone(),
            created_at: now.clone(),
            updated_at: now,
            created_by: res.created_by.clone(),
        };
        let created: Option<ReservationRecord> =
            self.inner.create("reservation").content(rec).await?;
        created
            .map(ReservationRecord::into_model)
            .ok_or_else(|| DbError::Constraint("reservation creation returned nothing".into()))
    }

    /// Delete a reservation by id.
    pub async fn delete_reservation(&self, id: &str) -> DbResult<()> {
        let _: Option<ReservationRecord> = self.inner.delete(("reservation", id)).await?;
        Ok(())
    }

    // ---- Leases -----------------------------------------------------------

    /// List leases, optionally filtered by pool, newest first.
    pub async fn list_leases(&self, pool_id: Option<&str>) -> DbResult<Vec<Lease>> {
        let recs: Vec<LeaseRecord> = match pool_id {
            Some(p) => self
                .inner
                .query("SELECT * FROM lease WHERE pool_ref = $p ORDER BY lease_start DESC")
                .bind(("p", p.to_string()))
                .await?
                .take(0)?,
            None => self
                .inner
                .query("SELECT * FROM lease ORDER BY lease_start DESC")
                .await?
                .take(0)?,
        };
        Ok(recs.into_iter().map(LeaseRecord::into_model).collect())
    }

    /// Upsert a lease keyed by (pool, ip): replace any existing row for that IP
    /// in the pool, then insert the given lease. Used by the embedded DHCP
    /// server when it offers/assigns an address (08_dhcp_logic §3).
    pub async fn upsert_lease(&self, lease: &Lease) -> DbResult<Lease> {
        self.inner
            .query("DELETE lease WHERE pool_ref = $p AND ip_address = $ip")
            .bind(("p", lease.pool_ref.clone()))
            .bind(("ip", lease.ip_address.clone()))
            .await?;
        let created: Option<LeaseRecord> = self
            .inner
            .create("lease")
            .content(LeaseRecord::from_model(lease))
            .await?;
        created
            .map(LeaseRecord::into_model)
            .ok_or_else(|| DbError::Constraint("lease upsert failed".into()))
    }

    /// Build the DHCP lease-replication feed for a peer: the leases whose `updated_at`
    /// is newer than `cursor` (RFC 3339; empty = full sync), oldest first, capped at
    /// `limit`, plus the cursor to request next (the newest served `updated_at`).
    ///
    /// # Errors
    /// A store error.
    pub async fn dhcp_lease_feed(&self, cursor: &str, limit: usize) -> DbResult<DhcpLeaseFeed> {
        // Compound cursor `"<updated_at>|<pool_ref>|<ip_address>"`: the lease's natural
        // key (pool_ref, ip_address) breaks ties so an exactly-full page does not skip
        // leases sharing the boundary `updated_at` (a bulk update within one clock tick).
        // The `(updated_at, pool_ref, ip_address)` tuple is compared level-by-level in the
        // WHERE (SurrealDB `ORDER BY` cannot take a function expression). A legacy
        // timestamp-only cursor parses as empty key parts and is still accepted.
        let mut parts = cursor.splitn(3, '|');
        let ts = parts.next().unwrap_or("").to_string();
        let pool = parts.next().unwrap_or("").to_string();
        let ip = parts.next().unwrap_or("").to_string();
        let recs: Vec<LeaseRecord> = self
            .inner
            .query(
                "SELECT * FROM lease \
                 WHERE updated_at > $ts \
                    OR (updated_at = $ts AND pool_ref > $p) \
                    OR (updated_at = $ts AND pool_ref = $p AND ip_address > $i) \
                 ORDER BY updated_at ASC, pool_ref ASC, ip_address ASC LIMIT $l",
            )
            .bind(("ts", ts))
            .bind(("p", pool))
            .bind(("i", ip))
            .bind(("l", limit as i64))
            .await?
            .take(0)?;
        let next = recs
            .last()
            .map(|r| format!("{}|{}|{}", r.updated_at, r.pool_ref, r.ip_address))
            .unwrap_or_else(|| cursor.to_string());
        let leases = recs.into_iter().map(LeaseRecord::into_model).collect();
        Ok(DhcpLeaseFeed {
            leases,
            cursor: next,
        })
    }

    /// Apply one lease replicated from a peer, keyed by `(pool_ref, ip_address)`. With
    /// split-scope allocation the peer owns a disjoint pool slice, so its leases never
    /// conflict with ours; storing them gives us the full picture (a client can renew
    /// against either server, and we won't offer an address the peer already leased).
    /// A **no-regress** guard skips the write when we already hold an at-least-as-new
    /// lease for that address, so re-applying the feed is idempotent. Returns whether it
    /// wrote.
    ///
    /// # Errors
    /// A store error.
    pub async fn apply_replicated_lease(&self, lease: &Lease) -> DbResult<bool> {
        let existing: Vec<LeaseRecord> = self
            .inner
            .query("SELECT * FROM lease WHERE pool_ref = $p AND ip_address = $ip LIMIT 1")
            .bind(("p", lease.pool_ref.clone()))
            .bind(("ip", lease.ip_address.clone()))
            .await?
            .take(0)?;
        if let Some(cur) = existing.first() {
            if parse_rfc3339(&cur.updated_at) >= lease.updated_at {
                return Ok(false); // we already hold this or a newer lease for the address
            }
        }
        self.upsert_lease(lease).await?;
        Ok(true)
    }

    /// Expire active/offered leases whose lease time has elapsed (08_dhcp_logic
    /// §3). Returns the number of leases transitioned to `expired`. Called
    /// periodically by the embedded DHCP server's sweep task.
    pub async fn expire_stale_leases(&self) -> DbResult<usize> {
        let now = to_rfc3339(Utc::now());
        let updated: Vec<LeaseRecord> = self
            .inner
            .query(
                "UPDATE lease SET state = 'expired', updated_at = $t \
                 WHERE (state = 'active' OR state = 'offered') AND lease_expiry < $now",
            )
            .bind(("t", now.clone()))
            .bind(("now", now))
            .await?
            .take(0)?;
        Ok(updated.len())
    }

    /// Release a lease (08_dhcp_logic §4): only active/offered leases can be
    /// released; sets state to `released`.
    pub async fn release_lease(&self, id: &str) -> DbResult<()> {
        let lease: Option<LeaseRecord> = self.inner.select(("lease", id)).await?;
        let lease = lease.ok_or(DbError::NotFound)?;
        let state = LeaseState::from_str(&lease.state).unwrap_or(LeaseState::Expired);
        if !state.is_releasable() {
            return Err(DbError::Constraint("このリースは解放できません。".into()));
        }
        let now = to_rfc3339(Utc::now());
        self.inner
            .query("UPDATE type::record('lease', $id) SET state = 'released', updated_at = $t")
            .bind(("id", id.to_string()))
            .bind(("t", now))
            .await?;
        Ok(())
    }

    // ---- Config -----------------------------------------------------------

    /// Fetch the DHCP config, creating the default singleton on first read.
    pub async fn get_dhcp_config(&self) -> DbResult<DhcpConfig> {
        let existing: Vec<ConfigRecord> = self
            .inner
            .query("SELECT * FROM dhcp_config LIMIT 1")
            .await?
            .take(0)?;
        if let Some(rec) = existing.into_iter().next() {
            return Ok(rec.into_model());
        }
        let default = DhcpConfig::default();
        let created: Option<ConfigRecord> = self
            .inner
            .create("dhcp_config")
            .content(ConfigRecord::from_model(&default))
            .await?;
        created
            .map(ConfigRecord::into_model)
            .ok_or_else(|| DbError::Constraint("dhcp_config create failed".into()))
    }

    /// Save the DHCP config singleton (replace the single row).
    pub async fn save_dhcp_config(&self, config: &DhcpConfig) -> DbResult<()> {
        // Ensure the table/row exists, then replace it.
        let _ = self.get_dhcp_config().await?;
        self.inner.query("DELETE dhcp_config").await?;
        let _: Option<ConfigRecord> = self
            .inner
            .create("dhcp_config")
            .content(ConfigRecord::from_model(config))
            .await?;
        Ok(())
    }

    /// The persisted DHCP lease-replication pull cursor (empty when never synced),
    /// so a secondary resumes from where it left off instead of re-syncing from empty
    /// on every restart.
    ///
    /// # Errors
    /// A store error.
    pub async fn get_dhcp_repl_cursor(&self) -> DbResult<String> {
        let recs: Vec<DhcpReplStateRecord> = self
            .inner
            .query("SELECT * FROM dhcp_repl_state LIMIT 1")
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .next()
            .map(|r| r.cursor)
            .unwrap_or_default())
    }

    /// Persist the DHCP lease-replication pull cursor after a pull pass (singleton).
    ///
    /// # Errors
    /// A store error.
    pub async fn set_dhcp_repl_cursor(&self, cursor: &str) -> DbResult<()> {
        let now = to_rfc3339(Utc::now());
        let existing: Vec<DhcpReplStateRecord> = self
            .inner
            .query("SELECT * FROM dhcp_repl_state LIMIT 1")
            .await?
            .take(0)?;
        if existing.is_empty() {
            let rec = DhcpReplStateRecord {
                id: None,
                cursor: cursor.to_string(),
                last_sync: Some(now),
            };
            let _: Option<DhcpReplStateRecord> =
                self.inner.create("dhcp_repl_state").content(rec).await?;
        } else {
            self.inner
                .query("UPDATE dhcp_repl_state SET cursor = $c, last_sync = $t")
                .bind(("c", cursor.to_string()))
                .bind(("t", now))
                .await?;
        }
        Ok(())
    }

    /// Headline DHCP metrics: pool count, reservation count, active lease count.
    pub async fn dhcp_metrics(&self) -> DbResult<(usize, usize, usize)> {
        let pools = self.list_pools().await?.len();
        let reservations: Vec<ReservationRecord> = self
            .inner
            .query("SELECT * FROM reservation")
            .await?
            .take(0)?;
        let now = Utc::now();
        let active = self
            .list_leases(None)
            .await?
            .into_iter()
            .filter(|l| l.is_active_at(now))
            .count();
        Ok((pools, reservations.len(), active))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_db() -> (Db, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        (db, dir)
    }

    fn pool(name: &str, start: &str, end: &str) -> Pool {
        Pool {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "admin".into(),
            name: name.into(),
            subnet_v4: Some("192.168.1.0/24".into()),
            range_start_v4: Some(start.into()),
            range_end_v4: Some(end.into()),
            subnet_v6: None,
            range_start_v6: None,
            range_end_v6: None,
            gateway: None,
            dns_servers: vec![],
            domain_name: None,
            lease_duration_secs: None,
            enabled: true,
        }
    }

    fn lease(pool_id: &str, ip: &str, mac: &str, at: chrono::DateTime<Utc>) -> Lease {
        Lease {
            id: String::new(),
            created_at: at,
            updated_at: at,
            created_by: "dhcp".into(),
            pool_ref: pool_id.into(),
            ip_address: ip.into(),
            mac_address: Some(mac.into()),
            client_id: None,
            hostname: None,
            state: LeaseState::Active,
            lease_start: at,
            lease_expiry: at,
            last_renewal: None,
            protocol_version: ProtoVer::V4,
        }
    }

    #[tokio::test]
    async fn lease_feed_serves_changes_and_replicated_apply_is_idempotent() {
        let (primary, _d1) = test_db().await;
        let p = primary
            .create_pool(&pool("a", "192.168.1.10", "192.168.1.100"))
            .await
            .unwrap();
        primary
            .upsert_lease(&lease(
                &p.id,
                "192.168.1.20",
                "aa:bb:cc:00:00:01",
                Utc::now(),
            ))
            .await
            .unwrap();

        // Full feed (empty cursor) carries the lease plus a non-empty cursor.
        let feed = primary.dhcp_lease_feed("", 100).await.unwrap();
        assert_eq!(feed.leases.len(), 1);
        assert_eq!(feed.leases[0].ip_address, "192.168.1.20");
        assert!(!feed.cursor.is_empty());

        // A peer applies it, and re-applying the same feed is a no-op (no-regress).
        let (peer, _d2) = test_db().await;
        assert!(peer.apply_replicated_lease(&feed.leases[0]).await.unwrap());
        assert!(!peer.apply_replicated_lease(&feed.leases[0]).await.unwrap());
        let got = peer.list_leases(Some(&p.id)).await.unwrap();
        assert_eq!(got.len(), 1, "the peer holds the replicated lease");
        assert_eq!(got[0].ip_address, "192.168.1.20");

        // From the returned cursor there is nothing newer.
        assert!(primary
            .dhcp_lease_feed(&feed.cursor, 100)
            .await
            .unwrap()
            .leases
            .is_empty());
    }

    #[tokio::test]
    async fn pool_overlap_is_rejected() {
        let (db, _dir) = test_db().await;
        db.create_pool(&pool("a", "192.168.1.10", "192.168.1.100"))
            .await
            .unwrap();
        // Overlapping range → rejected.
        assert!(db
            .create_pool(&pool("b", "192.168.1.50", "192.168.1.150"))
            .await
            .is_err());
        // Disjoint range → allowed.
        assert!(db
            .create_pool(&pool("c", "192.168.1.150", "192.168.1.200"))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn reservation_uniqueness_and_range() {
        let (db, _dir) = test_db().await;
        let p = db
            .create_pool(&pool("a", "192.168.1.10", "192.168.1.100"))
            .await
            .unwrap();
        let res = Reservation {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "admin".into(),
            pool_ref: p.id.clone(),
            mac_address: "aa:bb:cc:dd:ee:ff".into(),
            ip_address: "192.168.1.50".into(),
            hostname: None,
            description: None,
        };
        db.create_reservation(&res).await.unwrap();
        // Duplicate MAC rejected.
        let mut dup_mac = res.clone();
        dup_mac.ip_address = "192.168.1.51".into();
        assert!(db.create_reservation(&dup_mac).await.is_err());
        // Out-of-range IP rejected.
        let mut oor = res.clone();
        oor.mac_address = "11:22:33:44:55:66".into();
        oor.ip_address = "192.168.1.5".into();
        assert!(db.create_reservation(&oor).await.is_err());
    }

    #[tokio::test]
    async fn pool_delete_guarded_by_reservations() {
        let (db, _dir) = test_db().await;
        let p = db
            .create_pool(&pool("a", "192.168.1.10", "192.168.1.100"))
            .await
            .unwrap();
        db.create_reservation(&Reservation {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "admin".into(),
            pool_ref: p.id.clone(),
            mac_address: "aa:bb:cc:dd:ee:ff".into(),
            ip_address: "192.168.1.50".into(),
            hostname: None,
            description: None,
        })
        .await
        .unwrap();
        assert!(db.delete_pool(&p.id).await.is_err());
    }

    #[tokio::test]
    async fn config_singleton_roundtrip() {
        let (db, _dir) = test_db().await;
        let cfg = db.get_dhcp_config().await.unwrap();
        assert!(cfg.v4_enabled);
        let mut updated = cfg;
        updated.default_lease_secs = 3600;
        db.save_dhcp_config(&updated).await.unwrap();
        assert_eq!(db.get_dhcp_config().await.unwrap().default_lease_secs, 3600);
    }
}
