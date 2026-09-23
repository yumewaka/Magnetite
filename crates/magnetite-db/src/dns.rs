//! DNS domain repository (07_data_dns / 08_dns_logic): zones (with cascade
//! delete), records (with CNAME-coexistence guard) and RPZ rules.

use crate::error::{DbError, DbResult};
use crate::records::{parse_rfc3339, record_key, to_rfc3339};
use crate::store::Db;
use chrono::Utc;
use magnetite_core::domains::dns::model::{
    DdnsConfig, DdnsStatus, GeoRule, Record, RecordType, RpzAction, RpzRule, Soa, TsigAlgorithm,
    TsigKey, Zone, ZoneRole, ZoneTransferState,
};
use magnetite_core::domains::dns::validate::normalize_name;
use serde::{Deserialize, Serialize};
use surrealdb::types::{RecordId, SurrealValue};

const CNAME_CONFLICT: &str = "CNAME レコードは同名の他レコードと共存できません。";

// ---- Zone -----------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct ZoneRecord {
    id: Option<RecordId>,
    name: String,
    /// JSON-encoded `Soa`.
    soa: String,
    enabled: bool,
    #[serde(default)]
    dnssec_enabled: bool,
    #[serde(default)]
    nsec3_enabled: bool,
    // ---- replication (07_data_dns replication extension) ----
    #[serde(default)]
    role: String,
    #[serde(default)]
    allow_transfer: Vec<String>,
    #[serde(default)]
    also_notify: Vec<String>,
    #[serde(default)]
    notify_enabled: bool,
    #[serde(default)]
    primaries: Vec<String>,
    #[serde(default)]
    tsig_key_name: Option<String>,
    /// JSON-encoded `ZoneTransferState` (secondary runtime state).
    #[serde(default)]
    transfer_state: Option<String>,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl ZoneRecord {
    fn into_model(self) -> Zone {
        Zone {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            name: self.name,
            soa: serde_json::from_str(&self.soa).unwrap_or_default(),
            enabled: self.enabled,
            dnssec_enabled: self.dnssec_enabled,
            nsec3_enabled: self.nsec3_enabled,
            role: match self.role.as_str() {
                "secondary" => ZoneRole::Secondary,
                _ => ZoneRole::Primary,
            },
            allow_transfer: self.allow_transfer,
            also_notify: self.also_notify,
            notify_enabled: self.notify_enabled,
            primaries: self.primaries,
            tsig_key_name: self.tsig_key_name,
            transfer_state: self
                .transfer_state
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct RecordRecord {
    id: Option<RecordId>,
    zone: String,
    name: String,
    ttl: u32,
    record_type: String,
    /// JSON-encoded record data.
    data: String,
    enabled: bool,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl RecordRecord {
    fn into_model(self) -> Record {
        Record {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            zone: self.zone,
            name: self.name,
            ttl: self.ttl,
            record_type: RecordType::from_str(&self.record_type).unwrap_or(RecordType::A),
            data: serde_json::from_str(&self.data).unwrap_or(serde_json::Value::Null),
            enabled: self.enabled,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct RpzRecord {
    id: Option<RecordId>,
    domain: String,
    action: String,
    redirect_to: Option<String>,
    enabled: bool,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl RpzRecord {
    fn into_model(self) -> RpzRule {
        RpzRule {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            domain: self.domain,
            action: RpzAction::from_str(&self.action).unwrap_or(RpzAction::Nxdomain),
            redirect_to: self.redirect_to,
            enabled: self.enabled,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct TsigKeyRecord {
    id: Option<RecordId>,
    name: String,
    algorithm: String,
    /// Base64 HMAC secret — server-side material, never projected.
    secret: String,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl TsigKeyRecord {
    fn algorithm(&self) -> TsigAlgorithm {
        match self.algorithm.as_str() {
            "hmac-sha512" => TsigAlgorithm::HmacSha512,
            "hmac-sha384" => TsigAlgorithm::HmacSha384,
            _ => TsigAlgorithm::HmacSha256,
        }
    }

    /// Projection for clients: the secret is blanked out.
    fn into_model_redacted(self) -> TsigKey {
        let algorithm = self.algorithm();
        TsigKey {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            name: self.name,
            algorithm,
            secret: String::new(),
        }
    }
}

/// One IXFR journal delta (records added/removed to reach `serial`).
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct JournalRecord {
    id: Option<RecordId>,
    zone: String,
    serial: u32,
    /// JSON-encoded `Vec<Record>` added at this serial.
    added: String,
    /// JSON-encoded `Vec<Record>` removed at this serial.
    removed: String,
    at: String,
}

impl Db {
    // ---- Zones ------------------------------------------------------------

    /// Create a zone.
    ///
    /// # Errors
    /// [`DbError::Constraint`] if the zone name already exists.
    pub async fn create_zone(
        &self,
        name: &str,
        soa: &Soa,
        enabled: bool,
        actor: &str,
    ) -> DbResult<Zone> {
        let name = normalize_name(name);
        if self.find_zone_by_name(&name).await?.is_some() {
            return Err(DbError::Constraint(
                "同じ名前のゾーンが既に存在します。".into(),
            ));
        }
        let now = to_rfc3339(Utc::now());
        let rec = ZoneRecord {
            id: None,
            name,
            soa: serde_json::to_string(soa).unwrap_or_default(),
            enabled,
            dnssec_enabled: false,
            nsec3_enabled: false,
            role: "primary".into(),
            allow_transfer: Vec::new(),
            also_notify: Vec::new(),
            notify_enabled: false,
            primaries: Vec::new(),
            tsig_key_name: None,
            transfer_state: None,
            created_at: now.clone(),
            updated_at: now,
            created_by: actor.to_string(),
        };
        let created: Option<ZoneRecord> = self.inner.create("zone").content(rec).await?;
        created
            .map(ZoneRecord::into_model)
            .ok_or_else(|| DbError::Constraint("zone creation returned nothing".into()))
    }

    /// List all zones, ordered by name.
    pub async fn list_zones(&self) -> DbResult<Vec<Zone>> {
        let recs: Vec<ZoneRecord> = self
            .inner
            .query("SELECT * FROM zone ORDER BY name ASC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(ZoneRecord::into_model).collect())
    }

    /// Fetch a zone by id.
    pub async fn get_zone(&self, id: &str) -> DbResult<Option<Zone>> {
        let rec: Option<ZoneRecord> = self.inner.select(("zone", id)).await?;
        Ok(rec.map(ZoneRecord::into_model))
    }

    async fn find_zone_by_name(&self, name: &str) -> DbResult<Option<Zone>> {
        let recs: Vec<ZoneRecord> = self
            .inner
            .query("SELECT * FROM zone WHERE name = $n LIMIT 1")
            .bind(("n", name.to_string()))
            .await?
            .take(0)?;
        Ok(recs.into_iter().next().map(ZoneRecord::into_model))
    }

    /// Update a zone's SOA/enabled state.
    pub async fn update_zone(&self, id: &str, soa: &Soa, enabled: bool) -> DbResult<Option<Zone>> {
        let soa_json = serde_json::to_string(soa).unwrap_or_default();
        let now = to_rfc3339(Utc::now());
        let updated: Vec<ZoneRecord> = self
            .inner
            .query(
                "UPDATE type::record('zone', $id) SET soa = $soa, enabled = $en, updated_at = $t",
            )
            .bind(("id", id.to_string()))
            .bind(("soa", soa_json))
            .bind(("en", enabled))
            .bind(("t", now))
            .await?
            .take(0)?;
        Ok(updated.into_iter().next().map(ZoneRecord::into_model))
    }

    /// Toggle DNSSEC online signing for a zone.
    pub async fn set_zone_dnssec_enabled(&self, id: &str, enabled: bool) -> DbResult<()> {
        self.inner
            .query("UPDATE type::record('zone', $id) SET dnssec_enabled = $en, updated_at = $t")
            .bind(("id", id.to_string()))
            .bind(("en", enabled))
            .bind(("t", to_rfc3339(Utc::now())))
            .await?;
        Ok(())
    }

    /// Toggle NSEC3 (RFC 5155) hashed denial of existence for a zone (vs plain
    /// NSEC). Only takes effect when the zone also has DNSSEC signing enabled.
    ///
    /// # Errors
    /// Propagates a store error.
    pub async fn set_zone_nsec3_enabled(&self, id: &str, enabled: bool) -> DbResult<()> {
        self.inner
            .query("UPDATE type::record('zone', $id) SET nsec3_enabled = $en, updated_at = $t")
            .bind(("id", id.to_string()))
            .bind(("en", enabled))
            .bind(("t", to_rfc3339(Utc::now())))
            .await?;
        Ok(())
    }

    // ---- Replication (07_data_dns replication extension) ------------------

    /// Update a zone's replication settings (role, transfer/notify config).
    #[allow(clippy::too_many_arguments)]
    pub async fn update_zone_replication(
        &self,
        id: &str,
        role: ZoneRole,
        allow_transfer: &[String],
        also_notify: &[String],
        notify_enabled: bool,
        primaries: &[String],
        tsig_key_name: Option<&str>,
    ) -> DbResult<()> {
        let role_str = match role {
            ZoneRole::Primary => "primary",
            ZoneRole::Secondary => "secondary",
        };
        self.inner
            .query(
                "UPDATE type::record('zone', $id) SET role = $role, \
                 allow_transfer = $at, also_notify = $an, notify_enabled = $ne, \
                 primaries = $pr, tsig_key_name = $tk, updated_at = $t",
            )
            .bind(("id", id.to_string()))
            .bind(("role", role_str.to_string()))
            .bind(("at", allow_transfer.to_vec()))
            .bind(("an", also_notify.to_vec()))
            .bind(("ne", notify_enabled))
            .bind(("pr", primaries.to_vec()))
            .bind(("tk", tsig_key_name.map(|s| s.to_string())))
            .bind(("t", to_rfc3339(Utc::now())))
            .await?;
        Ok(())
    }

    /// Record the outcome of a secondary zone's transfer attempt.
    pub async fn set_zone_transfer_state(
        &self,
        id: &str,
        state: &ZoneTransferState,
    ) -> DbResult<()> {
        let json = serde_json::to_string(state).unwrap_or_default();
        self.inner
            .query("UPDATE type::record('zone', $id) SET transfer_state = $s")
            .bind(("id", id.to_string()))
            .bind(("s", json))
            .await?;
        Ok(())
    }

    /// Increment a zone's SOA serial (called after any record change so
    /// secondaries detect updates). Returns the new serial, if the zone exists.
    pub async fn bump_zone_serial(&self, zone_id: &str) -> DbResult<Option<u32>> {
        let Some(mut zone) = self.get_zone(zone_id).await? else {
            return Ok(None);
        };
        // Wrapping increment keeps the serial in u32 (RFC 1982 serial arithmetic
        // is honored by peers); avoid 0 which some implementations treat oddly.
        zone.soa.serial = zone.soa.serial.wrapping_add(1).max(1);
        let soa_json = serde_json::to_string(&zone.soa).unwrap_or_default();
        self.inner
            .query("UPDATE type::record('zone', $id) SET soa = $soa, updated_at = $t")
            .bind(("id", zone_id.to_string()))
            .bind(("soa", soa_json))
            .bind(("t", to_rfc3339(Utc::now())))
            .await?;
        Ok(Some(zone.soa.serial))
    }

    /// Replace all records of a (secondary) zone with a freshly transferred set,
    /// and update its SOA. Used by the AXFR client after a successful transfer.
    pub async fn replace_zone_records(
        &self,
        zone_id: &str,
        soa: &Soa,
        records: &[Record],
    ) -> DbResult<()> {
        // Update the SOA, then swap the record set atomically enough for our
        // single-writer store (delete-then-insert).
        let soa_json = serde_json::to_string(soa).unwrap_or_default();
        self.inner
            .query("UPDATE type::record('zone', $id) SET soa = $soa, updated_at = $t")
            .bind(("id", zone_id.to_string()))
            .bind(("soa", soa_json))
            .bind(("t", to_rfc3339(Utc::now())))
            .await?;
        self.inner
            .query("DELETE record WHERE zone = $z")
            .bind(("z", zone_id.to_string()))
            .await?;
        // Apply every record; surface (rather than swallow) failures so a partial
        // AXFR load is not reported as success — the secondary refresh logs it and
        // retries instead of silently serving an incomplete zone.
        let mut failed = 0usize;
        for rec in records {
            if self.create_record(rec).await.is_err() {
                failed += 1;
            }
        }
        if failed > 0 {
            return Err(DbError::Constraint(format!(
                "{failed} record(s) failed to apply during zone load"
            )));
        }
        Ok(())
    }

    /// Set a (secondary) zone's SOA without touching its records (used after
    /// applying IXFR deltas).
    pub async fn set_zone_soa(&self, zone_id: &str, soa: &Soa) -> DbResult<()> {
        let soa_json = serde_json::to_string(soa).unwrap_or_default();
        self.inner
            .query("UPDATE type::record('zone', $id) SET soa = $soa, updated_at = $t")
            .bind(("id", zone_id.to_string()))
            .bind(("soa", soa_json))
            .bind(("t", to_rfc3339(Utc::now())))
            .await?;
        Ok(())
    }

    /// Apply one IXFR difference sequence to a secondary zone: delete records
    /// matching `removed` (by name/type/data) and create `added`.
    pub async fn apply_zone_delta(
        &self,
        zone_id: &str,
        removed: &[Record],
        added: &[Record],
    ) -> DbResult<()> {
        let existing = self.list_records(zone_id).await?;
        for rem in removed {
            let target = normalize_name(&rem.name);
            if let Some(m) = existing.iter().find(|e| {
                normalize_name(&e.name) == target
                    && e.record_type == rem.record_type
                    && e.data == rem.data
            }) {
                let _: Option<RecordRecord> = self.inner.delete(("record", m.id.as_str())).await?;
            }
        }
        let mut failed = 0usize;
        for add in added {
            let mut rec = add.clone();
            rec.zone = zone_id.to_string();
            if self.create_record(&rec).await.is_err() {
                failed += 1;
            }
        }
        if failed > 0 {
            return Err(DbError::Constraint(format!(
                "{failed} record(s) failed to apply during IXFR delta"
            )));
        }
        Ok(())
    }

    /// Repoint (upsert) the address record for `fqdn` in the zone whose apex is
    /// `zone_apex` to `ip`, replacing any existing record of the same family (A for IPv4,
    /// AAAA for IPv6) at that name. Bumps the zone serial and journals the change, so
    /// secondaries transfer it and the live server — which reads a fresh snapshot per query
    /// — answers with the new address immediately. Used by the control plane to steer client
    /// traffic to a newly-promoted server on failover.
    ///
    /// Returns the new zone serial, or `Ok(None)` if this node does not serve that zone.
    ///
    /// # Errors
    /// A store error while listing, deleting, creating, or journaling.
    pub async fn repoint_address_record(
        &self,
        zone_apex: &str,
        fqdn: &str,
        ip: std::net::IpAddr,
        ttl: u32,
        actor: &str,
    ) -> DbResult<Option<u32>> {
        let apex = normalize_name(zone_apex);
        let owner = normalize_name(fqdn);
        let Some(zone) = self
            .list_zones()
            .await?
            .into_iter()
            .find(|z| normalize_name(&z.name) == apex)
        else {
            return Ok(None);
        };
        let (rtype, data) = match ip {
            std::net::IpAddr::V4(v4) => (
                RecordType::A,
                serde_json::json!({ "address": v4.to_string() }),
            ),
            std::net::IpAddr::V6(v6) => (
                RecordType::Aaaa,
                serde_json::json!({ "address": v6.to_string() }),
            ),
        };
        // Replace only the same address family at this name (leave a dual-stack peer alone).
        let removed: Vec<Record> = self
            .list_records(&zone.id)
            .await?
            .into_iter()
            .filter(|r| r.record_type == rtype && normalize_name(&r.name) == owner)
            .collect();
        // No-op when the record already holds exactly this address (avoid a needless serial
        // bump + zone transfer on every poll after a steady-state failover).
        if removed.len() == 1 && removed[0].data == data && removed[0].ttl == ttl {
            return Ok(None);
        }
        let now = Utc::now();
        let new_record = Record {
            id: String::new(),
            created_at: now,
            updated_at: now,
            created_by: actor.to_string(),
            zone: zone.id.clone(),
            name: owner,
            ttl,
            record_type: rtype,
            data,
            enabled: true,
        };
        for r in &removed {
            self.delete_record(&r.id).await?;
        }
        let created = self.create_record(&new_record).await?;
        let serial = self.bump_zone_serial(&zone.id).await?.unwrap_or(0);
        self.append_zone_journal(&zone.id, serial, std::slice::from_ref(&created), &removed)
            .await?;
        Ok(Some(serial))
    }

    // ---- TSIG keys (RFC 8945) ---------------------------------------------

    /// List TSIG keys with secrets redacted (safe for clients).
    pub async fn list_tsig_keys(&self) -> DbResult<Vec<TsigKey>> {
        let recs: Vec<TsigKeyRecord> = self
            .inner
            .query("SELECT * FROM tsig_key ORDER BY name ASC")
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .map(TsigKeyRecord::into_model_redacted)
            .collect())
    }

    /// Create a TSIG key. The secret is stored server-side and never projected.
    pub async fn create_tsig_key(
        &self,
        name: &str,
        algorithm: TsigAlgorithm,
        secret_b64: &str,
        actor: &str,
    ) -> DbResult<TsigKey> {
        let now = to_rfc3339(Utc::now());
        let rec = TsigKeyRecord {
            id: None,
            name: name.to_string(),
            algorithm: algorithm.wire_name().to_string(),
            secret: secret_b64.to_string(),
            created_at: now.clone(),
            updated_at: now,
            created_by: actor.to_string(),
        };
        let created: Option<TsigKeyRecord> = self.inner.create("tsig_key").content(rec).await?;
        created
            .map(TsigKeyRecord::into_model_redacted)
            .ok_or_else(|| DbError::Constraint("tsig key creation returned nothing".into()))
    }

    /// Delete a TSIG key by id.
    pub async fn delete_tsig_key(&self, id: &str) -> DbResult<()> {
        let _: Option<TsigKeyRecord> = self.inner.delete(("tsig_key", id)).await?;
        Ok(())
    }

    /// The algorithm + base64 secret for a TSIG key by name (server-side use in
    /// the DNS transfer path). Never exposed through a server function.
    pub async fn get_tsig_secret(&self, name: &str) -> DbResult<Option<(TsigAlgorithm, String)>> {
        let recs: Vec<TsigKeyRecord> = self
            .inner
            .query("SELECT * FROM tsig_key WHERE name = $n LIMIT 1")
            .bind(("n", name.to_string()))
            .await?
            .take(0)?;
        Ok(recs.into_iter().next().map(|r| {
            let alg = r.algorithm();
            (alg, r.secret)
        }))
    }

    /// The stored DNSSEC private key (PKCS#8 DER) for a zone, if generated. Keys
    /// are server-side material and never projected to clients.
    pub async fn get_zone_dnssec_key(&self, zone_name: &str) -> DbResult<Option<Vec<u8>>> {
        let encoded: Vec<String> = self
            .inner
            .query("SELECT VALUE key_der FROM dns_dnssec_key WHERE zone_name = $z LIMIT 1")
            .bind(("z", normalize_name(zone_name)))
            .await?
            .take(0)?;
        Ok(encoded.into_iter().next().and_then(|e| {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.decode(e).ok()
        }))
    }

    /// Store (or replace) a zone's DNSSEC private key (PKCS#8 DER).
    pub async fn put_zone_dnssec_key(&self, zone_name: &str, key_der: &[u8]) -> DbResult<()> {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(key_der);
        let zone = normalize_name(zone_name);
        // Replace any existing key, then insert the new one (single row per zone).
        self.inner
            .query("DELETE dns_dnssec_key WHERE zone_name = $z")
            .bind(("z", zone.clone()))
            .await?;
        self.inner
            .query("CREATE dns_dnssec_key CONTENT { zone_name: $z, key_der: $k }")
            .bind(("z", zone))
            .bind(("k", encoded))
            .await?;
        Ok(())
    }

    /// The owning zone id of a record, if it exists (used to bump the zone
    /// serial after a record delete).
    pub async fn get_record_zone(&self, record_id: &str) -> DbResult<Option<String>> {
        let zones: Vec<String> = self
            .inner
            .query("SELECT VALUE zone FROM type::record('record', $id)")
            .bind(("id", record_id.to_string()))
            .await?
            .take(0)?;
        Ok(zones.into_iter().next())
    }

    /// Number of records owned by a zone (for the AC-13 cascade prompt).
    pub async fn count_records_in_zone(&self, zone_id: &str) -> DbResult<usize> {
        Ok(self.list_records(zone_id).await?.len())
    }

    /// Delete a zone and cascade-delete its records (AC-13). Returns how many
    /// records were removed alongside the zone.
    pub async fn delete_zone_cascade(&self, zone_id: &str) -> DbResult<usize> {
        let count = self.count_records_in_zone(zone_id).await?;
        self.inner
            .query("DELETE record WHERE zone = $z")
            .bind(("z", zone_id.to_string()))
            .await?;
        self.inner
            .query("DELETE zone_journal WHERE zone = $z")
            .bind(("z", zone_id.to_string()))
            .await?;
        let _: Option<ZoneRecord> = self.inner.delete(("zone", zone_id)).await?;
        Ok(count)
    }

    // ---- Records ----------------------------------------------------------

    /// List records within a zone, ordered by name then type.
    pub async fn list_records(&self, zone_id: &str) -> DbResult<Vec<Record>> {
        let recs: Vec<RecordRecord> = self
            .inner
            .query("SELECT * FROM record WHERE zone = $z ORDER BY name ASC, record_type ASC")
            .bind(("z", zone_id.to_string()))
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(RecordRecord::into_model).collect())
    }

    /// Reject a create/update that would break CNAME coexistence (08 §5.2):
    /// a CNAME cannot share a name with any other record, and vice versa.
    async fn check_cname_coexistence(
        &self,
        zone_id: &str,
        name: &str,
        record_type: RecordType,
        exclude_id: Option<&str>,
    ) -> DbResult<()> {
        let target = normalize_name(name);
        let siblings: Vec<Record> = self
            .list_records(zone_id)
            .await?
            .into_iter()
            .filter(|r| normalize_name(&r.name) == target)
            .filter(|r| exclude_id != Some(r.id.as_str()))
            .collect();
        let new_is_cname = record_type == RecordType::Cname;
        let conflict = siblings
            .iter()
            .any(|r| new_is_cname || r.record_type == RecordType::Cname)
            && !siblings.is_empty();
        if conflict {
            return Err(DbError::Constraint(CNAME_CONFLICT.into()));
        }
        Ok(())
    }

    /// Create a record (CNAME coexistence enforced).
    pub async fn create_record(&self, record: &Record) -> DbResult<Record> {
        self.check_cname_coexistence(&record.zone, &record.name, record.record_type, None)
            .await?;
        let now = to_rfc3339(Utc::now());
        let rec = RecordRecord {
            id: None,
            zone: record.zone.clone(),
            name: normalize_name(&record.name),
            ttl: record.ttl,
            record_type: record.record_type.as_str().to_string(),
            data: serde_json::to_string(&record.data).unwrap_or_default(),
            enabled: record.enabled,
            created_at: now.clone(),
            updated_at: now,
            created_by: record.created_by.clone(),
        };
        let created: Option<RecordRecord> = self.inner.create("record").content(rec).await?;
        created
            .map(RecordRecord::into_model)
            .ok_or_else(|| DbError::Constraint("record creation returned nothing".into()))
    }

    /// Update a record's mutable fields.
    pub async fn update_record(&self, record: &Record) -> DbResult<Option<Record>> {
        self.check_cname_coexistence(
            &record.zone,
            &record.name,
            record.record_type,
            Some(&record.id),
        )
        .await?;
        let now = to_rfc3339(Utc::now());
        let updated: Vec<RecordRecord> = self
            .inner
            .query(
                "UPDATE type::record('record', $id) SET name = $name, ttl = $ttl, \
                 record_type = $rt, data = $data, enabled = $en, updated_at = $t",
            )
            .bind(("id", record.id.clone()))
            .bind(("name", normalize_name(&record.name)))
            .bind(("ttl", record.ttl))
            .bind(("rt", record.record_type.as_str().to_string()))
            .bind((
                "data",
                serde_json::to_string(&record.data).unwrap_or_default(),
            ))
            .bind(("en", record.enabled))
            .bind(("t", now))
            .await?
            .take(0)?;
        Ok(updated.into_iter().next().map(RecordRecord::into_model))
    }

    /// Delete a record by id.
    pub async fn delete_record(&self, id: &str) -> DbResult<()> {
        let _: Option<RecordRecord> = self.inner.delete(("record", id)).await?;
        Ok(())
    }

    /// Fetch a single record by id (used to capture the pre-image for the IXFR
    /// journal on update/delete).
    pub async fn get_record(&self, id: &str) -> DbResult<Option<Record>> {
        let rec: Option<RecordRecord> = self.inner.select(("record", id)).await?;
        Ok(rec.map(RecordRecord::into_model))
    }

    // ---- IXFR change journal (RFC 1995) -----------------------------------

    /// Append an IXFR journal entry for a zone: the delta (records added and
    /// removed) that produced `serial`. Enables incremental transfers.
    pub async fn append_zone_journal(
        &self,
        zone_id: &str,
        serial: u32,
        added: &[Record],
        removed: &[Record],
    ) -> DbResult<()> {
        let rec = JournalRecord {
            id: None,
            zone: zone_id.to_string(),
            serial,
            added: serde_json::to_string(added).unwrap_or_else(|_| "[]".into()),
            removed: serde_json::to_string(removed).unwrap_or_else(|_| "[]".into()),
            at: to_rfc3339(Utc::now()),
        };
        let _: Option<JournalRecord> = self.inner.create("zone_journal").content(rec).await?;
        Ok(())
    }

    /// Journal deltas for a zone with serial greater than `from_serial`, ordered
    /// ascending. The caller checks continuity and falls back to AXFR if the
    /// chain does not reach back to the client's serial.
    pub async fn zone_journal_since(
        &self,
        zone_id: &str,
        from_serial: u32,
    ) -> DbResult<Vec<(u32, Vec<Record>, Vec<Record>)>> {
        let recs: Vec<JournalRecord> = self
            .inner
            .query("SELECT * FROM zone_journal WHERE zone = $z AND serial > $s ORDER BY serial ASC")
            .bind(("z", zone_id.to_string()))
            .bind(("s", from_serial))
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .map(|r| {
                let added = serde_json::from_str(&r.added).unwrap_or_default();
                let removed = serde_json::from_str(&r.removed).unwrap_or_default();
                (r.serial, added, removed)
            })
            .collect())
    }

    // ---- RPZ --------------------------------------------------------------

    /// List all RPZ rules.
    pub async fn list_rpz(&self) -> DbResult<Vec<RpzRule>> {
        let recs: Vec<RpzRecord> = self
            .inner
            .query("SELECT * FROM rpz ORDER BY domain ASC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(RpzRecord::into_model).collect())
    }

    /// Create an RPZ rule.
    pub async fn create_rpz(&self, rule: &RpzRule) -> DbResult<RpzRule> {
        let now = to_rfc3339(Utc::now());
        let rec = RpzRecord {
            id: None,
            domain: normalize_name(&rule.domain),
            action: rule.action.as_str().to_string(),
            redirect_to: rule.redirect_to.clone(),
            enabled: rule.enabled,
            created_at: now.clone(),
            updated_at: now,
            created_by: rule.created_by.clone(),
        };
        let created: Option<RpzRecord> = self.inner.create("rpz").content(rec).await?;
        created
            .map(RpzRecord::into_model)
            .ok_or_else(|| DbError::Constraint("rpz creation returned nothing".into()))
    }

    /// Update an RPZ rule.
    pub async fn update_rpz(&self, rule: &RpzRule) -> DbResult<Option<RpzRule>> {
        let now = to_rfc3339(Utc::now());
        let updated: Vec<RpzRecord> = self
            .inner
            .query(
                "UPDATE type::record('rpz', $id) SET domain = $d, action = $a, \
                 redirect_to = $r, enabled = $en, updated_at = $t",
            )
            .bind(("id", rule.id.clone()))
            .bind(("d", normalize_name(&rule.domain)))
            .bind(("a", rule.action.as_str().to_string()))
            .bind(("r", rule.redirect_to.clone()))
            .bind(("en", rule.enabled))
            .bind(("t", now))
            .await?
            .take(0)?;
        Ok(updated.into_iter().next().map(RpzRecord::into_model))
    }

    /// Delete an RPZ rule by id.
    pub async fn delete_rpz(&self, id: &str) -> DbResult<()> {
        let _: Option<RpzRecord> = self.inner.delete(("rpz", id)).await?;
        Ok(())
    }

    /// Headline DNS metrics for the dashboard (07_data_dns §5 note / §3.11):
    /// zone count and record count.
    pub async fn dns_metrics(&self) -> DbResult<(usize, usize)> {
        let zones = self.list_zones().await?.len();
        let records: Vec<RecordRecord> = self.inner.query("SELECT * FROM record").await?.take(0)?;
        Ok((zones, records.len()))
    }

    // ---- GeoDNS rules -----------------------------------------------------

    /// List all GeoDNS rules.
    pub async fn list_geo_rules(&self) -> DbResult<Vec<GeoRule>> {
        let recs: Vec<GeoRuleRecord> = self
            .inner
            .query("SELECT * FROM geo_rule ORDER BY name ASC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(GeoRuleRecord::into_model).collect())
    }

    /// Enabled GeoDNS rules for a `name` + `record_type` (embedded server path).
    pub async fn find_geo_rules(
        &self,
        name: &str,
        record_type: RecordType,
    ) -> DbResult<Vec<GeoRule>> {
        let recs: Vec<GeoRuleRecord> = self
            .inner
            .query("SELECT * FROM geo_rule WHERE name = $n AND record_type = $t AND enabled = true")
            .bind(("n", normalize_name(name)))
            .bind(("t", record_type.as_str().to_string()))
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(GeoRuleRecord::into_model).collect())
    }

    /// Create a GeoDNS rule.
    pub async fn create_geo_rule(&self, rule: &GeoRule) -> DbResult<GeoRule> {
        let now = to_rfc3339(Utc::now());
        let rec = GeoRuleRecord {
            id: None,
            zone: rule.zone.clone(),
            name: normalize_name(&rule.name),
            record_type: rule.record_type.as_str().to_string(),
            ttl: rule.ttl,
            default_data: serde_json::to_string(&rule.default_data)
                .unwrap_or_else(|_| "null".into()),
            regions: serde_json::to_string(&rule.regions).unwrap_or_else(|_| "[]".into()),
            enabled: rule.enabled,
            created_at: now.clone(),
            updated_at: now,
            created_by: rule.created_by.clone(),
        };
        let created: Option<GeoRuleRecord> = self.inner.create("geo_rule").content(rec).await?;
        created
            .map(GeoRuleRecord::into_model)
            .ok_or_else(|| DbError::Constraint("geo rule creation returned nothing".into()))
    }

    /// Delete a GeoDNS rule.
    pub async fn delete_geo_rule(&self, id: &str) -> DbResult<()> {
        let _: Option<GeoRuleRecord> = self.inner.delete(("geo_rule", id)).await?;
        Ok(())
    }

    /// Toggle a GeoDNS rule.
    pub async fn set_geo_rule_enabled(&self, id: &str, enabled: bool) -> DbResult<()> {
        self.inner
            .query("UPDATE type::record('geo_rule', $id) SET enabled = $en, updated_at = $t")
            .bind(("id", id.to_string()))
            .bind(("en", enabled))
            .bind(("t", to_rfc3339(Utc::now())))
            .await?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct GeoRuleRecord {
    id: Option<RecordId>,
    zone: String,
    name: String,
    record_type: String,
    ttl: u32,
    /// JSON-encoded default answer data.
    default_data: String,
    /// JSON-encoded `Vec<GeoRegion>`.
    regions: String,
    enabled: bool,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl GeoRuleRecord {
    fn into_model(self) -> GeoRule {
        GeoRule {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            zone: self.zone,
            name: self.name,
            record_type: RecordType::from_str(&self.record_type).unwrap_or(RecordType::A),
            ttl: self.ttl,
            default_data: serde_json::from_str(&self.default_data)
                .unwrap_or(serde_json::Value::Null),
            regions: serde_json::from_str(&self.regions).unwrap_or_default(),
            enabled: self.enabled,
        }
    }
}

// ---- DNS server settings (forwarders) -------------------------------------

/// Singleton row holding the editable DNS server settings. Currently just the
/// upstream forwarders; kept as its own JSON field so future settings can be added.
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct DnsSettingsRecord {
    id: Option<RecordId>,
    /// JSON-encoded `Vec<String>` of upstream forwarder `host:port` entries.
    forwarders: String,
}

impl Db {
    /// The configured DNS forwarders (upstream resolvers as `host:port`), or `None`
    /// when never seeded. The DNS server seeds this from the file config on first run
    /// via [`ensure_dns_forwarders`](Self::ensure_dns_forwarders); thereafter the
    /// stored value is authoritative and editable from the Web UI.
    pub async fn get_dns_forwarders(&self) -> DbResult<Option<Vec<String>>> {
        let recs: Vec<DnsSettingsRecord> = self
            .inner
            .query("SELECT * FROM dns_settings LIMIT 1")
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .next()
            .map(|r| serde_json::from_str(&r.forwarders).unwrap_or_default()))
    }

    /// Seed the DNS forwarders from `seed` (the file config) on first run and return
    /// the effective list. If a row already exists (operator-edited), it wins and
    /// `seed` is ignored — the same config→DB-once, DB-wins-after contract used for
    /// the LDAP base DN.
    pub async fn ensure_dns_forwarders(&self, seed: &[String]) -> DbResult<Vec<String>> {
        if let Some(existing) = self.get_dns_forwarders().await? {
            return Ok(existing);
        }
        self.save_dns_forwarders(seed).await?;
        Ok(seed.to_vec())
    }

    /// Replace the DNS forwarders (upsert the singleton). Applied without a restart —
    /// the DNS server re-reads the list periodically.
    pub async fn save_dns_forwarders(&self, forwarders: &[String]) -> DbResult<()> {
        let json = serde_json::to_string(forwarders).unwrap_or_else(|_| "[]".into());
        let recs: Vec<DnsSettingsRecord> = self
            .inner
            .query("SELECT * FROM dns_settings LIMIT 1")
            .await?
            .take(0)?;
        if recs.is_empty() {
            let _: Option<DnsSettingsRecord> = self
                .inner
                .create("dns_settings")
                .content(DnsSettingsRecord {
                    id: None,
                    forwarders: json,
                })
                .await?;
        } else {
            self.inner
                .query("UPDATE dns_settings SET forwarders = $f")
                .bind(("f", json))
                .await?;
        }
        Ok(())
    }

    // ---- Dynamic-DNS client (settings + last status) ----------------------

    /// The stored dynamic-DNS client settings, or `None` when never seeded. Includes the
    /// provider secret for the updater; the server-fn layer scrubs it before projecting.
    pub async fn get_ddns_config(&self) -> DbResult<Option<DdnsConfig>> {
        let recs: Vec<SingletonRecord> = self
            .inner
            .query("SELECT * FROM ddnsconfig LIMIT 1")
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .next()
            .and_then(|r| serde_json::from_str(&r.config).ok()))
    }

    /// Seed the DDNS settings from `seed` (file config) on first run; a stored row
    /// (Web-UI edited) wins thereafter. `None` seed with no row leaves DDNS unset.
    pub async fn ensure_ddns_config(
        &self,
        seed: Option<DdnsConfig>,
    ) -> DbResult<Option<DdnsConfig>> {
        if let Some(existing) = self.get_ddns_config().await? {
            return Ok(Some(existing));
        }
        match seed {
            Some(cfg) => {
                self.save_ddns_config(&cfg).await?;
                Ok(Some(cfg))
            }
            None => Ok(None),
        }
    }

    /// Create or replace the DDNS settings (upsert the singleton). Applied without a
    /// restart — the DDNS scheduler re-reads them on its next poll.
    pub async fn save_ddns_config(&self, config: &DdnsConfig) -> DbResult<()> {
        let json = serde_json::to_string(config).unwrap_or_default();
        self.upsert_singleton("ddnsconfig", &json).await
    }

    /// The outcome of the last DDNS update (for the Web UI), defaulting when never run.
    pub async fn get_ddns_status(&self) -> DbResult<DdnsStatus> {
        let recs: Vec<SingletonRecord> = self
            .inner
            .query("SELECT * FROM ddnsstatus LIMIT 1")
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .next()
            .and_then(|r| serde_json::from_str(&r.config).ok())
            .unwrap_or_default())
    }

    /// Record the outcome of a DDNS update run.
    pub async fn record_ddns_status(&self, status: &DdnsStatus) -> DbResult<()> {
        let json = serde_json::to_string(status).unwrap_or_default();
        self.upsert_singleton("ddnsstatus", &json).await
    }

    /// Upsert a `{ config: <json> }` singleton row in `table`.
    async fn upsert_singleton(&self, table: &str, json: &str) -> DbResult<()> {
        let recs: Vec<SingletonRecord> = self
            .inner
            .query(format!("SELECT * FROM {table} LIMIT 1"))
            .await?
            .take(0)?;
        if recs.is_empty() {
            let _: Option<SingletonRecord> = self
                .inner
                .create(table.to_string())
                .content(SingletonRecord {
                    id: None,
                    config: json.to_string(),
                })
                .await?;
        } else {
            self.inner
                .query(format!("UPDATE {table} SET config = $c"))
                .bind(("c", json.to_string()))
                .await?;
        }
        Ok(())
    }
}

/// A generic `{ config: <json> }` singleton row (DDNS config / status).
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct SingletonRecord {
    id: Option<RecordId>,
    config: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    async fn test_db() -> (Db, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        (db, dir)
    }

    fn record(zone: &str, name: &str, rt: RecordType, data: serde_json::Value) -> Record {
        Record {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "admin".into(),
            zone: zone.to_string(),
            name: name.to_string(),
            ttl: 3600,
            record_type: rt,
            data,
            enabled: true,
        }
    }

    #[tokio::test]
    async fn ddns_config_and_status_roundtrip() {
        let (db, _dir) = test_db().await;
        assert!(db.get_ddns_config().await.unwrap().is_none());
        // Seed on first run.
        let seed = DdnsConfig {
            enabled: true,
            hostname: "home.example.com".into(),
            server: "dynupdate.no-ip.com".into(),
            username: "u".into(),
            password: "secret".into(),
            update_time: "04:30".into(),
            ..Default::default()
        };
        let eff = db
            .ensure_ddns_config(Some(seed.clone()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(eff.hostname, "home.example.com");
        assert_eq!(eff.update_time, "04:30");
        // Edit wins over the seed.
        let mut edited = seed.clone();
        edited.update_time = "06:00".into();
        db.save_ddns_config(&edited).await.unwrap();
        let after = db.ensure_ddns_config(Some(seed)).await.unwrap().unwrap();
        assert_eq!(after.update_time, "06:00");
        assert_eq!(after.password, "secret");
        // Status defaults, then records.
        assert!(db.get_ddns_status().await.unwrap().last_run.is_none());
        db.record_ddns_status(&DdnsStatus {
            last_run: Some("2026-09-05T04:30:00+00:00".into()),
            last_ok: true,
            last_message: "good".into(),
            last_ip: Some("203.0.113.5".into()),
        })
        .await
        .unwrap();
        let st = db.get_ddns_status().await.unwrap();
        assert!(st.last_ok);
        assert_eq!(st.last_ip.as_deref(), Some("203.0.113.5"));
    }

    #[tokio::test]
    async fn repoint_address_record_upserts_a_and_bumps_serial() {
        let (db, _dir) = test_db().await;
        let zone = db
            .create_zone("example.com", &Soa::default(), true, "admin")
            .await
            .unwrap();
        // Seed an existing A record pointing at the old primary.
        db.create_record(&record(
            &zone.id,
            "app.example.com.",
            RecordType::A,
            json!({ "address": "10.0.0.1" }),
        ))
        .await
        .unwrap();

        // Repoint it to the new active server.
        let serial = db
            .repoint_address_record(
                "example.com",
                "app.example.com",
                "10.0.0.2".parse().unwrap(),
                60,
                "center",
            )
            .await
            .unwrap();
        assert!(serial.is_some(), "zone found → serial bumped");

        // Exactly one A record at that name, holding the new address + ttl.
        let a: Vec<_> = db
            .list_records(&zone.id)
            .await
            .unwrap()
            .into_iter()
            .filter(|r| {
                normalize_name(&r.name) == "app.example.com" && r.record_type == RecordType::A
            })
            .collect();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].data, json!({ "address": "10.0.0.2" }));
        assert_eq!(a[0].ttl, 60);

        // Re-applying the same address is a no-op (no needless serial bump / transfer).
        let again = db
            .repoint_address_record(
                "example.com",
                "app.example.com",
                "10.0.0.2".parse().unwrap(),
                60,
                "center",
            )
            .await
            .unwrap();
        assert!(again.is_none(), "idempotent repoint does nothing");

        // An unknown zone is reported as not served here.
        let missing = db
            .repoint_address_record(
                "nope.example.org",
                "x.nope.example.org",
                "10.0.0.9".parse().unwrap(),
                60,
                "center",
            )
            .await
            .unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn dns_forwarders_seed_then_db_wins() {
        let (db, _dir) = test_db().await;
        // Unseeded: no value.
        assert!(db.get_dns_forwarders().await.unwrap().is_none());
        // First run seeds from the file config.
        let seed = vec!["8.8.8.8:53".to_string(), "1.1.1.1:53".to_string()];
        assert_eq!(db.ensure_dns_forwarders(&seed).await.unwrap(), seed);
        // A Web-UI edit is persisted and wins over the seed thereafter.
        db.save_dns_forwarders(&["9.9.9.9:53".to_string()])
            .await
            .unwrap();
        assert_eq!(
            db.ensure_dns_forwarders(&seed).await.unwrap(),
            vec!["9.9.9.9:53".to_string()]
        );
        assert_eq!(
            db.get_dns_forwarders().await.unwrap(),
            Some(vec!["9.9.9.9:53".to_string()])
        );
    }

    #[tokio::test]
    async fn zone_crud_and_unique_name() {
        let (db, _dir) = test_db().await;
        let zone = db
            .create_zone("example.com", &Soa::default(), true, "admin")
            .await
            .unwrap();
        assert_eq!(zone.name, "example.com");
        assert!(db
            .create_zone("example.com", &Soa::default(), true, "admin")
            .await
            .is_err());
        assert_eq!(db.list_zones().await.unwrap().len(), 1);
        assert!(db.get_zone(&zone.id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn cascade_delete_reports_record_count() {
        let (db, _dir) = test_db().await;
        let zone = db
            .create_zone("example.com", &Soa::default(), true, "admin")
            .await
            .unwrap();
        db.create_record(&record(
            &zone.id,
            "www.example.com",
            RecordType::A,
            json!({"address": "192.0.2.1"}),
        ))
        .await
        .unwrap();
        db.create_record(&record(
            &zone.id,
            "mail.example.com",
            RecordType::A,
            json!({"address": "192.0.2.2"}),
        ))
        .await
        .unwrap();
        assert_eq!(db.count_records_in_zone(&zone.id).await.unwrap(), 2);
        assert_eq!(db.delete_zone_cascade(&zone.id).await.unwrap(), 2);
        assert!(db.get_zone(&zone.id).await.unwrap().is_none());
        assert_eq!(db.list_records(&zone.id).await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn zone_update_persists() {
        let (db, _dir) = test_db().await;
        let zone = db
            .create_zone("example.com", &Soa::default(), true, "admin")
            .await
            .unwrap();
        let soa = Soa {
            serial: 42,
            ..Default::default()
        };
        db.update_zone(&zone.id, &soa, false).await.unwrap();
        let fetched = db.get_zone(&zone.id).await.unwrap().unwrap();
        assert_eq!(fetched.soa.serial, 42);
        assert!(!fetched.enabled);
    }

    #[tokio::test]
    async fn cname_coexistence_is_rejected() {
        let (db, _dir) = test_db().await;
        let zone = db
            .create_zone("example.com", &Soa::default(), true, "admin")
            .await
            .unwrap();
        db.create_record(&record(
            &zone.id,
            "www.example.com",
            RecordType::A,
            json!({"address": "192.0.2.1"}),
        ))
        .await
        .unwrap();
        // A CNAME at the same name must be rejected.
        let err = db
            .create_record(&record(
                &zone.id,
                "www.example.com",
                RecordType::Cname,
                json!({"target": "host.example.com"}),
            ))
            .await;
        assert!(err.is_err());
    }
}
