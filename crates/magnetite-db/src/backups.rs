//! Cross-cutting configuration backup / restore (07 §3.6 / F-06 / screen_backup).
//!
//! A backup captures the target domain's tables as a JSON snapshot stored
//! inline on the `backup` row. Restore replaces those tables from the snapshot.
//! Admin-only and audited at the server-fn layer; restore is destructive.

use crate::error::{DbError, DbResult};
use crate::records::{parse_rfc3339, record_key, to_rfc3339};
use crate::store::Db;
use chrono::Utc;
use magnetite_core::domain::DomainKey;
use magnetite_core::models::common::{BackupKind, RecordMeta};
use magnetite_core::models::Backup;
use serde::{Deserialize, Serialize};
use surrealdb::types::{RecordId, SurrealValue};

/// Current snapshot format. Restore refuses anything else (AC-09 / E-04).
const FORMAT_VERSION: &str = "1";
const MSG_INCOMPATIBLE: &str = "このバックアップはリストアできません（形式が不正です）。";

/// Tables owned by a domain. `Portal` means a whole-system (all-domain) backup.
fn domain_tables(domain: DomainKey) -> Vec<&'static str> {
    match domain {
        DomainKey::Dns => vec!["zone", "record", "rpz"],
        DomainKey::Dhcp => vec!["pool", "reservation", "lease", "dhcp_config"],
        DomainKey::Ldap => vec!["entry"],
        DomainKey::Mail => vec![
            "maildomain",
            "mailuser",
            "alias",
            "mailinglist",
            "mailserverconfig",
        ],
        DomainKey::Proxy => vec!["vhost", "certificate", "acl_rule", "ip_block"],
        DomainKey::K8s => vec!["k8s_host", "k8s_cluster", "k8s_alert_rule", "k8s_template"],
        DomainKey::Sso => vec!["sso_provider", "sso_client", "sso_session"],
        DomainKey::Watch => vec![
            "watch_host",
            "watch_group",
            "watch_rule",
            "watch_maintenance",
            "watch_metric",
        ],
        DomainKey::Addc => vec!["ad_principal"],
        DomainKey::Portal => DomainKey::DOMAINS
            .into_iter()
            .flat_map(domain_tables)
            .collect(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct BackupRecord {
    id: Option<RecordId>,
    domain: String,
    kind: String,
    size_bytes: i64,
    format_version: String,
    /// Inline JSON snapshot ({table: [rows...]}).
    artifact: String,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl BackupRecord {
    fn into_model(self) -> Backup {
        let id = record_key(&self.id);
        Backup {
            meta: RecordMeta {
                id: id.clone(),
                created_at: parse_rfc3339(&self.created_at),
                updated_at: parse_rfc3339(&self.updated_at),
                created_by: self.created_by,
            },
            domain: DomainKey::from_str(&self.domain).unwrap_or(DomainKey::Portal),
            kind: if self.kind == "auto" {
                BackupKind::Auto
            } else {
                BackupKind::Manual
            },
            size_bytes: self.size_bytes.max(0) as u64,
            artifact_ref: id,
            format_version: self.format_version,
        }
    }
}

impl Db {
    async fn snapshot_tables(&self, tables: &[&str]) -> DbResult<String> {
        let mut map = serde_json::Map::new();
        for table in tables {
            let rows: Vec<serde_json::Value> = self
                .inner
                .query(format!("SELECT * FROM {table}"))
                .await?
                .take(0)?;
            map.insert((*table).to_string(), serde_json::Value::Array(rows));
        }
        serde_json::to_string(&serde_json::Value::Object(map))
            .map_err(|e| DbError::Constraint(format!("snapshot serialization failed: {e}")))
    }

    /// Create a manual backup of the target domain (E-01).
    pub async fn create_backup(&self, domain: DomainKey, actor: &str) -> DbResult<Backup> {
        let artifact = self.snapshot_tables(&domain_tables(domain)).await?;
        let now = to_rfc3339(Utc::now());
        let rec = BackupRecord {
            id: None,
            domain: domain.as_str().to_string(),
            kind: "manual".into(),
            size_bytes: artifact.len() as i64,
            format_version: FORMAT_VERSION.into(),
            artifact,
            created_at: now.clone(),
            updated_at: now,
            created_by: actor.to_string(),
        };
        let created: Option<BackupRecord> = self.inner.create("backup").content(rec).await?;
        created
            .map(BackupRecord::into_model)
            .ok_or_else(|| DbError::Constraint("backup creation failed".into()))
    }

    /// List backups (optionally filtered by domain), newest-first (C-03).
    pub async fn list_backups(&self, domain: Option<DomainKey>) -> DbResult<Vec<Backup>> {
        let recs: Vec<BackupRecord> = match domain {
            Some(d) => self
                .inner
                .query("SELECT * FROM backup WHERE domain = $d ORDER BY created_at DESC")
                .bind(("d", d.as_str().to_string()))
                .await?
                .take(0)?,
            None => self
                .inner
                .query("SELECT * FROM backup ORDER BY created_at DESC")
                .await?
                .take(0)?,
        };
        Ok(recs.into_iter().map(BackupRecord::into_model).collect())
    }

    async fn find_backup(&self, id: &str) -> DbResult<Option<BackupRecord>> {
        let rec: Option<BackupRecord> = self.inner.select(("backup", id)).await?;
        Ok(rec)
    }

    /// Restore a backup, replacing its tables from the snapshot (E-03). Refuses
    /// a snapshot whose format is unknown or corrupt (E-04 / AC-09).
    pub async fn restore_backup(&self, id: &str) -> DbResult<()> {
        let rec = self.find_backup(id).await?.ok_or(DbError::NotFound)?;
        if rec.format_version != FORMAT_VERSION {
            return Err(DbError::Constraint(MSG_INCOMPATIBLE.into()));
        }
        let snapshot: serde_json::Value = serde_json::from_str(&rec.artifact)
            .map_err(|_| DbError::Constraint(MSG_INCOMPATIBLE.into()))?;
        let tables = snapshot
            .as_object()
            .ok_or_else(|| DbError::Constraint(MSG_INCOMPATIBLE.into()))?;
        for (table, rows) in tables {
            self.inner.query(format!("DELETE {table}")).await?;
            if let Some(arr) = rows.as_array() {
                if !arr.is_empty() {
                    self.inner
                        .query(format!("INSERT INTO {table} $rows"))
                        .bind(("rows", rows.clone()))
                        .await?;
                }
            }
        }
        Ok(())
    }

    /// Delete a backup (E-05).
    pub async fn delete_backup(&self, id: &str) -> DbResult<()> {
        let _: Option<BackupRecord> = self.inner.delete(("backup", id)).await?;
        Ok(())
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

    #[tokio::test]
    async fn backup_restore_round_trips_dns() {
        use magnetite_core::domains::dns::model::Soa;
        let (db, _dir) = test_db().await;
        // Seed a DNS zone.
        db.create_zone("example.com", &Soa::default(), true, "admin")
            .await
            .unwrap();
        assert_eq!(db.list_zones().await.unwrap().len(), 1);

        // Back it up.
        let backup = db.create_backup(DomainKey::Dns, "admin").await.unwrap();
        assert!(backup.size_bytes > 0);
        assert_eq!(
            db.list_backups(Some(DomainKey::Dns)).await.unwrap().len(),
            1
        );

        // Destroy the live data, then restore.
        for z in db.list_zones().await.unwrap() {
            db.delete_zone_cascade(&z.id).await.unwrap();
        }
        assert!(db.list_zones().await.unwrap().is_empty());

        db.restore_backup(&backup.meta.id).await.unwrap();
        let zones = db.list_zones().await.unwrap();
        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].name, "example.com");
    }

    #[tokio::test]
    async fn restore_rejects_bad_format() {
        let (db, _dir) = test_db().await;
        let backup = db.create_backup(DomainKey::Dns, "admin").await.unwrap();
        // Corrupt the stored format version.
        db.inner
            .query("UPDATE type::record('backup', $id) SET format_version = 'x'")
            .bind(("id", backup.meta.id.clone()))
            .await
            .unwrap();
        let err = db.restore_backup(&backup.meta.id).await.unwrap_err();
        assert!(err.to_string().contains("リストアできません"));
    }
}
