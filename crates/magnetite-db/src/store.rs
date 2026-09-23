//! The single embedded database that is the sole source of truth (09 §0).

use crate::error::{DbError, DbResult};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use surrealdb::engine::any::{self, Any};
use surrealdb::types::SurrealValue;
use surrealdb::Surreal;

const NAMESPACE: &str = "magnetite";
const DATABASE: &str = "main";

/// The sentinel row written by [`Db::probe_writable`] to confirm the store commits.
#[derive(Debug, Serialize, Deserialize, SurrealValue)]
struct DurabilityProbe {
    nonce: i64,
}

/// Force per-commit fsync (`SyncMode::Every`) on an embedded RocksDB connection URL, so
/// durability is enforced rather than left to the engine default. A `rocksdb://` URL with
/// no explicit `sync=` gets `sync=every` appended (via `?` or `&`); other schemes
/// (networked `ws://`, `memory`) are returned unchanged — their durability is the remote
/// server's concern, or not applicable. Idempotent: an operator's explicit `sync=…` is
/// preserved. SurrealDB parses this query key off the path into `datastore_sync`.
fn ensure_rocksdb_sync(url: &str) -> String {
    if !url.starts_with("rocksdb:") || url.contains("sync=") {
        return url.to_string();
    }
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}sync=every")
}

/// Handle to the SurrealDB instance, over the **any** engine — the same handle
/// speaks to either an embedded RocksDB store (`rocksdb://<path>`) or a networked
/// SurrealDB server (`ws://<host>`), selected purely by the connection URL. This is
/// the seam that lets several DC front-ends share one store (Tier B multi-DC).
///
/// Cloning is cheap (shared connection). All repositories are implemented as
/// inherent methods on this type in sibling modules.
#[derive(Clone)]
pub struct Db {
    pub(crate) inner: Arc<Surreal<Any>>,
    /// Serializes first-run admin creation so two concurrent setup requests
    /// cannot both pass the "no accounts yet" check (TOCTOU guard).
    pub(crate) setup_lock: Arc<tokio::sync::Mutex<()>>,
}

impl Db {
    /// Open (creating if necessary) an **embedded** RocksDB store at `path` and
    /// ensure the schema/indexes exist. A convenience over [`Self::connect_url`]
    /// that builds the `rocksdb://<path>` URL (with forward slashes so a Windows
    /// path parses).
    ///
    /// # Errors
    /// Returns [`DbError`](crate::error::DbError) if the directory cannot be
    /// created or the database cannot be opened/initialized.
    pub async fn connect(path: impl AsRef<Path>) -> DbResult<Self> {
        let path = path.as_ref();
        std::fs::create_dir_all(path)?;
        // Absolutise before building the URL: a relative `./data` or a bare Windows
        // drive letter otherwise confuses the `rocksdb://` authority parsing. Forward
        // slashes so a Windows path is a valid URL.
        let abs = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        let url = format!("rocksdb://{}", abs.display().to_string().replace('\\', "/"));
        Self::connect_url(&url).await
    }

    /// Open the database at a SurrealDB connection `url` and ensure the schema
    /// exists. `url` is either an embedded store (`rocksdb://<path>`, `memory`) or a
    /// networked server (`ws://<host>:<port>`) — the latter lets multiple DC
    /// front-ends share one store.
    ///
    /// A `rocksdb://` URL is normalised to force per-commit fsync ([`ensure_rocksdb_sync`])
    /// — for BOTH the embedded default and a `MAGNETITE_DB_URL=rocksdb://…` override — so
    /// durability does not depend on the engine default and applies regardless of how the
    /// store was opened.
    ///
    /// # Errors
    /// Returns [`DbError`](crate::error::DbError) if the store cannot be
    /// opened/initialized.
    pub async fn connect_url(url: &str) -> DbResult<Self> {
        let url = ensure_rocksdb_sync(url);
        let inner = any::connect(url.as_str()).await?;
        inner.use_ns(NAMESPACE).use_db(DATABASE).await?;
        let db = Self {
            inner: Arc::new(inner),
            setup_lock: Arc::new(tokio::sync::Mutex::new(())),
        };
        db.init_schema().await?;
        // Apply any once-only schema migrations layered on the idempotent baseline
        // above (forward-only, recorded in `schema_meta`). No-op until a migration is
        // added; coordinated by an advisory lock when several nodes share the store.
        db.run_migrations().await?;
        Ok(db)
    }

    /// Cheap liveness/connectivity probe: run a trivial query to confirm the
    /// store still answers. Backs the unauthenticated `/readyz` endpoint so a
    /// load balancer or Kubernetes readiness probe can tell whether this node is
    /// able to serve (an embedded store that failed to reopen, or a networked
    /// store that dropped, surfaces here rather than as opaque 500s later).
    ///
    /// # Errors
    /// Returns [`DbError`](crate::error::DbError) if the store is unreachable.
    pub async fn ping(&self) -> DbResult<()> {
        self.inner.query("RETURN true").await?.check()?;
        Ok(())
    }

    /// Probe that the store actually *persists* a write — not merely that it answers
    /// reads like [`Self::ping`]. Writes a sentinel row with a fresh nonce, reads it
    /// back, and deletes it, exercising the real commit path, so a store that has
    /// silently gone read-only (a full disk, a lost writable mount) is caught at startup
    /// rather than on the first user write.
    ///
    /// The sentinel id is unique per process (pid + timestamp) and removed on success,
    /// so concurrent nodes sharing one store (Tier B multi-DC) never read each other's
    /// sentinel — a shared fixed id would race two simultaneous startups into a spurious
    /// mismatch. This confirms the write *reaches* the store; whether RocksDB fsyncs each
    /// commit is a separate durability posture surfaced by the server's startup log.
    ///
    /// # Errors
    /// Returns [`DbError`] if the write fails, the read-back fails, or the value does
    /// not round-trip.
    pub async fn probe_writable(&self) -> DbResult<()> {
        let nonce = chrono::Utc::now().timestamp_micros();
        let id = format!("probe-{}-{nonce}", std::process::id());
        self.inner
            .query("UPSERT type::record('durability_probe', $id) SET nonce = $n")
            .bind(("id", id.clone()))
            .bind(("n", nonce))
            .await?
            .check()?;
        let recs: Vec<DurabilityProbe> = self
            .inner
            .query("SELECT * FROM type::record('durability_probe', $id)")
            .bind(("id", id.clone()))
            .await?
            .take(0)?;
        let round_trips = recs.into_iter().next().is_some_and(|r| r.nonce == nonce);
        // Best-effort cleanup so the probe table does not accumulate a row per startup;
        // a failed delete does not fail the probe (the write+read already proved commit).
        let _ = self
            .inner
            .query("DELETE type::record('durability_probe', $id)")
            .bind(("id", id))
            .await;
        if round_trips {
            Ok(())
        } else {
            Err(DbError::Constraint(
                "durability probe write did not round-trip — store may be read-only".into(),
            ))
        }
    }

    /// Write a full logical backup of the entire store — a SurrealQL dump of the
    /// schema definitions and every record — to `path`. Unlike the in-DB config
    /// `backup` rows (which live inside the store and vanish with it), this is an
    /// engine-independent snapshot written OFF the live store, so it survives loss or
    /// corruption of the store itself: the disaster-recovery backup.
    ///
    /// # Errors
    /// Returns [`DbError`](crate::error::DbError) if the engine cannot export or the
    /// file cannot be written.
    pub async fn export_backup(&self, path: impl AsRef<Path>) -> DbResult<()> {
        self.inner.export(path.as_ref()).await?;
        Ok(())
    }

    /// Restore the store from a SurrealQL backup produced by [`Self::export_backup`],
    /// applying its statements. Intended for an empty/fresh store; importing into a
    /// populated store merges records by id. Indexes are (re)created by `init_schema`
    /// when the store is opened, so a restore only needs to reload the data.
    ///
    /// Opening a store runs migrations, which create the `schema_meta:current` bookkeeping
    /// row; the backup carries its own, and SurrealDB's import replays it as a CREATE that
    /// would collide. So the locally-created migration bookkeeping is cleared first — the
    /// backup's own `schema_meta` (its schema version) then loads authoritatively.
    ///
    /// # Errors
    /// Returns [`DbError`](crate::error::DbError) if the file cannot be read or a
    /// statement fails.
    pub async fn import_backup(&self, path: impl AsRef<Path>) -> DbResult<()> {
        let _ = self.inner.query("DELETE schema_meta").await;
        self.inner.import(path.as_ref()).await?;
        Ok(())
    }

    /// Define the indexes that back the uniqueness/lookup guarantees. Uses
    /// `IF NOT EXISTS` so it is safe to run on every startup.
    async fn init_schema(&self) -> DbResult<()> {
        self.inner
            .query("DEFINE INDEX IF NOT EXISTS account_username ON TABLE account COLUMNS username UNIQUE")
            .query("DEFINE INDEX IF NOT EXISTS session_sid ON TABLE session COLUMNS session_id UNIQUE")
            .query("DEFINE INDEX IF NOT EXISTS session_subject ON TABLE session COLUMNS subject")
            .query("DEFINE INDEX IF NOT EXISTS audit_at ON TABLE audit COLUMNS at")
            .query("DEFINE INDEX IF NOT EXISTS zone_name ON TABLE zone COLUMNS name UNIQUE")
            .query("DEFINE INDEX IF NOT EXISTS record_zone ON TABLE record COLUMNS zone")
            .query("DEFINE INDEX IF NOT EXISTS pool_name ON TABLE pool COLUMNS name UNIQUE")
            .query("DEFINE INDEX IF NOT EXISTS reservation_pool ON TABLE reservation COLUMNS pool_ref")
            .query("DEFINE INDEX IF NOT EXISTS lease_pool ON TABLE lease COLUMNS pool_ref")
            .query("DEFINE TABLE IF NOT EXISTS dhcp_config")
            .query("DEFINE TABLE IF NOT EXISTS ad_principal")
            .query("DEFINE INDEX IF NOT EXISTS ad_principal_sam ON TABLE ad_principal COLUMNS sam_account_name UNIQUE")
            .query("DEFINE INDEX IF NOT EXISTS ad_group_sid ON TABLE ad_group COLUMNS sid UNIQUE")
            .query("DEFINE TABLE IF NOT EXISTS dsa_state")
            .query("DEFINE INDEX IF NOT EXISTS repl_metadata_object ON TABLE repl_metadata COLUMNS object_key UNIQUE")
            .query("DEFINE INDEX IF NOT EXISTS repl_cursor_dsa ON TABLE repl_cursor COLUMNS dsa UNIQUE")
            .query("DEFINE INDEX IF NOT EXISTS entry_dn ON TABLE entry COLUMNS dn UNIQUE")
            .query("DEFINE INDEX IF NOT EXISTS entry_parent ON TABLE entry COLUMNS parent_dn")
            .query("DEFINE INDEX IF NOT EXISTS maildomain_name ON TABLE maildomain COLUMNS name UNIQUE")
            .query("DEFINE INDEX IF NOT EXISTS mailuser_email ON TABLE mailuser COLUMNS email UNIQUE")
            .query("DEFINE INDEX IF NOT EXISTS mailuser_domain ON TABLE mailuser COLUMNS domain_ref")
            .query("DEFINE INDEX IF NOT EXISTS alias_source ON TABLE alias COLUMNS source_address UNIQUE")
            .query("DEFINE INDEX IF NOT EXISTS mlist_address ON TABLE mailinglist COLUMNS address UNIQUE")
            .query("DEFINE TABLE IF NOT EXISTS mailserverconfig")
            .query("DEFINE TABLE IF NOT EXISTS mailrelayconfig")
            .query("DEFINE TABLE IF NOT EXISTS dns_settings")
            // Uniqueness is per (hostname, path_prefix): one host may hold several
            // path-routed vhosts (`/`, `/export`, …), only an identical pair collides.
            // (Migration 1 drops the old single-column `vhost_hostname` index on existing
            // stores; this composite one is the baseline for fresh stores.)
            .query("DEFINE INDEX IF NOT EXISTS vhost_host_path ON TABLE vhost COLUMNS hostname, path_prefix UNIQUE")
            .query("DEFINE INDEX IF NOT EXISTS cert_name ON TABLE certificate COLUMNS name UNIQUE")
            .query("DEFINE INDEX IF NOT EXISTS acl_priority ON TABLE acl_rule COLUMNS priority")
            .query("DEFINE INDEX IF NOT EXISTS ipblock_ord ON TABLE ip_block COLUMNS ord")
            .query("DEFINE INDEX IF NOT EXISTS k8shost_hostname ON TABLE k8s_host COLUMNS hostname UNIQUE")
            .query("DEFINE INDEX IF NOT EXISTS k8scluster_name ON TABLE k8s_cluster COLUMNS name UNIQUE")
            .query("DEFINE INDEX IF NOT EXISTS k8srule_name ON TABLE k8s_alert_rule COLUMNS name")
            .query("DEFINE INDEX IF NOT EXISTS k8stmpl_name ON TABLE k8s_template COLUMNS name UNIQUE")
            .query("DEFINE INDEX IF NOT EXISTS sso_provider_name ON TABLE sso_provider COLUMNS name UNIQUE")
            .query("DEFINE INDEX IF NOT EXISTS sso_client_name ON TABLE sso_client COLUMNS client_name UNIQUE")
            .query("DEFINE INDEX IF NOT EXISTS sso_session_ref ON TABLE sso_session COLUMNS session_ref UNIQUE")
            .query("DEFINE INDEX IF NOT EXISTS sso_session_subject ON TABLE sso_session COLUMNS subject")
            .query("DEFINE INDEX IF NOT EXISTS watch_host_name ON TABLE watch_host COLUMNS name UNIQUE")
            .query("DEFINE INDEX IF NOT EXISTS watch_group_name ON TABLE watch_group COLUMNS name UNIQUE")
            .query("DEFINE INDEX IF NOT EXISTS watch_rule_name ON TABLE watch_rule COLUMNS name")
            .query("DEFINE INDEX IF NOT EXISTS watch_maint_name ON TABLE watch_maintenance COLUMNS name")
            .query("DEFINE INDEX IF NOT EXISTS watch_metric_host ON TABLE watch_metric COLUMNS host_ref")
            .query("DEFINE INDEX IF NOT EXISTS alert_state ON TABLE alert COLUMNS state")
            .query("DEFINE INDEX IF NOT EXISTS notify_target_name ON TABLE notify_target COLUMNS name UNIQUE")
            .query("DEFINE TABLE IF NOT EXISTS app_settings")
            .query("DEFINE TABLE IF NOT EXISTS rpz")
            .query("DEFINE INDEX IF NOT EXISTS dnssec_key_zone ON TABLE dns_dnssec_key COLUMNS zone_name UNIQUE")
            .query("DEFINE INDEX IF NOT EXISTS geo_rule_name ON TABLE geo_rule COLUMNS name")
            .query("DEFINE INDEX IF NOT EXISTS mail_dkim_domain ON TABLE mail_dkim COLUMNS domain UNIQUE")
            .query("DEFINE INDEX IF NOT EXISTS ldap_acl_priority ON TABLE ldap_acl COLUMNS priority")
            .query("DEFINE INDEX IF NOT EXISTS tsig_key_name ON TABLE tsig_key COLUMNS name UNIQUE")
            .query("DEFINE INDEX IF NOT EXISTS zone_journal_zone ON TABLE zone_journal COLUMNS zone")
            .query("DEFINE INDEX IF NOT EXISTS backup_domain ON TABLE backup COLUMNS domain")
            .query("DEFINE INDEX IF NOT EXISTS log_at ON TABLE log COLUMNS at")
            .query("DEFINE INDEX IF NOT EXISTS mail_message_recipient ON TABLE mail_message COLUMNS recipient")
            .query("DEFINE INDEX IF NOT EXISTS ldap_changelog_csn ON TABLE ldap_changelog COLUMNS csn")
            .query("DEFINE INDEX IF NOT EXISTS entry_source_uuid ON TABLE entry COLUMNS source_uuid")
            .query("DEFINE INDEX IF NOT EXISTS ldap_sync_state_cookie ON TABLE ldap_sync_state COLUMNS cookie")
            .query("DEFINE INDEX IF NOT EXISTS backup_mx_name ON TABLE backup_mx COLUMNS name UNIQUE")
            .query("DEFINE INDEX IF NOT EXISTS mail_queue_next ON TABLE mail_queue COLUMNS next_attempt")
            .query("DEFINE INDEX IF NOT EXISTS mail_message_repl ON TABLE mail_message COLUMNS repl_id")
            .query("DEFINE INDEX IF NOT EXISTS mail_changelog_csn ON TABLE mail_changelog COLUMNS csn")
            .query("DEFINE INDEX IF NOT EXISTS mail_flags_changelog_csn ON TABLE mail_flags_changelog COLUMNS csn")
            // Defining an index also creates the (singleton) table, so SELECT on
            // it before the first write returns empty instead of erroring.
            .query("DEFINE INDEX IF NOT EXISTS mail_repl_state_cursor ON TABLE mail_repl_state COLUMNS cursor")
            .query("DEFINE INDEX IF NOT EXISTS sso_signing_key_kid ON TABLE sso_signing_key COLUMNS kid UNIQUE")
            .query("DEFINE INDEX IF NOT EXISTS sysvol_file_path ON TABLE sysvol_file COLUMNS path UNIQUE")
            .query("DEFINE TABLE IF NOT EXISTS dhcp_repl_state")
            .query("DEFINE TABLE IF NOT EXISTS sysvol_repl_state")
            .query("DEFINE TABLE IF NOT EXISTS proxy_repl_state")
            .query("DEFINE TABLE IF NOT EXISTS sso_repl_state")
            .query("DEFINE TABLE IF NOT EXISTS server_identity")
            // Internal proxy key/value store — persists the ACME account credentials so a
            // restart reuses the account instead of registering a new one each time (which
            // would hit Let's Encrypt's new-account rate limit).
            .query("DEFINE TABLE IF NOT EXISTS proxy_kv")
            .query("DEFINE INDEX IF NOT EXISTS proxy_kv_key ON TABLE proxy_kv COLUMNS key UNIQUE")
            // DB-backed ACME settings (editable from the Web UI, hot-reloaded by the manager).
            .query("DEFINE TABLE IF NOT EXISTS acmeconfig")
            // DB-backed dynamic-DNS client settings + last-run status.
            .query("DEFINE TABLE IF NOT EXISTS ddnsconfig")
            .query("DEFINE TABLE IF NOT EXISTS ddnsstatus")
            .query("DEFINE INDEX IF NOT EXISTS forward_rule_priority ON TABLE forward_rule COLUMNS priority")
            .query("DEFINE INDEX IF NOT EXISTS forward_user_name ON TABLE forward_user COLUMNS username UNIQUE")
            // Schema-migration bookkeeping: `schema_meta` records the highest applied
            // migration id; `schema_migration_lock` is the shared-DB advisory lock.
            // Defined here so a SELECT before the first write returns empty, not an error.
            .query("DEFINE TABLE IF NOT EXISTS schema_meta")
            .query("DEFINE TABLE IF NOT EXISTS schema_migration_lock")
            // Sentinel row for the startup write-durability probe (`probe_writable`).
            .query("DEFINE TABLE IF NOT EXISTS durability_probe")
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn export_backup_then_import_into_fresh_store_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        // A durable datum to prove data survives the export → import.
        let server_id = db.get_or_create_server_id().await.unwrap();

        let backup = dir.path().join("backup.surql");
        db.export_backup(&backup).await.unwrap();
        assert!(
            std::fs::metadata(&backup).unwrap().len() > 0,
            "backup file should be non-empty"
        );

        // Restore into a brand-new store and confirm the datum came back.
        let restored = Db::connect(dir.path().join("db2")).await.unwrap();
        restored.import_backup(&backup).await.unwrap();
        assert_eq!(restored.get_or_create_server_id().await.unwrap(), server_id);
    }

    #[test]
    fn rocksdb_sync_is_forced_for_every_rocksdb_url() {
        // Embedded default and a MAGNETITE_DB_URL=rocksdb:// override both get sync=every.
        assert_eq!(
            ensure_rocksdb_sync("rocksdb://C:/x/db"),
            "rocksdb://C:/x/db?sync=every"
        );
        assert_eq!(
            ensure_rocksdb_sync("rocksdb:/var/lib/db?foo=1"),
            "rocksdb:/var/lib/db?foo=1&sync=every"
        );
        // An explicit operator choice is preserved.
        assert_eq!(
            ensure_rocksdb_sync("rocksdb://db?sync=never"),
            "rocksdb://db?sync=never"
        );
        // Networked / memory stores are untouched (durability is the server's concern).
        assert_eq!(ensure_rocksdb_sync("ws://dbhost:8000"), "ws://dbhost:8000");
        assert_eq!(ensure_rocksdb_sync("memory"), "memory");
    }

    #[tokio::test]
    async fn probe_writable_round_trips_a_write() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        // A writable store round-trips the sentinel; repeated probes overwrite the same
        // fixed row and keep succeeding.
        db.probe_writable().await.unwrap();
        db.probe_writable().await.unwrap();
    }
}
