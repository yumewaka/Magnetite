//! Schema versioning & forward-only migrations (09 §0).
//!
//! [`Db::init_schema`](crate::store) is the **baseline**: idempotent
//! `DEFINE ... IF NOT EXISTS` statements re-run on every startup, so additive index/
//! table changes belong there. This module handles the changes that must run *exactly
//! once* — an index REDEFINITION (`DEFINE INDEX IF NOT EXISTS` will not update a
//! changed index), a table removal, or a data backfill/transform — and records how
//! far a store has been migrated so each such change is applied once and only once.
//!
//! Tables are SurrealDB **schemaless**, so the usual "add a field" change needs no
//! migration at all — give every new persisted field `Option`/`#[serde(default)]` and
//! old rows deserialize fine. Migrations are forward-only; a rollback is a restore
//! from backup.
//!
//! When several front-ends share one store (`MAGNETITE_DB_URL`, Tier B), a best-effort
//! advisory lock lets a single node migrate while the others wait; write migration
//! statements idempotently so a crash between a statement and the version bump is safe
//! to re-run, and keep them backward-compatible within a rolling upgrade (expand now,
//! contract only after old nodes are gone).

use crate::error::{DbError, DbResult};
use crate::records::to_rfc3339;
use crate::store::Db;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use surrealdb::types::{RecordId, SurrealValue};

/// A forward-only schema migration, applied exactly once in ascending `id` order.
/// `statements` run in order; write them idempotently where possible.
struct Migration {
    /// Strictly increasing, never reused or edited once shipped.
    id: u32,
    /// Human-readable summary, logged when the migration runs.
    description: &'static str,
    /// SurrealQL statements to apply, in order.
    statements: &'static [&'static str],
}

/// The ordered migration list. Append entries with strictly increasing ids (module docs).
const MIGRATIONS: &[Migration] = &[Migration {
    id: 1,
    description: "vhost uniqueness: single-column hostname index → composite (hostname, path_prefix)",
    // Drop the old single-column UNIQUE index (which forbade a second vhost on the same
    // host) and add the composite one, so a host can hold several path-routed vhosts while
    // an identical (hostname, path_prefix) is still rejected. Idempotent: IF EXISTS / IF
    // NOT EXISTS make a re-run (or a fresh store that already has the composite) a no-op.
    statements: &[
        "REMOVE INDEX IF EXISTS vhost_hostname ON TABLE vhost",
        "DEFINE INDEX IF NOT EXISTS vhost_host_path ON TABLE vhost COLUMNS hostname, path_prefix UNIQUE",
    ],
}];

/// Seconds after which a held migration lock is treated as abandoned (a crashed
/// migrator) and may be stolen — and the longest another node waits for the migrator.
const LOCK_STALE_SECS: i64 = 300;
/// Poll interval while waiting for another node to finish migrating.
const MIGRATION_POLL: Duration = Duration::from_secs(1);

/// The `schema_meta` singleton: the highest applied migration id.
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct SchemaMetaRecord {
    id: Option<RecordId>,
    version: u32,
    updated_at: String,
}

impl Db {
    /// Apply any pending schema migrations (forward-only), recording the highest
    /// applied id in `schema_meta` so each runs once. Called from `connect_url` after
    /// [`init_schema`](crate::store); a no-op while [`MIGRATIONS`] is empty.
    ///
    /// # Errors
    /// Returns [`DbError`] if a migration statement fails, or if this node cannot
    /// acquire the lock and another node does not complete the migration in time.
    pub(crate) async fn run_migrations(&self) -> DbResult<()> {
        self.apply_migrations(MIGRATIONS).await
    }

    /// The runner, parameterised over the migration list so it is unit-testable.
    async fn apply_migrations(&self, migrations: &[Migration]) -> DbResult<()> {
        debug_assert!(
            migrations.windows(2).all(|w| w[0].id < w[1].id),
            "migrations must have strictly increasing ids"
        );
        let target = migrations.iter().map(|m| m.id).max().unwrap_or(0);
        if self.schema_version().await? >= target {
            return Ok(()); // up to date (also the no-migrations fast path)
        }
        if !self.claim_migration_lock().await? {
            // Another node is migrating this shared store; wait for it to finish.
            return self.await_schema_version(target).await;
        }
        let result = self.run_pending(migrations).await;
        self.release_migration_lock().await; // best-effort
        result
    }

    /// Apply the migrations whose id is above the recorded version, in order.
    async fn run_pending(&self, migrations: &[Migration]) -> DbResult<()> {
        // Re-read under the lock in case another node advanced it just before we won.
        let from = self.schema_version().await?;
        for m in migrations.iter().filter(|m| m.id > from) {
            tracing::info!(target: "schema", id = m.id, "applying schema migration: {}", m.description);
            for stmt in m.statements {
                self.inner.query(*stmt).await?.check()?;
            }
            self.set_schema_version(m.id).await?;
        }
        Ok(())
    }

    /// The highest applied migration id (`0` on a fresh or pre-versioning store).
    async fn schema_version(&self) -> DbResult<u32> {
        let recs: Vec<SchemaMetaRecord> = self
            .inner
            .query("SELECT * FROM schema_meta LIMIT 1")
            .await?
            .take(0)?;
        Ok(recs.into_iter().next().map(|r| r.version).unwrap_or(0))
    }

    /// Record the applied migration id. A single atomic UPSERT of the fixed
    /// `schema_meta:current` row — not a delete-then-create — so a crash can never
    /// leave the version cell absent (which would reset to 0 and re-run every
    /// migration). Creates the row on first run, replaces it thereafter.
    async fn set_schema_version(&self, version: u32) -> DbResult<()> {
        self.inner
            .query("UPSERT schema_meta:current SET version = $v, updated_at = $t")
            .bind(("v", version))
            .bind(("t", to_rfc3339(Utc::now())))
            .await?
            .check()?;
        Ok(())
    }

    /// Try to become the sole migrator: steal an abandoned lock, then create the lock
    /// record (which fails if another node already holds it). `true` ⇒ lock acquired.
    async fn claim_migration_lock(&self) -> DbResult<bool> {
        let now = Utc::now().timestamp();
        self.inner
            .query("DELETE schema_migration_lock WHERE held_at < $stale")
            .bind(("stale", now - LOCK_STALE_SECS))
            .await?
            .check()?;
        // CREATE with a fixed id fails (statement error) if the record already exists.
        let acquired = match self
            .inner
            .query("CREATE schema_migration_lock:lock SET held_at = $now")
            .bind(("now", now))
            .await
        {
            Ok(resp) => resp.check().is_ok(),
            Err(_) => false,
        };
        Ok(acquired)
    }

    /// Release the advisory lock (best-effort; a crash leaves it to the stale-steal).
    async fn release_migration_lock(&self) {
        let _ = self.inner.query("DELETE schema_migration_lock:lock").await;
    }

    /// Wait (bounded) for another node's migration to reach `target`.
    async fn await_schema_version(&self, target: u32) -> DbResult<()> {
        for _ in 0..LOCK_STALE_SECS {
            if self.schema_version().await? >= target {
                return Ok(());
            }
            tokio::time::sleep(MIGRATION_POLL).await;
        }
        Err(DbError::Migration(format!(
            "timed out waiting for another node to migrate the schema to version {target}"
        )))
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
    async fn fresh_db_is_migrated_to_the_latest_version_and_rerun_is_a_noop() {
        let (db, _d) = test_db().await;
        // `connect()` already ran the real migrations, so a fresh store is at the latest.
        let latest = MIGRATIONS.iter().map(|m| m.id).max().unwrap_or(0);
        assert_eq!(db.schema_version().await.unwrap(), latest);
        // Re-running the real list changes nothing (idempotent), and an empty list is a
        // no-op that never lowers the version.
        db.run_migrations().await.unwrap();
        db.apply_migrations(&[]).await.unwrap();
        assert_eq!(db.schema_version().await.unwrap(), latest);
    }

    #[tokio::test]
    async fn migration_runs_once_and_is_idempotent() {
        let (db, _d) = test_db().await;
        const M: &[Migration] = &[Migration {
            id: 1,
            description: "create a probe table",
            statements: &["DEFINE TABLE IF NOT EXISTS migration_probe"],
        }];
        db.apply_migrations(M).await.unwrap();
        assert_eq!(db.schema_version().await.unwrap(), 1);
        // Re-running is a no-op: version stays and no error is raised.
        db.apply_migrations(M).await.unwrap();
        assert_eq!(db.schema_version().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn multiple_migrations_apply_in_order_and_resume() {
        let (db, _d) = test_db().await;
        const FIRST: &[Migration] = &[Migration {
            id: 1,
            description: "first",
            statements: &["DEFINE TABLE IF NOT EXISTS probe_one"],
        }];
        const BOTH: &[Migration] = &[
            Migration {
                id: 1,
                description: "first",
                statements: &["DEFINE TABLE IF NOT EXISTS probe_one"],
            },
            Migration {
                id: 2,
                description: "second",
                statements: &["DEFINE TABLE IF NOT EXISTS probe_two"],
            },
        ];
        db.apply_migrations(FIRST).await.unwrap();
        assert_eq!(db.schema_version().await.unwrap(), 1);
        // A later release adds migration 2; only the pending one runs.
        db.apply_migrations(BOTH).await.unwrap();
        assert_eq!(db.schema_version().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn version_set_and_read_roundtrip() {
        let (db, _d) = test_db().await;
        db.set_schema_version(7).await.unwrap();
        assert_eq!(db.schema_version().await.unwrap(), 7);
        db.set_schema_version(9).await.unwrap();
        assert_eq!(db.schema_version().await.unwrap(), 9);
    }
}
