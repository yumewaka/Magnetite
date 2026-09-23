//! SYSVOL file replication store (a DFS-R-equivalent for Group Policy).
//!
//! A domain's Group Policy Template (GPT) lives as files on the SYSVOL share
//! (`GPT.INI`, `Machine/Registry.pol`, …). Real AD keeps SYSVOL consistent across
//! DCs with DFS-R; magnetite mirrors that with the same versioned feed/pull shape
//! used elsewhere: each file carries a monotonically increasing `version` and an
//! `updated_at`, a primary serves changed files at a cursor, and a peer applies
//! them under a no-regress ([`wins`]) rule. Deletes replicate as tombstones.

use crate::error::DbResult;
use crate::records::{parse_rfc3339, split_ts_cursor, to_rfc3339};
use crate::store::Db;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::types::{RecordId, SurrealValue};

/// A single replicated SYSVOL file (or a tombstone when `deleted`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SysvolFile {
    /// `\`-separated path relative to the SysVol share root, e.g.
    /// `example.com\Policies\{GUID}\GPT.INI`.
    pub path: String,
    /// File bytes (base64 on the wire). Empty for a tombstone.
    #[serde(with = "content_b64")]
    pub content: Vec<u8>,
    /// Monotonic per-file version; bumped on every content change or delete.
    pub version: i64,
    /// Tombstone marker: the file was deleted at the origin.
    pub deleted: bool,
    pub updated_at: DateTime<Utc>,
}

impl SysvolFile {
    /// DFS-R-style conflict rule: does `self` win over `other` (higher version,
    /// or same version but a newer timestamp)?
    fn wins(&self, other: &SysvolFile) -> bool {
        (self.version, self.updated_at) > (other.version, other.updated_at)
    }
}

/// The change feed a primary serves to a peer: the files changed since the
/// requested cursor (oldest first), plus the cursor to request next.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SysvolFeed {
    pub files: Vec<SysvolFile>,
    /// The newest `updated_at` served (RFC 3339), to request next.
    pub cursor: String,
}

/// base64 (de)serialization for the file body, so the JSON feed stays compact
/// and text-safe.
mod content_b64 {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct SysvolRecord {
    id: Option<RecordId>,
    path: String,
    /// base64 of the file bytes.
    content: String,
    version: i64,
    deleted: bool,
    updated_at: String,
}

impl SysvolRecord {
    fn into_model(self) -> SysvolFile {
        use base64::Engine;
        let content = base64::engine::general_purpose::STANDARD
            .decode(&self.content)
            .unwrap_or_default();
        SysvolFile {
            path: self.path,
            content,
            version: self.version,
            deleted: self.deleted,
            updated_at: parse_rfc3339(&self.updated_at),
        }
    }
}

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

impl Db {
    async fn find_sysvol(&self, path: &str) -> DbResult<Option<SysvolRecord>> {
        let recs: Vec<SysvolRecord> = self
            .inner
            .query("SELECT * FROM sysvol_file WHERE path = $p LIMIT 1")
            .bind(("p", path.to_string()))
            .await?
            .take(0)?;
        Ok(recs.into_iter().next())
    }

    async fn write_sysvol(&self, rec: &SysvolRecord) -> DbResult<()> {
        // UPSERT by the unique `path` key.
        self.inner
            .query("UPSERT sysvol_file SET path = $p, content = $c, version = $v, deleted = $d, updated_at = $u WHERE path = $p")
            .bind(("p", rec.path.clone()))
            .bind(("c", rec.content.clone()))
            .bind(("v", rec.version))
            .bind(("d", rec.deleted))
            .bind(("u", rec.updated_at.clone()))
            .await?;
        Ok(())
    }

    /// Store (or update) a SYSVOL file. Unchanged content is a no-op (the version
    /// and timestamp are preserved), so re-seeding is idempotent. Returns the
    /// stored file.
    pub async fn upsert_sysvol_file(&self, path: &str, content: &[u8]) -> DbResult<SysvolFile> {
        let existing = self.find_sysvol(path).await?;
        if let Some(rec) = &existing {
            if !rec.deleted && rec.content == b64(content) {
                return Ok(rec.clone().into_model());
            }
        }
        let version = existing.as_ref().map_or(1, |r| r.version + 1);
        let rec = SysvolRecord {
            id: None,
            path: path.to_string(),
            content: b64(content),
            version,
            deleted: false,
            updated_at: to_rfc3339(Utc::now()),
        };
        self.write_sysvol(&rec).await?;
        Ok(rec.into_model())
    }

    /// Tombstone a SYSVOL file (replicates the delete). No-op if already deleted
    /// or never present.
    pub async fn delete_sysvol_file(&self, path: &str) -> DbResult<()> {
        let Some(rec) = self.find_sysvol(path).await? else {
            return Ok(());
        };
        if rec.deleted {
            return Ok(());
        }
        let tombstone = SysvolRecord {
            id: None,
            path: path.to_string(),
            content: String::new(),
            version: rec.version + 1,
            deleted: true,
            updated_at: to_rfc3339(Utc::now()),
        };
        self.write_sysvol(&tombstone).await
    }

    /// Seed several files at once (idempotent per [`Self::upsert_sysvol_file`]).
    pub async fn seed_sysvol_files(&self, files: &[(String, Vec<u8>)]) -> DbResult<()> {
        for (path, content) in files {
            self.upsert_sysvol_file(path, content).await?;
        }
        Ok(())
    }

    /// The live SYSVOL tree as `(path, bytes)` — non-deleted files only — ready to
    /// build the SMB [`Vfs`](../../magnetite_smb/vfs/struct.Vfs.html) from.
    pub async fn list_sysvol_files(&self) -> DbResult<Vec<(String, Vec<u8>)>> {
        let recs: Vec<SysvolRecord> = self
            .inner
            .query("SELECT * FROM sysvol_file WHERE deleted = false ORDER BY path ASC")
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .map(SysvolRecord::into_model)
            .map(|f| (f.path, f.content))
            .collect())
    }

    /// The replication feed: files changed since `cursor` (oldest first, deletes
    /// included as tombstones), plus the next cursor.
    ///
    /// The cursor is a compound `"<updated_at>|<path>"` (the unique `path` breaks ties):
    /// a plain `WHERE updated_at > ts` with an exactly-full page would permanently skip
    /// rows sharing the boundary timestamp (possible when a bulk seed stamps many files
    /// within one clock tick). A legacy timestamp-only cursor is still accepted.
    pub async fn sysvol_feed(&self, cursor: &str, limit: usize) -> DbResult<SysvolFeed> {
        let (ts, path) = split_ts_cursor(cursor);
        let recs: Vec<SysvolRecord> = self
            .inner
            .query(
                "SELECT * FROM sysvol_file \
                 WHERE updated_at > $ts OR (updated_at = $ts AND path > $p) \
                 ORDER BY updated_at ASC, path ASC LIMIT $l",
            )
            .bind(("ts", ts))
            .bind(("p", path))
            .bind(("l", limit as i64))
            .await?
            .take(0)?;
        let next = recs
            .last()
            .map(|r| format!("{}|{}", r.updated_at, r.path))
            .unwrap_or_else(|| cursor.to_string());
        let files: Vec<SysvolFile> = recs.into_iter().map(SysvolRecord::into_model).collect();
        Ok(SysvolFeed {
            files,
            cursor: next,
        })
    }

    /// Apply a replicated file under the no-regress rule: skip it if what we hold
    /// already wins (equal-or-higher version). Returns whether it was applied.
    pub async fn apply_replicated_sysvol_file(&self, incoming: &SysvolFile) -> DbResult<bool> {
        if let Some(rec) = self.find_sysvol(&incoming.path).await? {
            let current = rec.into_model();
            if !incoming.wins(&current) {
                return Ok(false);
            }
        }
        let rec = SysvolRecord {
            id: None,
            path: incoming.path.clone(),
            content: b64(&incoming.content),
            version: incoming.version,
            deleted: incoming.deleted,
            updated_at: to_rfc3339(incoming.updated_at),
        };
        self.write_sysvol(&rec).await?;
        Ok(true)
    }

    /// The persisted SYSVOL-replication pull cursor (empty when never synced), so a
    /// peer resumes from where it left off instead of re-syncing the whole share from
    /// empty on every restart.
    pub async fn get_sysvol_repl_cursor(&self) -> DbResult<String> {
        let recs: Vec<SysvolReplStateRecord> = self
            .inner
            .query("SELECT * FROM sysvol_repl_state LIMIT 1")
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .next()
            .map(|r| r.cursor)
            .unwrap_or_default())
    }

    /// Persist the SYSVOL-replication pull cursor after a pull pass (singleton).
    pub async fn set_sysvol_repl_cursor(&self, cursor: &str) -> DbResult<()> {
        let now = to_rfc3339(Utc::now());
        let existing: Vec<SysvolReplStateRecord> = self
            .inner
            .query("SELECT * FROM sysvol_repl_state LIMIT 1")
            .await?
            .take(0)?;
        if existing.is_empty() {
            let rec = SysvolReplStateRecord {
                id: None,
                cursor: cursor.to_string(),
                last_sync: Some(now),
            };
            let _: Option<SysvolReplStateRecord> =
                self.inner.create("sysvol_repl_state").content(rec).await?;
        } else {
            self.inner
                .query("UPDATE sysvol_repl_state SET cursor = $c, last_sync = $t")
                .bind(("c", cursor.to_string()))
                .bind(("t", now))
                .await?;
        }
        Ok(())
    }
}

/// Singleton row holding the SYSVOL-replication pull cursor for a peer.
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct SysvolReplStateRecord {
    id: Option<RecordId>,
    cursor: String,
    last_sync: Option<String>,
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
    async fn feed_paginates_past_same_timestamp_ties() {
        let (db, _d) = test_db().await;
        // Three files sharing the exact same updated_at (as a bulk clock-tick would).
        let ts = "2026-01-01T00:00:00+00:00";
        for p in ["dom\\a", "dom\\b", "dom\\c"] {
            db.write_sysvol(&SysvolRecord {
                id: None,
                path: p.into(),
                content: b64(b"x"),
                version: 1,
                deleted: false,
                updated_at: ts.into(),
            })
            .await
            .unwrap();
        }
        // Page through with limit 1: the compound (ts, path) cursor must serve all three
        // rather than skipping the ones past the first page (the tie-skip bug).
        let mut seen = Vec::new();
        let mut cursor = String::new();
        for _ in 0..6 {
            let feed = db.sysvol_feed(&cursor, 1).await.unwrap();
            if feed.files.is_empty() {
                break;
            }
            for f in &feed.files {
                seen.push(f.path.clone());
            }
            cursor = feed.cursor;
        }
        assert_eq!(seen, vec!["dom\\a", "dom\\b", "dom\\c"]);
    }

    #[tokio::test]
    async fn sysvol_repl_cursor_persists() {
        let (db, _d) = test_db().await;
        // Empty when never synced.
        assert_eq!(db.get_sysvol_repl_cursor().await.unwrap(), "");
        db.set_sysvol_repl_cursor("2026-01-01T00:00:00Z")
            .await
            .unwrap();
        assert_eq!(
            db.get_sysvol_repl_cursor().await.unwrap(),
            "2026-01-01T00:00:00Z"
        );
        // Singleton: a second set updates in place.
        db.set_sysvol_repl_cursor("2026-02-02T00:00:00Z")
            .await
            .unwrap();
        assert_eq!(
            db.get_sysvol_repl_cursor().await.unwrap(),
            "2026-02-02T00:00:00Z"
        );
    }

    #[tokio::test]
    async fn upsert_is_idempotent_and_bumps_version_on_change() {
        let (db, _d) = test_db().await;
        let a = db.upsert_sysvol_file("dom\\GPT.INI", b"v1").await.unwrap();
        assert_eq!(a.version, 1);
        // Same bytes → no version bump.
        let a2 = db.upsert_sysvol_file("dom\\GPT.INI", b"v1").await.unwrap();
        assert_eq!(a2.version, 1);
        // Changed bytes → version bumps.
        let b = db.upsert_sysvol_file("dom\\GPT.INI", b"v2").await.unwrap();
        assert_eq!(b.version, 2);
        assert_eq!(b.content, b"v2");
        let files = db.list_sysvol_files().await.unwrap();
        assert_eq!(files, vec![("dom\\GPT.INI".to_string(), b"v2".to_vec())]);
    }

    #[tokio::test]
    async fn feed_serves_changes_and_apply_respects_no_regress() {
        let (primary, _d1) = test_db().await;
        primary
            .upsert_sysvol_file("dom\\Policies\\{G}\\GPT.INI", b"hello")
            .await
            .unwrap();

        let feed = primary.sysvol_feed("", 100).await.unwrap();
        assert_eq!(feed.files.len(), 1);
        assert_eq!(feed.files[0].content, b"hello");

        // Peer applies it, idempotently.
        let (peer, _d2) = test_db().await;
        assert!(peer
            .apply_replicated_sysvol_file(&feed.files[0])
            .await
            .unwrap());
        assert!(!peer
            .apply_replicated_sysvol_file(&feed.files[0])
            .await
            .unwrap());
        assert_eq!(peer.list_sysvol_files().await.unwrap().len(), 1);

        // A stale (lower-version) update loses to what the peer already holds.
        let mut stale = feed.files[0].clone();
        stale.version = 0;
        stale.content = b"old".to_vec();
        assert!(!peer.apply_replicated_sysvol_file(&stale).await.unwrap());

        // The feed from the advanced cursor is empty.
        assert!(primary
            .sysvol_feed(&feed.cursor, 100)
            .await
            .unwrap()
            .files
            .is_empty());
    }

    #[tokio::test]
    async fn delete_tombstones_and_replicates() {
        let (primary, _d1) = test_db().await;
        primary
            .upsert_sysvol_file("dom\\a.pol", b"x")
            .await
            .unwrap();
        primary.delete_sysvol_file("dom\\a.pol").await.unwrap();
        // Gone from the live tree, present as a tombstone in the feed.
        assert!(primary.list_sysvol_files().await.unwrap().is_empty());
        let feed = primary.sysvol_feed("", 100).await.unwrap();
        let tomb = feed.files.iter().find(|f| f.path == "dom\\a.pol").unwrap();
        assert!(tomb.deleted);

        // A peer that had the file applies the tombstone and drops it.
        let (peer, _d2) = test_db().await;
        peer.upsert_sysvol_file("dom\\a.pol", b"x").await.unwrap();
        assert_eq!(peer.list_sysvol_files().await.unwrap().len(), 1);
        assert!(peer.apply_replicated_sysvol_file(tomb).await.unwrap());
        assert!(peer.list_sysvol_files().await.unwrap().is_empty());
    }
}
