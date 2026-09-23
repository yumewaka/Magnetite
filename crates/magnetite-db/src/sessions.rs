//! Session repository (07 §3.8 / 09 §6.5). Sessions are DB-persisted for
//! restart resilience; validity is re-checked on every request.

use crate::error::DbResult;
use crate::records::{to_rfc3339, SessionRecord};
use crate::store::Db;
use chrono::Utc;
use magnetite_core::models::{Session, SessionInfo};

impl Db {
    /// Persist a new session.
    pub async fn create_session(&self, session: &Session) -> DbResult<()> {
        let record = SessionRecord::from_model(session);
        let _created: Option<SessionRecord> = self.inner.create("session").content(record).await?;
        Ok(())
    }

    /// Fetch a session by id if it is currently valid (not revoked, not
    /// expired). Expired/revoked rows are treated as absent even before the
    /// cleanup task removes them (09 §6.5).
    pub async fn get_valid_session(&self, session_id: &str) -> DbResult<Option<Session>> {
        let records: Vec<SessionRecord> = self
            .inner
            .query("SELECT * FROM session WHERE session_id = $sid LIMIT 1")
            .bind(("sid", session_id.to_string()))
            .await?
            .take(0)?;
        let now = Utc::now();
        Ok(records
            .into_iter()
            .next()
            .map(SessionRecord::into_model)
            .filter(|s| s.is_valid_at(now)))
    }

    /// Revoke a single session by id (sets `revoked_at`).
    pub async fn revoke_session(&self, session_id: &str) -> DbResult<()> {
        let now = to_rfc3339(Utc::now());
        self.inner
            .query(
                "UPDATE session SET revoked_at = $t WHERE session_id = $sid AND revoked_at IS NONE",
            )
            .bind(("t", now))
            .bind(("sid", session_id.to_string()))
            .await?;
        Ok(())
    }

    /// Revoke every active session for a subject (account deletion/disable,
    /// SSO subject removal — AC-05).
    pub async fn revoke_sessions_for_subject(&self, subject: &str) -> DbResult<()> {
        let now = to_rfc3339(Utc::now());
        self.inner
            .query("UPDATE session SET revoked_at = $t WHERE subject = $sub AND revoked_at IS NONE")
            .bind(("t", now))
            .bind(("sub", subject.to_string()))
            .await?;
        Ok(())
    }

    /// List currently active (valid) sessions as display-safe summaries.
    pub async fn list_active_sessions(&self) -> DbResult<Vec<SessionInfo>> {
        let records: Vec<SessionRecord> = self
            .inner
            .query("SELECT * FROM session ORDER BY created_at DESC")
            .await?
            .take(0)?;
        let now = Utc::now();
        Ok(records
            .into_iter()
            .map(SessionRecord::into_model)
            .filter(|s| s.is_valid_at(now))
            .map(|s| SessionInfo::from(&s))
            .collect())
    }

    /// Physically delete expired/revoked sessions (periodic cleanup, 09 §1).
    pub async fn cleanup_expired_sessions(&self) -> DbResult<()> {
        let now = to_rfc3339(Utc::now());
        self.inner
            .query("DELETE FROM session WHERE expires_at < $t OR revoked_at IS NOT NONE")
            .bind(("t", now))
            .await?;
        Ok(())
    }

    /// Enforce the retention window on the append-only observability tables (operational
    /// logs, audit trail, watch metrics), which otherwise grow without bound. Deletes rows
    /// older than `retention_days`; a non-positive value disables pruning (keep everything).
    /// Returns the total number of rows removed across the three tables.
    pub async fn run_retention(&self, retention_days: u32) -> DbResult<usize> {
        if retention_days == 0 {
            return Ok(0);
        }
        let cutoff = to_rfc3339(Utc::now() - chrono::Duration::days(i64::from(retention_days)));
        let logs = self.prune_logs_before(&cutoff).await?;
        let audit = self.prune_audit_before(&cutoff).await?;
        let metrics = self.prune_watch_metrics_before(&cutoff).await?;
        Ok(logs + audit + metrics)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use magnetite_core::authz::Role;
    use magnetite_core::models::common::AuthMethod;

    fn sample_session(sid: &str, subject: &str, expires_in: Duration) -> Session {
        let now = Utc::now();
        Session {
            session_id: sid.into(),
            subject: subject.into(),
            auth_method: AuthMethod::Local,
            role: Role::Admin,
            display_name: Some("Admin".into()),
            email: None,
            sso_tokens: None,
            login_ip: "127.0.0.1".into(),
            created_at: now,
            expires_at: now + expires_in,
            revoked_at: None,
        }
    }

    async fn test_db() -> (Db, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        (db, dir)
    }

    #[tokio::test]
    async fn create_and_fetch_valid_session() {
        let (db, _dir) = test_db().await;
        db.create_session(&sample_session("s1", "admin", Duration::hours(1)))
            .await
            .unwrap();
        assert!(db.get_valid_session("s1").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn expired_session_is_absent() {
        let (db, _dir) = test_db().await;
        db.create_session(&sample_session("s2", "admin", Duration::hours(-1)))
            .await
            .unwrap();
        assert!(db.get_valid_session("s2").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn revocation_invalidates_immediately() {
        let (db, _dir) = test_db().await;
        db.create_session(&sample_session("s3", "bob", Duration::hours(1)))
            .await
            .unwrap();
        db.revoke_session("s3").await.unwrap();
        assert!(db.get_valid_session("s3").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn revoke_by_subject_affects_all() {
        let (db, _dir) = test_db().await;
        db.create_session(&sample_session("a", "carol", Duration::hours(1)))
            .await
            .unwrap();
        db.create_session(&sample_session("b", "carol", Duration::hours(1)))
            .await
            .unwrap();
        db.revoke_sessions_for_subject("carol").await.unwrap();
        assert!(db.list_active_sessions().await.unwrap().is_empty());
    }
}
