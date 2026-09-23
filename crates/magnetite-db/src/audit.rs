//! Audit log repository (07 §3.2 / F-04). Append-only: no update or delete API.

use crate::error::DbResult;
use crate::records::{action_str, to_rfc3339, AuditRecord};
use crate::store::Db;
use chrono::Utc;
use magnetite_core::models::common::OpResult;
use magnetite_core::models::{AuditEntry, NewAuditEntry};
use serde::Deserialize;
use surrealdb::types::SurrealValue;

/// One row of a `SELECT count() … GROUP ALL` aggregate. SurrealDB v3 returns the count
/// as an object (`{ count: N }`), not a bare integer, so it must be deserialized as a
/// struct rather than `Vec<i64>` (which fails with "Expected int, got object").
#[derive(Debug, Deserialize, SurrealValue)]
struct CountRow {
    count: i64,
}

impl Db {
    /// Append an audit entry. The id and timestamp are assigned here.
    pub async fn append_audit(&self, entry: NewAuditEntry) -> DbResult<AuditEntry> {
        let record = AuditRecord {
            id: None,
            at: to_rfc3339(Utc::now()),
            actor: entry.actor,
            actor_role: entry.actor_role.as_str().to_string(),
            domain: entry.domain.as_str().to_string(),
            action: action_str(entry.action).to_string(),
            target_kind: entry.target_kind,
            target_id: entry.target_id,
            result: match entry.result {
                OpResult::Success => "success".into(),
                OpResult::Failure => "failure".into(),
            },
            ip: entry.ip,
            detail: entry
                .detail
                .as_ref()
                .and_then(|d| serde_json::to_string(d).ok()),
        };
        let created: Option<AuditRecord> = self.inner.create("audit").content(record).await?;
        created
            .map(AuditRecord::into_model)
            .ok_or(crate::error::DbError::Constraint(
                "audit append failed".into(),
            ))
    }

    /// List audit entries newest-first with pagination.
    pub async fn list_audit(&self, limit: usize, offset: usize) -> DbResult<Vec<AuditEntry>> {
        let records: Vec<AuditRecord> = self
            .inner
            .query("SELECT * FROM audit ORDER BY at DESC LIMIT $limit START $offset")
            .bind(("limit", limit as i64))
            .bind(("offset", offset as i64))
            .await?
            .take(0)?;
        Ok(records.into_iter().map(AuditRecord::into_model).collect())
    }

    /// Total number of audit entries. Uses a `count()` aggregate rather than reading every
    /// row (the table grows unbounded, so a full scan was O(n) memory + time).
    pub async fn count_audit(&self) -> DbResult<usize> {
        let counts: Vec<CountRow> = self
            .inner
            .query("SELECT count() FROM audit GROUP ALL")
            .await?
            .take(0)?;
        Ok(counts
            .into_iter()
            .next()
            .map(|r| r.count)
            .unwrap_or(0)
            .max(0) as usize)
    }

    /// Delete audit entries older than `cutoff` (RFC3339). Returns how many were removed.
    /// Called periodically so the audit log does not grow without bound.
    pub async fn prune_audit_before(&self, cutoff: &str) -> DbResult<usize> {
        let removed: Vec<AuditRecord> = self
            .inner
            .query("DELETE FROM audit WHERE at < $c RETURN BEFORE")
            .bind(("c", cutoff.to_string()))
            .await?
            .take(0)?;
        Ok(removed.len())
    }

    /// Query audit entries with optional filters (S-Audit / AC-07), returning
    /// the requested page and the total match count for pagination.
    ///
    /// `domain` and `action` are exact string matches, `actor` is a
    /// case-insensitive substring, and `from`/`to` are inclusive RFC3339
    /// bounds on the timestamp. Ordering is by timestamp, newest-first unless
    /// `descending` is false.
    #[allow(clippy::too_many_arguments)]
    pub async fn query_audit(
        &self,
        domain: Option<&str>,
        action: Option<&str>,
        actor: Option<&str>,
        from: Option<&str>,
        to: Option<&str>,
        descending: bool,
        limit: usize,
        offset: usize,
    ) -> DbResult<(Vec<AuditEntry>, usize)> {
        let actor = actor.filter(|a| !a.trim().is_empty());

        let mut conds: Vec<&str> = Vec::new();
        if domain.is_some() {
            conds.push("domain = $domain");
        }
        if action.is_some() {
            conds.push("action = $action");
        }
        if actor.is_some() {
            conds.push("string::contains(string::lowercase(actor), string::lowercase($actor))");
        }
        if from.is_some() {
            conds.push("at >= $from");
        }
        if to.is_some() {
            conds.push("at <= $to");
        }
        let where_clause = if conds.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", conds.join(" AND "))
        };
        let order = if descending { "DESC" } else { "ASC" };
        let stmt = format!(
            "SELECT * FROM audit{where_clause} ORDER BY at {order} LIMIT $limit START $offset; \
             SELECT * FROM audit{where_clause};"
        );

        let mut q = self
            .inner
            .query(stmt)
            .bind(("limit", limit as i64))
            .bind(("offset", offset as i64));
        if let Some(d) = domain {
            q = q.bind(("domain", d.to_string()));
        }
        if let Some(a) = action {
            q = q.bind(("action", a.to_string()));
        }
        if let Some(a) = actor {
            q = q.bind(("actor", a.trim().to_string()));
        }
        if let Some(f) = from {
            q = q.bind(("from", f.to_string()));
        }
        if let Some(t) = to {
            q = q.bind(("to", t.to_string()));
        }

        let mut resp = q.await?;
        let page: Vec<AuditRecord> = resp.take(0)?;
        let all: Vec<AuditRecord> = resp.take(1)?;
        let entries = page.into_iter().map(AuditRecord::into_model).collect();
        Ok((entries, all.len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetite_core::authz::Role;
    use magnetite_core::domain::DomainKey;
    use magnetite_core::models::common::ActionKind;

    async fn test_db() -> (Db, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        (db, dir)
    }

    fn entry(target: &str) -> NewAuditEntry {
        NewAuditEntry {
            actor: "admin".into(),
            actor_role: Role::Admin,
            domain: DomainKey::Portal,
            action: ActionKind::Login,
            target_kind: "session".into(),
            target_id: target.into(),
            result: OpResult::Success,
            ip: "127.0.0.1".into(),
            detail: None,
        }
    }

    #[tokio::test]
    async fn append_and_list() {
        let (db, _dir) = test_db().await;
        db.append_audit(entry("t1")).await.unwrap();
        db.append_audit(entry("t2")).await.unwrap();
        assert_eq!(db.count_audit().await.unwrap(), 2);
        let listed = db.list_audit(10, 0).await.unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].actor, "admin");
    }

    #[tokio::test]
    async fn query_audit_filters_and_paginates() {
        let (db, _dir) = test_db().await;
        let mut dns = entry("z1");
        dns.actor = "oper1".into();
        dns.domain = DomainKey::Dns;
        dns.action = ActionKind::Delete;
        db.append_audit(dns).await.unwrap();
        db.append_audit(entry("s1")).await.unwrap();
        db.append_audit(entry("s2")).await.unwrap();

        // Domain filter narrows the set and reports the matching total.
        let (rows, total) = db
            .query_audit(Some("dns"), None, None, None, None, true, 50, 0)
            .await
            .unwrap();
        assert_eq!(total, 1);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].actor, "oper1");

        // Actor substring is case-insensitive.
        let (rows, total) = db
            .query_audit(None, None, Some("OPER"), None, None, true, 50, 0)
            .await
            .unwrap();
        assert_eq!(total, 1);
        assert_eq!(rows.len(), 1);

        // Total counts all matches; the page is bounded by the limit.
        let (rows, total) = db
            .query_audit(None, None, None, None, None, true, 2, 0)
            .await
            .unwrap();
        assert_eq!(total, 3);
        assert_eq!(rows.len(), 2);

        // No match yields an empty page with a zero total (AC-07 empty state).
        let (rows, total) = db
            .query_audit(Some("mail"), None, None, None, None, true, 50, 0)
            .await
            .unwrap();
        assert_eq!(total, 0);
        assert!(rows.is_empty());
    }
}
