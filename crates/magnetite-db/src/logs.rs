//! Integrated operational-log repository (07 §3.12 / F-08 / screen_logs).
//!
//! Distinct from the audit log: these are the domains' operation / query /
//! access logs, viewed read-only in S-Logs.
//!
//! TODO(ingestion): [`Db::append_log`] is the ingestion seam. Nothing calls it
//! yet — real log ingestion from the domain modules / external daemons (DNS
//! query logs, proxy access logs, …) is deferred (09_runtime_spec). Until that
//! lands the `log` table stays empty and S-Logs shows its empty state.

use crate::error::DbResult;
use crate::records::{parse_rfc3339, record_key, to_rfc3339};
use crate::store::Db;
use chrono::{DateTime, Utc};
use magnetite_core::domain::DomainKey;
use magnetite_core::models::common::{LogKind, LogLevel};
use magnetite_core::models::LogEntry;
use serde::{Deserialize, Serialize};
use surrealdb::types::{RecordId, SurrealValue};

fn log_kind_str(k: LogKind) -> &'static str {
    match k {
        LogKind::Operation => "operation",
        LogKind::Query => "query",
        LogKind::Access => "access",
    }
}
fn log_kind_from(s: &str) -> LogKind {
    match s {
        "query" => LogKind::Query,
        "access" => LogKind::Access,
        _ => LogKind::Operation,
    }
}
fn level_str(l: LogLevel) -> &'static str {
    match l {
        LogLevel::Debug => "DEBUG",
        LogLevel::Info => "INFO",
        LogLevel::Warn => "WARN",
        LogLevel::Error => "ERROR",
    }
}
fn level_from(s: &str) -> LogLevel {
    match s {
        "DEBUG" => LogLevel::Debug,
        "WARN" => LogLevel::Warn,
        "ERROR" => LogLevel::Error,
        _ => LogLevel::Info,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct LogRecord {
    id: Option<RecordId>,
    domain: String,
    log_kind: String,
    level: String,
    message: String,
    at: String,
    /// JSON-encoded structured metadata (source/tags).
    meta: Option<String>,
}

impl LogRecord {
    fn into_model(self) -> LogEntry {
        LogEntry {
            id: record_key(&self.id),
            domain: DomainKey::from_str(&self.domain).unwrap_or(DomainKey::Portal),
            log_kind: log_kind_from(&self.log_kind),
            level: level_from(&self.level),
            message: self.message,
            at: parse_rfc3339(&self.at),
            meta: self
                .meta
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok()),
        }
    }
}

/// Parameters for ingesting a log line (id/timestamp assigned by the store).
#[derive(Debug, Clone)]
pub struct NewLogEntry {
    pub domain: DomainKey,
    pub log_kind: LogKind,
    pub level: LogLevel,
    pub message: String,
    pub at: DateTime<Utc>,
    pub meta: Option<serde_json::Value>,
}

impl Db {
    /// Append a log line. The ingestion seam for domain modules / daemons.
    ///
    /// TODO(ingestion): not yet wired to any producer (see module docs).
    pub async fn append_log(&self, entry: NewLogEntry) -> DbResult<()> {
        let rec = LogRecord {
            id: None,
            domain: entry.domain.as_str().to_string(),
            log_kind: log_kind_str(entry.log_kind).to_string(),
            level: level_str(entry.level).to_string(),
            message: entry.message,
            at: to_rfc3339(entry.at),
            meta: entry
                .meta
                .as_ref()
                .and_then(|m| serde_json::to_string(m).ok()),
        };
        let _: Option<LogRecord> = self.inner.create("log").content(rec).await?;
        Ok(())
    }

    /// Delete operational log entries older than `cutoff` (RFC3339). Returns how many were
    /// removed. Called periodically so the `log` table does not grow without bound.
    pub async fn prune_logs_before(&self, cutoff: &str) -> DbResult<usize> {
        let removed: Vec<LogRecord> = self
            .inner
            .query("DELETE FROM log WHERE at < $c RETURN BEFORE")
            .bind(("c", cutoff.to_string()))
            .await?
            .take(0)?;
        Ok(removed.len())
    }

    /// Query logs filtered by domain / kind / level, newest-first (E-01). Empty
    /// filters match everything; `limit` bounds the ring-buffer window.
    pub async fn query_logs(
        &self,
        domain: Option<&str>,
        log_kind: Option<&str>,
        level: Option<&str>,
        limit: usize,
    ) -> DbResult<Vec<LogEntry>> {
        let mut conds: Vec<&str> = Vec::new();
        if domain.is_some() {
            conds.push("domain = $domain");
        }
        if log_kind.is_some() {
            conds.push("log_kind = $log_kind");
        }
        if level.is_some() {
            conds.push("level = $level");
        }
        let where_clause = if conds.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", conds.join(" AND "))
        };
        let stmt = format!("SELECT * FROM log{where_clause} ORDER BY at DESC LIMIT $limit");

        let mut q = self.inner.query(stmt).bind(("limit", limit as i64));
        if let Some(d) = domain {
            q = q.bind(("domain", d.to_string()));
        }
        if let Some(k) = log_kind {
            q = q.bind(("log_kind", k.to_string()));
        }
        if let Some(l) = level {
            q = q.bind(("level", l.to_string()));
        }
        let recs: Vec<LogRecord> = q.await?.take(0)?;
        Ok(recs.into_iter().map(LogRecord::into_model).collect())
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

    fn entry(domain: DomainKey, kind: LogKind, level: LogLevel, msg: &str) -> NewLogEntry {
        NewLogEntry {
            domain,
            log_kind: kind,
            level,
            message: msg.to_string(),
            at: Utc::now(),
            meta: None,
        }
    }

    #[tokio::test]
    async fn retention_prunes_old_logs_and_run_retention_honours_days() {
        let (db, _dir) = test_db().await;
        // One old (100 days ago) and one fresh log line.
        let mut old = entry(DomainKey::Dns, LogKind::Operation, LogLevel::Info, "old");
        old.at = Utc::now() - chrono::Duration::days(100);
        db.append_log(old).await.unwrap();
        db.append_log(entry(
            DomainKey::Dns,
            LogKind::Operation,
            LogLevel::Info,
            "fresh",
        ))
        .await
        .unwrap();
        assert_eq!(db.query_logs(None, None, None, 10).await.unwrap().len(), 2);

        // run_retention(90) drops anything older than 90 days → only "fresh" remains.
        let pruned = db.run_retention(90).await.unwrap();
        assert_eq!(pruned, 1);
        let left = db.query_logs(None, None, None, 10).await.unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].message, "fresh");

        // retention_days = 0 disables pruning.
        assert_eq!(db.run_retention(0).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn append_and_filter() {
        let (db, _dir) = test_db().await;
        db.append_log(entry(
            DomainKey::Dns,
            LogKind::Operation,
            LogLevel::Info,
            "zone reloaded",
        ))
        .await
        .unwrap();
        db.append_log(entry(
            DomainKey::Proxy,
            LogKind::Access,
            LogLevel::Error,
            "upstream timeout",
        ))
        .await
        .unwrap();

        // No filter -> both, newest-first.
        let all = db.query_logs(None, None, None, 100).await.unwrap();
        assert_eq!(all.len(), 2);

        // Domain filter.
        let dns = db.query_logs(Some("dns"), None, None, 100).await.unwrap();
        assert_eq!(dns.len(), 1);
        assert_eq!(dns[0].message, "zone reloaded");

        // Level filter.
        let errors = db.query_logs(None, None, Some("ERROR"), 100).await.unwrap();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].domain, DomainKey::Proxy);

        // Kind filter.
        let access = db
            .query_logs(None, Some("access"), None, 100)
            .await
            .unwrap();
        assert_eq!(access.len(), 1);
    }
}
