//! Cross-cutting alert & notification-target repository (07 §3.3–3.4 / F-05 /
//! screen_alerts). Alerts are *generated* by domains/monitor rules via
//! [`Db::raise_alert`] and here we provide the横断 read + lifecycle management
//! (acknowledge/resolve) plus notification-target CRUD.

use crate::error::{DbError, DbResult};
use crate::records::{parse_rfc3339, record_key, to_rfc3339};
use crate::store::Db;
use chrono::Utc;
use magnetite_core::domain::DomainKey;
use magnetite_core::models::common::{AlertState, NotifyKind, RecordMeta, Severity};
use magnetite_core::models::{Alert, NotificationTarget};
use serde::{Deserialize, Serialize};
use surrealdb::types::{RecordId, SurrealValue};

const MSG_TARGET_DUP: &str = "同じ名称の通知先が既に存在します。";

/// How long a dispatcher's notification claim (lease) on an alert is honoured before
/// another dispatcher may reclaim it. Longer than any single delivery attempt (webhook /
/// SMTP timeouts) so a working dispatcher is never double-claimed, but short enough that
/// an alert whose dispatcher crashed mid-delivery is retried promptly.
const NOTIFY_LEASE_SECS: i64 = 300;

fn severity_str(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::Warning => "warning",
        Severity::Info => "info",
    }
}
fn severity_from(s: &str) -> Severity {
    match s {
        "critical" => Severity::Critical,
        "info" => Severity::Info,
        _ => Severity::Warning,
    }
}
fn state_from(s: &str) -> AlertState {
    match s {
        "acknowledged" => AlertState::Acknowledged,
        "resolved" => AlertState::Resolved,
        _ => AlertState::Open,
    }
}
fn notify_kind_str(k: NotifyKind) -> &'static str {
    match k {
        NotifyKind::Webhook => "webhook",
        NotifyKind::AuditSink => "audit_sink",
        NotifyKind::Email => "email",
    }
}
fn notify_kind_from(s: &str) -> NotifyKind {
    match s {
        "audit_sink" => NotifyKind::AuditSink,
        "email" => NotifyKind::Email,
        _ => NotifyKind::Webhook,
    }
}

// ---- Records --------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct AlertRecord {
    id: Option<RecordId>,
    domain: String,
    severity: String,
    state: String,
    summary: String,
    source_ref: Option<String>,
    rule_ref: Option<String>,
    acknowledged_by: Option<String>,
    resolved_by: Option<String>,
    acknowledged_at: Option<String>,
    resolved_at: Option<String>,
    suppressed: bool,
    /// Whether the notification dispatcher has already fanned this alert out to the
    /// configured targets. Absent on alerts raised before delivery existed (treated as
    /// already handled — never re-notified).
    #[serde(default)]
    notified: Option<bool>,
    /// Epoch-seconds lease taken by a dispatcher when it starts delivering this alert.
    /// A dispatcher only claims an alert whose lease is absent or older than
    /// [`NOTIFY_LEASE_SECS`], so a crash between claim and delivery is retried once the
    /// lease goes stale (rather than the alert being marked delivered and lost). Absent
    /// on unclaimed alerts.
    #[serde(default)]
    notify_claimed_at: Option<i64>,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl AlertRecord {
    fn into_model(self) -> Alert {
        Alert {
            meta: RecordMeta {
                id: record_key(&self.id),
                created_at: parse_rfc3339(&self.created_at),
                updated_at: parse_rfc3339(&self.updated_at),
                created_by: self.created_by,
            },
            domain: DomainKey::from_str(&self.domain).unwrap_or(DomainKey::Portal),
            severity: severity_from(&self.severity),
            state: state_from(&self.state),
            summary: self.summary,
            source_ref: self.source_ref,
            rule_ref: self.rule_ref,
            acknowledged_by: self.acknowledged_by,
            resolved_by: self.resolved_by,
            acknowledged_at: self.acknowledged_at.as_deref().map(parse_rfc3339),
            resolved_at: self.resolved_at.as_deref().map(parse_rfc3339),
            suppressed: self.suppressed,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct NotifyTargetRecord {
    id: Option<RecordId>,
    name: String,
    kind: String,
    endpoint: String,
    min_severity: Option<String>,
    event_filter: Vec<String>,
    signing_secret: Option<String>,
    domains: Vec<String>,
    enabled: bool,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl NotifyTargetRecord {
    fn into_model(self) -> NotificationTarget {
        NotificationTarget {
            meta: RecordMeta {
                id: record_key(&self.id),
                created_at: parse_rfc3339(&self.created_at),
                updated_at: parse_rfc3339(&self.updated_at),
                created_by: self.created_by,
            },
            name: self.name,
            kind: notify_kind_from(&self.kind),
            endpoint: self.endpoint,
            min_severity: self.min_severity.as_deref().map(severity_from),
            event_filter: self.event_filter.into_iter().collect(),
            signing_secret: self.signing_secret,
            domains: self
                .domains
                .iter()
                .filter_map(|d| DomainKey::from_str(d))
                .collect(),
            enabled: self.enabled,
        }
    }
}

/// Parameters for generating a new alert (id/timestamps assigned by the store).
#[derive(Debug, Clone)]
pub struct NewAlert {
    pub domain: DomainKey,
    pub severity: Severity,
    pub summary: String,
    pub source_ref: Option<String>,
    pub rule_ref: Option<String>,
    pub suppressed: bool,
}

impl Db {
    // ---- Alerts -----------------------------------------------------------

    /// Generate (raise) a new alert. Called by domains / the monitor engine;
    /// the alert starts in the `open` state.
    pub async fn raise_alert(&self, alert: NewAlert) -> DbResult<Alert> {
        let now = to_rfc3339(Utc::now());
        let rec = AlertRecord {
            id: None,
            domain: alert.domain.as_str().to_string(),
            severity: severity_str(alert.severity).to_string(),
            state: "open".into(),
            summary: alert.summary,
            source_ref: alert.source_ref,
            rule_ref: alert.rule_ref,
            acknowledged_by: None,
            resolved_by: None,
            acknowledged_at: None,
            resolved_at: None,
            suppressed: alert.suppressed,
            notified: Some(false),
            notify_claimed_at: None,
            created_at: now.clone(),
            updated_at: now,
            created_by: "system".into(),
        };
        let created: Option<AlertRecord> = self.inner.create("alert").content(rec).await?;
        created
            .map(AlertRecord::into_model)
            .ok_or_else(|| DbError::Constraint("alert creation failed".into()))
    }

    /// Open, non-suppressed alerts the notification dispatcher has not yet delivered
    /// (`notified = false`), oldest-first so they fan out in the order raised.
    ///
    /// # Errors
    /// A store error.
    pub async fn list_undelivered_alerts(&self) -> DbResult<Vec<Alert>> {
        let recs: Vec<AlertRecord> = self
            .inner
            .query("SELECT * FROM alert WHERE notified = false AND state = 'open' AND suppressed = false ORDER BY created_at ASC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(AlertRecord::into_model).collect())
    }

    /// Mark an alert as delivered so the dispatcher does not fan it out again.
    ///
    /// # Errors
    /// A store error.
    pub async fn mark_alert_notified(&self, id: &str) -> DbResult<()> {
        self.inner
            .query("UPDATE type::record('alert', $id) SET notified = true")
            .bind(("id", id.to_string()))
            .await?;
        Ok(())
    }

    /// Atomically LEASE an alert for notification: stamp `notify_claimed_at` with the
    /// current time, but only if the alert is still undelivered (`notified = false`) and
    /// not already under a live lease (no claim, or one older than [`NOTIFY_LEASE_SECS`]).
    /// Reports whether THIS caller won the lease. Serialised by the store (`RETURN BEFORE`
    /// yields the pre-update row only when the `WHERE` matched), so when several
    /// dispatchers share one DB (Tier B) exactly one wins and sends — no duplicates.
    ///
    /// Unlike an up-front `notified = true`, the lease does NOT mark the alert delivered:
    /// [`mark_alert_notified`](Self::mark_alert_notified) does that only after a
    /// successful send. A dispatcher that crashes between the lease and the send leaves
    /// the alert `notified = false`; once its lease goes stale another dispatcher reclaims
    /// and retries it — closing the claim→crash window that used to lose the alert.
    ///
    /// # Errors
    /// A store error.
    pub async fn claim_alert_for_notify(&self, id: &str) -> DbResult<bool> {
        let now = Utc::now().timestamp();
        let before: Vec<AlertRecord> = self
            .inner
            .query(
                "UPDATE type::record('alert', $id) SET notify_claimed_at = $now \
                 WHERE notified = false \
                 AND (notify_claimed_at IS NONE OR notify_claimed_at < $stale) \
                 RETURN BEFORE",
            )
            .bind(("id", id.to_string()))
            .bind(("now", now))
            .bind(("stale", now - NOTIFY_LEASE_SECS))
            .await?
            .take(0)?;
        Ok(!before.is_empty())
    }

    /// Release a notification lease when delivery failed, so the alert is retried on the
    /// next dispatch cycle rather than waiting out the full lease. Clears
    /// `notify_claimed_at` (leaving `notified = false`); scoped to open alerts.
    ///
    /// # Errors
    /// A store error.
    pub async fn revert_alert_notified(&self, id: &str) -> DbResult<()> {
        self.inner
            .query(
                "UPDATE type::record('alert', $id) SET notify_claimed_at = NONE \
                 WHERE state = 'open'",
            )
            .bind(("id", id.to_string()))
            .await?;
        Ok(())
    }

    /// List alerts filtered by state / severity / domain, newest-first. Empty
    /// filters match everything (screen_alerts C-01..C-03).
    pub async fn list_alerts(
        &self,
        state: Option<&str>,
        severity: Option<&str>,
        domain: Option<&str>,
    ) -> DbResult<Vec<Alert>> {
        let mut conds: Vec<&str> = Vec::new();
        if state.is_some() {
            conds.push("state = $state");
        }
        if severity.is_some() {
            conds.push("severity = $severity");
        }
        if domain.is_some() {
            conds.push("domain = $domain");
        }
        let where_clause = if conds.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", conds.join(" AND "))
        };
        let stmt = format!("SELECT * FROM alert{where_clause} ORDER BY created_at DESC");

        let mut q = self.inner.query(stmt);
        if let Some(s) = state {
            q = q.bind(("state", s.to_string()));
        }
        if let Some(s) = severity {
            q = q.bind(("severity", s.to_string()));
        }
        if let Some(d) = domain {
            q = q.bind(("domain", d.to_string()));
        }
        let recs: Vec<AlertRecord> = q.await?.take(0)?;
        Ok(recs.into_iter().map(AlertRecord::into_model).collect())
    }

    /// Number of alerts still in the `open` state (header badge / S-00).
    pub async fn count_open_alerts(&self) -> DbResult<usize> {
        let recs: Vec<AlertRecord> = self
            .inner
            .query("SELECT * FROM alert WHERE state = 'open'")
            .await?
            .take(0)?;
        Ok(recs.len())
    }

    async fn find_alert(&self, id: &str) -> DbResult<Option<AlertRecord>> {
        let rec: Option<AlertRecord> = self.inner.select(("alert", id)).await?;
        Ok(rec)
    }

    /// Acknowledge an open alert (E-01). Returns whether the state changed;
    /// alerts not in the `open` state are left untouched (idempotent for bulk).
    pub async fn acknowledge_alert(&self, id: &str, actor: &str) -> DbResult<bool> {
        if self.find_alert(id).await?.is_none() {
            return Err(DbError::NotFound);
        }
        let now = to_rfc3339(Utc::now());
        // Atomic transition: only an alert still `open` is changed; `RETURN BEFORE`
        // reports whether THIS caller made the change, so two concurrent operators
        // don't both "win" (TOCTOU-free).
        let before: Vec<AlertRecord> = self
            .inner
            .query(
                "UPDATE type::record('alert', $id) SET state = 'acknowledged', \
                 acknowledged_by = $by, acknowledged_at = $t, updated_at = $t \
                 WHERE state = 'open' RETURN BEFORE",
            )
            .bind(("id", id.to_string()))
            .bind(("by", actor.to_string()))
            .bind(("t", now))
            .await?
            .take(0)?;
        Ok(!before.is_empty())
    }

    /// Resolve an open/acknowledged alert (E-02). Already-resolved alerts are
    /// left untouched (E-03). Returns whether the state changed.
    pub async fn resolve_alert(&self, id: &str, actor: &str) -> DbResult<bool> {
        if self.find_alert(id).await?.is_none() {
            return Err(DbError::NotFound);
        }
        let now = to_rfc3339(Utc::now());
        // Atomic transition: only a not-yet-resolved alert is changed (TOCTOU-free).
        let before: Vec<AlertRecord> = self
            .inner
            .query(
                "UPDATE type::record('alert', $id) SET state = 'resolved', \
                 resolved_by = $by, resolved_at = $t, updated_at = $t \
                 WHERE state != 'resolved' RETURN BEFORE",
            )
            .bind(("id", id.to_string()))
            .bind(("by", actor.to_string()))
            .bind(("t", now))
            .await?
            .take(0)?;
        Ok(!before.is_empty())
    }

    // ---- Notification targets --------------------------------------------

    pub async fn list_notification_targets(&self) -> DbResult<Vec<NotificationTarget>> {
        let recs: Vec<NotifyTargetRecord> = self
            .inner
            .query("SELECT * FROM notify_target ORDER BY name ASC")
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .map(NotifyTargetRecord::into_model)
            .collect())
    }

    async fn find_target_by_name(&self, name: &str) -> DbResult<Option<NotifyTargetRecord>> {
        let recs: Vec<NotifyTargetRecord> = self
            .inner
            .query("SELECT * FROM notify_target WHERE name = $n LIMIT 1")
            .bind(("n", name.to_string()))
            .await?
            .take(0)?;
        Ok(recs.into_iter().next())
    }

    /// Create a notification target (E-06). The name must be unique.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_notification_target(
        &self,
        name: &str,
        kind: NotifyKind,
        endpoint: &str,
        min_severity: Option<Severity>,
        domains: &[DomainKey],
        signing_secret: Option<&str>,
        enabled: bool,
        actor: &str,
    ) -> DbResult<NotificationTarget> {
        if self.find_target_by_name(name).await?.is_some() {
            return Err(DbError::Constraint(MSG_TARGET_DUP.into()));
        }
        let now = to_rfc3339(Utc::now());
        let rec = NotifyTargetRecord {
            id: None,
            name: name.to_string(),
            kind: notify_kind_str(kind).to_string(),
            endpoint: endpoint.to_string(),
            min_severity: min_severity.map(|s| severity_str(s).to_string()),
            event_filter: Vec::new(),
            signing_secret: signing_secret
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            domains: domains.iter().map(|d| d.as_str().to_string()).collect(),
            enabled,
            created_at: now.clone(),
            updated_at: now,
            created_by: actor.to_string(),
        };
        let created: Option<NotifyTargetRecord> =
            self.inner.create("notify_target").content(rec).await?;
        created
            .map(NotifyTargetRecord::into_model)
            .ok_or_else(|| DbError::Constraint("notification target creation failed".into()))
    }

    /// Enable/disable a notification target.
    pub async fn set_notification_target_enabled(&self, id: &str, enabled: bool) -> DbResult<()> {
        self.inner
            .query("UPDATE type::record('notify_target', $id) SET enabled = $e, updated_at = $t")
            .bind(("id", id.to_string()))
            .bind(("e", enabled))
            .bind(("t", to_rfc3339(Utc::now())))
            .await?;
        Ok(())
    }

    /// Delete a notification target (E-06).
    pub async fn delete_notification_target(&self, id: &str) -> DbResult<()> {
        let _: Option<NotifyTargetRecord> = self.inner.delete(("notify_target", id)).await?;
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

    fn sample(summary: &str, severity: Severity, domain: DomainKey) -> NewAlert {
        NewAlert {
            domain,
            severity,
            summary: summary.to_string(),
            source_ref: None,
            rule_ref: None,
            suppressed: false,
        }
    }

    #[tokio::test]
    async fn alert_lifecycle_and_filters() {
        let (db, _dir) = test_db().await;
        let a = db
            .raise_alert(sample("host down", Severity::Critical, DomainKey::Watch))
            .await
            .unwrap();
        db.raise_alert(sample("cert expiry", Severity::Warning, DomainKey::Proxy))
            .await
            .unwrap();

        assert_eq!(db.count_open_alerts().await.unwrap(), 2);

        // Filter by domain and severity.
        let watch = db.list_alerts(None, None, Some("watch")).await.unwrap();
        assert_eq!(watch.len(), 1);
        let crit = db.list_alerts(None, Some("critical"), None).await.unwrap();
        assert_eq!(crit.len(), 1);

        // Acknowledge moves open -> acknowledged (once).
        assert!(db.acknowledge_alert(&a.meta.id, "oper1").await.unwrap());
        assert!(!db.acknowledge_alert(&a.meta.id, "oper1").await.unwrap());
        assert_eq!(db.count_open_alerts().await.unwrap(), 1);
        let ack = db
            .list_alerts(Some("acknowledged"), None, None)
            .await
            .unwrap();
        assert_eq!(ack.len(), 1);
        assert_eq!(ack[0].acknowledged_by.as_deref(), Some("oper1"));

        // Resolve is idempotent (E-03).
        assert!(db.resolve_alert(&a.meta.id, "oper1").await.unwrap());
        assert!(!db.resolve_alert(&a.meta.id, "oper1").await.unwrap());
        let resolved = db.list_alerts(Some("resolved"), None, None).await.unwrap();
        assert_eq!(resolved.len(), 1);
    }

    #[tokio::test]
    async fn notification_target_crud() {
        let (db, _dir) = test_db().await;
        let t = db
            .create_notification_target(
                "ops-webhook",
                NotifyKind::Webhook,
                "https://example.com/hook",
                Some(Severity::Warning),
                &[],
                None,
                true,
                "admin",
            )
            .await
            .unwrap();
        // Name uniqueness.
        assert!(db
            .create_notification_target(
                "ops-webhook",
                NotifyKind::Webhook,
                "https://example.com/other",
                None,
                &[],
                None,
                true,
                "admin",
            )
            .await
            .is_err());

        db.set_notification_target_enabled(&t.meta.id, false)
            .await
            .unwrap();
        let listed = db.list_notification_targets().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert!(!listed[0].enabled);

        db.delete_notification_target(&t.meta.id).await.unwrap();
        assert!(db.list_notification_targets().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn undelivered_alert_tracking() {
        let (db, _dir) = test_db().await;
        let a = db
            .raise_alert(sample("host down", Severity::Critical, DomainKey::Watch))
            .await
            .unwrap();
        // A freshly raised alert is undelivered.
        let pending = db.list_undelivered_alerts().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].meta.id, a.meta.id);

        // After marking it, it drops out of the undelivered set.
        db.mark_alert_notified(&a.meta.id).await.unwrap();
        assert!(db.list_undelivered_alerts().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn claim_alert_for_notify_is_single_winner() {
        let (db, _dir) = test_db().await;
        let a = db
            .raise_alert(sample("host down", Severity::Critical, DomainKey::Watch))
            .await
            .unwrap();
        // The first claim wins the lease; a second (another dispatcher) loses while the
        // lease is live.
        assert!(db.claim_alert_for_notify(&a.meta.id).await.unwrap());
        assert!(!db.claim_alert_for_notify(&a.meta.id).await.unwrap());
        // The lease does NOT mark the alert delivered — it stays undelivered until a
        // successful send calls mark_alert_notified, so a dispatcher that crashes
        // mid-delivery does not silently lose the alert.
        assert_eq!(db.list_undelivered_alerts().await.unwrap().len(), 1);
        db.mark_alert_notified(&a.meta.id).await.unwrap();
        assert!(db.list_undelivered_alerts().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn reverting_a_failed_delivery_releases_the_lease() {
        let (db, _dir) = test_db().await;
        let a = db
            .raise_alert(sample("host down", Severity::Critical, DomainKey::Watch))
            .await
            .unwrap();
        // Lease it; a second dispatcher cannot claim while the lease is live.
        assert!(db.claim_alert_for_notify(&a.meta.id).await.unwrap());
        assert!(!db.claim_alert_for_notify(&a.meta.id).await.unwrap());
        // A delivery failure releases the lease, so the next claim wins immediately
        // (retried without waiting out the full lease); the alert was never lost.
        db.revert_alert_notified(&a.meta.id).await.unwrap();
        assert!(db.claim_alert_for_notify(&a.meta.id).await.unwrap());
        assert_eq!(db.list_undelivered_alerts().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_stale_lease_is_reclaimed_after_a_crash() {
        let (db, _dir) = test_db().await;
        let a = db
            .raise_alert(sample("host down", Severity::Critical, DomainKey::Watch))
            .await
            .unwrap();
        // A dispatcher leases the alert, then "crashes" before delivering or marking it.
        assert!(db.claim_alert_for_notify(&a.meta.id).await.unwrap());
        // Simulate the lease having been taken long ago (older than NOTIFY_LEASE_SECS).
        let key = a.meta.id.clone();
        db.inner
            .query("UPDATE type::record('alert', $id) SET notify_claimed_at = 1")
            .bind(("id", key))
            .await
            .unwrap()
            .check()
            .unwrap();
        // Another dispatcher reclaims the now-stale lease and can retry — the alert is
        // not stuck claimed-but-undelivered forever (the closed crash window).
        assert!(
            db.claim_alert_for_notify(&a.meta.id).await.unwrap(),
            "a stale lease must be reclaimable"
        );
    }
}
