//! `magnetite-notify` — the alert notification dispatcher.
//!
//! Threshold evaluation raises alert rows; this crate turns them into actual
//! notifications. It polls the DB for undelivered open alerts and fans each out to
//! the enabled notification targets whose severity floor and domain filter match:
//!
//! - **Webhook** / **AuditSink** — HTTP `POST` of the alert JSON, optionally signed
//!   with `X-Magnetite-Signature: sha256=<hmac>` when the target has a secret.
//! - **Email** — a plain-text mail through the configured relay (via `magnetite-mail`).
//!
//! It lives in its own crate (not in `magnetite-watch`, which stays db/core-only) so
//! it can depend on both an HTTP client and the mail sender; the daemon spawns it.

#![forbid(unsafe_code)]

use std::time::Duration;

use magnetite_core::config::RelayConfig;
use magnetite_core::models::common::{NotifyKind, Severity};
use magnetite_core::models::{Alert, NotificationTarget};
use magnetite_db::Db;
use tokio::sync::watch;

mod webhook;

/// How often the dispatcher scans for undelivered alerts.
const POLL_INTERVAL: Duration = Duration::from_secs(15);

/// Mail settings the dispatcher needs to deliver `Email` targets.
#[derive(Debug, Clone)]
pub struct NotifyConfig {
    /// Outbound relay (smarthost); `None` = direct MX delivery.
    pub relay: Option<RelayConfig>,
    /// The `From:` address notification mails are sent as.
    pub from_address: String,
}

/// Spawn the notification dispatcher loop. It runs until `shutdown` flips to `true`,
/// scanning every [`POLL_INTERVAL`] and fanning out any newly-raised alerts.
pub fn spawn_dispatcher(db: Db, config: NotifyConfig, mut shutdown: watch::Receiver<bool>) {
    tokio::spawn(async move {
        tracing::info!("notification dispatcher started (poll {:?})", POLL_INTERVAL);
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { break; }
                }
                _ = tokio::time::sleep(POLL_INTERVAL) => {
                    if let Err(e) = dispatch_pending(&db, &config).await {
                        tracing::warn!("notification dispatch pass failed: {e}");
                    }
                }
            }
        }
        tracing::info!("notification dispatcher stopped");
    });
}

/// Numeric rank so severity floors compare without relying on enum ordering.
fn rank(s: Severity) -> u8 {
    match s {
        Severity::Critical => 3,
        Severity::Warning => 2,
        Severity::Info => 1,
    }
}

/// Whether `target` should receive `alert`: enabled, severity at or above the floor,
/// and (when the target scopes domains) the alert's domain is in the set.
fn matches(target: &NotificationTarget, alert: &Alert) -> bool {
    if !target.enabled {
        return false;
    }
    if let Some(floor) = target.min_severity {
        if rank(alert.severity) < rank(floor) {
            return false;
        }
    }
    if !target.domains.is_empty() && !target.domains.contains(&alert.domain) {
        return false;
    }
    true
}

/// One dispatch pass: deliver every undelivered alert to its matching targets, then
/// mark it notified (best-effort — a failing target is logged, not retried, so a
/// single bad endpoint cannot wedge the queue).
///
/// # Errors
/// A DB read error while listing alerts or targets.
async fn dispatch_pending(
    db: &Db,
    config: &NotifyConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let alerts = db.list_undelivered_alerts().await?;
    if alerts.is_empty() {
        return Ok(());
    }
    let targets = db.list_notification_targets().await?;

    for alert in &alerts {
        // Lease the alert before delivering, so when several instances share one DB
        // (Tier B) exactly one dispatcher sends it — no duplicate notifications. A
        // `false` claim means another instance holds a live lease; skip.
        match db.claim_alert_for_notify(&alert.meta.id).await {
            Ok(true) => {}
            Ok(false) => continue,
            Err(e) => {
                tracing::warn!("failed to claim alert {} for notify: {e}", alert.meta.id);
                continue;
            }
        }
        // Deliver to every matching target, then mark notified ONLY on full success. A
        // crash between the lease and this point leaves the alert undelivered; its lease
        // goes stale and another cycle retries it (at-least-once, never silently lost).
        let mut all_ok = true;
        for target in targets.iter().filter(|t| matches(t, alert)) {
            if !deliver(config, target, alert).await {
                all_ok = false;
            }
        }
        if all_ok {
            if let Err(e) = db.mark_alert_notified(&alert.meta.id).await {
                // Delivered but couldn't record it: the lease expiry will let a later
                // cycle resend (a duplicate notification, not a lost one).
                tracing::warn!(
                    "alert {} delivered but could not be marked notified; may resend: {e}",
                    alert.meta.id
                );
            }
        } else {
            tracing::error!(
                "alert {} delivery failed on ≥1 target; will retry next cycle",
                alert.meta.id
            );
            if let Err(e) = db.revert_alert_notified(&alert.meta.id).await {
                tracing::warn!("could not requeue alert {} for retry: {e}", alert.meta.id);
            }
        }
    }
    Ok(())
}

/// Deliver one alert to one target by its kind, logging any failure. Returns whether
/// delivery succeeded (so the caller can requeue the alert if any target failed).
async fn deliver(config: &NotifyConfig, target: &NotificationTarget, alert: &Alert) -> bool {
    match target.kind {
        NotifyKind::Webhook | NotifyKind::AuditSink => {
            if let Err(e) =
                webhook::post(&target.endpoint, target.signing_secret.as_deref(), alert).await
            {
                tracing::warn!(
                    "webhook notify to '{}' ({}) failed: {e}",
                    target.name,
                    target.endpoint
                );
                return false;
            }
            true
        }
        NotifyKind::Email => {
            let subject = format!(
                "[magnetite/{}] {:?} alert",
                alert.domain.as_str(),
                alert.severity
            );
            let body = format!(
                "重大度: {:?}\nドメイン: {}\n概要: {}\n発生時刻: {}\n{}{}",
                alert.severity,
                alert.domain.as_str(),
                alert.summary,
                alert.meta.created_at.to_rfc3339(),
                alert
                    .source_ref
                    .as_deref()
                    .map(|s| format!("対象: {s}\n"))
                    .unwrap_or_default(),
                alert
                    .rule_ref
                    .as_deref()
                    .map(|r| format!("ルール: {r}\n"))
                    .unwrap_or_default(),
            );
            let accepted = magnetite_mail::send_mail(
                config.relay.as_ref(),
                &config.from_address,
                std::slice::from_ref(&target.endpoint),
                &subject,
                &body,
            )
            .await;
            if accepted == 0 {
                tracing::warn!(
                    "email notify to '{}' ({}) delivered to 0 recipients",
                    target.name,
                    target.endpoint
                );
                return false;
            }
            true
        }
    }
}
