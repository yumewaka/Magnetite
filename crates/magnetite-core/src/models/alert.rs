//! Cross-cutting alerting structures (07 §3.3–3.4 / F-05).

use super::common::{AlertState, NotifyKind, RecordMeta, Severity};
use crate::domain::DomainKey;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A single cross-cutting alert (07 §3.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    #[serde(flatten)]
    pub meta: RecordMeta,
    pub domain: DomainKey,
    pub severity: Severity,
    #[serde(default)]
    pub state: AlertState,
    pub summary: String,
    /// Reference to the originating object (host/cert/…).
    #[serde(default)]
    pub source_ref: Option<String>,
    /// Reference to the rule that generated this alert (K8s AlertRule /
    /// Watch MonitorRule).
    #[serde(default)]
    pub rule_ref: Option<String>,
    #[serde(default)]
    pub acknowledged_by: Option<String>,
    #[serde(default)]
    pub resolved_by: Option<String>,
    #[serde(default)]
    pub acknowledged_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub resolved_at: Option<DateTime<Utc>>,
    /// Suppressed by a maintenance window etc. Orthogonal to `state`.
    #[serde(default)]
    pub suppressed: bool,
}

/// A notification / integration target (07 §3.4). The old per-service webhooks
/// are fully consolidated here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationTarget {
    #[serde(flatten)]
    pub meta: RecordMeta,
    /// Unique target name.
    pub name: String,
    pub kind: NotifyKind,
    pub endpoint: String,
    /// Minimum severity to deliver — required for `webhook`, unused for
    /// `audit_sink`.
    #[serde(default)]
    pub min_severity: Option<Severity>,
    /// For `audit_sink`: which event kinds to forward.
    #[serde(default)]
    pub event_filter: BTreeSet<String>,
    /// Signing secret; never written back to audit (masked).
    #[serde(default)]
    pub signing_secret: Option<String>,
    /// Target domains (empty = all).
    #[serde(default)]
    pub domains: BTreeSet<DomainKey>,
    pub enabled: bool,
}
