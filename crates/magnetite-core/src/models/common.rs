//! Shared enumerations and the common-field record metadata (07 §3.1).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Common fields carried by every persistent entity (07 §3.1).
///
/// Domain and cross-cutting records embed this rather than re-declaring
/// `id`/timestamps/`created_by`. `id` is the DB-assigned identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordMeta {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// Actor (username / SSO subject) that created or last updated the record.
    pub created_by: String,
}

/// Alert / status severity, shared between `DomainStatus` health and `Alert`
/// (06 §2 gives them common semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Critical,
    Warning,
    Info,
}

/// Lifecycle state of an alert (07 §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AlertState {
    #[default]
    Open,
    Acknowledged,
    Resolved,
}

/// Domain operational health (07 §3.11 / 06 §2). Replaces the old
/// process-oriented `ServiceStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    Healthy,
    Warning,
    Error,
    Unknown,
}

/// Kind of operational log line (09 §9). The old stdout/stderr stream concept
/// is gone; logs are normalized into these categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogKind {
    /// Internal module operation log.
    Operation,
    /// Query log ingested from a real daemon (e.g. DNS queries).
    Query,
    /// Access log ingested from a real daemon (e.g. proxy access).
    Access,
}

/// Severity level of a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// Audited action kind (07 §3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    Create,
    Update,
    Delete,
    Control,
    Login,
    Logout,
    Restore,
}

/// Outcome recorded on an audit entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpResult {
    Success,
    Failure,
}

/// Authentication path used to establish a session (07 §3.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    Local,
    Sso,
}

/// Notification target kind (07 §3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotifyKind {
    /// Alert webhook (HTTP POST of the alert, optionally HMAC-signed).
    Webhook,
    /// External audit sink (SIEM etc.) — absorbs the old per-service audit
    /// webhooks. Delivered as an HTTP POST like a webhook.
    AuditSink,
    /// Email notification: the target `endpoint` is the recipient address; the alert
    /// is delivered as a mail through the configured relay.
    Email,
}

/// Whether a backup was taken manually or by the scheduler (07 §3.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupKind {
    Manual,
    Auto,
}
