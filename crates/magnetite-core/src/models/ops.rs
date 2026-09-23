//! Templates, backups, domain status and operational logs (07 §3.5–3.6, 3.11–3.12).

use super::common::{BackupKind, HealthState, LogKind, LogLevel, RecordMeta};
use crate::domain::DomainKey;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A reusable configuration template (07 §3.5 / F-07).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Template {
    #[serde(flatten)]
    pub meta: RecordMeta,
    pub domain: DomainKey,
    /// Unique within its domain.
    pub name: String,
    /// Domain-specific body (JSON/YAML rendered to JSON).
    pub body: serde_json::Value,
    #[serde(default)]
    pub description: Option<String>,
}

/// Configuration backup metadata (07 §3.6 / F-06). The `domain` field may be a
/// specific domain or `Portal` for a whole-system backup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Backup {
    #[serde(flatten)]
    pub meta: RecordMeta,
    pub domain: DomainKey,
    pub kind: BackupKind,
    pub size_bytes: u64,
    /// Reference to the stored artifact (BLOB/file).
    pub artifact_ref: String,
    /// Backup format version, for restore compatibility checks.
    pub format_version: String,
}

/// Cached operational status of a domain (07 §3.11). A derived value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainStatus {
    pub domain: DomainKey,
    pub state: HealthState,
    /// Domain-specific headline metrics (e.g. DNS zone count).
    #[serde(default)]
    pub metrics: BTreeMap<String, serde_json::Value>,
    pub checked_at: DateTime<Utc>,
}

impl DomainStatus {
    /// A placeholder status for a domain whose health has not been probed yet.
    pub fn unknown(domain: DomainKey, checked_at: DateTime<Utc>) -> Self {
        Self {
            domain,
            state: HealthState::Unknown,
            metrics: BTreeMap::new(),
            checked_at,
        }
    }
}

/// A normalized operational/query/access log line (07 §3.12). Distinct from the
/// audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub id: String,
    /// Originating domain, or `Portal` for system logs.
    pub domain: DomainKey,
    pub log_kind: LogKind,
    pub level: LogLevel,
    pub message: String,
    pub at: DateTime<Utc>,
    #[serde(default)]
    pub meta: Option<serde_json::Value>,
}
