//! Cross-cutting audit log (07 §3.2 / F-04).
//!
//! Append-only and immutable: there is no update or delete API. Every
//! successful mutating operation across every domain records one entry.

use super::common::{ActionKind, OpResult};
use crate::authz::Role;
use crate::domain::DomainKey;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single audit record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub at: DateTime<Utc>,
    /// Actor (username / SSO subject).
    pub actor: String,
    /// Effective role at execution time.
    pub actor_role: Role,
    /// Target domain, or `Portal` for cross-cutting operations.
    pub domain: DomainKey,
    pub action: ActionKind,
    /// Target data kind (e.g. "zone", "local_account").
    pub target_kind: String,
    pub target_id: String,
    pub result: OpResult,
    /// Source IP of the request.
    pub ip: String,
    /// Structured change detail; sensitive values are masked (05 §5).
    #[serde(default)]
    pub detail: Option<serde_json::Value>,
}

/// A page of audit entries plus the total number of matches for the active
/// filter (S-Audit pagination).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPage {
    pub entries: Vec<AuditEntry>,
    pub total: usize,
}

/// Parameters for recording a new audit entry (id/timestamp assigned by the
/// store).
#[derive(Debug, Clone)]
pub struct NewAuditEntry {
    pub actor: String,
    pub actor_role: Role,
    pub domain: DomainKey,
    pub action: ActionKind,
    pub target_kind: String,
    pub target_id: String,
    pub result: OpResult,
    pub ip: String,
    pub detail: Option<serde_json::Value>,
}
