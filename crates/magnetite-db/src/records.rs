//! On-disk record shapes and their conversions to/from core models.
//!
//! Core models stay database-agnostic (they compile to WASM). These record
//! structs carry the SurrealDB `RecordId`, derive `SurrealValue` for typed
//! query results, and store timestamps as RFC3339 strings (which sort
//! chronologically) and nested JSON as encoded strings.

use chrono::{DateTime, Utc};
use magnetite_core::authz::Role;
use magnetite_core::domain::DomainKey;
use magnetite_core::models::common::{ActionKind, AuthMethod, OpResult};
use magnetite_core::models::{AuditEntry, LocalAccount, OidcTokenResponse, Session};
use serde::{Deserialize, Serialize};
use surrealdb::types::{RecordId, RecordIdKey, SurrealValue};

pub(crate) fn to_rfc3339(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339()
}

/// Split a compound replication cursor `"<timestamp>|<tiebreak-key>"` into its parts.
/// A legacy timestamp-only cursor (no `|`) yields an empty key, so the boundary rows are
/// re-fetched (harmless — the idempotent apply dedups them) rather than skipped.
pub(crate) fn split_ts_cursor(cursor: &str) -> (String, String) {
    match cursor.split_once('|') {
        Some((ts, key)) => (ts.to_string(), key.to_string()),
        None => (cursor.to_string(), String::new()),
    }
}

pub(crate) fn parse_rfc3339(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

/// String key of a SurrealDB record id, suitable to feed back into
/// `select`/`update`/`delete` by `(table, key)`.
pub(crate) fn record_key(id: &Option<RecordId>) -> String {
    id.as_ref()
        .map(|record| match &record.key {
            RecordIdKey::String(s) => s.clone(),
            RecordIdKey::Number(n) => n.to_string(),
            RecordIdKey::Uuid(u) => u.to_string(),
            other => format!("{other:?}"),
        })
        .unwrap_or_default()
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub(crate) struct AccountRecord {
    pub id: Option<RecordId>,
    pub username: String,
    pub password_hash: String,
    pub role: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
    pub last_login_at: Option<String>,
}

impl AccountRecord {
    pub fn into_model(self) -> LocalAccount {
        LocalAccount {
            id: record_key(&self.id),
            username: self.username,
            password_hash: self.password_hash,
            role: Role::from_str(&self.role).unwrap_or_default(),
            enabled: self.enabled,
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            last_login_at: self.last_login_at.as_deref().map(parse_rfc3339),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub(crate) struct SessionRecord {
    pub id: Option<RecordId>,
    pub session_id: String,
    pub subject: String,
    pub auth_method: String,
    pub role: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    /// JSON-encoded `OidcTokenResponse` (SSO sessions only).
    pub sso_tokens: Option<String>,
    pub login_ip: String,
    pub created_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
}

impl SessionRecord {
    pub fn from_model(session: &Session) -> Self {
        Self {
            id: None,
            session_id: session.session_id.clone(),
            subject: session.subject.clone(),
            auth_method: match session.auth_method {
                AuthMethod::Local => "local".into(),
                AuthMethod::Sso => "sso".into(),
            },
            role: session.role.as_str().to_string(),
            display_name: session.display_name.clone(),
            email: session.email.clone(),
            sso_tokens: session
                .sso_tokens
                .as_ref()
                .and_then(|t| serde_json::to_string(t).ok()),
            login_ip: session.login_ip.clone(),
            created_at: to_rfc3339(session.created_at),
            expires_at: to_rfc3339(session.expires_at),
            revoked_at: session.revoked_at.map(to_rfc3339),
        }
    }

    pub fn into_model(self) -> Session {
        Session {
            session_id: self.session_id,
            subject: self.subject,
            auth_method: if self.auth_method == "sso" {
                AuthMethod::Sso
            } else {
                AuthMethod::Local
            },
            role: Role::from_str(&self.role).unwrap_or_default(),
            display_name: self.display_name,
            email: self.email,
            sso_tokens: self
                .sso_tokens
                .as_deref()
                .and_then(|s| serde_json::from_str::<OidcTokenResponse>(s).ok()),
            login_ip: self.login_ip,
            created_at: parse_rfc3339(&self.created_at),
            expires_at: parse_rfc3339(&self.expires_at),
            revoked_at: self.revoked_at.as_deref().map(parse_rfc3339),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub(crate) struct AuditRecord {
    pub id: Option<RecordId>,
    pub at: String,
    pub actor: String,
    pub actor_role: String,
    pub domain: String,
    pub action: String,
    pub target_kind: String,
    pub target_id: String,
    pub result: String,
    pub ip: String,
    /// JSON-encoded change detail (sensitive values masked upstream).
    pub detail: Option<String>,
}

impl AuditRecord {
    pub fn into_model(self) -> AuditEntry {
        AuditEntry {
            id: record_key(&self.id),
            at: parse_rfc3339(&self.at),
            actor: self.actor,
            actor_role: Role::from_str(&self.actor_role).unwrap_or_default(),
            domain: DomainKey::from_str(&self.domain).unwrap_or(DomainKey::Portal),
            action: parse_action(&self.action),
            target_kind: self.target_kind,
            target_id: self.target_id,
            result: if self.result == "failure" {
                OpResult::Failure
            } else {
                OpResult::Success
            },
            ip: self.ip,
            detail: self
                .detail
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok()),
        }
    }
}

pub(crate) fn action_str(action: ActionKind) -> &'static str {
    match action {
        ActionKind::Create => "create",
        ActionKind::Update => "update",
        ActionKind::Delete => "delete",
        ActionKind::Control => "control",
        ActionKind::Login => "login",
        ActionKind::Logout => "logout",
        ActionKind::Restore => "restore",
    }
}

fn parse_action(value: &str) -> ActionKind {
    match value {
        "create" => ActionKind::Create,
        "update" => ActionKind::Update,
        "delete" => ActionKind::Delete,
        "control" => ActionKind::Control,
        "login" => ActionKind::Login,
        "logout" => ActionKind::Logout,
        "restore" => ActionKind::Restore,
        _ => ActionKind::Update,
    }
}
