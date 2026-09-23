//! Authentication identities and sessions (07 §3.7–3.8).
//!
//! A [`LocalAccount`] is a *login* identity — deliberately separate from the
//! per-domain user entities (LDAP/Mail/…). Sessions are persisted in the DB for
//! restart resilience (09 §6); their validity/expiry semantics live in 09 §6.5.

use super::common::AuthMethod;
use crate::authz::Role;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A local login account (07 §3.7). Never serialize the hash to the client —
/// use [`LocalAccountInfo`] for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalAccount {
    pub id: String,
    pub username: String,
    /// Argon2 PHC-format hash.
    pub password_hash: String,
    pub role: Role,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub last_login_at: Option<DateTime<Utc>>,
}

/// Display-safe projection of a [`LocalAccount`] (no password hash).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalAccountInfo {
    pub id: String,
    pub username: String,
    pub role: Role,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub last_login_at: Option<DateTime<Utc>>,
}

impl From<&LocalAccount> for LocalAccountInfo {
    fn from(account: &LocalAccount) -> Self {
        Self {
            id: account.id.clone(),
            username: account.username.clone(),
            role: account.role,
            enabled: account.enabled,
            created_at: account.created_at,
            last_login_at: account.last_login_at,
        }
    }
}

/// OIDC token bundle, held only for SSO sessions (07 §3.8).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcTokenResponse {
    pub access_token: String,
    pub token_type: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

/// A persisted login session (07 §3.8). Covers both local and SSO paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Cookie value / session identifier.
    pub session_id: String,
    /// Authenticated subject: local account id or SSO subject.
    pub subject: String,
    pub auth_method: AuthMethod,
    pub role: Role,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    /// SSO tokens (SSO sessions only).
    #[serde(default)]
    pub sso_tokens: Option<OidcTokenResponse>,
    pub login_ip: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// When set, the session is revoked and invalid regardless of expiry.
    #[serde(default)]
    pub revoked_at: Option<DateTime<Utc>>,
}

impl Session {
    /// Whether the session is currently valid at `now`: not revoked and not
    /// expired (09 §6.5, points 1–2; SSO refresh handled at the call site).
    pub fn is_valid_at(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }
}

/// The authenticated user as seen by the UI (07 §1 `CurrentUser`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurrentUser {
    pub subject: String,
    pub display_name: String,
    #[serde(default)]
    pub email: Option<String>,
    pub role: Role,
    pub auth_method: AuthMethod,
}

/// Display-safe summary of an active session (S-Account).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Truncated session id for display.
    pub session_id_short: String,
    /// Full session id (used for revocation).
    pub session_id: String,
    pub subject: String,
    #[serde(default)]
    pub display_name: Option<String>,
    pub role: Role,
    pub auth_method: AuthMethod,
    pub login_ip: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl From<&Session> for SessionInfo {
    fn from(session: &Session) -> Self {
        let short = if session.session_id.len() > 8 {
            format!("{}…", &session.session_id[..8])
        } else {
            session.session_id.clone()
        };
        Self {
            session_id_short: short,
            session_id: session.session_id.clone(),
            subject: session.subject.clone(),
            display_name: session.display_name.clone(),
            role: session.role,
            auth_method: session.auth_method,
            login_ip: session.login_ip.clone(),
            created_at: session.created_at,
            expires_at: session.expires_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_session(expires_at: DateTime<Utc>, revoked: bool) -> Session {
        Session {
            session_id: "abcdef0123456789".into(),
            subject: "admin".into(),
            auth_method: AuthMethod::Local,
            role: Role::Admin,
            display_name: Some("Administrator".into()),
            email: None,
            sso_tokens: None,
            login_ip: "127.0.0.1".into(),
            created_at: Utc::now(),
            expires_at,
            revoked_at: revoked.then(Utc::now),
        }
    }

    #[test]
    fn session_validity_checks_expiry_and_revocation() {
        let now = Utc::now();
        assert!(base_session(now + chrono::Duration::hours(1), false).is_valid_at(now));
        assert!(!base_session(now - chrono::Duration::hours(1), false).is_valid_at(now));
        assert!(!base_session(now + chrono::Duration::hours(1), true).is_valid_at(now));
    }

    #[test]
    fn session_info_truncates_id() {
        let info = SessionInfo::from(&base_session(Utc::now(), false));
        assert_eq!(info.session_id_short, "abcdef01…");
        assert_eq!(info.session_id, "abcdef0123456789");
    }

    #[test]
    fn account_info_drops_hash() {
        let account = LocalAccount {
            id: "1".into(),
            username: "admin".into(),
            password_hash: "secret-hash".into(),
            role: Role::Admin,
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login_at: None,
        };
        let info = LocalAccountInfo::from(&account);
        assert_eq!(info.username, "admin");
        let json = serde_json::to_string(&info).unwrap();
        assert!(!json.contains("secret-hash"));
    }
}
