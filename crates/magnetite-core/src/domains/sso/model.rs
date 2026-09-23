//! SSO domain data (07_data_sso): the management face of the unified auth
//! platform — upstream IdP providers, registered OIDC clients and issued SSO
//! sessions. Tenants are fully removed (single implicit tenant).
//!
//! Secrets are never projected: models carry a `has_secret` flag, and the raw
//! secret lives server-side only (07_data_sso §5.1).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// An upstream/federated IdP provider (07_data_sso §2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Provider {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub name: String,
    /// `oidc` / `google` / `github` / `azure` / `custom`.
    pub provider_type: String,
    #[serde(default)]
    pub issuer: Option<String>,
    pub client_id: String,
    /// Whether a client secret is stored (the value itself is never returned).
    pub has_secret: bool,
    #[serde(default)]
    pub authorize_url: Option<String>,
    #[serde(default)]
    pub token_url: Option<String>,
    #[serde(default)]
    pub userinfo_url: Option<String>,
    pub scopes: Vec<String>,
    pub redirect_uri: String,
    pub auto_provision: bool,
    pub enabled: bool,
}

/// The full server-side login configuration for an upstream provider, **including
/// its client secret** — used only by the federation flow (browser login via an
/// external IdP), never projected to the browser. Distinct from [`Provider`] (the
/// masked management view).
#[derive(Debug, Clone)]
pub struct ProviderLoginConfig {
    pub name: String,
    pub provider_type: String,
    pub client_id: String,
    pub client_secret: String,
    pub authorize_url: Option<String>,
    pub token_url: Option<String>,
    pub userinfo_url: Option<String>,
    pub scopes: Vec<String>,
    pub redirect_uri: String,
    pub auto_provision: bool,
    pub enabled: bool,
}

/// A registered OIDC client / relying party (07_data_sso §3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcClient {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub client_name: String,
    /// Issued OAuth client id.
    pub client_id: String,
    pub has_secret: bool,
    /// `confidential` / `public`.
    pub client_type: String,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub redirect_uris: Vec<String>,
    pub scopes: Vec<String>,
    /// `client_secret_basic` / `client_secret_post` / `none`.
    pub token_endpoint_auth_method: String,
    #[serde(default)]
    pub provider_ref: Option<String>,
    pub enabled: bool,
}

/// An issued SSO session (07_data_sso §4). Tokens are never projected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoSession {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub session_ref: String,
    pub subject: String,
    #[serde(default)]
    pub client_ref: Option<String>,
    #[serde(default)]
    pub provider_ref: Option<String>,
    pub scopes: Vec<String>,
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub user_agent: Option<String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub revoked_at: Option<DateTime<Utc>>,
}

impl SsoSession {
    /// Whether the session is currently active (not revoked, not expired).
    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }
}
