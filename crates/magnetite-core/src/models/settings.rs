//! Runtime-editable system settings (07 §3.10 / F-09 / screen_settings).
//!
//! These mirror the editable subset of [`crate::config::AppConfig`] that the
//! S-Settings screen manages at runtime (domain enablement, operational policy
//! and the SSO connection). Server-binding fields stay restart-only and are not
//! represented here. Secrets are never projected to the client — only a
//! [`SsoSettings::has_secret`] flag is.

use crate::domain::DomainKey;
use serde::{Deserialize, Serialize};

/// One domain's enablement toggle (screen_settings C-05).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainToggle {
    pub key: DomainKey,
    /// Human label carried through from `AppConfig` for display.
    pub display_name: String,
    pub enabled: bool,
}

/// SSO connection settings as shown to the client — the secret is masked and
/// only its presence is reported.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SsoSettings {
    pub enabled: bool,
    pub issuer_url: String,
    pub client_id: String,
    pub redirect_uri: String,
    /// Whether a client secret is currently stored (the value is never sent).
    pub has_secret: bool,
}

/// The editable system settings surfaced to (and saved from) S-Settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSettings {
    /// All eight domains in canonical order with their enablement.
    pub domains: Vec<DomainToggle>,
    pub dashboard_refresh_secs: u64,
    pub retention_days: u32,
    pub sso: SsoSettings,
}
