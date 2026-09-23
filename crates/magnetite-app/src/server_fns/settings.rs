//! System-settings server functions (S-Settings / F-09). Reading and saving the
//! runtime system settings are Admin-only (AC-04); personal settings
//! (language/theme) are handled entirely on the client. Saves are validated
//! (screen_settings §5) and audited (F-04) under `Portal`.

use leptos::prelude::*;
use magnetite_core::models::SystemSettings;

/// Fetch the effective system settings (Admin). Secrets are masked.
#[server(GetSystemSettings, "/api")]
pub async fn get_system_settings() -> Result<SystemSettings, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Admin).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .get_system_settings(&state.config)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[cfg(feature = "ssr")]
fn is_http_url(value: &str) -> bool {
    let v = value.trim();
    (v.starts_with("http://") || v.starts_with("https://")) && v.len() > "https://".len()
}

/// Save the system settings and hot-reload (E-05). Admin-only, validated.
#[server(SaveSystemSettings, "/api")]
#[allow(clippy::too_many_arguments)]
pub async fn save_system_settings(
    enabled_domains: Vec<String>,
    dashboard_refresh_secs: u64,
    retention_days: u32,
    sso_enabled: bool,
    issuer_url: String,
    client_id: String,
    redirect_uri: String,
    client_secret: String,
) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::{client_ip, require};
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domain::DomainKey;
    use magnetite_core::models::common::{ActionKind, OpResult};

    let user = require(ActionClass::Admin).await?;

    if !(5..=3600).contains(&dashboard_refresh_secs) {
        return Err(ServerFnError::new("5〜3600 秒の範囲で入力してください。"));
    }
    if !(1..=3650).contains(&retention_days) {
        return Err(ServerFnError::new("1〜3650 日の範囲で入力してください。"));
    }
    if sso_enabled {
        if !is_http_url(&issuer_url) {
            return Err(ServerFnError::new("有効な issuer URL を入力してください。"));
        }
        if client_id.trim().is_empty() {
            return Err(ServerFnError::new("client_id を入力してください。"));
        }
        if !is_http_url(&redirect_uri) {
            return Err(ServerFnError::new(
                "有効な redirect URI を入力してください。",
            ));
        }
    }

    let domains: Vec<DomainKey> = enabled_domains
        .iter()
        .filter_map(|k| DomainKey::from_str(k))
        .collect();
    let secret = if client_secret.trim().is_empty() {
        None
    } else {
        Some(client_secret.as_str())
    };

    let state = expect_context::<AppState>();
    state
        .db
        .save_system_settings(
            &domains,
            dashboard_refresh_secs,
            retention_days,
            sso_enabled,
            issuer_url.trim(),
            client_id.trim(),
            redirect_uri.trim(),
            secret,
        )
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let _ = state
        .db
        .append_audit(magnetite_core::models::NewAuditEntry {
            actor: user.subject.clone(),
            actor_role: user.role,
            domain: DomainKey::Portal,
            action: ActionKind::Update,
            target_kind: "app_settings".to_string(),
            target_id: "current".to_string(),
            result: OpResult::Success,
            ip: client_ip().await,
            detail: None,
        })
        .await;
    Ok(())
}
