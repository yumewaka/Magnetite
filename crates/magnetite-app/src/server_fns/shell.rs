//! Shell/dashboard server functions.

use crate::types::{DomainStatusCard, ShellInfo};
use leptos::prelude::*;

/// Build the navigation domain list from the runtime settings overlay (E-04):
/// a domain shows only when enabled in settings and present in config (so it
/// carries a display name/icon).
#[cfg(feature = "ssr")]
async fn nav_domains(state: &crate::state::AppState) -> Vec<crate::types::DomainNav> {
    use crate::types::DomainNav;
    let settings = state
        .db
        .get_system_settings(&state.config)
        .await
        .unwrap_or_else(|_| magnetite_core::models::SystemSettings {
            domains: Vec::new(),
            dashboard_refresh_secs: state.config.policy.dashboard_refresh_secs,
            retention_days: state.config.policy.retention_days,
            sso: Default::default(),
        });
    settings
        .domains
        .into_iter()
        .filter(|d| d.enabled)
        .filter_map(|d| {
            state.config.domains.get(&d.key).map(|cfg| DomainNav {
                key: d.key,
                display_name: cfg.display_name.clone(),
                icon: cfg.icon.clone(),
            })
        })
        .collect()
}

/// Fetch everything the authenticated shell needs. Returns an error when
/// unauthenticated so the layout can redirect to login.
#[server(GetShellInfo, "/api")]
pub async fn get_shell_info() -> Result<ShellInfo, ServerFnError> {
    use crate::server_fns::auth::current_user;
    use crate::state::AppState;

    let user = current_user()
        .await?
        .ok_or_else(|| ServerFnError::new("unauthenticated"))?;
    let state = expect_context::<AppState>();
    let settings = state
        .db
        .get_system_settings(&state.config)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let open_alert_count = state.db.count_open_alerts().await.unwrap_or(0) as u32;
    Ok(ShellInfo {
        user,
        domains: nav_domains(&state).await,
        open_alert_count,
        dashboard_refresh_secs: settings.dashboard_refresh_secs,
    })
}

/// Fetch the integrated dashboard cards (F-03). Phase 0 reports `unknown`
/// health for every enabled domain; live health arrives with daemon
/// integration (09 §4).
#[server(GetDashboardCards, "/api")]
pub async fn get_dashboard_cards() -> Result<Vec<DomainStatusCard>, ServerFnError> {
    use crate::server_fns::auth::current_user;
    use crate::state::AppState;

    current_user()
        .await?
        .ok_or_else(|| ServerFnError::new("unauthenticated"))?;
    let state = expect_context::<AppState>();
    // Health comes from the embedded protocol server for each domain (09b §-1).
    // With no server registered (Phase E0) this is `Disabled` → "unknown", so
    // the dashboard is unchanged until domains are ported.
    let cards = nav_domains(&state)
        .await
        .into_iter()
        .map(|d| {
            let health = state.services.health(d.key).as_str().to_string();
            DomainStatusCard {
                key: d.key,
                display_name: d.display_name,
                icon: d.icon,
                health,
                metrics: Vec::new(),
            }
        })
        .collect();
    Ok(cards)
}
