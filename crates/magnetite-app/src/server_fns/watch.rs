//! Watch (monitoring) domain server functions (F-18 / S-WATCH-01..06).
//! Authorized (08_authz), validated (screen_watch §3/§5), audited (F-04).

use crate::types::WatchMetrics;
use leptos::prelude::*;
use magnetite_core::domains::watch::model::{
    HostGroup, MaintenanceWindow, Metric, MonitorRule, MonitoredHost,
};

#[cfg(feature = "ssr")]
async fn audit_watch(
    user: &magnetite_core::models::CurrentUser,
    action: magnetite_core::models::common::ActionKind,
    target_kind: &str,
    target_id: &str,
) {
    use crate::server_fns::auth::client_ip;
    use crate::state::AppState;
    let state = expect_context::<AppState>();
    let _ = state
        .db
        .append_audit(magnetite_core::models::NewAuditEntry {
            actor: user.subject.clone(),
            actor_role: user.role,
            domain: magnetite_core::domain::DomainKey::Watch,
            action,
            target_kind: target_kind.to_string(),
            target_id: target_id.to_string(),
            result: magnetite_core::models::common::OpResult::Success,
            ip: client_ip().await,
            detail: None,
        })
        .await;
}

#[server(GetWatchMetrics, "/api")]
pub async fn get_watch_metrics() -> Result<WatchMetrics, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    let (total, online, offline, warning, rules) = state
        .db
        .watch_metrics()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(WatchMetrics {
        host_total: total as u64,
        online: online as u64,
        offline: offline as u64,
        warning: warning as u64,
        rule_count: rules as u64,
    })
}

// ---- Hosts (S-WATCH-02) ---------------------------------------------------

#[server(ListWatchHosts, "/api")]
pub async fn list_watch_hosts() -> Result<Vec<MonitoredHost>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_watch_hosts()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server(HostsUnderMaintenance, "/api")]
pub async fn hosts_under_maintenance() -> Result<Vec<String>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .hosts_under_maintenance()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server(SaveWatchHost, "/api")]
pub async fn save_watch_host(host: MonitoredHost) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::watch::validate::check_host;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    check_host(&host.name, &host.ip_address, &host.tags).map_err(ServerFnError::new)?;
    let is_create = host.id.is_empty();
    let state = expect_context::<AppState>();
    let saved = state
        .db
        .save_watch_host(&host)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_watch(
        &user,
        if is_create {
            ActionKind::Create
        } else {
            ActionKind::Update
        },
        "watch_host",
        &saved.name,
    )
    .await;
    Ok(())
}

#[server(DeleteWatchHost, "/api")]
pub async fn delete_watch_host(id: String, name: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_watch_host(&id, &name)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_watch(&user, ActionKind::Delete, "watch_host", &name).await;
    Ok(())
}

// ---- Rules (S-WATCH-03) ---------------------------------------------------

#[server(ListWatchRules, "/api")]
pub async fn list_watch_rules() -> Result<Vec<MonitorRule>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_watch_rules()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server(SaveWatchRule, "/api")]
pub async fn save_watch_rule(rule: MonitorRule) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::watch::validate::check_rule;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    check_rule(
        &rule.name,
        &rule.metric,
        rule.warning_threshold,
        rule.critical_threshold,
    )
    .map_err(ServerFnError::new)?;
    let is_create = rule.id.is_empty();
    let state = expect_context::<AppState>();
    let saved = state
        .db
        .save_watch_rule(&rule)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_watch(
        &user,
        if is_create {
            ActionKind::Create
        } else {
            ActionKind::Update
        },
        "watch_rule",
        &saved.name,
    )
    .await;
    Ok(())
}

#[server(ToggleWatchRule, "/api")]
pub async fn toggle_watch_rule(id: String, enabled: bool) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .set_watch_rule_enabled(&id, enabled)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_watch(&user, ActionKind::Update, "watch_rule", &id).await;
    Ok(())
}

#[server(DeleteWatchRule, "/api")]
pub async fn delete_watch_rule(id: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_watch_rule(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_watch(&user, ActionKind::Delete, "watch_rule", &id).await;
    Ok(())
}

// ---- Groups (S-WATCH-04) --------------------------------------------------

#[server(ListWatchGroups, "/api")]
pub async fn list_watch_groups() -> Result<Vec<HostGroup>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_watch_groups()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server(SaveWatchGroup, "/api")]
pub async fn save_watch_group(group: HostGroup) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    if group.name.trim().is_empty() {
        return Err(ServerFnError::new("名称を正しく入力してください。"));
    }
    let is_create = group.id.is_empty();
    let state = expect_context::<AppState>();
    let saved = state
        .db
        .save_watch_group(&group)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_watch(
        &user,
        if is_create {
            ActionKind::Create
        } else {
            ActionKind::Update
        },
        "watch_group",
        &saved.name,
    )
    .await;
    Ok(())
}

#[server(DeleteWatchGroup, "/api")]
pub async fn delete_watch_group(id: String, name: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_watch_group(&id, &name)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_watch(&user, ActionKind::Delete, "watch_group", &name).await;
    Ok(())
}

// ---- Maintenance windows (S-WATCH-05) -------------------------------------

#[server(ListWatchMaintenance, "/api")]
pub async fn list_watch_maintenance() -> Result<Vec<MaintenanceWindow>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_watch_maintenance()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server(CreateWatchMaintenance, "/api")]
pub async fn create_watch_maintenance(window: MaintenanceWindow) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::watch::validate::check_maintenance;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    check_maintenance(&window.name, window.starts_at, window.ends_at)
        .map_err(ServerFnError::new)?;
    let state = expect_context::<AppState>();
    let created = state
        .db
        .create_watch_maintenance(&window)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_watch(
        &user,
        ActionKind::Create,
        "watch_maintenance",
        &created.name,
    )
    .await;
    Ok(())
}

#[server(DeleteWatchMaintenance, "/api")]
pub async fn delete_watch_maintenance(id: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_watch_maintenance(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_watch(&user, ActionKind::Delete, "watch_maintenance", &id).await;
    Ok(())
}

// ---- Metrics (S-WATCH-06) -------------------------------------------------

#[server(ListHostMetrics, "/api")]
pub async fn list_host_metrics(host_name: String) -> Result<Vec<Metric>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_host_metrics(&host_name)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}
