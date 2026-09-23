//! Account / session management server functions (S-Account / F-10). Every
//! operation is Admin-only (08_authz), validated (screen_account §5) and
//! audited (F-04). Manages local *login* accounts and active sessions.

use leptos::prelude::*;
use magnetite_core::models::{LocalAccountInfo, SessionInfo};

#[cfg(feature = "ssr")]
async fn audit_account(
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
            domain: magnetite_core::domain::DomainKey::Portal,
            action,
            target_kind: target_kind.to_string(),
            target_id: target_id.to_string(),
            result: magnetite_core::models::common::OpResult::Success,
            ip: client_ip().await,
            detail: None,
        })
        .await;
}

// ---- Accounts -------------------------------------------------------------

/// List local login accounts (display-safe, no password hash).
#[server(ListLocalAccounts, "/api")]
pub async fn list_local_accounts() -> Result<Vec<LocalAccountInfo>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Admin).await?;
    let state = expect_context::<AppState>();
    let accounts = state
        .db
        .list_accounts()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(accounts.iter().map(LocalAccountInfo::from).collect())
}

/// Create a local account (E-01/E-02).
#[server(CreateLocalAccount, "/api")]
pub async fn create_local_account(
    username: String,
    password: String,
    role: String,
) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::{ActionClass, Role};
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Admin).await?;
    if username.trim().is_empty() || username.trim().chars().count() > 64 {
        return Err(ServerFnError::new("ユーザ名を入力してください。"));
    }
    let role =
        Role::from_str(&role).ok_or_else(|| ServerFnError::new("ロールを選択してください。"))?;
    let state = expect_context::<AppState>();
    let min = state.config.policy.password_min_length;
    if magnetite_core::password::check_password(&password, min).is_err() {
        return Err(ServerFnError::new(
            "パスワードは8文字以上で、英字と数字を含めてください。",
        ));
    }
    let account = state
        .db
        .create_account(&username, &password, role)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_account(
        &user,
        ActionKind::Create,
        "local_account",
        &account.username,
    )
    .await;
    Ok(())
}

/// Change an account's role (E-03).
#[server(SetAccountRole, "/api")]
pub async fn set_account_role(username: String, role: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::{ActionClass, Role};
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Admin).await?;
    let role =
        Role::from_str(&role).ok_or_else(|| ServerFnError::new("ロールを選択してください。"))?;
    let state = expect_context::<AppState>();
    state
        .db
        .set_account_role(&username, role)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_account(&user, ActionKind::Update, "local_account", &username).await;
    Ok(())
}

/// Enable/disable an account (E-04).
#[server(SetAccountEnabled, "/api")]
pub async fn set_account_enabled(username: String, enabled: bool) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Admin).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .set_account_enabled(&username, enabled)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_account(&user, ActionKind::Update, "local_account", &username).await;
    Ok(())
}

/// Delete an account (E-05/E-06, last-admin guarded).
#[server(DeleteLocalAccount, "/api")]
pub async fn delete_local_account(username: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Admin).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_account(&username)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_account(&user, ActionKind::Delete, "local_account", &username).await;
    Ok(())
}

/// Reset an account's password (E-07).
#[server(ResetAccountPassword, "/api")]
pub async fn reset_account_password(
    username: String,
    new_password: String,
) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Admin).await?;
    let state = expect_context::<AppState>();
    let min = state.config.policy.password_min_length;
    if magnetite_core::password::check_password(&new_password, min).is_err() {
        return Err(ServerFnError::new(
            "パスワードは8文字以上で、英字と数字を含めてください。",
        ));
    }
    state
        .db
        .reset_account_password(&username, &new_password)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_account(
        &user,
        ActionKind::Update,
        "local_account_password",
        &username,
    )
    .await;
    Ok(())
}

// ---- Sessions -------------------------------------------------------------

/// List active portal sessions (E-08).
#[server(ListActiveSessions, "/api")]
pub async fn list_active_sessions() -> Result<Vec<SessionInfo>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Admin).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_active_sessions()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Revoke sessions by id (E-08/E-09; single or bulk).
#[server(RevokePortalSessions, "/api")]
pub async fn revoke_portal_sessions(session_ids: Vec<String>) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::models::common::ActionKind;

    let user = require(magnetite_core::authz::ActionClass::Admin).await?;
    let state = expect_context::<AppState>();
    for id in &session_ids {
        state
            .db
            .revoke_session(id)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        audit_account(&user, ActionKind::Control, "session", id).await;
    }
    Ok(())
}
