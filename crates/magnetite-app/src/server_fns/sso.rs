//! SSO domain server functions (F-17 / S-SSO-01..05). Authorized (08_authz),
//! validated (screen_sso §5), audited (F-04). Secret regen and session revoke
//! are Admin.

use crate::types::SsoMetrics;
use leptos::prelude::*;
use magnetite_core::domains::sso::model::{OidcClient, Provider, SsoSession};

#[cfg(feature = "ssr")]
async fn audit_sso(
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
            domain: magnetite_core::domain::DomainKey::Sso,
            action,
            target_kind: target_kind.to_string(),
            target_id: target_id.to_string(),
            result: magnetite_core::models::common::OpResult::Success,
            ip: client_ip().await,
            detail: None,
        })
        .await;
}

#[server(GetSsoMetrics, "/api")]
pub async fn get_sso_metrics() -> Result<SsoMetrics, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    let (providers, clients, sessions) = state
        .db
        .sso_metrics()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(SsoMetrics {
        provider_count: providers as u64,
        client_count: clients as u64,
        session_count: sessions as u64,
    })
}

// ---- Providers (S-SSO-01/02) ----------------------------------------------

#[server(ListSsoProviders, "/api")]
pub async fn list_sso_providers() -> Result<Vec<Provider>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_sso_providers()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server(SaveProvider, "/api")]
pub async fn save_provider(provider: Provider, secret: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::sso::validate::{check_custom_urls, check_provider};
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let is_create = provider.id.is_empty();
    let has_secret_input = !secret.trim().is_empty();
    check_provider(
        &provider.name,
        &provider.provider_type,
        &provider.client_id,
        is_create,
        has_secret_input,
    )
    .map_err(ServerFnError::new)?;
    check_custom_urls(
        &provider.provider_type,
        provider.authorize_url.as_deref().unwrap_or(""),
        provider.token_url.as_deref().unwrap_or(""),
        provider.userinfo_url.as_deref().unwrap_or(""),
    )
    .map_err(ServerFnError::new)?;
    let secret_opt = if has_secret_input {
        Some(secret.as_str())
    } else {
        None
    };
    let state = expect_context::<AppState>();
    let saved = state
        .db
        .save_provider(&provider, secret_opt)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_sso(
        &user,
        if is_create {
            ActionKind::Create
        } else {
            ActionKind::Update
        },
        "sso_provider",
        &saved.name,
    )
    .await;
    Ok(())
}

#[server(DeleteProvider, "/api")]
pub async fn delete_provider(id: String, name: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Destroy).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_provider(&id, &name)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_sso(&user, ActionKind::Delete, "sso_provider", &name).await;
    Ok(())
}

// ---- OIDC clients (S-SSO-03/04) -------------------------------------------

#[server(ListOidcClients, "/api")]
pub async fn list_oidc_clients() -> Result<Vec<OidcClient>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_oidc_clients()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server(SaveOidcClient, "/api")]
pub async fn save_oidc_client(client: OidcClient) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::sso::validate::check_client;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    check_client(
        &client.client_name,
        &client.redirect_uris,
        &client.grant_types,
    )
    .map_err(ServerFnError::new)?;
    let is_create = client.id.is_empty();
    let state = expect_context::<AppState>();
    if is_create {
        let created = state
            .db
            .create_oidc_client(&client)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        audit_sso(
            &user,
            ActionKind::Create,
            "sso_client",
            &created.client_name,
        )
        .await;
    } else {
        state
            .db
            .update_oidc_client(&client)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        audit_sso(&user, ActionKind::Update, "sso_client", &client.client_name).await;
    }
    Ok(())
}

/// Regenerate a client's secret, returning the new value once (Admin — E-S05).
#[server(RegenerateClientSecret, "/api")]
pub async fn regenerate_client_secret(id: String) -> Result<String, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Admin).await?;
    let state = expect_context::<AppState>();
    let secret = state
        .db
        .regenerate_client_secret(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_sso(&user, ActionKind::Update, "sso_client_secret", &id).await;
    Ok(secret)
}

#[server(DeleteOidcClient, "/api")]
pub async fn delete_oidc_client(id: String, client_id: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Destroy).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_oidc_client(&id, &client_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_sso(&user, ActionKind::Delete, "sso_client", &client_id).await;
    Ok(())
}

// ---- Sessions (S-SSO-05) --------------------------------------------------

#[server(ListSsoSessions, "/api")]
pub async fn list_sso_sessions() -> Result<Vec<SsoSession>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_active_sso_sessions()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server(RevokeSsoSessions, "/api")]
pub async fn revoke_sso_sessions(ids: Vec<String>) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Admin).await?;
    let state = expect_context::<AppState>();
    for id in &ids {
        state
            .db
            .revoke_sso_session(id)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        audit_sso(&user, ActionKind::Control, "sso_session", id).await;
    }
    Ok(())
}
