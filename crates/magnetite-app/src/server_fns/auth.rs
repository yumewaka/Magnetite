//! Authentication server functions (F-01/F-10): current user, first-run setup,
//! local login and logout. SSO login start is a Phase-1 stub.

use leptos::prelude::*;
use magnetite_core::models::CurrentUser;

/// Name of the session cookie (HttpOnly, per 05 §5).
#[cfg(feature = "ssr")]
pub const SESSION_COOKIE_NAME: &str = "magnetite_session";

/// Resolve the current user from the request's session cookie, re-validating
/// the session against the database each call (09 §6.5).
#[cfg(feature = "ssr")]
pub async fn current_user() -> Result<Option<CurrentUser>, ServerFnError> {
    use crate::state::AppState;
    use tower_cookies::Cookies;

    let cookies: Cookies = leptos_axum::extract()
        .await
        .map_err(|e| ServerFnError::new(format!("cookie extract failed: {e}")))?;
    let Some(cookie) = cookies.get(SESSION_COOKIE_NAME) else {
        return Ok(None);
    };
    let state = expect_context::<AppState>();
    let session = state
        .db
        .get_valid_session(cookie.value())
        .await
        .map_err(|e| ServerFnError::new(format!("session lookup failed: {e}")))?;
    Ok(session.map(|s| CurrentUser {
        subject: s.subject,
        display_name: s.display_name.unwrap_or_default(),
        email: s.email,
        role: s.role,
        auth_method: s.auth_method,
    }))
}

/// The authenticated user, or `None` if unauthenticated.
#[server(GetCurrentUser, "/api")]
pub async fn get_current_user() -> Result<Option<CurrentUser>, ServerFnError> {
    current_user().await
}

/// Whether first-run setup is required (no local accounts exist — AC-03).
#[server(NeedsSetup, "/api")]
pub async fn needs_setup() -> Result<bool, ServerFnError> {
    use crate::state::AppState;
    let state = expect_context::<AppState>();
    let has = state
        .db
        .has_accounts()
        .await
        .map_err(|e| ServerFnError::new(format!("account check failed: {e}")))?;
    Ok(!has)
}

/// A login button for an enabled upstream SSO provider (name + type). Safe to expose
/// unauthenticated: it carries no secret, only what the login page needs to render a
/// "log in with …" link to `/auth/sso/{name}/start`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct LoginProvider {
    pub name: String,
    pub kind: String,
}

/// List the enabled upstream SSO providers for the (unauthenticated) login page.
/// Deliberately requires no session — it is called before the user has one.
#[server(ListLoginProviders, "/api")]
pub async fn list_login_providers() -> Result<Vec<LoginProvider>, ServerFnError> {
    use crate::state::AppState;
    let state = expect_context::<AppState>();
    let providers = state
        .db
        .list_enabled_provider_logins()
        .await
        .map_err(|e| ServerFnError::new(format!("provider list failed: {e}")))?;
    Ok(providers
        .into_iter()
        .map(|(name, kind)| LoginProvider { name, kind })
        .collect())
}

/// Create the first administrator account (only when none exist yet, AC-03),
/// then log the new admin in (establish a session + redirect to the dashboard)
/// so setup completes with an obvious screen transition.
#[server(SetupFirstAdmin, "/api")]
pub async fn setup_first_admin(username: String, password: String) -> Result<(), ServerFnError> {
    use crate::state::AppState;
    use magnetite_core::models::common::{ActionKind, OpResult};
    use magnetite_core::models::NewAuditEntry;

    let state = expect_context::<AppState>();
    let min = state.config.policy.password_min_length;
    if let Err(key) = magnetite_core::password::check_password(&password, min) {
        return Err(ServerFnError::new(key.to_string()));
    }
    let account = state
        .db
        .create_first_admin(&username, &password)
        .await
        .map_err(|e| ServerFnError::new(format!("setup failed: {e}")))?;

    let _ = state
        .db
        .append_audit(NewAuditEntry {
            actor: account.username.clone(),
            actor_role: account.role,
            domain: magnetite_core::domain::DomainKey::Portal,
            action: ActionKind::Create,
            target_kind: "local_account".into(),
            target_id: account.username.clone(),
            result: OpResult::Success,
            ip: client_ip().await,
            detail: None,
        })
        .await;

    // Auto-login the freshly created admin so the UI advances to the dashboard.
    start_session(&state, &account.username, account.role).await?;
    Ok(())
}

/// Create a session for `subject`, set the session cookie, and issue a redirect
/// to the dashboard. Shared by local login and first-run setup.
#[cfg(feature = "ssr")]
async fn start_session(
    state: &crate::state::AppState,
    subject: &str,
    role: magnetite_core::authz::Role,
) -> Result<(), ServerFnError> {
    use chrono::Utc;
    use magnetite_core::models::common::AuthMethod;
    use magnetite_core::models::Session;
    use tower_cookies::{Cookie, Cookies};

    let now = Utc::now();
    let session = Session {
        session_id: uuid::Uuid::new_v4().to_string(),
        subject: subject.to_string(),
        auth_method: AuthMethod::Local,
        role,
        display_name: Some(subject.to_string()),
        email: None,
        sso_tokens: None,
        login_ip: client_ip().await,
        created_at: now,
        expires_at: now + chrono::Duration::hours(24),
        revoked_at: None,
    };
    state
        .db
        .create_session(&session)
        .await
        .map_err(|e| ServerFnError::new(format!("session create failed: {e}")))?;
    let _ = state.db.touch_last_login(subject).await;

    let cookies: Cookies = leptos_axum::extract()
        .await
        .map_err(|e| ServerFnError::new(format!("cookie extract failed: {e}")))?;
    let cookie: Cookie = Cookie::build((SESSION_COOKIE_NAME, session.session_id))
        .path("/")
        .http_only(true)
        .same_site(tower_cookies::cookie::SameSite::Lax)
        .into();
    cookies.add(cookie);

    leptos_axum::redirect("/");
    Ok(())
}

/// Authenticate with a local username/password, establishing a session.
#[server(LocalLogin, "/api")]
pub async fn local_login(username: String, password: String) -> Result<(), ServerFnError> {
    use crate::state::AppState;
    use chrono::Utc;
    use magnetite_core::models::common::{ActionKind, AuthMethod, OpResult};
    use magnetite_core::models::{NewAuditEntry, Session};
    use tower_cookies::{Cookie, Cookies};

    let state = expect_context::<AppState>();
    let ip = client_ip().await;

    let account = state
        .db
        .verify_login(&username, &password)
        .await
        .map_err(|e| ServerFnError::new(format!("login failed: {e}")))?;

    let Some(account) = account else {
        let _ = state
            .db
            .append_audit(NewAuditEntry {
                actor: username.clone(),
                actor_role: magnetite_core::authz::Role::Viewer,
                domain: magnetite_core::domain::DomainKey::Portal,
                action: ActionKind::Login,
                target_kind: "session".into(),
                target_id: username.clone(),
                result: OpResult::Failure,
                ip,
                detail: None,
            })
            .await;
        return Err(ServerFnError::new("login.error".to_string()));
    };

    let now = Utc::now();
    let session = Session {
        session_id: uuid::Uuid::new_v4().to_string(),
        subject: account.username.clone(),
        auth_method: AuthMethod::Local,
        role: account.role,
        display_name: Some(account.username.clone()),
        email: None,
        sso_tokens: None,
        login_ip: ip.clone(),
        created_at: now,
        expires_at: now + chrono::Duration::hours(24),
        revoked_at: None,
    };
    state
        .db
        .create_session(&session)
        .await
        .map_err(|e| ServerFnError::new(format!("session create failed: {e}")))?;
    let _ = state.db.touch_last_login(&account.username).await;
    let _ = state
        .db
        .append_audit(NewAuditEntry {
            actor: account.username.clone(),
            actor_role: account.role,
            domain: magnetite_core::domain::DomainKey::Portal,
            action: ActionKind::Login,
            target_kind: "session".into(),
            target_id: session.session_id.clone(),
            result: OpResult::Success,
            ip,
            detail: None,
        })
        .await;

    let cookies: Cookies = leptos_axum::extract()
        .await
        .map_err(|e| ServerFnError::new(format!("cookie extract failed: {e}")))?;
    let cookie: Cookie = Cookie::build((SESSION_COOKIE_NAME, session.session_id))
        .path("/")
        .http_only(true)
        .same_site(tower_cookies::cookie::SameSite::Lax)
        .into();
    cookies.add(cookie);

    leptos_axum::redirect("/");
    Ok(())
}

/// Log out: revoke the session and clear the cookie (AC-05b / 09 §6.5).
#[server(Logout, "/api")]
pub async fn logout() -> Result<(), ServerFnError> {
    use crate::state::AppState;
    use magnetite_core::models::common::{ActionKind, OpResult};
    use magnetite_core::models::NewAuditEntry;
    use tower_cookies::Cookies;

    let cookies: Cookies = leptos_axum::extract()
        .await
        .map_err(|e| ServerFnError::new(format!("cookie extract failed: {e}")))?;
    if let Some(cookie) = cookies.get(SESSION_COOKIE_NAME) {
        let state = expect_context::<AppState>();
        let sid = cookie.value().to_string();
        let subject = state
            .db
            .get_valid_session(&sid)
            .await
            .ok()
            .flatten()
            .map(|s| s.subject)
            .unwrap_or_default();
        let _ = state.db.revoke_session(&sid).await;
        let _ = state
            .db
            .append_audit(NewAuditEntry {
                actor: subject.clone(),
                actor_role: magnetite_core::authz::Role::Viewer,
                domain: magnetite_core::domain::DomainKey::Portal,
                action: ActionKind::Logout,
                target_kind: "session".into(),
                target_id: sid,
                result: OpResult::Success,
                ip: client_ip().await,
                detail: None,
            })
            .await;
    }
    cookies.remove(
        tower_cookies::Cookie::build(SESSION_COOKIE_NAME)
            .path("/")
            .into(),
    );
    leptos_axum::redirect("/auth/login");
    Ok(())
}

/// Require an authenticated session whose role satisfies `action`, returning
/// the current user. Server-side authorization gate for every mutating and
/// reading server function (08_authz §3).
///
/// # Errors
/// Returns an error carrying the confirmed unauthenticated/forbidden message.
#[cfg(feature = "ssr")]
pub async fn require(
    action: magnetite_core::authz::ActionClass,
) -> Result<CurrentUser, ServerFnError> {
    let user = current_user()
        .await?
        .ok_or_else(|| ServerFnError::new("認証が必要です。"))?;
    if magnetite_core::authz::is_allowed(user.role, action) {
        Ok(user)
    } else {
        Err(ServerFnError::new("この操作を行う権限がありません。"))
    }
}

/// Best-effort source IP for audit records.
#[cfg(feature = "ssr")]
pub(crate) async fn client_ip() -> String {
    use axum::extract::ConnectInfo;
    use std::net::SocketAddr;
    leptos_axum::extract::<ConnectInfo<SocketAddr>>()
        .await
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}
