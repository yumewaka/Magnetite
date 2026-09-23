//! `magnetite-federation` — upstream SSO login (the relying-party side).
//!
//! Complements `magnetite-sso` (which makes magnetite an OIDC *issuer*): this lets a
//! user log **into** magnetite through an external provider (Google / Azure /
//! Keycloak / any OIDC). It mounts two browser endpoints:
//!
//! - `GET /auth/sso/{provider}/start` — begin the flow: mint state + PKCE, then
//!   redirect to the provider's `authorize` endpoint.
//! - `GET /auth/sso/callback` — the provider redirects back here with a `code`; we
//!   exchange it for tokens at the provider's `token` endpoint, read the identity
//!   from its `userinfo` endpoint, map it to a local account (or auto-provision a
//!   read-only session), create a portal session and set the session cookie.
//!
//! TLS to the provider accepts the presented certificate without verification, to
//! match the rest of magnetite's outbound clients (feeds / webhooks / kube) — many
//! deployments front an internal, self-signed IdP. Harden with a pinned CA if the
//! provider is public.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use chrono::{DateTime, Duration, Utc};
use magnetite_core::authz::Role;
use magnetite_core::models::common::AuthMethod;
use magnetite_core::models::Session;
use magnetite_db::Db;

mod client;

/// The session cookie name — must match the app's `SESSION_COOKIE_NAME`.
const SESSION_COOKIE: &str = "magnetite_session";
/// How long a started flow may sit before its callback must arrive.
const FLOW_TTL: Duration = Duration::minutes(10);

/// A started-but-not-completed login flow, keyed by its `state` value.
struct PendingFlow {
    provider: String,
    pkce_verifier: String,
    created_at: DateTime<Utc>,
}

/// Router state: the DB, this server's base URL, and the in-flight flows.
#[derive(Clone)]
pub struct FederationState {
    db: Db,
    base_url: String,
    flows: Arc<Mutex<HashMap<String, PendingFlow>>>,
}

impl FederationState {
    #[must_use]
    pub fn new(db: Db, base_url: String) -> Self {
        Self {
            db,
            base_url: base_url.trim_end_matches('/').to_string(),
            flows: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

/// Build the federation router, ready to merge into the app.
pub fn federation_router(state: FederationState) -> Router {
    Router::new()
        .route("/auth/sso/{provider}/start", get(start))
        .route("/auth/sso/callback", get(callback))
        .with_state(state)
}

/// Default OAuth endpoints for the well-known provider types, used when a provider's
/// URLs are not explicitly configured.
fn default_endpoints(provider_type: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match provider_type {
        "google" => Some((
            "https://accounts.google.com/o/oauth2/v2/auth",
            "https://oauth2.googleapis.com/token",
            "https://openidconnect.googleapis.com/v1/userinfo",
        )),
        "github" => Some((
            "https://github.com/login/oauth/authorize",
            "https://github.com/login/oauth/access_token",
            "https://api.github.com/user",
        )),
        "azure" => Some((
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            "https://graph.microsoft.com/oidc/userinfo",
        )),
        _ => None,
    }
}

/// Resolve a provider's `(authorize, token, userinfo)` URLs, preferring the stored
/// values and falling back to the type's defaults.
fn resolve_urls(
    cfg: &magnetite_core::domains::sso::model::ProviderLoginConfig,
) -> Option<(String, String, String)> {
    let defaults = default_endpoints(&cfg.provider_type);
    let authorize = cfg
        .authorize_url
        .clone()
        .filter(|u| !u.trim().is_empty())
        .or_else(|| defaults.map(|d| d.0.to_string()))?;
    let token = cfg
        .token_url
        .clone()
        .filter(|u| !u.trim().is_empty())
        .or_else(|| defaults.map(|d| d.1.to_string()))?;
    let userinfo = cfg
        .userinfo_url
        .clone()
        .filter(|u| !u.trim().is_empty())
        .or_else(|| defaults.map(|d| d.2.to_string()))?;
    Some((authorize, token, userinfo))
}

/// The redirect URI the provider calls back to (this server's callback endpoint).
fn callback_uri(base_url: &str) -> String {
    format!("{base_url}/auth/sso/callback")
}

/// `GET /auth/sso/{provider}/start` — mint state + PKCE and redirect to the provider.
async fn start(State(state): State<FederationState>, Path(provider): Path<String>) -> Response {
    let cfg = match state.db.provider_login_config(&provider).await {
        Ok(Some(cfg)) => cfg,
        Ok(None) => return login_error("unknown_or_disabled_provider"),
        Err(e) => {
            tracing::warn!("federation start: provider lookup failed: {e}");
            return login_error("server_error");
        }
    };
    let Some((authorize_url, _, _)) = resolve_urls(&cfg) else {
        return login_error("provider_urls_unconfigured");
    };

    // PKCE (S256) + an unguessable state token.
    let verifier = random_token(48);
    let challenge = client::pkce_challenge(&verifier);
    let state_tok = random_token(32);
    let redirect_uri = if cfg.redirect_uri.trim().is_empty() {
        callback_uri(&state.base_url)
    } else {
        cfg.redirect_uri.clone()
    };
    let scope = if cfg.scopes.is_empty() {
        "openid profile email".to_string()
    } else {
        cfg.scopes.join(" ")
    };

    if let Ok(mut flows) = state.flows.lock() {
        prune(&mut flows);
        flows.insert(
            state_tok.clone(),
            PendingFlow {
                provider: provider.clone(),
                pkce_verifier: verifier,
                created_at: Utc::now(),
            },
        );
    }

    let url = format!(
        "{authorize_url}?response_type=code&client_id={cid}&redirect_uri={ruri}&scope={scope}&state={state_tok}&code_challenge={challenge}&code_challenge_method=S256",
        cid = urlencode(&cfg.client_id),
        ruri = urlencode(&redirect_uri),
        scope = urlencode(&scope),
    );
    Redirect::to(&url).into_response()
}

#[derive(serde::Deserialize)]
struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// `GET /auth/sso/callback` — validate state, exchange the code, resolve the identity
/// and establish a session.
async fn callback(
    State(state): State<FederationState>,
    Query(params): Query<CallbackParams>,
) -> Response {
    if let Some(err) = params.error {
        tracing::info!("federation callback: provider returned error '{err}'");
        return login_error("provider_denied");
    }
    let (Some(code), Some(state_tok)) = (params.code, params.state) else {
        return login_error("missing_code_or_state");
    };

    // Consume the pending flow (single use, unexpired).
    let flow = match state.flows.lock() {
        Ok(mut flows) => {
            prune(&mut flows);
            flows.remove(&state_tok)
        }
        Err(_) => None,
    };
    let Some(flow) = flow else {
        return login_error("invalid_or_expired_state");
    };

    let cfg = match state.db.provider_login_config(&flow.provider).await {
        Ok(Some(cfg)) => cfg,
        _ => return login_error("unknown_or_disabled_provider"),
    };
    let Some((_, token_url, userinfo_url)) = resolve_urls(&cfg) else {
        return login_error("provider_urls_unconfigured");
    };
    let redirect_uri = if cfg.redirect_uri.trim().is_empty() {
        callback_uri(&state.base_url)
    } else {
        cfg.redirect_uri.clone()
    };

    // Exchange the authorization code for tokens.
    let tokens = match client::exchange_code(
        &token_url,
        &cfg.client_id,
        &cfg.client_secret,
        &code,
        &redirect_uri,
        &flow.pkce_verifier,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("federation callback: token exchange failed: {e}");
            return login_error("token_exchange_failed");
        }
    };

    // Read the identity from the userinfo endpoint.
    let identity = match client::fetch_userinfo(&userinfo_url, &tokens.access_token).await {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!("federation callback: userinfo failed: {e}");
            return login_error("userinfo_failed");
        }
    };

    // Map the federated identity to a local account (or auto-provision a session).
    let (subject, role, email, display) = match resolve_identity(&state.db, &cfg, &identity).await {
        Some(v) => v,
        None => return login_error("no_matching_account"),
    };

    // Establish the portal session.
    let now = Utc::now();
    let session = Session {
        session_id: uuid::Uuid::new_v4().to_string(),
        subject: subject.clone(),
        auth_method: AuthMethod::Sso,
        role,
        display_name: display,
        email,
        sso_tokens: Some(tokens),
        login_ip: String::new(),
        created_at: now,
        expires_at: now + Duration::hours(24),
        revoked_at: None,
    };
    if let Err(e) = state.db.create_session(&session).await {
        tracing::warn!("federation callback: session create failed: {e}");
        return login_error("session_failed");
    }
    let _ = state.db.touch_last_login(&subject).await;
    tracing::info!("federated login for '{subject}' via '{}'", flow.provider);

    // Redirect home with the session cookie set.
    let cookie = format!(
        "{SESSION_COOKIE}={}; Path=/; HttpOnly; SameSite=Lax",
        session.session_id
    );
    (
        axum::http::StatusCode::SEE_OTHER,
        [
            (axum::http::header::SET_COOKIE, cookie),
            (axum::http::header::LOCATION, "/".to_string()),
        ],
    )
        .into_response()
}

/// Map the userinfo identity to `(subject, role, email, display_name)`. Prefers an
/// existing enabled local account (matched by email, then preferred_username, then
/// sub); otherwise, if the provider allows auto-provisioning, grants a read-only
/// (`Viewer`) session keyed by the best available identifier.
async fn resolve_identity(
    db: &Db,
    cfg: &magnetite_core::domains::sso::model::ProviderLoginConfig,
    id: &client::Identity,
) -> Option<(String, Role, Option<String>, Option<String>)> {
    let candidates: Vec<&str> = [
        id.email.as_deref(),
        id.preferred_username.as_deref(),
        id.sub.as_deref(),
    ]
    .into_iter()
    .flatten()
    .collect();

    for cand in &candidates {
        if let Ok(Some(account)) = db.find_account_by_username(cand).await {
            if account.enabled {
                return Some((
                    account.username,
                    account.role,
                    id.email.clone(),
                    id.name.clone(),
                ));
            }
        }
    }

    if cfg.auto_provision {
        let subject = candidates.first().map(|s| s.to_string())?;
        return Some((subject, Role::Viewer, id.email.clone(), id.name.clone()));
    }
    None
}

/// Redirect to the login page with an `sso_error` query so the UI can explain.
fn login_error(reason: &str) -> Response {
    Redirect::to(&format!("/auth/login?sso_error={reason}")).into_response()
}

/// Drop expired pending flows.
fn prune(flows: &mut HashMap<String, PendingFlow>) {
    let now = Utc::now();
    flows.retain(|_, f| now - f.created_at < FLOW_TTL);
}

/// A URL-safe random token of `bytes` random bytes, base64url-encoded (no padding).
fn random_token(bytes: usize) -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

/// Minimal percent-encoding for query-parameter values.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
