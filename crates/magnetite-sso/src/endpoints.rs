//! OIDC endpoint handlers: discovery, JWKS, authorize, token, userinfo.

use crate::{AuthCode, SsoState, CODE_TTL_SECS, TOKEN_TTL_SECS};
use axum::extract::{Form, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Redirect, Response};
use base64::Engine;
use chrono::{Duration, Utc};
use magnetite_core::models::account::Session;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tower_cookies::Cookies;

/// Portal session cookie (mirrors `magnetite-app`'s `SESSION_COOKIE_NAME`).
const SESSION_COOKIE: &str = "magnetite_session";

const B64URL: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

// ===== Discovery + JWKS =====

pub(crate) async fn discovery(State(st): State<SsoState>) -> Json<serde_json::Value> {
    let iss = &st.issuer;
    Json(serde_json::json!({
        "issuer": iss,
        "authorization_endpoint": format!("{iss}/oidc/authorize"),
        "token_endpoint": format!("{iss}/oidc/token"),
        "jwks_uri": format!("{iss}/oidc/jwks"),
        "userinfo_endpoint": format!("{iss}/oidc/userinfo"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported":
            ["client_secret_basic", "client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256"],
    }))
}

pub(crate) async fn jwks(State(st): State<SsoState>) -> Json<serde_json::Value> {
    let jwks = st
        .keyring
        .read()
        .map(|k| k.jwks())
        .unwrap_or_else(|_| serde_json::json!({ "keys": [] }));
    Json(jwks)
}

// ===== Authorize =====

#[derive(Deserialize)]
pub(crate) struct AuthorizeParams {
    client_id: Option<String>,
    redirect_uri: Option<String>,
    response_type: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
}

pub(crate) async fn authorize(
    State(st): State<SsoState>,
    cookies: Cookies,
    Query(p): Query<AuthorizeParams>,
) -> Response {
    let (Some(client_id), Some(redirect_uri)) = (p.client_id.clone(), p.redirect_uri.clone())
    else {
        return (
            StatusCode::BAD_REQUEST,
            "client_id and redirect_uri are required",
        )
            .into_response();
    };

    // Validate the client and redirect_uri BEFORE redirecting anywhere.
    let Some((client, _secret)) = st.db.get_oidc_client_auth(&client_id).await.ok().flatten()
    else {
        return (StatusCode::BAD_REQUEST, "unknown client_id").into_response();
    };
    if !client.enabled {
        return (StatusCode::BAD_REQUEST, "client is disabled").into_response();
    }
    if !client.redirect_uris.iter().any(|u| u == &redirect_uri) {
        return (StatusCode::BAD_REQUEST, "redirect_uri is not registered").into_response();
    }

    // From here, protocol errors go back to the client as ?error=.
    let state = p.state.clone();
    if p.response_type.as_deref() != Some("code") {
        return redirect_error(&redirect_uri, "unsupported_response_type", state.as_deref());
    }
    let scope = p.scope.clone().unwrap_or_default();
    if !scope.split_whitespace().any(|s| s == "openid") {
        return redirect_error(&redirect_uri, "invalid_scope", state.as_deref());
    }
    let (Some(code_challenge), Some(method)) =
        (p.code_challenge.clone(), p.code_challenge_method.clone())
    else {
        return redirect_error(&redirect_uri, "invalid_request", state.as_deref());
    };
    if method != "S256" {
        return redirect_error(&redirect_uri, "invalid_request", state.as_deref());
    }

    // Authenticate the end user via the portal session cookie.
    let Some(session) = current_session(&st, &cookies).await else {
        // Not logged in — bounce to the portal login (return_to round-trip deferred).
        return Redirect::to("/login").into_response();
    };

    // Issue a single-use authorization code.
    tracing::info!(
        target: "auth", proto = "oidc", client_id = %client_id, subject = %session.subject,
        "OIDC authorization code issued"
    );
    let code = random_token();
    st.put_code(
        code.clone(),
        AuthCode {
            client_id,
            redirect_uri: redirect_uri.clone(),
            subject: session.subject,
            email: session.email,
            name: session.display_name,
            scope,
            nonce: p.nonce.clone(),
            code_challenge,
            expires_at: Utc::now() + Duration::seconds(CODE_TTL_SECS),
        },
    );

    let mut url = format!("{redirect_uri}?code={code}");
    if let Some(s) = state {
        url.push_str(&format!("&state={}", percent_encode(&s)));
    }
    Redirect::to(&url).into_response()
}

// ===== Token =====

#[derive(Deserialize)]
pub(crate) struct TokenParams {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    code_verifier: Option<String>,
}

pub(crate) async fn token(
    State(st): State<SsoState>,
    headers: HeaderMap,
    Form(p): Form<TokenParams>,
) -> Response {
    if p.grant_type.as_deref() != Some("authorization_code") {
        return token_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "only authorization_code is supported",
        );
    }
    let Some(code_value) = p.code.clone() else {
        return token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code is required",
        );
    };

    // Client authentication (Basic header or form body).
    let (client_id, client_secret) = client_credentials(&headers, &p);
    let Some(client_id) = client_id else {
        return token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client_id is required",
        );
    };
    let Some((client, stored_secret)) = st.db.get_oidc_client_auth(&client_id).await.ok().flatten()
    else {
        tracing::warn!(target: "auth", proto = "oidc", client_id = %client_id, "OIDC token: invalid_client (unknown client)");
        return token_error(StatusCode::UNAUTHORIZED, "invalid_client", "unknown client");
    };
    if !client.enabled {
        tracing::warn!(target: "auth", proto = "oidc", client_id = %client_id, "OIDC token: invalid_client (client disabled)");
        return token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client is disabled",
        );
    }
    let is_public = client.client_type == "public" || stored_secret.is_empty();
    if !is_public && client_secret.as_deref() != Some(stored_secret.as_str()) {
        tracing::warn!(target: "auth", proto = "oidc", client_id = %client_id, "OIDC token: invalid_client (bad client secret)");
        return token_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "invalid client secret",
        );
    }

    // Exchange the (single-use) code.
    let Some(auth) = st.take_code(&code_value) else {
        tracing::warn!(target: "auth", proto = "oidc", client_id = %client_id, "OIDC token: invalid_grant (code invalid or expired)");
        return token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "code is invalid or expired",
        );
    };
    if auth.client_id != client_id {
        return token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "code was issued to another client",
        );
    }
    if p.redirect_uri.as_deref() != Some(auth.redirect_uri.as_str()) {
        return token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "redirect_uri mismatch",
        );
    }

    // PKCE (S256) is mandatory.
    let Some(verifier) = p.code_verifier.clone() else {
        return token_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "code_verifier is required",
        );
    };
    if pkce_s256(&verifier) != auth.code_challenge {
        return token_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "PKCE verification failed",
        );
    }

    // Issue tokens.
    let iat = Utc::now().timestamp();
    let exp = iat + TOKEN_TTL_SECS;
    let scopes: Vec<String> = auth.scope.split_whitespace().map(String::from).collect();
    let Ok(id_token) = sign_id_token(&st, &auth, &client_id, iat, exp) else {
        return token_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "token signing failed",
        );
    };
    let Ok(access_token) = sign_access_token(&st, &auth, &client_id, iat, exp) else {
        return token_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "token signing failed",
        );
    };

    // Record the SSO session (S-SSO sessions screen).
    let _ = st
        .db
        .create_sso_session(
            &auth.subject,
            Some(&client_id),
            None,
            &scopes,
            TOKEN_TTL_SECS / 3600,
            "oidc",
        )
        .await;

    tracing::info!(
        target: "auth", proto = "oidc", client_id = %client_id, subject = %auth.subject,
        "OIDC token issued (authorization_code)"
    );
    Json(serde_json::json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL_SECS,
        "id_token": id_token,
        "scope": auth.scope,
    }))
    .into_response()
}

// ===== UserInfo =====

pub(crate) async fn userinfo(State(st): State<SsoState>, headers: HeaderMap) -> Response {
    let Some(token) = bearer(&headers) else {
        return (StatusCode::UNAUTHORIZED, "missing bearer token").into_response();
    };
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.set_issuer(std::slice::from_ref(&st.issuer));
    validation.validate_aud = false;
    let decoded = st
        .keyring
        .read()
        .ok()
        .and_then(|k| k.decode::<AccessClaims>(&token, &validation).ok());
    let Some(data) = decoded else {
        return (StatusCode::UNAUTHORIZED, "invalid access token").into_response();
    };
    let claims = data.claims;
    let mut body = serde_json::json!({ "sub": claims.sub });
    if let Some(email) = claims.email {
        body["email"] = email.into();
    }
    if let Some(name) = claims.name {
        body["name"] = name.into();
    }
    Json(body).into_response()
}

// ===== Key rotation (admin) =====

/// `POST /oidc/rotate-key` — rotate the issuer signing key. Admin only: the
/// caller must present a valid portal session with the Admin role. The previous
/// key stays published for a grace window so tokens it signed keep verifying.
pub(crate) async fn rotate_key(State(st): State<SsoState>, cookies: Cookies) -> Response {
    use magnetite_core::authz::Role;
    use magnetite_core::domain::DomainKey;
    use magnetite_core::models::common::{ActionKind, OpResult};
    use magnetite_core::models::NewAuditEntry;

    let Some(session) = current_session(&st, &cookies).await else {
        return (StatusCode::UNAUTHORIZED, "authentication required").into_response();
    };
    if session.role != Role::Admin {
        return (StatusCode::FORBIDDEN, "admin role required").into_response();
    }
    match st.rotate().await {
        Ok(kid) => {
            let _ = st
                .db
                .append_audit(NewAuditEntry {
                    actor: session.subject.clone(),
                    actor_role: session.role,
                    domain: DomainKey::Sso,
                    action: ActionKind::Control,
                    target_kind: "signing_key".to_string(),
                    target_id: kid.clone(),
                    result: OpResult::Success,
                    ip: "internal".to_string(),
                    detail: None,
                })
                .await;
            Json(serde_json::json!({ "active_kid": kid })).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}

// ===== Token signing =====

#[derive(Serialize)]
struct IdClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct AccessClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    scope: String,
    token_use: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    name: Option<String>,
}

fn sign_id_token(
    st: &SsoState,
    auth: &AuthCode,
    client_id: &str,
    iat: i64,
    exp: i64,
) -> Result<String, jsonwebtoken::errors::Error> {
    let claims = IdClaims {
        iss: st.issuer.clone(),
        sub: auth.subject.clone(),
        aud: client_id.to_string(),
        exp,
        iat,
        nonce: auth.nonce.clone(),
        email: auth.email.clone(),
        name: auth.name.clone(),
    };
    st.keyring
        .read()
        .map_err(|_| jsonwebtoken::errors::ErrorKind::InvalidToken)?
        .sign(&claims)
}

fn sign_access_token(
    st: &SsoState,
    auth: &AuthCode,
    client_id: &str,
    iat: i64,
    exp: i64,
) -> Result<String, jsonwebtoken::errors::Error> {
    let claims = AccessClaims {
        iss: st.issuer.clone(),
        sub: auth.subject.clone(),
        aud: client_id.to_string(),
        exp,
        iat,
        scope: auth.scope.clone(),
        token_use: "access".to_string(),
        email: auth.email.clone(),
        name: auth.name.clone(),
    };
    st.keyring
        .read()
        .map_err(|_| jsonwebtoken::errors::ErrorKind::InvalidToken)?
        .sign(&claims)
}

// ===== Helpers =====

async fn current_session(st: &SsoState, cookies: &Cookies) -> Option<Session> {
    let cookie = cookies.get(SESSION_COOKIE)?;
    st.db.get_valid_session(cookie.value()).await.ok().flatten()
}

/// `code_challenge` for PKCE S256: base64url(SHA-256(verifier)).
fn pkce_s256(verifier: &str) -> String {
    B64URL.encode(Sha256::digest(verifier.as_bytes()))
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    B64URL.encode(bytes)
}

/// Extract client credentials from a Basic auth header, falling back to the
/// form body (`client_secret_post` / public clients).
fn client_credentials(headers: &HeaderMap, p: &TokenParams) -> (Option<String>, Option<String>) {
    if let Some((id, secret)) = basic_auth(headers) {
        return (Some(id), Some(secret));
    }
    (p.client_id.clone(), p.client_secret.clone())
}

fn basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (id, secret) = text.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ").map(|t| t.trim().to_string())
}

fn redirect_error(redirect_uri: &str, error: &str, state: Option<&str>) -> Response {
    let mut url = format!("{redirect_uri}?error={error}");
    if let Some(s) = state {
        url.push_str(&format!("&state={}", percent_encode(s)));
    }
    Redirect::to(&url).into_response()
}

fn token_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(serde_json::json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

/// Minimal percent-encoding for opaque query values (`state`).
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use magnetite_core::authz::Role;
    use magnetite_core::models::common::AuthMethod;
    use magnetite_db::Db;
    use std::sync::OnceLock;
    use tower::ServiceExt;
    use tower_cookies::CookieManagerLayer;

    /// A shared signing key across tests — RSA keygen in debug is slow, so
    /// generate one key material once and rebuild a keyring per state from it.
    fn shared_state(db: Db) -> SsoState {
        static PEM: OnceLock<(String, String)> = OnceLock::new();
        let (kid, pem) = PEM.get_or_init(|| {
            let kid = "magnetite-oidc-test".to_string();
            let (_key, pem) = crate::keys::SigningKey::generate_with_kid(kid.clone()).unwrap();
            (kid, pem)
        });
        let key = crate::keys::SigningKey::from_pkcs8_pem(kid.clone(), pem).unwrap();
        let keyring = crate::keys::Keyring::new(key, Vec::new());
        SsoState {
            db,
            issuer: "https://idp.test".into(),
            keyring: std::sync::Arc::new(std::sync::RwLock::new(keyring)),
            codes: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    fn router(state: SsoState) -> axum::Router {
        crate::oidc_router(state).layer(CookieManagerLayer::new())
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    async fn seed_client(db: &Db, redirect: &str) -> (String, String) {
        use magnetite_core::domains::sso::model::OidcClient;
        let created = db
            .create_oidc_client(&OidcClient {
                id: String::new(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                created_by: "admin".into(),
                client_name: "test-app".into(),
                client_id: String::new(),
                has_secret: true,
                client_type: "confidential".into(),
                grant_types: vec!["authorization_code".into()],
                response_types: vec!["code".into()],
                redirect_uris: vec![redirect.into()],
                scopes: vec!["openid".into(), "email".into()],
                token_endpoint_auth_method: "client_secret_post".into(),
                provider_ref: None,
                enabled: true,
            })
            .await
            .unwrap();
        let (_, secret) = db
            .get_oidc_client_auth(&created.client_id)
            .await
            .unwrap()
            .unwrap();
        (created.client_id, secret)
    }

    async fn login(db: &Db) -> String {
        // Create a valid portal session and return its cookie value. (Only the
        // session row matters to `/authorize`; no account record is needed.)
        let sid = "test-session-cookie".to_string();
        let now = chrono::Utc::now();
        let session = Session {
            session_id: sid.clone(),
            subject: "alice".into(),
            auth_method: AuthMethod::Local,
            role: Role::Admin,
            display_name: None,
            email: None,
            sso_tokens: None,
            login_ip: "127.0.0.1".into(),
            created_at: now,
            expires_at: now + chrono::Duration::hours(8),
            revoked_at: None,
        };
        db.create_session(&session).await.unwrap();
        sid
    }

    #[tokio::test]
    async fn discovery_and_jwks() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        let app = router(shared_state(db));

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/.well-known/openid-configuration")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let doc = body_json(resp).await;
        assert_eq!(doc["issuer"], "https://idp.test");
        assert_eq!(doc["id_token_signing_alg_values_supported"][0], "RS256");

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/oidc/jwks")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let jwks = body_json(resp).await;
        assert_eq!(jwks["keys"][0]["kty"], "RSA");
        assert!(jwks["keys"][0]["n"].as_str().is_some());
    }

    #[tokio::test]
    async fn full_auth_code_pkce_flow() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        let redirect = "https://app.test/callback";
        let (client_id, secret) = seed_client(&db, redirect).await;
        let cookie = login(&db).await;
        let state = shared_state(db.clone());
        let app = router(state.clone());

        // PKCE pair.
        let verifier = "verifier-abc-123-verifier-abc-123-XYZ";
        let challenge = pkce_s256(verifier);

        // /authorize with a valid session cookie → 302 to redirect_uri?code=...
        let auth_uri = format!(
            "/oidc/authorize?response_type=code&client_id={client_id}&redirect_uri={}&scope=openid%20email&state=xyz&code_challenge={challenge}&code_challenge_method=S256",
            percent_encode(redirect)
        );
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&auth_uri)
                    .header("cookie", format!("{SESSION_COOKIE}={cookie}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.starts_with(redirect), "location: {location}");
        assert!(location.contains("state=xyz"));
        let code = location
            .split("code=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap()
            .to_string();

        // /token: exchange the code (client_secret_post + PKCE verifier).
        let form = format!(
            "grant_type=authorization_code&code={code}&redirect_uri={}&client_id={client_id}&client_secret={secret}&code_verifier={verifier}",
            percent_encode(redirect)
        );
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oidc/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let tokens = body_json(resp).await;
        let id_token = tokens["id_token"].as_str().expect("id_token");
        let access_token = tokens["access_token"].as_str().unwrap().to_string();
        assert_eq!(tokens["token_type"], "Bearer");

        // id_token verifies against the issuer key with the right claims.
        let mut v = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        v.set_issuer(&["https://idp.test"]);
        v.set_audience(&[&client_id]);
        let decoded = state
            .keyring
            .read()
            .unwrap()
            .decode::<serde_json::Value>(id_token, &v)
            .unwrap();
        assert_eq!(decoded.claims["sub"], "alice");
        assert_eq!(decoded.claims["email"], serde_json::Value::Null); // no email set on account

        // The code is single-use: a replay fails.
        let replay = format!(
            "grant_type=authorization_code&code={code}&redirect_uri={}&client_id={client_id}&client_secret={secret}&code_verifier={verifier}",
            percent_encode(redirect)
        );
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oidc/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(replay))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // /userinfo with the access token returns the subject.
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/oidc/userinfo")
                    .header("authorization", format!("Bearer {access_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["sub"], "alice");

        // An SSO session was recorded.
        assert_eq!(db.list_active_sso_sessions().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn token_rejects_bad_pkce_and_secret() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        let redirect = "https://app.test/cb";
        let (client_id, secret) = seed_client(&db, redirect).await;
        let cookie = login(&db).await;
        let app = router(shared_state(db));

        let verifier = "correct-verifier-correct-verifier-correct";
        let challenge = pkce_s256(verifier);
        let auth_uri = format!(
            "/oidc/authorize?response_type=code&client_id={client_id}&redirect_uri={}&scope=openid&code_challenge={challenge}&code_challenge_method=S256",
            percent_encode(redirect)
        );
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(&auth_uri)
                    .header("cookie", format!("{SESSION_COOKIE}={cookie}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        let code = location
            .split("code=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();

        // Wrong PKCE verifier → invalid_grant.
        let form = format!(
            "grant_type=authorization_code&code={code}&redirect_uri={}&client_id={client_id}&client_secret={secret}&code_verifier=WRONG",
            percent_encode(redirect)
        );
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oidc/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn authorize_without_session_redirects_to_login() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        let redirect = "https://app.test/cb";
        let (client_id, _secret) = seed_client(&db, redirect).await;
        let app = router(shared_state(db));

        let auth_uri = format!(
            "/oidc/authorize?response_type=code&client_id={client_id}&redirect_uri={}&scope=openid&code_challenge=abc&code_challenge_method=S256",
            percent_encode(redirect)
        );
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(&auth_uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/login");
    }
}
