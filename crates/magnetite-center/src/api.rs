//! The control plane's JSON HTTP API (axum). Every route except `/healthz` requires
//! `Authorization: Bearer <CENTER_ADMIN_TOKEN>`.
//!
//! Routes:
//!   GET  /healthz            — unauthenticated liveness probe (no dependencies)
//!   GET  /readyz             — unauthenticated readiness probe (datastore reachable)
//!   GET  /clusters           — list clusters
//!   POST /clusters           — create a cluster            {name}
//!   GET  /servers            — list registered servers (with last health)
//!   POST /servers            — register a server           {name, base_url, token, cluster?}
//!   DELETE /servers/:id      — deregister a server
//!   GET  /status             — clusters + their servers, one combined snapshot

use crate::store::CenterDb;
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

/// The single-page dashboard, embedded at compile time. It is static markup with no
/// secrets — the operator enters the admin token in-page, and it is used only client-side
/// for the authenticated JSON calls below.
const DASHBOARD_HTML: &str = include_str!("../static/index.html");

#[derive(Clone)]
pub struct ApiState {
    pub db: CenterDb,
    pub admin_token: String,
    /// This center instance's stable id (for HA leadership reporting).
    pub center_id: String,
    /// Whether this instance currently holds the leader lease.
    pub is_leader: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/clusters", get(list_clusters).post(create_cluster))
        .route("/servers", get(list_servers).post(register_server))
        .route("/servers/{id}", axum::routing::delete(delete_server))
        .route("/servers/{id}/promote", axum::routing::post(promote_server))
        .route("/servers/{id}/demote", axum::routing::post(demote_server))
        .route("/servers/{id}/intent", axum::routing::post(set_intent))
        .route(
            "/servers/{id}/dns-target",
            axum::routing::post(set_dns_target),
        )
        .route(
            "/clusters/{id}/failover-policy",
            axum::routing::post(set_failover_policy),
        )
        .route(
            "/clusters/{id}/dns-policy",
            axum::routing::post(set_dns_policy),
        )
        .route("/events", get(list_events))
        .route("/status", get(status))
        .with_state(state)
}

/// Serve the embedded dashboard (unauthenticated — it holds no secrets).
async fn dashboard() -> impl IntoResponse {
    ([(header::CACHE_CONTROL, "no-cache")], Html(DASHBOARD_HTML))
}

/// Constant-time-ish bearer check against the configured admin token.
fn authorized(headers: &HeaderMap, expected: &str) -> bool {
    let Some(auth) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let Some(token) = auth.strip_prefix("Bearer ") else {
        return false;
    };
    let (a, b) = (token.as_bytes(), expected.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn unauthorized() -> axum::response::Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({"error": "unauthorized"})),
    )
        .into_response()
}

fn bad_request(msg: impl std::fmt::Display) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": msg.to_string()})),
    )
        .into_response()
}

fn server_error(msg: impl std::fmt::Display) -> axum::response::Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": msg.to_string()})),
    )
        .into_response()
}

async fn healthz() -> impl IntoResponse {
    Json(json!({"status": "ok"}))
}

/// Readiness: safe to route traffic here. Unlike `/healthz` (liveness — never touches
/// a dependency, so a datastore blip can't make Kubernetes restart the pod), this
/// probes the datastore. On failure it returns `503` so a load balancer drains this
/// instance; the reason is logged, not returned (no internals in the response body).
async fn readyz(State(state): State<ApiState>) -> impl IntoResponse {
    match state.db.ping().await {
        Ok(()) => (StatusCode::OK, Json(json!({"status": "ready"}))),
        Err(e) => {
            tracing::warn!("readiness probe failed: datastore unreachable: {e}");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"status": "unavailable"})),
            )
        }
    }
}

// ---- Clusters --------------------------------------------------------------

async fn list_clusters(State(st): State<ApiState>, headers: HeaderMap) -> axum::response::Response {
    if !authorized(&headers, &st.admin_token) {
        return unauthorized();
    }
    match st.db.list_clusters().await {
        Ok(cs) => Json(cs).into_response(),
        Err(e) => server_error(e),
    }
}

#[derive(Deserialize)]
struct CreateCluster {
    name: String,
}

async fn create_cluster(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Json(body): Json<CreateCluster>,
) -> axum::response::Response {
    if !authorized(&headers, &st.admin_token) {
        return unauthorized();
    }
    if body.name.trim().is_empty() {
        return bad_request("name must not be empty");
    }
    match st.db.create_cluster(body.name.trim()).await {
        Ok(c) => (StatusCode::CREATED, Json(c)).into_response(),
        Err(e) => server_error(e),
    }
}

// ---- Servers ---------------------------------------------------------------

async fn list_servers(State(st): State<ApiState>, headers: HeaderMap) -> axum::response::Response {
    if !authorized(&headers, &st.admin_token) {
        return unauthorized();
    }
    match st.db.list_servers().await {
        Ok(ss) => Json(ss).into_response(),
        Err(e) => server_error(e),
    }
}

#[derive(Deserialize)]
struct RegisterServer {
    name: String,
    base_url: String,
    token: String,
    #[serde(default)]
    cluster: Option<String>,
}

async fn register_server(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Json(body): Json<RegisterServer>,
) -> axum::response::Response {
    if !authorized(&headers, &st.admin_token) {
        return unauthorized();
    }
    if body.name.trim().is_empty() {
        return bad_request("name must not be empty");
    }
    if !(body.base_url.starts_with("http://") || body.base_url.starts_with("https://")) {
        return bad_request("base_url must start with http:// or https://");
    }
    if body.token.trim().is_empty() {
        return bad_request("token must not be empty");
    }
    match st
        .db
        .register_server(
            body.name.trim(),
            body.base_url.trim(),
            body.token.trim(),
            body.cluster.as_deref().filter(|c| !c.is_empty()),
        )
        .await
    {
        Ok(s) => (StatusCode::CREATED, Json(s)).into_response(),
        // A rejected registration is almost always a bad cluster ref → 400.
        Err(e) => bad_request(e),
    }
}

async fn delete_server(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> axum::response::Response {
    if !authorized(&headers, &st.admin_token) {
        return unauthorized();
    }
    match st.db.delete_server(&id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "no such server"})),
        )
            .into_response(),
        Err(e) => server_error(e),
    }
}

// ---- Failover control (forward to the managed server's /mgmt) ---------------

async fn promote_server(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Option<Json<Value>>,
) -> axum::response::Response {
    forward_role_change(st, headers, id, body, "promote").await
}

async fn demote_server(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Option<Json<Value>>,
) -> axum::response::Response {
    forward_role_change(st, headers, id, body, "demote").await
}

/// Look up the managed server and forward a promote/demote command to its `/mgmt/<action>`,
/// relaying the server's status and JSON body verbatim. An optional `{"domain":"proxy"}` in
/// the request is passed through (absent → the server flips every managed domain).
async fn forward_role_change(
    st: ApiState,
    headers: HeaderMap,
    id: String,
    body: Option<Json<Value>>,
    action: &str,
) -> axum::response::Response {
    if !authorized(&headers, &st.admin_token) {
        return unauthorized();
    }
    let target = match st.db.get_target(&id).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "no such server" })),
            )
                .into_response()
        }
        Err(e) => return server_error(e),
    };
    // Forward only the domain selector, never anything else the caller sent.
    let forwarded = match body.map(|Json(b)| b) {
        Some(Value::Object(m)) if m.get("domain").is_some() => {
            json!({ "domain": m.get("domain") })
        }
        _ => json!({}),
    };
    // A whole-node manual promote (no specific domain) also moves client traffic: record
    // this server as its cluster's active primary and steer the DNS record to it.
    let whole_node = forwarded.get("domain").is_none();
    let url = format!("{}/mgmt/{action}", target.base_url);
    match magnetite_feed::post_command(&url, &target.token, &forwarded).await {
        Ok((status, value)) => {
            if action == "promote" && whole_node && (200..300).contains(&status) {
                if let Ok(Some(cid)) = st.db.server_cluster(&id).await {
                    let _ = st.db.set_active_primary(&cid, Some(&id)).await;
                    crate::poll::steer_dns(&st.db, &cid).await;
                }
            }
            let code = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
            (code, Json(value)).into_response()
        }
        // Transport failure reaching the server (down / wrong url / bad token TLS).
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({ "error": format!("could not reach server: {e}") })),
        )
            .into_response(),
    }
}

// ---- P3 failover policy / intent / events -----------------------------------

#[derive(Deserialize)]
struct IntentBody {
    intent: String,
}

async fn set_intent(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<IntentBody>,
) -> axum::response::Response {
    if !authorized(&headers, &st.admin_token) {
        return unauthorized();
    }
    let Some(intent) = crate::failover::RoleIntent::parse(&body.intent) else {
        return bad_request("intent must be primary, standby, or unset");
    };
    match st.db.set_intent(&id, intent).await {
        Ok(true) => Json(json!({ "id": id, "intent": intent.as_str() })).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such server" })),
        )
            .into_response(),
        Err(e) => server_error(e),
    }
}

#[derive(Deserialize)]
struct FailoverPolicyBody {
    auto_failover: bool,
    #[serde(default)]
    failure_threshold: Option<u32>,
}

async fn set_failover_policy(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<FailoverPolicyBody>,
) -> axum::response::Response {
    if !authorized(&headers, &st.admin_token) {
        return unauthorized();
    }
    let threshold = body.failure_threshold.unwrap_or(3);
    match st
        .db
        .set_failover_policy(&id, body.auto_failover, threshold)
        .await
    {
        Ok(true) => Json(json!({
            "id": id,
            "auto_failover": body.auto_failover,
            "failure_threshold": threshold.max(1),
        }))
        .into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such cluster" })),
        )
            .into_response(),
        Err(e) => server_error(e),
    }
}

#[derive(Deserialize)]
struct DnsPolicyBody {
    #[serde(default)]
    zone: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    ttl: Option<u32>,
}

async fn set_dns_policy(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<DnsPolicyBody>,
) -> axum::response::Response {
    if !authorized(&headers, &st.admin_token) {
        return unauthorized();
    }
    let clean = |o: Option<String>| o.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let zone = clean(body.zone);
    let name = clean(body.name);
    let ttl = body.ttl.unwrap_or(60).max(1);
    match st
        .db
        .set_dns_policy(&id, zone.as_deref(), name.as_deref(), ttl)
        .await
    {
        Ok(true) => Json(json!({ "id": id, "dns_zone": zone, "dns_name": name, "dns_ttl": ttl }))
            .into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such cluster" })),
        )
            .into_response(),
        Err(e) => server_error(e),
    }
}

#[derive(Deserialize)]
struct DnsTargetBody {
    #[serde(default)]
    ip: Option<String>,
}

async fn set_dns_target(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<DnsTargetBody>,
) -> axum::response::Response {
    if !authorized(&headers, &st.admin_token) {
        return unauthorized();
    }
    let ip = body
        .ip
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    // Validate a provided IP so a typo doesn't silently break steering later.
    if let Some(v) = &ip {
        if v.parse::<std::net::IpAddr>().is_err() {
            return bad_request(format!("invalid ip '{v}'"));
        }
    }
    match st.db.set_dns_target(&id, ip.as_deref()).await {
        Ok(true) => Json(json!({ "id": id, "dns_target": ip })).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "no such server" })),
        )
            .into_response(),
        Err(e) => server_error(e),
    }
}

async fn list_events(State(st): State<ApiState>, headers: HeaderMap) -> axum::response::Response {
    if !authorized(&headers, &st.admin_token) {
        return unauthorized();
    }
    match st.db.list_events(100).await {
        Ok(evts) => Json(evts).into_response(),
        Err(e) => server_error(e),
    }
}

// ---- Combined status -------------------------------------------------------

async fn status(State(st): State<ApiState>, headers: HeaderMap) -> axum::response::Response {
    if !authorized(&headers, &st.admin_token) {
        return unauthorized();
    }
    let clusters = match st.db.list_clusters().await {
        Ok(c) => c,
        Err(e) => return server_error(e),
    };
    let servers = match st.db.list_servers().await {
        Ok(s) => s,
        Err(e) => return server_error(e),
    };
    let events = match st.db.list_events(50).await {
        Ok(e) => e,
        Err(e) => return server_error(e),
    };
    let leader = st.db.current_leader(&st.center_id).await.ok();
    let center = json!({
        "id": st.center_id,
        "is_leader": st.is_leader.load(std::sync::atomic::Ordering::SeqCst),
        "leader": leader,
    });
    Json(json!({
        "clusters": clusters,
        "servers": servers,
        "events": events,
        "center": center,
    }))
    .into_response()
}
