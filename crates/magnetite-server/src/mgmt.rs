//! Management-plane agent API (the `/mgmt/*` routes). A `magnetite-center` control
//! plane polls these to inventory and monitor this server — and, in later phases,
//! orchestrate failover. Server-to-server only, like `/repl/*`: the shared `[mgmt]`
//! token is the only auth (constant-time compared) and TLS peer certs are not verified.

use crate::role::RoleController;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use magnetite_core::config::AppConfig;
use magnetite_core::domain::DomainKey;
use magnetite_db::{Db, ServiceRegistry};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
struct MgmtState {
    db: Db,
    config: Arc<AppConfig>,
    services: ServiceRegistry,
    roles: RoleController,
    token: String,
}

/// Per-domain status: enablement, live health, and the replication role this node
/// currently plays (from its `[domains.<d>.server.replication]` config).
#[derive(Serialize)]
struct DomainStatus {
    domain: &'static str,
    enabled: bool,
    health: &'static str,
    /// `"primary"` | `"secondary"` | `"standalone"`.
    role: &'static str,
}

/// Stable inventory of this server (id, address, version, domains + roles).
#[derive(Serialize)]
struct Identity {
    server_id: String,
    base_url: String,
    version: &'static str,
    domains: Vec<DomainStatus>,
}

/// Live health snapshot (per-domain health + role, plus the sample time).
#[derive(Serialize)]
struct Health {
    server_id: String,
    at: String,
    domains: Vec<DomainStatus>,
}

/// The router exposing the management agent API. Mounted only when `[mgmt]` is enabled
/// with a non-empty token.
pub fn mgmt_router(
    db: Db,
    config: Arc<AppConfig>,
    services: ServiceRegistry,
    roles: RoleController,
    token: String,
) -> Router {
    Router::new()
        .route("/mgmt/identity", get(serve_identity))
        .route("/mgmt/health", get(serve_health))
        .route("/mgmt/promote", post(serve_promote))
        .route("/mgmt/demote", post(serve_demote))
        .route("/mgmt/dns", post(serve_dns_repoint))
        .with_state(MgmtState {
            db,
            config,
            services,
            roles,
            token,
        })
}

/// Whether the request presents the correct `Authorization: Bearer <token>`.
fn authorized(headers: &HeaderMap, token: &str) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| bearer_eq(t, token))
        .unwrap_or(false)
}

/// Length-checked constant-time token comparison.
fn bearer_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The replication role a domain currently plays. The runtime controller wins when it
/// manages the domain (a configured secondary that may have been promoted): `pulling`
/// means it still tracks a primary (`secondary`), otherwise it has been promoted
/// (`primary`). Domains the controller does not manage fall back to their static config:
/// a `secondary` pulls from a primary, a `primary` serves the feed, else `standalone`.
fn domain_role(state: &MgmtState, key: DomainKey) -> &'static str {
    if let Some(pulling) = state.roles.is_pulling(key) {
        return if pulling { "secondary" } else { "primary" };
    }
    let repl = state
        .config
        .domains
        .get(&key)
        .and_then(|d| d.server.as_ref())
        .and_then(|s| s.replication.as_ref());
    match repl {
        Some(r) if r.enabled && r.is_secondary() => "secondary",
        Some(r) if r.enabled => "primary",
        _ => "standalone",
    }
}

/// Build the per-domain status list (the manageable domains plus the AD DC).
fn domain_statuses(state: &MgmtState) -> Vec<DomainStatus> {
    DomainKey::DOMAINS
        .iter()
        .copied()
        .chain(std::iter::once(DomainKey::Addc))
        .map(|key| DomainStatus {
            domain: key.as_str(),
            enabled: state
                .config
                .domains
                .get(&key)
                .map(|d| d.enabled)
                .unwrap_or(false),
            health: state.services.health(key).as_str(),
            role: domain_role(state, key),
        })
        .collect()
}

async fn serve_identity(
    State(state): State<MgmtState>,
    headers: HeaderMap,
) -> Result<Json<Identity>, StatusCode> {
    if !authorized(&headers, &state.token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let server_id = state
        .db
        .get_or_create_server_id()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(Identity {
        server_id,
        base_url: state.config.server.base_url.clone(),
        version: env!("CARGO_PKG_VERSION"),
        domains: domain_statuses(&state),
    }))
}

async fn serve_health(
    State(state): State<MgmtState>,
    headers: HeaderMap,
) -> Result<Json<Health>, StatusCode> {
    if !authorized(&headers, &state.token) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let server_id = state
        .db
        .get_or_create_server_id()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(Health {
        server_id,
        at: chrono::Utc::now().to_rfc3339(),
        domains: domain_statuses(&state),
    }))
}

/// Body for a role change: an optional single domain; when omitted, every managed domain
/// is flipped (whole-node failover / failback).
#[derive(Deserialize, Default)]
struct RoleChange {
    #[serde(default)]
    domain: Option<String>,
}

/// `POST /mgmt/promote` — pause the pull loop(s) so this node's last-synced config becomes
/// authoritative (acts as primary). With `{"domain":"proxy"}` promotes one domain; with no
/// body (or `{}`) promotes every managed domain.
async fn serve_promote(
    State(state): State<MgmtState>,
    headers: HeaderMap,
    body: Option<Json<RoleChange>>,
) -> axum::response::Response {
    change_role(&state, &headers, body, true)
}

/// `POST /mgmt/demote` — resume pulling so this node tracks its primary again (secondary).
async fn serve_demote(
    State(state): State<MgmtState>,
    headers: HeaderMap,
    body: Option<Json<RoleChange>>,
) -> axum::response::Response {
    change_role(&state, &headers, body, false)
}

fn change_role(
    state: &MgmtState,
    headers: &HeaderMap,
    body: Option<Json<RoleChange>>,
    promote: bool,
) -> axum::response::Response {
    if !authorized(headers, &state.token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let action = if promote { "promote" } else { "demote" };
    let flip = |key: DomainKey| {
        if promote {
            state.roles.promote(key)
        } else {
            state.roles.demote(key)
        }
    };

    let changed: Vec<&'static str> = match body.map(|Json(b)| b.domain).unwrap_or(None) {
        // A specific domain: it must be a managed secondary, else 409.
        Some(name) => {
            let Some(key) = DomainKey::from_str(&name) else {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": format!("unknown domain '{name}'") })),
                )
                    .into_response();
            };
            if !flip(key) {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({
                        "error": format!(
                            "domain '{name}' is not a runtime-flippable secondary on this node"
                        )
                    })),
                )
                    .into_response();
            }
            vec![key.as_str()]
        }
        // No domain: flip every managed domain (whole-node failover).
        None => {
            let mut names: Vec<&'static str> = Vec::new();
            for (key, _) in state.roles.managed() {
                if flip(key) {
                    names.push(key.as_str());
                }
            }
            names
        }
    };

    Json(json!({
        "action": action,
        "changed": changed,
        "domains": domain_statuses(state),
    }))
    .into_response()
}

/// Body for `POST /mgmt/dns`: repoint an address record so clients follow a failover.
#[derive(Deserialize)]
struct DnsRepoint {
    /// Apex of the zone to update (e.g. `example.com`).
    zone: String,
    /// The record name to steer (FQDN, e.g. `app.example.com`).
    name: String,
    /// The address to point it at (IPv4 or IPv6).
    ip: String,
    /// TTL for the steered record (seconds).
    #[serde(default = "default_ttl")]
    ttl: u32,
}

fn default_ttl() -> u32 {
    60
}

/// `POST /mgmt/dns` — the control plane steers a service record to a newly-promoted server.
/// Upserts the A/AAAA record in the given zone (served live), or reports that this node does
/// not serve the zone (so the caller can try another node).
async fn serve_dns_repoint(
    State(state): State<MgmtState>,
    headers: HeaderMap,
    Json(body): Json<DnsRepoint>,
) -> axum::response::Response {
    if !authorized(&headers, &state.token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let Ok(ip) = body.ip.trim().parse::<std::net::IpAddr>() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": format!("invalid ip '{}'", body.ip) })),
        )
            .into_response();
    };
    match state
        .db
        .repoint_address_record(
            &body.zone,
            &body.name,
            ip,
            body.ttl.max(1),
            "magnetite-center",
        )
        .await
    {
        Ok(Some(serial)) => Json(json!({
            "zone": body.zone,
            "name": body.name,
            "ip": ip.to_string(),
            "ttl": body.ttl.max(1),
            "serial": serial,
            "changed": true,
        }))
        .into_response(),
        // Zone not served here, or the record already held this address (idempotent).
        Ok(None) => Json(json!({
            "zone": body.zone,
            "name": body.name,
            "changed": false,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}
