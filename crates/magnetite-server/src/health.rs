//! Unauthenticated liveness / readiness / metrics endpoints (09 §3).
//!
//! These are the probes a load balancer, Kubernetes, or Prometheus scrapes, so —
//! unlike `/mgmt/*` (token-gated) — they carry no auth. They expose only
//! operational state (up/ready flags, per-domain health, task-panic and
//! open-alert counts, uptime); never configuration or secrets.
//!
//! - `GET /healthz` — liveness: `200 ok` if the process can answer at all.
//! - `GET /readyz`  — readiness: `200 ready` when the DB answers and no served
//!   domain is in `Error`; otherwise `503` naming the failed check.
//! - `GET /metrics` — Prometheus text exposition of the same signals.

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use magnetite_db::{Db, ServiceHealth, ServiceRegistry};
use std::fmt::Write as _;
use std::time::Instant;

#[derive(Clone)]
struct HealthState {
    db: Db,
    services: ServiceRegistry,
    version: &'static str,
    started: Instant,
}

/// The router exposing the unauthenticated `/healthz`, `/readyz`, and `/metrics`
/// endpoints. Always mounted (probes must work regardless of config).
pub fn health_router(db: Db, services: ServiceRegistry) -> Router {
    Router::new()
        .route("/healthz", get(serve_healthz))
        .route("/readyz", get(serve_readyz))
        .route("/metrics", get(serve_metrics))
        .with_state(HealthState {
            db,
            services,
            version: env!("CARGO_PKG_VERSION"),
            started: Instant::now(),
        })
}

/// Liveness: the process is running and the HTTP stack answers. Deliberately
/// does no I/O — a readiness failure (DB down) must not fail liveness, or an
/// orchestrator would kill a node that is merely degraded.
async fn serve_healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

/// Result of the readiness checks: the DB probe and whether any served domain is
/// in `Error`.
struct Readiness {
    db_ok: bool,
    errored: Vec<&'static str>,
}

async fn evaluate_readiness(state: &HealthState) -> Readiness {
    let db_ok = state.db.ping().await.is_ok();
    let errored = state
        .services
        .statuses()
        .into_iter()
        .filter(|(_, h)| *h == ServiceHealth::Error)
        .map(|(d, _)| d.as_str())
        .collect();
    Readiness { db_ok, errored }
}

/// Readiness: safe to route traffic here. Fails (`503`) if the DB is unreachable
/// or a served domain reports `Error`, so a load balancer drains this node.
async fn serve_readyz(State(state): State<HealthState>) -> impl IntoResponse {
    let r = evaluate_readiness(&state).await;
    if r.db_ok && r.errored.is_empty() {
        return (StatusCode::OK, "ready\n".to_string());
    }
    let mut body = String::from("not ready\n");
    if !r.db_ok {
        body.push_str("db: unreachable\n");
    }
    if !r.errored.is_empty() {
        let _ = writeln!(body, "domains in error: {}", r.errored.join(","));
    }
    (StatusCode::SERVICE_UNAVAILABLE, body)
}

/// Map a service health to the numeric gauge value used in `/metrics`:
/// healthy=1, warning=0.5, unknown=0, error=-1, disabled=-2. (A negative error
/// value stands out on a dashboard from the neutral 0 of "unknown".)
fn health_gauge(h: ServiceHealth) -> f64 {
    match h {
        ServiceHealth::Healthy => 1.0,
        ServiceHealth::Warning => 0.5,
        ServiceHealth::Unknown => 0.0,
        ServiceHealth::Error => -1.0,
        ServiceHealth::Disabled => -2.0,
    }
}

/// Prometheus text exposition (v0.0.4). Renders the same operational signals as
/// the probes plus per-domain health gauges and process counters.
async fn serve_metrics(State(state): State<HealthState>) -> impl IntoResponse {
    let r = evaluate_readiness(&state).await;
    let ready = r.db_ok && r.errored.is_empty();
    let uptime = state.started.elapsed().as_secs();
    let panics = magnetite_db::task_panic_count();

    let mut out = String::with_capacity(1024);

    out.push_str("# HELP magnetite_up 1 if the process is serving.\n");
    out.push_str("# TYPE magnetite_up gauge\n");
    out.push_str("magnetite_up 1\n");

    out.push_str("# HELP magnetite_ready 1 if the DB answers and no served domain is in error.\n");
    out.push_str("# TYPE magnetite_ready gauge\n");
    let _ = writeln!(out, "magnetite_ready {}", u8::from(ready));

    out.push_str("# HELP magnetite_db_up 1 if the embedded database answered the probe.\n");
    out.push_str("# TYPE magnetite_db_up gauge\n");
    let _ = writeln!(out, "magnetite_db_up {}", u8::from(r.db_ok));

    out.push_str("# HELP magnetite_uptime_seconds seconds since process start.\n");
    out.push_str("# TYPE magnetite_uptime_seconds gauge\n");
    let _ = writeln!(out, "magnetite_uptime_seconds {uptime}");

    out.push_str(
        "# HELP magnetite_task_panics_total supervised background tasks that have panicked.\n",
    );
    out.push_str("# TYPE magnetite_task_panics_total counter\n");
    let _ = writeln!(out, "magnetite_task_panics_total {panics}");

    out.push_str(
        "# HELP magnetite_domain_health per served domain (1=healthy,0.5=warning,0=unknown,-1=error,-2=disabled).\n",
    );
    out.push_str("# TYPE magnetite_domain_health gauge\n");
    for (domain, health) in state.services.statuses() {
        let _ = writeln!(
            out,
            "magnetite_domain_health{{domain=\"{}\"}} {}",
            domain.as_str(),
            health_gauge(health)
        );
    }

    out.push_str("# HELP magnetite_build_info build metadata (constant 1).\n");
    out.push_str("# TYPE magnetite_build_info gauge\n");
    let _ = writeln!(
        out,
        "magnetite_build_info{{version=\"{}\"}} 1",
        state.version
    );

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        out,
    )
}
