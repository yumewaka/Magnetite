//! `magnetite-center` — a vCenter-like control plane for a fleet of Magnetite servers.
//!
//! This headless daemon keeps its own small datastore (clusters + registered servers),
//! polls every server's `/mgmt/*` agent API for health, and exposes a JSON HTTP API to
//! register servers, create clusters, and read fleet status. The Web UI is layered on
//! later; this binary is the control core.
//!
//! Configuration is environment-only (no config file yet):
//!   CENTER_DB_PATH      datastore directory                  (default ./center-data)
//!   CENTER_DB_URL       shared SurrealDB URL for HA           (optional; overrides DB_PATH)
//!   CENTER_LISTEN       API bind address                     (default 127.0.0.1:5555)
//!   CENTER_ADMIN_TOKEN  bearer token for the API             (REQUIRED)
//!   CENTER_POLL_SECS    seconds between health polls         (default 30)
//!   CENTER_ID           stable instance id for HA            (default a random uuid)
//!   CENTER_LEASE_SECS   leader-lease TTL for HA              (default 15)
//!
//! For high availability (P5) run several instances against one shared `CENTER_DB_URL`
//! (e.g. `ws://dbhost:8000`). They elect a single leader via a lease in that store; only
//! the leader runs the failover loop, and a standby takes over within one lease TTL if the
//! leader stops renewing. A single embedded-DB instance is always its own leader.

mod api;
mod failover;
mod leader;
mod poll;
mod store;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let db_path = env_or("CENTER_DB_PATH", "./center-data");
    let listen = env_or("CENTER_LISTEN", "127.0.0.1:5555");
    let poll_secs: u64 = env_or("CENTER_POLL_SECS", "30").parse().unwrap_or(30);
    let admin_token = std::env::var("CENTER_ADMIN_TOKEN").unwrap_or_default();
    if admin_token.trim().is_empty() {
        error!("CENTER_ADMIN_TOKEN is required (bearer token for the control-plane API)");
        anyhow::bail!("CENTER_ADMIN_TOKEN not set");
    }

    // A shared SurrealDB URL enables HA (several centers coordinate through it); otherwise
    // an embedded per-instance RocksDB (single node).
    let db = match std::env::var("CENTER_DB_URL") {
        Ok(url) if !url.trim().is_empty() => {
            let url = url.trim().to_string();
            info!("control-plane datastore: shared SurrealDB at {url} (HA mode)");
            store::CenterDb::connect_url(&url).await?
        }
        _ => {
            info!("control-plane datastore: embedded at {db_path}");
            store::CenterDb::connect(&db_path).await?
        }
    };

    let center_id = env_or("CENTER_ID", &uuid::Uuid::new_v4().to_string());
    let lease_secs: u64 = env_or("CENTER_LEASE_SECS", "15").parse().unwrap_or(15);
    let is_leader = Arc::new(AtomicBool::new(false));

    // Leader election: only the lease holder runs the failover loop.
    let elect_db = db.clone();
    let elect_id = center_id.clone();
    let elect_flag = is_leader.clone();
    tokio::spawn(async move {
        leader::run(elect_db, elect_id, lease_secs.max(3), elect_flag).await;
    });

    // Background health poller (acts only while this instance is the leader).
    let poll_db = db.clone();
    let poll_flag = is_leader.clone();
    let interval = Duration::from_secs(poll_secs.max(1));
    tokio::spawn(async move {
        poll::run(poll_db, interval, poll_flag).await;
    });

    // Release the lease on a clean shutdown so a standby center takes over immediately
    // (rather than waiting a full lease TTL for it to expire).
    let shutdown_db = db.clone();
    let shutdown_id = center_id.clone();

    let state = api::ApiState {
        db,
        admin_token,
        center_id,
        is_leader,
    };
    let app = api::router(state);

    let listener = tokio::net::TcpListener::bind(&listen).await?;
    info!("Magnetite Center listening on http://{listen} (dashboard at /, API under /clusters,/servers,/status)");
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            info!("shutting down: releasing leadership");
            let _ = shutdown_db.release_leadership(&shutdown_id).await;
        })
        .await?;
    Ok(())
}
