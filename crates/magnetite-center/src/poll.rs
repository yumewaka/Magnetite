//! The health-polling loop. Every `interval` the center walks all registered servers,
//! fetches each one's `/mgmt/health` (and, until known, `/mgmt/identity` for its stable
//! id) over the shared bearer-GET client, and records the outcome.

use crate::failover::{evaluate, Action};
use crate::store::CenterDb;
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tracing::{debug, info, warn};

/// Poll every registered server once.
pub async fn poll_once(db: &CenterDb) {
    let targets = match db.poll_targets().await {
        Ok(t) => t,
        Err(e) => {
            warn!("poll: could not list servers: {e}");
            return;
        }
    };
    for t in targets {
        let health_url = format!("{}/mgmt/health", t.base_url);
        match magnetite_feed::fetch_feed::<serde_json::Value>(&health_url, &t.token, "").await {
            Ok(health) => {
                // Prefer the id the server reports in its health body; fall back to a
                // dedicated identity fetch only if health didn't carry one.
                let server_id = match health.get("server_id").and_then(|v| v.as_str()) {
                    Some(s) => Some(s.to_string()),
                    None => fetch_identity_id(&t.base_url, &t.token).await,
                };
                if let Err(e) = db
                    .record_health(&t.sid, server_id, Some(health), None)
                    .await
                {
                    warn!("poll: could not record health for {}: {e}", t.base_url);
                } else {
                    debug!("poll: {} healthy", t.base_url);
                }
            }
            Err(e) => {
                let msg = e.to_string();
                if let Err(e) = db.record_health(&t.sid, None, None, Some(msg)).await {
                    warn!("poll: could not record failure for {}: {e}", t.base_url);
                } else {
                    debug!("poll: {} unreachable", t.base_url);
                }
            }
        }
    }
}

/// Evaluate every cluster's failover policy against the freshly-polled health and carry
/// out any promote/demote actions, persisting the resulting active-primary / fencing state
/// and appending an audit event per action. Runs once per poll tick, after `poll_once`.
pub async fn run_failover(db: &CenterDb) {
    let views = match db.cluster_views().await {
        Ok(v) => v,
        Err(e) => {
            warn!("failover: could not build cluster views: {e}");
            return;
        }
    };
    for (cid, view) in views {
        let decision = evaluate(&view);
        if decision.is_empty() {
            continue;
        }
        // Execute the control actions; a failed promote holds back the state change so we
        // don't record a standby as active when it never actually took over.
        let mut promote_ok = true;
        for action in &decision.actions {
            let (sid, cmd) = match action {
                Action::Promote(s) => (s, "promote"),
                Action::Demote(s) => (s, "demote"),
            };
            match send_command(db, sid, cmd).await {
                Ok(()) => info!("failover[{cid}]: {cmd} {sid} ok"),
                Err(e) => {
                    warn!("failover[{cid}]: {cmd} {sid} failed: {e}");
                    let _ = db
                        .record_event(Some(&cid), "error", &format!("{cmd} {sid} failed: {e}"))
                        .await;
                    if matches!(action, Action::Promote(_)) {
                        promote_ok = false;
                    }
                }
            }
        }

        if promote_ok {
            if let Some(primary) = &decision.new_active_primary {
                if let Err(e) = db.set_active_primary(&cid, Some(primary)).await {
                    warn!("failover[{cid}]: could not persist active primary: {e}");
                }
                // Steer client traffic to the new active primary (P4 DNS repoint).
                steer_dns(db, &cid).await;
            }
            for sid in &decision.fence {
                let _ = db.set_fenced(sid, true).await;
            }
            for sid in &decision.unfence {
                let _ = db.set_fenced(sid, false).await;
            }
        }

        for line in &decision.log {
            info!("failover[{cid}]: {line}");
            let _ = db.record_event(Some(&cid), "failover", line).await;
        }
    }
}

/// Steer the cluster's service DNS record to its current active primary (P4). Reads the
/// cluster's DNS policy (zone/name/ttl) and the active server's `dns_target`, then pushes a
/// repoint to every server in the cluster (best-effort — with DNS zone replication one
/// authoritative node suffices, but broadcasting is robust and idempotent). No-ops when the
/// policy or target is unset. Records one audit event with the outcome.
pub async fn steer_dns(db: &CenterDb, cid: &str) {
    let Ok(Some(cluster)) = db.get_cluster(cid).await else {
        return;
    };
    let (Some(zone), Some(name)) = (
        cluster.dns_zone.as_deref().filter(|s| !s.trim().is_empty()),
        cluster.dns_name.as_deref().filter(|s| !s.trim().is_empty()),
    ) else {
        return; // no DNS-failover policy configured for this cluster
    };
    let Some(active) = cluster.active_primary.as_deref() else {
        return;
    };
    let ip = match db.get_dns_target(active).await {
        Ok(Some(ip)) => ip,
        _ => {
            let _ = db
                .record_event(
                    Some(cid),
                    "dns",
                    &format!("DNS steer skipped: active primary {active} has no dns_target set"),
                )
                .await;
            return;
        }
    };
    let ttl = cluster.dns_ttl;
    let targets = db.cluster_targets(cid).await.unwrap_or_default();
    let body = json!({ "zone": zone, "name": name, "ip": ip, "ttl": ttl });
    let mut ok = 0usize;
    for t in &targets {
        let url = format!("{}/mgmt/dns", t.base_url);
        if let Ok((status, _)) = magnetite_feed::post_command(&url, &t.token, &body).await {
            if (200..300).contains(&status) {
                ok += 1;
            }
        }
    }
    let _ = db
        .record_event(
            Some(cid),
            "dns",
            &format!(
                "steered {name} (zone {zone}) → {ip} (ttl {ttl}) on {ok}/{} node(s)",
                targets.len()
            ),
        )
        .await;
}

/// POST an empty body to a server's `/mgmt/<cmd>` (promote/demote all managed domains),
/// treating any non-2xx as an error.
async fn send_command(db: &CenterDb, sid: &str, cmd: &str) -> anyhow::Result<()> {
    let target = db
        .get_target(sid)
        .await?
        .ok_or_else(|| anyhow::anyhow!("server {sid} not found"))?;
    let url = format!("{}/mgmt/{cmd}", target.base_url);
    let (status, body) = magnetite_feed::post_command(&url, &target.token, &json!({})).await?;
    if !(200..300).contains(&status) {
        anyhow::bail!("{cmd} returned {status}: {body}");
    }
    Ok(())
}

/// Best-effort fetch of a server's stable id from /mgmt/identity.
async fn fetch_identity_id(base_url: &str, token: &str) -> Option<String> {
    let url = format!("{base_url}/mgmt/identity");
    magnetite_feed::fetch_feed::<serde_json::Value>(&url, token, "")
        .await
        .ok()
        .and_then(|v| {
            v.get("server_id")
                .and_then(|s| s.as_str())
                .map(|s| s.to_string())
        })
}

/// Run the poll loop forever, once every `interval`. Only acts while this instance is the
/// leader (P5 HA): a standby center keeps the loop alive but skips polling/failover so a
/// single arbiter drives orchestration; it takes over the instant it wins the lease.
pub async fn run(db: CenterDb, interval: Duration, is_leader: std::sync::Arc<AtomicBool>) {
    info!("health poll loop started (every {}s)", interval.as_secs());
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut was_leader = false;
    loop {
        ticker.tick().await;
        if !is_leader.load(Ordering::SeqCst) {
            was_leader = false;
            continue;
        }
        if !was_leader {
            info!("this center is the leader — running health poll + failover");
            was_leader = true;
        }
        poll_once(&db).await;
        run_failover(&db).await;
    }
}
