//! Leader election for center HA (P5).
//!
//! Several center instances may share one datastore (via `CENTER_DB_URL`). Exactly one of
//! them must run the failover loop at a time — two orchestrators polling and promoting
//! independently would fight (double-promote, flap). This module keeps a lease in the
//! shared store: the instance holding it is the leader and runs the loop; the others stand
//! by, renewing their bid, and take over within one lease TTL if the leader stops renewing.
//!
//! A single-node deployment (embedded RocksDB) is unaffected: that instance simply always
//! wins its own lease and is always the leader.

use crate::store::CenterDb;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Run the election loop forever: every `ttl/3` seconds, try to acquire/renew the lease and
/// publish whether this instance is the leader into `is_leader`. Logs leadership transitions.
pub async fn run(db: CenterDb, center_id: String, ttl_secs: u64, is_leader: Arc<AtomicBool>) {
    // Renew comfortably inside the TTL so a slow tick doesn't drop leadership.
    let renew = Duration::from_secs((ttl_secs / 3).max(1));
    info!(
        "leader election started (center id {center_id}, lease {ttl_secs}s, renew every {}s)",
        renew.as_secs()
    );
    let mut ticker = tokio::time::interval(renew);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        match db.try_acquire_leadership(&center_id, ttl_secs).await {
            Ok(lease) => {
                let was = is_leader.swap(lease.is_self, Ordering::SeqCst);
                if lease.is_self && !was {
                    info!("became leader (term {})", lease.term);
                } else if !lease.is_self && was {
                    warn!("lost leadership to {} (term {})", lease.holder, lease.term);
                }
            }
            Err(e) => {
                // On a transient store error, step down rather than risk a split leader.
                if is_leader.swap(false, Ordering::SeqCst) {
                    warn!("stepping down: leadership renew failed: {e}");
                } else {
                    warn!("leadership renew failed: {e}");
                }
            }
        }
    }
}
