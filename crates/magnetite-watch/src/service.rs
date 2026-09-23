//! The embedded Watch collector service. Binds no socket — it runs a periodic
//! loop that drives [`collect_once`](crate::collector) and reports Healthy while
//! running. Registered as an [`EmbeddedService`] (09b §-1).

use crate::collector::collect_once;
use magnetite_core::domain::DomainKey;
use magnetite_db::{Db, EmbeddedService, ServiceHealth};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

const H_STARTING: u8 = 0;
const H_HEALTHY: u8 = 1;
/// Set if the collector loop panics (via the health-guarded spawn), so a dead
/// collector is reported as Error instead of a stale Healthy.
const H_ERROR: u8 = 2;

/// Minimum collector cadence, to bound probe load.
const MIN_INTERVAL_SECS: u32 = 5;

/// Embedded monitoring collector: probes hosts and evaluates rules on a timer.
pub struct WatchService {
    interval_secs: u32,
    probe_port: u16,
    log_events: bool,
    health: Arc<AtomicU8>,
}

impl WatchService {
    /// `interval_secs` between passes (clamped to ≥5), `probe_port` for the
    /// per-host TCP reachability check, `log_events` ⇒ a LogEntry per probe.
    pub fn new(interval_secs: u32, probe_port: u16, log_events: bool) -> Self {
        Self {
            interval_secs: interval_secs.max(MIN_INTERVAL_SECS),
            probe_port,
            log_events,
            health: Arc::new(AtomicU8::new(H_STARTING)),
        }
    }
}

impl EmbeddedService for WatchService {
    fn domain(&self) -> DomainKey {
        DomainKey::Watch
    }

    fn health(&self) -> ServiceHealth {
        match self.health.load(Ordering::Relaxed) {
            H_HEALTHY => ServiceHealth::Healthy,
            H_ERROR => ServiceHealth::Error,
            _ => ServiceHealth::Unknown,
        }
    }

    fn start(&self, db: Db, mut shutdown: watch::Receiver<bool>) {
        let interval = Duration::from_secs(self.interval_secs as u64);
        let probe_port = self.probe_port;
        let log_events = self.log_events;
        let health = self.health.clone();
        magnetite_db::spawn_health_guarded("watch", health.clone(), H_ERROR, async move {
            health.store(H_HEALTHY, Ordering::Relaxed);
            tracing::info!(
                "Watch collector running (interval {interval:?}, probe_port {probe_port})"
            );
            loop {
                collect_once(&db, probe_port, log_events).await;
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    _ = shutdown.changed() => break,
                }
                if *shutdown.borrow() {
                    break;
                }
            }
        });
    }
}
