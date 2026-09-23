//! Process-wide observability primitives shared across the platform (09 §3):
//! supervised background-task spawning and the counters that back the
//! unauthenticated `/metrics` endpoint.
//!
//! The platform starts dozens of long-running background tasks with
//! `tokio::spawn`. Tokio captures a panic from a spawned task in its
//! `JoinHandle` and **silently discards it** when the handle is dropped — so a
//! task that dies leaves no trace and the node keeps reporting "healthy". This
//! module's [`spawn_supervised`] awaits the inner handle, logs the panic under
//! `target: "task"`, and bumps a process-wide counter that `/metrics` exposes
//! (`magnetite_task_panics_total`) so a dead task is observable.

use std::future::Future;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use tokio::task::JoinHandle;

/// Number of supervised background tasks that have panicked since start-up.
static TASK_PANICS: AtomicU64 = AtomicU64::new(0);

/// Process-wide count of supervised background tasks that have panicked.
/// Exposed as the `magnetite_task_panics_total` metric.
pub fn task_panic_count() -> u64 {
    TASK_PANICS.load(Ordering::Relaxed)
}

/// Spawn a long-running background task under supervision.
///
/// Behaves like [`tokio::spawn`] but, because Tokio otherwise swallows a
/// spawned task's panic when its `JoinHandle` is dropped, this awaits the task
/// and, on panic, logs it (`target: "task"`, with the task `name`) and
/// increments the process-wide panic counter surfaced by `/metrics`. A normal
/// return (e.g. graceful shutdown) is logged at debug; a cancellation at warn.
///
/// The returned handle resolves once supervision completes; callers that do not
/// need to join it may drop it (the task keeps running regardless).
pub fn spawn_supervised<F>(name: &'static str, fut: F) -> JoinHandle<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        // Inner spawn so a panic is delivered as a `JoinError` we can observe,
        // rather than unwinding this supervisor.
        let inner = tokio::spawn(fut);
        match inner.await {
            Ok(()) => {
                tracing::debug!(target: "task", task = name, "background task exited")
            }
            Err(e) if e.is_panic() => {
                TASK_PANICS.fetch_add(1, Ordering::Relaxed);
                tracing::error!(target: "task", task = name, "background task PANICKED: {e}");
            }
            Err(e) => {
                tracing::warn!(target: "task", task = name, "background task cancelled: {e}")
            }
        }
    })
}

/// Like [`spawn_supervised`], but for a subsystem's MAIN loop: on panic it stores
/// `dead_value` into the shared `health` byte (in addition to logging + counting), so
/// the subsystem's `health()` reports the crashed loop instead of staying whatever it
/// was last set to. `health`/`dead_value` are the service's existing `Arc<AtomicU8>`
/// health cell and its "error" byte, so no new state is needed.
pub fn spawn_health_guarded<F>(
    name: &'static str,
    health: Arc<AtomicU8>,
    dead_value: u8,
    fut: F,
) -> JoinHandle<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let inner = tokio::spawn(fut);
        match inner.await {
            Ok(()) => {
                tracing::debug!(target: "task", task = name, "background task exited")
            }
            Err(e) if e.is_panic() => {
                health.store(dead_value, Ordering::Relaxed);
                TASK_PANICS.fetch_add(1, Ordering::Relaxed);
                tracing::error!(target: "task", task = name, "background task PANICKED: {e}");
            }
            Err(e) => {
                tracing::warn!(target: "task", task = name, "background task cancelled: {e}")
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_panicking_task_is_counted() {
        let before = task_panic_count();
        let h = spawn_supervised("test-panic", async {
            panic!("boom");
        });
        // Joining the supervisor waits until the panic has been observed+counted.
        // Use `>` not `== before + 1`: the counter is process-global and other
        // panic tests run in parallel, so only its monotonic increase is reliable.
        let _ = h.await;
        assert!(task_panic_count() > before);
    }

    #[tokio::test]
    async fn a_normal_supervised_task_runs_to_completion() {
        // The supervisor must actually run the task (not swallow it). A shared flag
        // avoids depending on the global panic counter, which other tests mutate.
        let ran = Arc::new(AtomicU8::new(0));
        let flag = ran.clone();
        let h = spawn_supervised("test-ok", async move {
            flag.store(1, Ordering::Relaxed);
        });
        let _ = h.await;
        assert_eq!(ran.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn a_guarded_task_stores_the_dead_value_on_panic() {
        const HEALTHY: u8 = 1;
        const DEAD: u8 = 2;
        let health = Arc::new(AtomicU8::new(HEALTHY));
        let h = spawn_health_guarded("test-guarded-panic", health.clone(), DEAD, async {
            panic!("down");
        });
        let _ = h.await;
        assert_eq!(
            health.load(Ordering::Relaxed),
            DEAD,
            "panic must store the dead value into the health byte"
        );
    }

    #[tokio::test]
    async fn a_guarded_task_leaves_health_untouched_on_normal_exit() {
        const HEALTHY: u8 = 1;
        let health = Arc::new(AtomicU8::new(HEALTHY));
        let h = spawn_health_guarded("test-guarded-ok", health.clone(), 2, async {});
        let _ = h.await;
        assert_eq!(health.load(Ordering::Relaxed), HEALTHY);
    }
}
