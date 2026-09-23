//! Self-contained SYSVOL (Group Policy) replication pull for `magnetite-addc`.
//!
//! A DC that keeps its own store (Tier C, `MAGNETITE_DB_PATH`) pulls SYSVOL
//! changes from a peer's `/repl/sysvol` feed directly — no shared database and no
//! separate puller process. Applied files land in this DC's store; the DC's live
//! SYSVOL re-serve (the 30 s timer in [`AddcService`](crate::AddcService)) then
//! serves them over SMB. This is the client counterpart of the feed that
//! `magnetite-server` exposes (`repl::sysvol_repl_router`).

use magnetite_db::{Db, SysvolFeed};
use std::time::Duration;
use tokio::sync::watch;

/// Configuration for the SYSVOL pull loop.
pub struct SysvolPullConfig {
    /// The primary's base URL (e.g. `https://peer:8443`); `/repl/sysvol` is appended.
    pub primary_url: String,
    /// The shared bearer secret guarding the feed.
    pub secret: String,
    /// Poll interval.
    pub interval: Duration,
}

/// Spawn the SYSVOL pull loop: poll the peer's feed on `interval`, apply each file
/// under the store's no-regress rule, and advance an in-memory cursor. Runs until
/// `shutdown` flips. The task is `Send` (unlike the DRS agent), so a plain
/// [`tokio::spawn`] hosts it.
pub fn spawn_sysvol_pull(cfg: SysvolPullConfig, db: Db, mut shutdown: watch::Receiver<bool>) {
    let base = cfg.primary_url.trim_end_matches('/').to_string();
    tokio::spawn(async move {
        let mut cursor = String::new();
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = tokio::time::sleep(cfg.interval) => {
                    match pull_once(&db, &base, &cfg.secret, &cursor).await {
                        Ok(next) => cursor = next,
                        Err(e) => tracing::warn!("SYSVOL replication pull from {base} failed: {e}"),
                    }
                }
            }
        }
    });
}

/// One pull: fetch the feed at `cursor`, apply its files, return the next cursor.
async fn pull_once(db: &Db, base: &str, secret: &str, cursor: &str) -> anyhow::Result<String> {
    let url = format!("{base}/repl/sysvol");
    let feed: SysvolFeed = magnetite_feed::fetch_feed(&url, secret, cursor).await?;
    let mut applied = 0u64;
    for file in &feed.files {
        if db.apply_replicated_sysvol_file(file).await? {
            applied += 1;
        }
    }
    if applied > 0 {
        tracing::info!("SYSVOL replication from {base}: applied={applied}");
    }
    Ok(feed.cursor)
}
