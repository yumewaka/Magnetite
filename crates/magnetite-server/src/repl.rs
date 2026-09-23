//! Mailbox replication wiring (Step 2 HA, Magnetite-to-Magnetite). A *primary*
//! serves the mailbox-change feed at `GET /repl/mail` (gated by a shared bearer
//! secret); a *secondary* polls a primary's feed on an interval and applies the
//! added / deleted messages to its own store, advancing a persisted cursor.
//!
//! The primary URL may be `http://` or `https://`; over TLS the peer certificate
//! is not verified (encryption without authentication — the bearer secret
//! authenticates the request, and internal HA peers commonly use self-signed
//! certs). The feed carries raw message bodies, so it is a server-to-server
//! channel only — never exposed to browsers and always behind the bearer secret.

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use magnetite_core::domain::DomainKey;
use magnetite_core::domains::dhcp::model::DhcpLeaseFeed;
use magnetite_core::domains::mail::model::MailReplFeed;
use magnetite_core::models::common::Severity;
use magnetite_db::{Db, NewAlert, ProxyReplFeed, SsoReplFeed, SysvolFeed};
use magnetite_feed::SINCE_HEADER;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;

/// Max messages / deletions returned in one feed batch (the secondary re-polls to
/// drain a large backlog).
const FEED_LIMIT: usize = 500;

#[derive(Clone)]
struct FeedState {
    db: Db,
    secret: String,
}

/// The router exposing the replication feed, mounted on the main HTTP server when
/// mail replication is configured with a secret.
pub fn mail_repl_router(db: Db, secret: String) -> Router {
    Router::new()
        .route("/repl/mail", get(serve_feed))
        .with_state(FeedState { db, secret })
}

async fn serve_feed(
    State(state): State<FeedState>,
    headers: HeaderMap,
) -> Result<Json<MailReplFeed>, StatusCode> {
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if !presented
        .map(|t| bearer_eq(t, &state.secret))
        .unwrap_or(false)
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let since = headers
        .get(SINCE_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    state
        .db
        .mail_repl_feed(since, FEED_LIMIT)
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Length-checked constant-time comparison of the presented token to the secret.
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

/// Consecutive failed polls before a feed is alerted. At the default poll interval this
/// is past a transient blip (a brief network hiccup or a primary restart) but well short
/// of a real outage going unnoticed.
const ALERT_AFTER_FAILURES: u32 = 3;

/// Consecutive polls that fetch items but apply none before a feed is flagged as stuck.
/// A single such poll is normal (re-fetching an already-applied batch); many in a row
/// mean the cursor is not advancing and real data is not landing — the "connected OK,
/// applied 0" silent drift a bare error check misses.
const STUCK_AFTER_CYCLES: u32 = 5;

/// The outcome of one successful pull pass, so the loop can distinguish real progress
/// from silent drift.
enum PullProgress {
    /// An incremental feed returned `fetched` change items, `applied` of which were new.
    /// `fetched > 0 && applied == 0` sustained across cycles is the stuck/drift signal.
    ///
    /// This relies on the feeds serving EXCLUSIVE cursors (strictly-after: the store
    /// queries use `received_at > $ts` / `updated_at > $ts`), so a healthy steady state
    /// fetches 0 and `fetched > 0` means genuinely new items — which should apply. A
    /// feed that re-sent its cursor row inclusively would make a healthy loop look stuck;
    /// keep new feeds strictly-after (verified for mail/dhcp/sysvol).
    Incremental { fetched: u64, applied: u64 },
    /// A serial-gated snapshot feed (proxy/SSO): "0 applied" is the normal steady state
    /// (serial unchanged), so it is exempt from stuck detection.
    Snapshot,
}

/// The pure failure-run state machine behind [`ReplAlerter`], split out so its
/// alert-once-per-outage logic is unit-testable without a live [`Db`].
#[derive(Default)]
struct FailureRun {
    consecutive: u32,
    alerted: bool,
}

impl FailureRun {
    /// Advance on a successful poll. Returns `true` if this ended an outage that had been
    /// alerted (so the caller logs a recovery).
    fn note_success(&mut self) -> bool {
        let recovered = self.alerted;
        self.alerted = false;
        self.consecutive = 0;
        recovered
    }

    /// Advance on a failed poll. Returns `true` exactly once per outage — when the run
    /// first reaches [`ALERT_AFTER_FAILURES`] — so the caller raises a single alert.
    fn note_failure(&mut self) -> bool {
        self.consecutive += 1;
        let should_alert = self.consecutive >= ALERT_AFTER_FAILURES && !self.alerted;
        if should_alert {
            self.alerted = true;
        }
        should_alert
    }
}

/// What a [`StuckRun`] transition should trigger.
#[derive(Debug, PartialEq, Eq)]
enum StuckEvent {
    /// Nothing to do (below threshold, already alerted, or steadily healthy).
    Quiet,
    /// The stall just crossed the threshold — raise a single drift alert.
    Raise,
    /// A previously-alerted stall ended — log that applying resumed.
    Resumed,
}

/// The pure "fetched but applied nothing" run behind the drift detector, split out so its
/// alert-once/resume logic is unit-testable without a live [`Db`].
#[derive(Default)]
struct StuckRun {
    cycles: u32,
    alerted: bool,
}

impl StuckRun {
    /// Advance given whether this successful poll stalled (fetched items, applied none).
    /// Raises exactly once when the stall first reaches `threshold`; reports a resume when
    /// a non-stalled poll follows an alerted stall.
    fn note(&mut self, stalled: bool, threshold: u32) -> StuckEvent {
        if !stalled {
            let resumed = self.alerted;
            self.cycles = 0;
            self.alerted = false;
            return if resumed {
                StuckEvent::Resumed
            } else {
                StuckEvent::Quiet
            };
        }
        self.cycles += 1;
        if self.cycles >= threshold && !self.alerted {
            self.alerted = true;
            StuckEvent::Raise
        } else {
            StuckEvent::Quiet
        }
    }
}

/// Per-feed replication failure tracker. A pull loop keeps running (and logging) when a
/// feed fails, so a secondary can be "alive but silently not replicating" — the HA copy
/// quietly goes stale. This raises ONE alert per outage episode, when failures first
/// cross [`ALERT_AFTER_FAILURES`] (not one per failed poll), and logs a recovery when the
/// feed next succeeds, so the silent-failure class is visible without flooding alerts.
struct ReplAlerter {
    db: Db,
    feed: &'static str,
    domain: DomainKey,
    run: FailureRun,
    /// Tracks consecutive successful polls that fetched items but applied none (drift).
    stuck: StuckRun,
}

impl ReplAlerter {
    fn new(db: Db, feed: &'static str, domain: DomainKey) -> Self {
        Self {
            db,
            feed,
            domain,
            run: FailureRun::default(),
            stuck: StuckRun::default(),
        }
    }

    /// Record a successful poll: reset the failure run and, on recovery from an alerted
    /// outage, log it.
    async fn success(&mut self) {
        if self.run.note_success() {
            tracing::info!(
                target: "repl",
                feed = self.feed,
                "replication feed recovered"
            );
        }
    }

    /// Assess a successful pass for silent drift: an incremental feed that keeps fetching
    /// items but applying none is not advancing. After [`STUCK_AFTER_CYCLES`] such polls
    /// in a row, raise ONE Warning alert; a poll that applies something (or advances to an
    /// empty steady state) clears it. Snapshot feeds are exempt.
    async fn note_progress(&mut self, progress: PullProgress) {
        let stalled = matches!(
            progress,
            PullProgress::Incremental { fetched, applied } if fetched > 0 && applied == 0
        );
        match self.stuck.note(stalled, STUCK_AFTER_CYCLES) {
            StuckEvent::Quiet => {}
            StuckEvent::Resumed => {
                tracing::info!(target: "repl", feed = self.feed, "replication feed resumed applying");
            }
            StuckEvent::Raise => {
                tracing::warn!(
                    target: "repl",
                    feed = self.feed,
                    "replication feed fetched items but applied none for {} cycles (possible silent drift)",
                    self.stuck.cycles
                );
                let _ = self
                    .db
                    .raise_alert(NewAlert {
                        domain: self.domain,
                        severity: Severity::Warning,
                        summary: format!(
                            "レプリケーションフィード「{}」が {} サイクル連続でデータを取得しているのに0件しか適用していません（無言ドリフトの疑い）。",
                            self.feed, self.stuck.cycles
                        ),
                        source_ref: Some(format!("repl-stuck:{}", self.feed)),
                        rule_ref: Some("replication-drift".to_string()),
                        suppressed: false,
                    })
                    .await;
            }
        }
    }

    /// Record a failed poll (an error or a panicked pass): count it, and on first
    /// crossing the threshold raise a single alert for the outage.
    async fn failure(&mut self, err: &str) {
        let raise = self.run.note_failure();
        tracing::warn!(
            target: "repl",
            feed = self.feed,
            "replication pull failed ({} consecutive): {err}",
            self.run.consecutive
        );
        if raise {
            let _ = self
                .db
                .raise_alert(NewAlert {
                    domain: self.domain,
                    severity: Severity::Critical,
                    summary: format!(
                        "レプリケーションフィード「{}」が {} 回連続で失敗しています。最新のエラー: {err}",
                        self.feed, self.run.consecutive
                    ),
                    source_ref: Some(format!("repl:{}", self.feed)),
                    rule_ref: Some("replication".to_string()),
                    suppressed: false,
                })
                .await;
        }
    }
}

/// Drive one replication feed's pull loop: on each `interval` tick (while `pulling`, when
/// gated), run one `pull_once` pass and route its outcome through a [`ReplAlerter`].
///
/// Each pass runs in its own task so a panic inside it is isolated: instead of killing
/// the whole loop (silently ending replication until a process restart), a panicked pass
/// is treated as a failed poll and the loop keeps going, self-healing on the next tick.
/// Repeated failures — errors or panics — escalate to a single alert. Ends on shutdown.
// The pull loop wires together its feed identity, domain, DB, endpoint, secret, cadence
// and pause flag; grouping them into a struct would not clarify this internal helper.
#[allow(clippy::too_many_arguments)]
async fn run_pull_loop<P, Fut>(
    feed: &'static str,
    domain: DomainKey,
    db: Db,
    base: String,
    secret: String,
    interval: u64,
    pulling: Option<Arc<AtomicBool>>,
    mut shutdown: watch::Receiver<bool>,
    pull_once: P,
) where
    P: Fn(Db, String, String) -> Fut,
    Fut: Future<Output = anyhow::Result<PullProgress>> + Send + 'static,
{
    let mut alerter = ReplAlerter::new(db.clone(), feed, domain);
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                // Paused while promoted to primary: keep the last-synced state
                // authoritative rather than overwriting it from the old primary.
                if let Some(p) = &pulling {
                    if !p.load(Ordering::Relaxed) {
                        continue;
                    }
                }
                let pass = pull_once(db.clone(), base.clone(), secret.clone());
                match tokio::spawn(pass).await {
                    Ok(Ok(progress)) => {
                        alerter.success().await;
                        alerter.note_progress(progress).await;
                    }
                    Ok(Err(e)) => alerter.failure(&e.to_string()).await,
                    Err(join) => alerter.failure(&format!("pull pass panicked: {join}")).await,
                }
            }
        }
    }
}

/// Spawn the secondary's pull loop: poll `<primary_url>/repl/mail` on `interval`,
/// apply changes, and persist the cursor + sync state. Ends on shutdown.
pub fn spawn_mail_pull(
    db: Db,
    primary_url: String,
    secret: String,
    interval: u64,
    pulling: Arc<AtomicBool>,
    shutdown: watch::Receiver<bool>,
) {
    let base = primary_url.trim_end_matches('/').to_string();
    magnetite_db::spawn_supervised(
        "mail-pull",
        run_pull_loop(
            "mail-pull",
            DomainKey::Mail,
            db,
            base,
            secret,
            interval,
            Some(pulling),
            shutdown,
            |db, base, secret| async move {
                let result = pull_once(&db, &base, &secret).await;
                if let Err(e) = &result {
                    // Preserve the mail-specific sync-state telemetry on a failed pull.
                    let cursor = db
                        .get_mail_repl_state()
                        .await
                        .map(|s| s.cursor)
                        .unwrap_or_default();
                    let _ = db
                        .record_mail_repl_sync(&cursor, 0, 0, Some(&e.to_string()))
                        .await;
                }
                result
            },
        ),
    );
}

/// One pull pass: fetch the feed from the current cursor, apply messages and
/// deletions idempotently, and persist the advanced cursor.
async fn pull_once(db: &Db, base: &str, secret: &str) -> anyhow::Result<PullProgress> {
    let cursor = db.get_mail_repl_state().await?.cursor;
    let feed: MailReplFeed =
        magnetite_feed::fetch_feed(&format!("{base}/repl/mail"), secret, &cursor).await?;
    let fetched = (feed.messages.len() + feed.deletions.len() + feed.flag_updates.len()) as u64;
    let mut applied = 0u64;
    for m in &feed.messages {
        if db.apply_replicated_message(m).await? {
            applied += 1;
        }
    }
    let mut deleted = 0u64;
    for repl_id in &feed.deletions {
        if db.apply_replicated_deletion(repl_id).await? {
            deleted += 1;
        }
    }
    let mut flagged = 0u64;
    for update in &feed.flag_updates {
        if db
            .apply_replicated_flags(&update.repl_id, &update.flags)
            .await?
        {
            flagged += 1;
        }
    }
    db.record_mail_repl_sync(&feed.cursor, applied, deleted, None)
        .await?;
    if applied > 0 || deleted > 0 || flagged > 0 {
        tracing::info!(
            "mail replication: applied={applied} deleted={deleted} flagged={flagged} cursor={}",
            feed.cursor
        );
    }
    Ok(PullProgress::Incremental {
        fetched,
        applied: applied + deleted + flagged,
    })
}

// --- DHCP lease replication (split-scope failover continuity) ----------------------
//
// A primary serves the lease feed at `GET /repl/dhcp` (same bearer secret); a peer
// polls it and applies the leases into its own store, so it has the full picture: a
// client can renew against either server, and split-scope allocation avoids handing
// out an address the peer already leased. The cursor is kept in memory (a restart
// re-syncs from empty — leases are bounded and the apply is idempotent).

/// The router exposing the DHCP lease feed, mounted when DHCP replication is configured.
pub fn dhcp_repl_router(db: Db, secret: String) -> Router {
    Router::new()
        .route("/repl/dhcp", get(serve_dhcp_feed))
        .with_state(FeedState { db, secret })
}

async fn serve_dhcp_feed(
    State(state): State<FeedState>,
    headers: HeaderMap,
) -> Result<Json<DhcpLeaseFeed>, StatusCode> {
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if !presented
        .map(|t| bearer_eq(t, &state.secret))
        .unwrap_or(false)
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let since = headers
        .get(SINCE_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    state
        .db
        .dhcp_lease_feed(since, FEED_LIMIT)
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Spawn the DHCP peer's pull loop: poll `<primary_url>/repl/dhcp` on `interval`,
/// apply the leases, and advance an in-memory cursor. Ends on shutdown.
pub fn spawn_dhcp_pull(
    db: Db,
    primary_url: String,
    secret: String,
    interval: u64,
    pulling: Arc<AtomicBool>,
    shutdown: watch::Receiver<bool>,
) {
    let base = primary_url.trim_end_matches('/').to_string();
    magnetite_db::spawn_supervised(
        "dhcp-pull",
        run_pull_loop(
            "dhcp-pull",
            DomainKey::Dhcp,
            db,
            base,
            secret,
            interval,
            Some(pulling),
            shutdown,
            |db, base, secret| async move { dhcp_pull_once(&db, &base, &secret).await },
        ),
    );
}

/// One DHCP pull pass. The cursor is read from and written back to the DB
/// (`dhcp_repl_state`), so a secondary resumes across restarts instead of
/// re-syncing from empty.
async fn dhcp_pull_once(db: &Db, base: &str, secret: &str) -> anyhow::Result<PullProgress> {
    let cursor = db.get_dhcp_repl_cursor().await?;
    let feed: DhcpLeaseFeed =
        magnetite_feed::fetch_feed(&format!("{base}/repl/dhcp"), secret, &cursor).await?;
    let fetched = feed.leases.len() as u64;
    let mut applied = 0u64;
    for lease in &feed.leases {
        if db.apply_replicated_lease(lease).await? {
            applied += 1;
        }
    }
    db.set_dhcp_repl_cursor(&feed.cursor).await?;
    if applied > 0 {
        tracing::info!("dhcp lease replication from {base}: applied={applied}");
    }
    Ok(PullProgress::Incremental { fetched, applied })
}

/// The router exposing the SYSVOL (Group Policy) file feed — a DFS-R-equivalent
/// so peer DCs keep the SysVol share consistent. Mounted when SYSVOL replication
/// is configured.
pub fn sysvol_repl_router(db: Db, secret: String) -> Router {
    Router::new()
        .route("/repl/sysvol", get(serve_sysvol_feed))
        .with_state(FeedState { db, secret })
}

async fn serve_sysvol_feed(
    State(state): State<FeedState>,
    headers: HeaderMap,
) -> Result<Json<SysvolFeed>, StatusCode> {
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if !presented
        .map(|t| bearer_eq(t, &state.secret))
        .unwrap_or(false)
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let since = headers
        .get(SINCE_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    state
        .db
        .sysvol_feed(since, FEED_LIMIT)
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Spawn the SYSVOL peer's pull loop: poll `<primary_url>/repl/sysvol` on
/// `interval`, apply the files (no-regress), and advance the DB-persisted cursor
/// so a restart resumes from where it left off instead of re-syncing the whole
/// share from empty. Ends on shutdown.
pub fn spawn_sysvol_pull(
    db: Db,
    primary_url: String,
    secret: String,
    interval: u64,
    shutdown: watch::Receiver<bool>,
) {
    let base = primary_url.trim_end_matches('/').to_string();
    magnetite_db::spawn_supervised(
        "sysvol-pull",
        run_pull_loop(
            "sysvol-pull",
            DomainKey::Addc,
            db,
            base,
            secret,
            interval,
            None,
            shutdown,
            |db, base, secret| async move { sysvol_pull_once(&db, &base, &secret).await },
        ),
    );
}

/// One SYSVOL pull pass. The cursor is read from and written back to the DB
/// (`sysvol_repl_state`), so a peer resumes across restarts.
async fn sysvol_pull_once(db: &Db, base: &str, secret: &str) -> anyhow::Result<PullProgress> {
    let cursor = db.get_sysvol_repl_cursor().await?;
    let feed: SysvolFeed =
        magnetite_feed::fetch_feed(&format!("{base}/repl/sysvol"), secret, &cursor).await?;
    let fetched = feed.files.len() as u64;
    let mut applied = 0u64;
    for file in &feed.files {
        if db.apply_replicated_sysvol_file(file).await? {
            applied += 1;
        }
    }
    db.set_sysvol_repl_cursor(&feed.cursor).await?;
    if applied > 0 {
        tracing::info!("sysvol replication from {base}: applied={applied}");
    }
    Ok(PullProgress::Incremental { fetched, applied })
}

// --- Proxy config replication (Tier C) ---------------------------------------
//
// A primary serves a full snapshot of its reverse-proxy configuration (vhosts,
// certificates *with material*, ACL rules, IP blocks) at `GET /repl/proxy` behind the
// shared bearer secret; a secondary polls it and, when the snapshot's serial changes,
// replaces its whole proxy config with the primary's. The feed carries private keys, so
// like the mail feed it is a server-to-server channel only. A secondary should NOT run
// its own ACME issuance (certs arrive via replication) — main.rs disables ACME on it.

/// The router exposing the proxy-config snapshot, mounted when proxy replication is
/// configured with a secret.
pub fn proxy_repl_router(db: Db, secret: String) -> Router {
    Router::new()
        .route("/repl/proxy", get(serve_proxy_feed))
        .with_state(FeedState { db, secret })
}

async fn serve_proxy_feed(
    State(state): State<FeedState>,
    headers: HeaderMap,
) -> Result<Json<ProxyReplFeed>, StatusCode> {
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if !presented
        .map(|t| bearer_eq(t, &state.secret))
        .unwrap_or(false)
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    state
        .db
        .proxy_repl_feed()
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Spawn the proxy secondary's pull loop: poll `<primary_url>/repl/proxy` on
/// `interval`, and replace the local proxy config when the snapshot changed. Ends on
/// shutdown.
pub fn spawn_proxy_pull(
    db: Db,
    primary_url: String,
    secret: String,
    interval: u64,
    pulling: Arc<AtomicBool>,
    shutdown: watch::Receiver<bool>,
) {
    let base = primary_url.trim_end_matches('/').to_string();
    magnetite_db::spawn_supervised(
        "proxy-pull",
        run_pull_loop(
            "proxy-pull",
            DomainKey::Proxy,
            db,
            base,
            secret,
            interval,
            Some(pulling),
            shutdown,
            |db, base, secret| async move { proxy_pull_once(&db, &base, &secret).await },
        ),
    );
}

async fn proxy_pull_once(db: &Db, base: &str, secret: &str) -> anyhow::Result<PullProgress> {
    // The snapshot is full each time; the `since` header is unused (the serial gate in
    // `apply_proxy_repl` skips re-applying an unchanged snapshot).
    let feed: ProxyReplFeed =
        magnetite_feed::fetch_feed(&format!("{base}/repl/proxy"), secret, "").await?;
    if db.apply_proxy_repl(&feed).await? {
        tracing::info!(
            "proxy config replication from {base}: applied snapshot serial={}",
            feed.serial
        );
    }
    Ok(PullProgress::Snapshot)
}

// --- SSO config replication (Tier C) -----------------------------------------
//
// A primary serves a full snapshot of its SSO config (identity providers, OIDC clients
// and issuer signing keys — all with secrets) at `GET /repl/sso`; a secondary replaces
// its providers/clients/keys when the serial changes. Sessions are NOT replicated (they
// re-establish on failover). Replicating the signing keys keeps the JWKS consistent so a
// token signed by one node verifies on another. The feed carries private keys, so like
// the mail/proxy feeds it is a server-to-server channel behind the shared secret.
//
// Note: a secondary that also runs the SSO issuer loads its signing keyring at startup /
// on rotation — after a pull that changes keys, restart it (or let it rotate) to pick up
// the replicated active key. A verify-only / standby secondary is unaffected.

/// The router exposing the SSO config snapshot, mounted when SSO replication is
/// configured with a secret.
pub fn sso_repl_router(db: Db, secret: String) -> Router {
    Router::new()
        .route("/repl/sso", get(serve_sso_feed))
        .with_state(FeedState { db, secret })
}

async fn serve_sso_feed(
    State(state): State<FeedState>,
    headers: HeaderMap,
) -> Result<Json<SsoReplFeed>, StatusCode> {
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if !presented
        .map(|t| bearer_eq(t, &state.secret))
        .unwrap_or(false)
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    state
        .db
        .sso_repl_feed()
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

/// Spawn the SSO secondary's pull loop: poll `<primary_url>/repl/sso` on `interval`, and
/// replace the local SSO config when the snapshot changed. Ends on shutdown.
pub fn spawn_sso_pull(
    db: Db,
    primary_url: String,
    secret: String,
    interval: u64,
    pulling: Arc<AtomicBool>,
    shutdown: watch::Receiver<bool>,
) {
    let base = primary_url.trim_end_matches('/').to_string();
    magnetite_db::spawn_supervised(
        "sso-pull",
        run_pull_loop(
            "sso-pull",
            DomainKey::Sso,
            db,
            base,
            secret,
            interval,
            Some(pulling),
            shutdown,
            |db, base, secret| async move { sso_pull_once(&db, &base, &secret).await },
        ),
    );
}

async fn sso_pull_once(db: &Db, base: &str, secret: &str) -> anyhow::Result<PullProgress> {
    let feed: SsoReplFeed =
        magnetite_feed::fetch_feed(&format!("{base}/repl/sso"), secret, "").await?;
    if db.apply_sso_repl(&feed).await? {
        tracing::info!(
            "sso config replication from {base}: applied snapshot serial={}",
            feed.serial
        );
    }
    Ok(PullProgress::Snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alerts_once_per_outage_and_resets_on_recovery() {
        let mut run = FailureRun::default();

        // Failures below the threshold do not alert.
        for _ in 0..ALERT_AFTER_FAILURES - 1 {
            assert!(!run.note_failure());
        }
        // The failure that reaches the threshold alerts exactly once...
        assert!(run.note_failure(), "should alert on crossing the threshold");
        // ...and further failures in the same outage do not re-alert.
        assert!(!run.note_failure());
        assert!(!run.note_failure());

        // Recovery reports that an alerted outage ended, then clears the run.
        assert!(
            run.note_success(),
            "recovery after an alert must be reported"
        );
        assert!(
            !run.note_success(),
            "a steady-healthy poll is not a recovery"
        );

        // A fresh outage alerts again (one alert per distinct outage).
        for _ in 0..ALERT_AFTER_FAILURES - 1 {
            assert!(!run.note_failure());
        }
        assert!(run.note_failure(), "a new outage re-alerts");
    }

    #[test]
    fn a_recovery_before_the_threshold_never_alerts() {
        let mut run = FailureRun::default();
        assert!(!run.note_failure());
        // Recovered before reaching ALERT_AFTER_FAILURES: no alert was raised, so the
        // recovery is silent (nothing to report).
        assert!(!run.note_success());
    }

    #[test]
    fn stuck_run_alerts_once_and_resumes() {
        let mut s = StuckRun::default();
        // Stalls below the threshold stay quiet.
        for _ in 0..STUCK_AFTER_CYCLES - 1 {
            assert_eq!(s.note(true, STUCK_AFTER_CYCLES), StuckEvent::Quiet);
        }
        // Crossing the threshold raises exactly once...
        assert_eq!(s.note(true, STUCK_AFTER_CYCLES), StuckEvent::Raise);
        // ...and further stalls in the same episode stay quiet.
        assert_eq!(s.note(true, STUCK_AFTER_CYCLES), StuckEvent::Quiet);
        // A poll that applies something reports a resume, then clears.
        assert_eq!(s.note(false, STUCK_AFTER_CYCLES), StuckEvent::Resumed);
        assert_eq!(s.note(false, STUCK_AFTER_CYCLES), StuckEvent::Quiet);
    }

    #[test]
    fn a_brief_stall_below_the_threshold_never_alerts() {
        let mut s = StuckRun::default();
        assert_eq!(s.note(true, STUCK_AFTER_CYCLES), StuckEvent::Quiet);
        // Applying resumes before the threshold: nothing was raised, so no resume event.
        assert_eq!(s.note(false, STUCK_AFTER_CYCLES), StuckEvent::Quiet);
    }
}
