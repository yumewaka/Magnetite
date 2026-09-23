//! Integrated log-viewer server function (S-Logs / F-08). Read-only, Viewer+
//! (screen_logs §7). Distinct from the audit log.
//!
//! TODO(ingestion): results are empty until log ingestion from the domain
//! modules / daemons is wired to `Db::append_log` (see magnetite-db logs repo).

use leptos::prelude::*;
use magnetite_core::models::LogEntry;

#[cfg(feature = "ssr")]
const LOG_WINDOW: usize = 500;

/// Query logs filtered by domain / kind / level (E-01). Empty strings clear a
/// filter. Newest-first, bounded to the most recent [`LOG_WINDOW`] lines.
#[server(QueryLogs, "/api")]
pub async fn query_logs(
    domain: String,
    log_kind: String,
    level: String,
) -> Result<Vec<LogEntry>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let opt = |s: &str| {
        let t = s.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    };
    let state = expect_context::<AppState>();
    state
        .db
        .query_logs(
            opt(&domain).as_deref(),
            opt(&log_kind).as_deref(),
            opt(&level).as_deref(),
            LOG_WINDOW,
        )
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}
