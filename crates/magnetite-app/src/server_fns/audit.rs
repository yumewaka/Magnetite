//! Cross-cutting audit log query server function (S-Audit / F-04 / AC-07).
//! Read-only: the audit log is append-only and exposes no mutation API here.
//! Viewer and above may read (screen_audit §7).

use leptos::prelude::*;
use magnetite_core::models::AuditPage;

/// Query the audit log with optional filters, returning one page plus the
/// total match count (E-01/E-03/E-04). Empty strings clear a filter.
// The filters map one-to-one to the UI's audit query form; a params struct would
// have to be threaded through the `#[server]` boundary for no real gain.
#[allow(clippy::too_many_arguments)]
#[server(QueryAuditLog, "/api")]
pub async fn query_audit_log(
    domain: String,
    action: String,
    actor: String,
    from: String,
    to: String,
    descending: bool,
    page: usize,
    per_page: usize,
) -> Result<AuditPage, ServerFnError> {
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
    let per_page = per_page.clamp(1, 200);
    let offset = page.saturating_mul(per_page);

    let state = expect_context::<AppState>();
    let (entries, total) = state
        .db
        .query_audit(
            opt(&domain).as_deref(),
            opt(&action).as_deref(),
            opt(&actor).as_deref(),
            opt(&from).as_deref(),
            opt(&to).as_deref(),
            descending,
            per_page,
            offset,
        )
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(AuditPage { entries, total })
}
