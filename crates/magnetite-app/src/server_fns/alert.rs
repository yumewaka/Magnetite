//! Cross-cutting alert & notification server functions (S-Alerts / F-05).
//! Listing is Viewer+ (read); acknowledge/resolve and target CRUD are
//! Operator+ (AC-04). Every state change is audited (AC-08) under `Portal`.

use leptos::prelude::*;
use magnetite_core::models::{Alert, NotificationTarget};

#[cfg(feature = "ssr")]
async fn audit_alert(
    user: &magnetite_core::models::CurrentUser,
    action: magnetite_core::models::common::ActionKind,
    target_kind: &str,
    target_id: &str,
) {
    use crate::server_fns::auth::client_ip;
    use crate::state::AppState;
    let state = expect_context::<AppState>();
    let _ = state
        .db
        .append_audit(magnetite_core::models::NewAuditEntry {
            actor: user.subject.clone(),
            actor_role: user.role,
            domain: magnetite_core::domain::DomainKey::Portal,
            action,
            target_kind: target_kind.to_string(),
            target_id: target_id.to_string(),
            result: magnetite_core::models::common::OpResult::Success,
            ip: client_ip().await,
            detail: None,
        })
        .await;
}

// ---- Alerts ---------------------------------------------------------------

/// List alerts filtered by state / severity / domain (E-05). Empty strings
/// clear the corresponding filter. Viewer and above.
#[server(ListAlerts, "/api")]
pub async fn list_alerts(
    state: String,
    severity: String,
    domain: String,
) -> Result<Vec<Alert>, ServerFnError> {
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
    let app = expect_context::<AppState>();
    app.db
        .list_alerts(
            opt(&state).as_deref(),
            opt(&severity).as_deref(),
            opt(&domain).as_deref(),
        )
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Acknowledge one or more open alerts (E-01/E-04). Returns the number that
/// actually transitioned. Operator and above.
#[server(AcknowledgeAlerts, "/api")]
pub async fn acknowledge_alerts(alert_ids: Vec<String>) -> Result<usize, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let app = expect_context::<AppState>();
    let mut changed = 0;
    for id in &alert_ids {
        if app
            .db
            .acknowledge_alert(id, &user.subject)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?
        {
            changed += 1;
            audit_alert(&user, ActionKind::Control, "alert.acknowledge", id).await;
        }
    }
    Ok(changed)
}

/// Resolve one or more open/acknowledged alerts (E-02/E-04). Returns the number
/// that actually transitioned. Operator and above.
#[server(ResolveAlerts, "/api")]
pub async fn resolve_alerts(alert_ids: Vec<String>) -> Result<usize, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let app = expect_context::<AppState>();
    let mut changed = 0;
    for id in &alert_ids {
        if app
            .db
            .resolve_alert(id, &user.subject)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?
        {
            changed += 1;
            audit_alert(&user, ActionKind::Control, "alert.resolve", id).await;
        }
    }
    Ok(changed)
}

// ---- Notification targets -------------------------------------------------

/// List notification targets (C-08). Signing secrets are never projected.
/// Viewer and above.
#[server(ListNotificationTargets, "/api")]
pub async fn list_notification_targets() -> Result<Vec<NotificationTarget>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let app = expect_context::<AppState>();
    let mut targets = app
        .db
        .list_notification_targets()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    for t in &mut targets {
        t.signing_secret = None;
    }
    Ok(targets)
}

/// Create a notification target (E-06). Validates name / URL / severity
/// (screen_alerts §5). Operator and above.
#[server(CreateNotificationTarget, "/api")]
pub async fn create_notification_target(
    name: String,
    kind: String,
    endpoint: String,
    min_severity: String,
    signing_secret: String,
    enabled: bool,
) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::{ActionKind, NotifyKind, Severity};

    let user = require(ActionClass::Write).await?;

    let name = name.trim().to_string();
    if name.is_empty() || name.chars().count() > 50 {
        return Err(ServerFnError::new("名称を入力してください。"));
    }
    let kind = match kind.as_str() {
        "audit_sink" => NotifyKind::AuditSink,
        "email" => NotifyKind::Email,
        _ => NotifyKind::Webhook,
    };
    let endpoint = endpoint.trim().to_string();
    match kind {
        NotifyKind::Email => {
            // A single email address: local@domain.
            if !endpoint.contains('@') || endpoint.starts_with('@') || endpoint.ends_with('@') {
                return Err(ServerFnError::new(
                    "有効なメールアドレスを入力してください。",
                ));
            }
        }
        _ => {
            let is_http_url = endpoint.starts_with("http://") || endpoint.starts_with("https://");
            if !is_http_url || endpoint.len() < "http://a".len() {
                return Err(ServerFnError::new("有効な URL を入力してください。"));
            }
        }
    }
    let min_severity = match min_severity.as_str() {
        "critical" => Some(Severity::Critical),
        "warning" => Some(Severity::Warning),
        "info" => Some(Severity::Info),
        _ => None,
    };
    if min_severity.is_none() {
        return Err(ServerFnError::new("通知する重大度を選択してください。"));
    }
    // A signing secret only applies to HTTP targets (webhook / audit sink).
    let signing_secret = signing_secret.trim();
    let signing_secret =
        (kind != NotifyKind::Email && !signing_secret.is_empty()).then_some(signing_secret);

    let app = expect_context::<AppState>();
    let target = app
        .db
        .create_notification_target(
            &name,
            kind,
            &endpoint,
            min_severity,
            &[],
            signing_secret,
            enabled,
            &user.subject,
        )
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_alert(&user, ActionKind::Create, "notify_target", &target.name).await;
    Ok(())
}

/// Enable/disable a notification target. Operator and above.
#[server(SetNotificationTargetEnabled, "/api")]
pub async fn set_notification_target_enabled(
    target_id: String,
    enabled: bool,
) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let app = expect_context::<AppState>();
    app.db
        .set_notification_target_enabled(&target_id, enabled)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_alert(&user, ActionKind::Update, "notify_target", &target_id).await;
    Ok(())
}

/// Delete a notification target (E-06). Operator and above.
#[server(DeleteNotificationTarget, "/api")]
pub async fn delete_notification_target(target_id: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let app = expect_context::<AppState>();
    app.db
        .delete_notification_target(&target_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_alert(&user, ActionKind::Delete, "notify_target", &target_id).await;
    Ok(())
}
