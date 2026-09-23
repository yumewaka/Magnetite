//! Cross-cutting backup / restore server functions (S-Backup / F-06). Listing
//! is Viewer+ (read); create / restore / delete are Admin-only (AC-04). Restore
//! is destructive and every mutation is audited (F-04) under `Portal`.

use leptos::prelude::*;
use magnetite_core::models::Backup;

#[cfg(feature = "ssr")]
async fn audit_backup(
    user: &magnetite_core::models::CurrentUser,
    action: magnetite_core::models::common::ActionKind,
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
            target_kind: "backup".to_string(),
            target_id: target_id.to_string(),
            result: magnetite_core::models::common::OpResult::Success,
            ip: client_ip().await,
            detail: None,
        })
        .await;
}

/// List backups, optionally filtered by domain (C-03). Empty = all. Viewer+.
#[server(ListBackups, "/api")]
pub async fn list_backups(domain: String) -> Result<Vec<Backup>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domain::DomainKey;

    require(ActionClass::Read).await?;
    let filter = if domain.trim().is_empty() {
        None
    } else {
        DomainKey::from_str(domain.trim())
    };
    let state = expect_context::<AppState>();
    state
        .db
        .list_backups(filter)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create a backup of the target domain (E-01). Admin-only.
#[server(CreateBackup, "/api")]
pub async fn create_backup(domain: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domain::DomainKey;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Admin).await?;
    let domain = DomainKey::from_str(domain.trim())
        .ok_or_else(|| ServerFnError::new("バックアップ対象を選択してください。"))?;
    let state = expect_context::<AppState>();
    let backup = state
        .db
        .create_backup(domain, &user.subject)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_backup(&user, ActionKind::Create, &backup.meta.id).await;
    Ok(())
}

/// Restore a backup, overwriting the current configuration (E-03). Admin-only.
#[server(RestoreBackup, "/api")]
pub async fn restore_backup(backup_id: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Admin).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .restore_backup(&backup_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_backup(&user, ActionKind::Restore, &backup_id).await;
    Ok(())
}

/// Delete a backup (E-05). Admin-only.
#[server(DeleteBackup, "/api")]
pub async fn delete_backup(backup_id: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Admin).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_backup(&backup_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_backup(&user, ActionKind::Delete, &backup_id).await;
    Ok(())
}
