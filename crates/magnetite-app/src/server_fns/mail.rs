//! Mail domain server functions (F-14 / S-MAIL-01..07). Authorized (08_authz),
//! validated (screen_mail §5), audited (F-04).

use crate::types::{MailMetrics, MailReplStatus};
use leptos::prelude::*;
use magnetite_core::domains::mail::model::{
    Alias, BackupMxDomain, MailDomain, MailMessage, MailQueueEntry, MailRelayConfig,
    MailServerConfig, MailUser, MailingList,
};

#[cfg(feature = "ssr")]
async fn audit_mail(
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
            domain: magnetite_core::domain::DomainKey::Mail,
            action,
            target_kind: target_kind.to_string(),
            target_id: target_id.to_string(),
            result: magnetite_core::models::common::OpResult::Success,
            ip: client_ip().await,
            detail: None,
        })
        .await;
}

/// Mail dashboard metrics (S-MAIL-01).
#[server(GetMailMetrics, "/api")]
pub async fn get_mail_metrics() -> Result<MailMetrics, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    let (users, domains, lists, used) = state
        .db
        .mail_metrics()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(MailMetrics {
        user_count: users as u64,
        domain_count: domains as u64,
        list_count: lists as u64,
        used_bytes: used,
    })
}

// ---- Domains (S-MAIL-03) --------------------------------------------------

#[server(ListMailDomains, "/api")]
pub async fn list_mail_domains() -> Result<Vec<MailDomain>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_mail_domains()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server(SaveMailDomain, "/api")]
pub async fn save_mail_domain(domain: MailDomain) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::mail::validate::check_domain;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    check_domain(&domain.name, domain.max_users).map_err(ServerFnError::new)?;
    let is_create = domain.id.is_empty();
    let state = expect_context::<AppState>();
    let saved = state
        .db
        .save_mail_domain(&domain)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_mail(
        &user,
        if is_create {
            ActionKind::Create
        } else {
            ActionKind::Update
        },
        "mail_domain",
        &saved.name,
    )
    .await;
    Ok(())
}

#[server(DeleteMailDomain, "/api")]
pub async fn delete_mail_domain(id: String, name: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Destroy).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_mail_domain(&id, &name)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_mail(&user, ActionKind::Delete, "mail_domain", &name).await;
    Ok(())
}

// ---- Users (S-MAIL-02) ----------------------------------------------------

#[server(ListMailUsers, "/api")]
pub async fn list_mail_users() -> Result<Vec<MailUser>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_mail_users()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server(CreateMailUser, "/api")]
pub async fn create_mail_user(
    local_part: String,
    domain: String,
    display_name: String,
    quota_mb: u64,
    password: String,
) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::mail::validate::{check_user, MSG_PASSWORD};
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    check_user(&local_part, &domain, Some(quota_mb)).map_err(ServerFnError::new)?;
    if password.trim().is_empty() {
        return Err(ServerFnError::new(MSG_PASSWORD));
    }
    let state = expect_context::<AppState>();
    let display = if display_name.trim().is_empty() {
        None
    } else {
        Some(display_name.as_str())
    };
    let created = state
        .db
        .create_mail_user(
            &local_part,
            &domain,
            display,
            quota_mb * 1_048_576,
            &password,
            &user.subject,
        )
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_mail(&user, ActionKind::Create, "mail_user", &created.email).await;
    Ok(())
}

#[server(ToggleMailUser, "/api")]
pub async fn toggle_mail_user(id: String, enabled: bool) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .set_mail_user_enabled(&id, enabled)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_mail(&user, ActionKind::Update, "mail_user", &id).await;
    Ok(())
}

#[server(ResetMailUserPassword, "/api")]
pub async fn reset_mail_user_password(id: String, password: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::mail::validate::MSG_PASSWORD;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    if password.trim().is_empty() {
        return Err(ServerFnError::new(MSG_PASSWORD));
    }
    let state = expect_context::<AppState>();
    state
        .db
        .set_mail_user_password(&id, &password)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_mail(&user, ActionKind::Update, "mail_user_password", &id).await;
    Ok(())
}

#[server(DeleteMailUser, "/api")]
pub async fn delete_mail_user(id: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Destroy).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_mail_user(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_mail(&user, ActionKind::Delete, "mail_user", &id).await;
    Ok(())
}

// ---- Aliases (S-MAIL-04) --------------------------------------------------

#[server(ListAliases, "/api")]
pub async fn list_aliases() -> Result<Vec<Alias>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_aliases()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server(SaveAlias, "/api")]
pub async fn save_alias(alias: Alias) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::mail::validate::check_alias;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    check_alias(&alias.source_address, &alias.destination_addresses).map_err(ServerFnError::new)?;
    let is_create = alias.id.is_empty();
    let source = alias.source_address.clone();
    let state = expect_context::<AppState>();
    state
        .db
        .save_alias(&alias)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_mail(
        &user,
        if is_create {
            ActionKind::Create
        } else {
            ActionKind::Update
        },
        "alias",
        &source,
    )
    .await;
    Ok(())
}

#[server(DeleteAlias, "/api")]
pub async fn delete_alias(id: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Destroy).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_alias(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_mail(&user, ActionKind::Delete, "alias", &id).await;
    Ok(())
}

// ---- Mailing lists (S-MAIL-05) --------------------------------------------

#[server(ListMailingLists, "/api")]
pub async fn list_mailing_lists() -> Result<Vec<MailingList>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_mailing_lists()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server(CreateMailingList, "/api")]
pub async fn create_mailing_list(
    address: String,
    domain: String,
    name: String,
    owner: String,
    reply_policy: String,
) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::mail::model::ReplyPolicy;
    use magnetite_core::domains::mail::validate::check_list;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    check_list(&address, &name, &owner).map_err(ServerFnError::new)?;
    let state = expect_context::<AppState>();
    let created = state
        .db
        .create_mailing_list(
            &address,
            &domain,
            &name,
            &owner,
            ReplyPolicy::from_str(&reply_policy),
            &user.subject,
        )
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_mail(&user, ActionKind::Create, "mailing_list", &created.address).await;
    Ok(())
}

#[server(DeleteMailingList, "/api")]
pub async fn delete_mailing_list(id: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Destroy).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_mailing_list(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_mail(&user, ActionKind::Delete, "mailing_list", &id).await;
    Ok(())
}

#[server(AddListMember, "/api")]
pub async fn add_list_member(
    id: String,
    email: String,
    name: String,
    receive: bool,
    can_post: bool,
) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::mail::model::MailingListMember;
    use magnetite_core::domains::mail::validate::{is_email, MSG_MEMBER_EMAIL};
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    if !is_email(&email) {
        return Err(ServerFnError::new(MSG_MEMBER_EMAIL));
    }
    let member = MailingListMember {
        email,
        name: if name.trim().is_empty() {
            None
        } else {
            Some(name)
        },
        receive,
        can_post,
    };
    let state = expect_context::<AppState>();
    state
        .db
        .add_list_member(&id, member)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_mail(&user, ActionKind::Update, "mailing_list_member", &id).await;
    Ok(())
}

#[server(RemoveListMember, "/api")]
pub async fn remove_list_member(id: String, email: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .remove_list_member(&id, &email)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_mail(&user, ActionKind::Update, "mailing_list_member", &id).await;
    Ok(())
}

// ---- Config (S-MAIL-06 / S-MAIL-07) ---------------------------------------

#[server(GetMailConfig, "/api")]
pub async fn get_mail_config() -> Result<MailServerConfig, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .get_mail_config()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server(SaveMailConfig, "/api")]
pub async fn save_mail_config(config: MailServerConfig) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::mail::validate::{check_protocols, check_server_config};
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    check_server_config(
        &config.hostname,
        config.max_message_size_bytes,
        config.acme_enabled,
        config.acme_email.as_deref(),
    )
    .map_err(ServerFnError::new)?;
    check_protocols(&config.protocols).map_err(ServerFnError::new)?;
    let state = expect_context::<AppState>();
    state
        .db
        .save_mail_config(&config)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_mail(&user, ActionKind::Control, "mail_config", "singleton").await;
    Ok(())
}

/// The outbound SMTP relay (smarthost) settings. The password is a secret and is
/// scrubbed before projection — the client sees whether one is set but never its
/// value.
#[server(GetMailRelay, "/api")]
pub async fn get_mail_relay() -> Result<MailRelayConfig, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    let mut relay = state
        .db
        .get_mail_relay()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .unwrap_or_default();
    // Never project the secret; keep a marker so the UI can show "設定済み".
    relay.password = if relay.password.as_deref().is_some_and(|p| !p.is_empty()) {
        Some(String::new())
    } else {
        None
    };
    Ok(relay)
}

/// Save the outbound relay settings. An empty submitted password preserves the stored
/// one (so editing other fields never wipes the secret); a non-empty value replaces it.
/// Applied without a restart (the mail server re-reads relay per connection).
#[server(SaveMailRelay, "/api")]
pub async fn save_mail_relay(config: MailRelayConfig) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    if config.enabled && config.host.trim().is_empty() {
        return Err(ServerFnError::new(
            "リレーを有効にするにはスマートホストのホスト名が必要です。".to_string(),
        ));
    }
    if config.enabled && config.port == 0 {
        return Err(ServerFnError::new(
            "ポート番号が不正です（1〜65535）。".to_string(),
        ));
    }
    let state = expect_context::<AppState>();
    let mut config = config;
    config.host = config.host.trim().to_string();
    config.username = config.username.filter(|u| !u.trim().is_empty());
    // Preserve the existing secret when the client submits an empty password.
    if config.password.as_deref().unwrap_or("").is_empty() {
        let existing = state
            .db
            .get_mail_relay()
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        config.password = existing.and_then(|r| r.password).filter(|p| !p.is_empty());
    }
    state
        .db
        .save_mail_relay(&config)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_mail(&user, ActionKind::Control, "mail_relay", "singleton").await;
    Ok(())
}

// ---- Mailbox (received messages, E4) --------------------------------------

/// List recently-received messages (metadata only; bodies are not projected).
/// Viewer and above.
#[server(ListMailMessages, "/api")]
pub async fn list_mail_messages() -> Result<Vec<MailMessage>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_mail_messages(None, 200)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Fetch a stored message's raw body (webmail read). Admin-only for privacy.
#[server(GetMailMessage, "/api")]
pub async fn get_mail_message(id: String) -> Result<String, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Admin).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .get_mail_message_raw(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| ServerFnError::new("メッセージが見つかりません。"))
}

// ---- DKIM (outbound signing) ----------------------------------------------

/// DKIM signing status for a domain, safe to send to clients. The `txt_record`
/// is the public value the operator publishes at `<selector>._domainkey.<domain>`;
/// the private key is never included.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DkimStatus {
    pub selector: String,
    pub enabled: bool,
    pub txt_record: String,
}

/// Current DKIM status for a domain (S-MAIL DKIM). `None` when no key exists.
#[server(GetDkim, "/api")]
pub async fn get_dkim(domain: String) -> Result<Option<DkimStatus>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    let stored = state
        .db
        .get_mail_dkim_any(&domain)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(stored.map(|(selector, enabled, pem)| DkimStatus {
        selector,
        enabled,
        txt_record: magnetite_mail::dkim_txt_from_private_pem(&pem).unwrap_or_default(),
    }))
}

/// Generate a fresh DKIM key for a domain and enable signing (S-MAIL DKIM).
/// Replaces any existing key. Returns the new public TXT record to publish.
#[server(GenerateDkim, "/api")]
pub async fn generate_dkim(domain: String, selector: String) -> Result<DkimStatus, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let domain = domain.trim().to_ascii_lowercase();
    let selector = selector.trim().to_string();
    if domain.is_empty() {
        return Err(ServerFnError::new("ドメインを選択してください。"));
    }
    if selector.is_empty()
        || !selector
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(ServerFnError::new(
            "セレクタは英数字とハイフンのみで入力してください。",
        ));
    }
    let material = magnetite_mail::generate_dkim_key()
        .ok_or_else(|| ServerFnError::new("鍵の生成に失敗しました。"))?;
    let state = expect_context::<AppState>();
    state
        .db
        .save_mail_dkim(&domain, &selector, &material.private_key_pem, true)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_mail(&user, ActionKind::Update, "mail_dkim", &domain).await;
    Ok(DkimStatus {
        selector,
        enabled: true,
        txt_record: material.txt_record,
    })
}

/// Enable or disable DKIM signing for a domain, preserving its key.
#[server(SetDkimEnabled, "/api")]
pub async fn set_dkim_enabled(domain: String, enabled: bool) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .set_mail_dkim_enabled(&domain, enabled)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_mail(&user, ActionKind::Update, "mail_dkim", &domain).await;
    Ok(())
}

// ---- Backup MX (secondary MX) + forwarding queue --------------------------

#[server(ListBackupMx, "/api")]
pub async fn list_backup_mx() -> Result<Vec<BackupMxDomain>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_backup_mx()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server(SaveBackupMx, "/api")]
pub async fn save_backup_mx(domain: BackupMxDomain) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    // Basic validation: a domain name and a primary host are required, and the
    // port must be non-zero.
    let name = domain.name.trim();
    let host = domain.primary_host.trim();
    if name.is_empty() || !name.contains('.') {
        return Err(ServerFnError::new("有効なドメイン名を入力してください。"));
    }
    if host.is_empty() {
        return Err(ServerFnError::new(
            "プライマリのホスト名を入力してください。",
        ));
    }
    if domain.primary_port == 0 {
        return Err(ServerFnError::new("ポート番号を指定してください。"));
    }
    let is_create = domain.id.is_empty();
    let state = expect_context::<AppState>();
    let saved = state
        .db
        .save_backup_mx(&domain)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_mail(
        &user,
        if is_create {
            ActionKind::Create
        } else {
            ActionKind::Update
        },
        "backup_mx",
        &saved.name,
    )
    .await;
    Ok(())
}

#[server(DeleteBackupMx, "/api")]
pub async fn delete_backup_mx(id: String, name: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Destroy).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_backup_mx(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_mail(&user, ActionKind::Delete, "backup_mx", &name).await;
    Ok(())
}

/// The current backup-MX forwarding queue (projection-safe metadata only).
#[server(ListBackupQueue, "/api")]
pub async fn list_backup_queue() -> Result<Vec<MailQueueEntry>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_backup_queue(500)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Drop a stuck message from the forwarding queue (manual intervention).
#[server(DeleteBackupQueue, "/api")]
pub async fn delete_backup_queue(id: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Destroy).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_backup_queue(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_mail(&user, ActionKind::Delete, "mail_queue", &id).await;
    Ok(())
}

// ---- Mailbox replication status (Step 2 HA) -------------------------------

/// Mailbox replication status: this instance's configured role plus the persisted
/// sync state. The shared secret is never included.
#[server(GetMailReplStatus, "/api")]
pub async fn get_mail_repl_status() -> Result<MailReplStatus, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domain::DomainKey;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    let cfg = state
        .config
        .domains
        .get(&DomainKey::Mail)
        .and_then(|d| d.server.as_ref())
        .and_then(|s| s.replication.as_ref());
    let (configured, enabled, is_secondary, primary_url, interval_secs) = match cfg {
        Some(r) => (
            true,
            r.enabled,
            r.is_secondary(),
            r.primary_url.clone(),
            r.interval(),
        ),
        None => (false, false, false, None, 30),
    };
    let repl_state = state
        .db
        .get_mail_repl_state()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(MailReplStatus {
        configured,
        enabled,
        is_secondary,
        primary_url,
        interval_secs,
        state: repl_state,
    })
}
