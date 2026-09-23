//! Proxy domain server functions (F-15 / S-PROXY-01..05). Authorized (08_authz),
//! validated (screen_proxy §5), audited (F-04).

use crate::types::ProxyMetrics;
use leptos::prelude::*;
use magnetite_core::domains::proxy::model::{
    AclRule, Certificate, ForwardRule, ForwardUser, IpBlock, VirtualHost,
};

#[cfg(feature = "ssr")]
async fn audit_proxy(
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
            domain: magnetite_core::domain::DomainKey::Proxy,
            action,
            target_kind: target_kind.to_string(),
            target_id: target_id.to_string(),
            result: magnetite_core::models::common::OpResult::Success,
            ip: client_ip().await,
            detail: None,
        })
        .await;
}

#[server(GetProxyMetrics, "/api")]
pub async fn get_proxy_metrics() -> Result<ProxyMetrics, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    let (vhosts, certs, acls) = state
        .db
        .proxy_metrics()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(ProxyMetrics {
        vhost_count: vhosts as u64,
        cert_count: certs as u64,
        acl_count: acls as u64,
    })
}

// ---- Virtual hosts (S-PROXY-02) -------------------------------------------

#[server(ListVhosts, "/api")]
pub async fn list_vhosts() -> Result<Vec<VirtualHost>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_vhosts()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server(SaveVhost, "/api")]
pub async fn save_vhost(vhost: VirtualHost) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::proxy::validate::check_vhost;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    check_vhost(
        &vhost.hostname,
        vhost.listen_port,
        vhost.tls_enabled,
        vhost.certificate_ref.as_deref(),
    )
    .map_err(ServerFnError::new)?;
    let is_create = vhost.id.is_empty();
    let state = expect_context::<AppState>();
    let saved = state
        .db
        .save_vhost(&vhost)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_proxy(
        &user,
        if is_create {
            ActionKind::Create
        } else {
            ActionKind::Update
        },
        "vhost",
        &saved.hostname,
    )
    .await;
    Ok(())
}

#[server(ToggleVhost, "/api")]
pub async fn toggle_vhost(id: String, enabled: bool) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .set_vhost_enabled(&id, enabled)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_proxy(&user, ActionKind::Update, "vhost", &id).await;
    Ok(())
}

#[server(DeleteVhost, "/api")]
pub async fn delete_vhost(id: String, hostname: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Destroy).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_vhost(&id, &hostname)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_proxy(&user, ActionKind::Delete, "vhost", &hostname).await;
    Ok(())
}

// ---- Certificates (S-PROXY-03) --------------------------------------------

#[server(ListCertificates, "/api")]
pub async fn list_certificates() -> Result<Vec<Certificate>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_certificates()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

// The certificate's fields map one-to-one to the create-certificate form.
#[allow(clippy::too_many_arguments)]
#[server(CreateCertificate, "/api")]
pub async fn create_certificate(
    name: String,
    subject: String,
    issuer: String,
    san: String,
    not_after: String,
    cert_pem: String,
    key_pem: String,
    chain_pem: String,
) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::proxy::validate::check_certificate;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    check_certificate(&name, &cert_pem, &chain_pem).map_err(ServerFnError::new)?;
    let not_after_dt = chrono::NaiveDate::parse_from_str(not_after.trim(), "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(23, 59, 59))
        .map(|dt| dt.and_utc())
        .ok_or_else(|| ServerFnError::new("有効期限を正しく入力してください。"))?;
    let san_list: Vec<String> = san
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let chain = if chain_pem.trim().is_empty() {
        None
    } else {
        Some(chain_pem.as_str())
    };
    let key = if key_pem.trim().is_empty() {
        None
    } else {
        Some(key_pem.as_str())
    };
    let state = expect_context::<AppState>();
    let created = state
        .db
        .create_certificate(
            &name,
            &subject,
            &issuer,
            &san_list,
            chrono::Utc::now(),
            not_after_dt,
            &cert_pem,
            chain,
            key,
            &user.subject,
        )
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_proxy(&user, ActionKind::Create, "certificate", &created.name).await;
    Ok(())
}

#[server(DeleteCertificate, "/api")]
pub async fn delete_certificate(id: String, name: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Destroy).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_certificate(&id, &name)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_proxy(&user, ActionKind::Delete, "certificate", &name).await;
    Ok(())
}

// ---- ACL rules (S-PROXY-04) -----------------------------------------------

#[server(ListAclRules, "/api")]
pub async fn list_acl_rules() -> Result<Vec<AclRule>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_acl_rules()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server(SaveAclRule, "/api")]
pub async fn save_acl_rule(rule: AclRule) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::proxy::model::AclScope;
    use magnetite_core::domains::proxy::validate::check_acl;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    check_acl(
        &rule.cidr,
        rule.scope == AclScope::Vhost,
        rule.vhost_ref.as_deref(),
    )
    .map_err(ServerFnError::new)?;
    let is_create = rule.id.is_empty();
    let state = expect_context::<AppState>();
    let saved = state
        .db
        .save_acl_rule(&rule)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_proxy(
        &user,
        if is_create {
            ActionKind::Create
        } else {
            ActionKind::Update
        },
        "acl_rule",
        &saved.id,
    )
    .await;
    Ok(())
}

#[server(SetAclPriority, "/api")]
pub async fn set_acl_priority(id: String, priority: i32) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .set_acl_priority(&id, priority)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_proxy(&user, ActionKind::Update, "acl_rule", &id).await;
    Ok(())
}

#[server(ToggleAcl, "/api")]
pub async fn toggle_acl(id: String, enabled: bool) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .set_acl_enabled(&id, enabled)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_proxy(&user, ActionKind::Update, "acl_rule", &id).await;
    Ok(())
}

#[server(DeleteAclRule, "/api")]
pub async fn delete_acl_rule(id: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Destroy).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_acl_rule(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_proxy(&user, ActionKind::Delete, "acl_rule", &id).await;
    Ok(())
}

// ---- IP blocks (S-PROXY-05) -----------------------------------------------

#[server(ListIpBlocks, "/api")]
pub async fn list_ip_blocks() -> Result<Vec<IpBlock>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_ip_blocks()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server(SaveIpBlock, "/api")]
pub async fn save_ip_block(block: IpBlock) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::proxy::validate::check_ip_block;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    check_ip_block(&block.cidr).map_err(ServerFnError::new)?;
    let is_create = block.id.is_empty();
    let state = expect_context::<AppState>();
    let saved = state
        .db
        .save_ip_block(&block)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_proxy(
        &user,
        if is_create {
            ActionKind::Create
        } else {
            ActionKind::Update
        },
        "ip_block",
        &saved.id,
    )
    .await;
    Ok(())
}

#[server(SetIpBlockOrder, "/api")]
pub async fn set_ip_block_order(id: String, order: i32) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .set_ip_block_order(&id, order)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_proxy(&user, ActionKind::Update, "ip_block", &id).await;
    Ok(())
}

#[server(ToggleIpBlock, "/api")]
pub async fn toggle_ip_block(id: String, enabled: bool) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .set_ip_block_enabled(&id, enabled)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_proxy(&user, ActionKind::Update, "ip_block", &id).await;
    Ok(())
}

#[server(DeleteIpBlock, "/api")]
pub async fn delete_ip_block(id: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Destroy).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_ip_block(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_proxy(&user, ActionKind::Delete, "ip_block", &id).await;
    Ok(())
}

// ---- Forward proxy: access rules + client users ---------------------------

#[server(ListForwardRules, "/api")]
pub async fn list_forward_rules() -> Result<Vec<ForwardRule>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_forward_rules()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server(SaveForwardRule, "/api")]
pub async fn save_forward_rule(rule: ForwardRule) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::proxy::model::ForwardRuleKind;
    use magnetite_core::domains::proxy::validate::check_forward_rule;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    check_forward_rule(rule.kind == ForwardRuleKind::Source, &rule.matcher)
        .map_err(ServerFnError::new)?;
    let is_create = rule.id.is_empty();
    let state = expect_context::<AppState>();
    let saved = state
        .db
        .save_forward_rule(&rule)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_proxy(
        &user,
        if is_create {
            ActionKind::Create
        } else {
            ActionKind::Update
        },
        "forward_rule",
        &saved.id,
    )
    .await;
    Ok(())
}

#[server(ToggleForwardRule, "/api")]
pub async fn toggle_forward_rule(id: String, enabled: bool) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .set_forward_rule_enabled(&id, enabled)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_proxy(&user, ActionKind::Update, "forward_rule", &id).await;
    Ok(())
}

#[server(DeleteForwardRule, "/api")]
pub async fn delete_forward_rule(id: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Destroy).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_forward_rule(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_proxy(&user, ActionKind::Delete, "forward_rule", &id).await;
    Ok(())
}

#[server(ListForwardUsers, "/api")]
pub async fn list_forward_users() -> Result<Vec<ForwardUser>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_forward_users()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server(CreateForwardUser, "/api")]
pub async fn create_forward_user(
    username: String,
    password: String,
    description: String,
) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let username = username.trim().to_string();
    if username.is_empty() {
        return Err(ServerFnError::new("ユーザ名を入力してください。"));
    }
    if password.is_empty() {
        return Err(ServerFnError::new("パスワードを入力してください。"));
    }
    let description = description.trim();
    let state = expect_context::<AppState>();
    let created = state
        .db
        .create_forward_user(
            &username,
            &password,
            (!description.is_empty()).then_some(description),
            &user.subject,
        )
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_proxy(&user, ActionKind::Create, "forward_user", &created.id).await;
    Ok(())
}

#[server(ToggleForwardUser, "/api")]
pub async fn toggle_forward_user(id: String, enabled: bool) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .set_forward_user_enabled(&id, enabled)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_proxy(&user, ActionKind::Update, "forward_user", &id).await;
    Ok(())
}

#[server(DeleteForwardUser, "/api")]
pub async fn delete_forward_user(id: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Destroy).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_forward_user(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_proxy(&user, ActionKind::Delete, "forward_user", &id).await;
    Ok(())
}

// ---- Health (S-PROXY-07) --------------------------------------------------

/// Live status of the embedded reverse proxy plus a config summary.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProxyHealth {
    /// "healthy" | "warning" | "error" | "unknown" (unknown ⇒ not running).
    pub health: String,
    pub vhosts: usize,
    pub enabled_vhosts: usize,
    pub upstreams: usize,
    pub active_blocks: usize,
}

/// Report the proxy server's health and a summary of its routing config.
#[server(GetProxyHealth, "/api")]
pub async fn get_proxy_health() -> Result<ProxyHealth, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domain::DomainKey;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    let vhosts = state
        .db
        .list_vhosts()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let blocks = state
        .db
        .list_ip_blocks()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(ProxyHealth {
        health: state.services.health(DomainKey::Proxy).as_str().to_string(),
        vhosts: vhosts.len(),
        enabled_vhosts: vhosts.iter().filter(|v| v.enabled).count(),
        upstreams: vhosts.iter().map(|v| v.upstream.len()).sum(),
        active_blocks: blocks.iter().filter(|b| b.enabled).count(),
    })
}

// ---- ACME settings (DB-backed, hot-reloaded — no restart) ------------------

/// The current ACME settings (for the Web UI). Defaults (disabled) when never configured.
#[server(GetAcmeConfig, "/api")]
pub async fn get_acme_config() -> Result<magnetite_core::config::AcmeConfig, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    Ok(state
        .db
        .get_acme_config()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .unwrap_or_default())
}

/// Save the ACME settings. Applied WITHOUT a restart — the ACME manager re-reads them on
/// its next poll (~1 min) and re-issues the shared certificate when the domain set changed.
#[server(SaveAcmeConfig, "/api")]
pub async fn save_acme_config(
    config: magnetite_core::config::AcmeConfig,
) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let mut config = config;
    // Normalise the domain list: trim, lowercase, drop blanks, dedup (order preserved — the
    // first is the certificate subject CN).
    let mut seen = std::collections::HashSet::new();
    config.domains = config
        .domains
        .into_iter()
        .map(|d| d.trim().to_ascii_lowercase())
        .filter(|d| !d.is_empty() && seen.insert(d.clone()))
        .collect();
    if config.enabled && config.domains.is_empty() {
        return Err(ServerFnError::new(
            "ACME を有効にするには少なくとも1つのドメインが必要です。".to_string(),
        ));
    }
    config.contact_email = config
        .contact_email
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty());
    config.directory_url = config
        .directory_url
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty());
    config.certificate_name = config
        .certificate_name
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty());

    let state = expect_context::<AppState>();
    state
        .db
        .save_acme_config(&config)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_proxy(&user, ActionKind::Control, "acme_config", "singleton").await;
    Ok(())
}
