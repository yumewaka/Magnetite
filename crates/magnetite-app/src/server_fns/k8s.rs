//! K8s (container) domain server functions (F-16 / S-K8S-01..04, 06).
//! Authorized (08_authz), validated (screen_k8s §5), audited (F-04).

use crate::types::K8sMetrics;
use leptos::prelude::*;
use magnetite_core::domains::k8s::model::{AlertRule, Cluster, Host, K8sTemplate, K8sWorkloads};

#[cfg(feature = "ssr")]
async fn audit_k8s(
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
            domain: magnetite_core::domain::DomainKey::K8s,
            action,
            target_kind: target_kind.to_string(),
            target_id: target_id.to_string(),
            result: magnetite_core::models::common::OpResult::Success,
            ip: client_ip().await,
            detail: None,
        })
        .await;
}

#[server(GetK8sMetrics, "/api")]
pub async fn get_k8s_metrics() -> Result<K8sMetrics, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    let (clusters, hosts, rules) = state
        .db
        .k8s_metrics()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(K8sMetrics {
        cluster_count: clusters as u64,
        host_count: hosts as u64,
        rule_count: rules as u64,
    })
}

// ---- Hosts (S-K8S-02) -----------------------------------------------------

#[server(ListK8sHosts, "/api")]
pub async fn list_k8s_hosts() -> Result<Vec<Host>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_k8s_hosts()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server(CreateK8sHost, "/api")]
pub async fn create_k8s_host(
    hostname: String,
    address: String,
    ssh_port: u16,
    ssh_user: String,
    auth_method: String,
    credential: String,
) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::k8s::model::HostAuthMethod;
    use magnetite_core::domains::k8s::validate::check_host;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    check_host(&hostname, &address, ssh_port, &credential).map_err(ServerFnError::new)?;
    let method = if auth_method == "key" {
        HostAuthMethod::Key
    } else {
        HostAuthMethod::Password
    };
    let state = expect_context::<AppState>();
    let created = state
        .db
        .create_k8s_host(
            &hostname,
            &address,
            ssh_port,
            &ssh_user,
            method,
            &credential,
            &user.subject,
        )
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_k8s(&user, ActionKind::Create, "k8s_host", &created.hostname).await;
    Ok(())
}

#[server(DeleteK8sHost, "/api")]
pub async fn delete_k8s_host(id: String, hostname: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Destroy).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_k8s_host(&id, &hostname)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_k8s(&user, ActionKind::Delete, "k8s_host", &hostname).await;
    Ok(())
}

// ---- Clusters (S-K8S-03) --------------------------------------------------

#[server(ListK8sClusters, "/api")]
pub async fn list_k8s_clusters() -> Result<Vec<Cluster>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_k8s_clusters()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server(CreateK8sCluster, "/api")]
pub async fn create_k8s_cluster(
    name: String,
    k8s_version: String,
    pod_cidr: String,
    service_cidr: String,
    cni: String,
    member_hostnames: Vec<String>,
) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::k8s::validate::check_cluster;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    check_cluster(&name, &pod_cidr, &service_cidr).map_err(ServerFnError::new)?;
    let state = expect_context::<AppState>();
    let created = state
        .db
        .create_k8s_cluster(
            &name,
            &k8s_version,
            &pod_cidr,
            &service_cidr,
            &cni,
            &member_hostnames,
            &user.subject,
        )
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_k8s(&user, ActionKind::Create, "k8s_cluster", &created.name).await;
    Ok(())
}

#[server(DeleteK8sCluster, "/api")]
pub async fn delete_k8s_cluster(id: String, name: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Destroy).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_k8s_cluster(&id, &name)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_k8s(&user, ActionKind::Delete, "k8s_cluster", &name).await;
    Ok(())
}

// ---- Alert rules (S-K8S-04) -----------------------------------------------

#[server(ListK8sAlertRules, "/api")]
pub async fn list_k8s_alert_rules() -> Result<Vec<AlertRule>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_k8s_alert_rules()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server(SaveK8sAlertRule, "/api")]
pub async fn save_k8s_alert_rule(rule: AlertRule) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::k8s::validate::check_alert_rule;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    check_alert_rule(&rule.name, rule.condition, rule.threshold).map_err(ServerFnError::new)?;
    let is_create = rule.id.is_empty();
    let state = expect_context::<AppState>();
    let saved = state
        .db
        .save_k8s_alert_rule(&rule)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_k8s(
        &user,
        if is_create {
            ActionKind::Create
        } else {
            ActionKind::Update
        },
        "k8s_alert_rule",
        &saved.name,
    )
    .await;
    Ok(())
}

#[server(ToggleK8sRule, "/api")]
pub async fn toggle_k8s_rule(id: String, enabled: bool) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .set_k8s_rule_enabled(&id, enabled)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_k8s(&user, ActionKind::Update, "k8s_alert_rule", &id).await;
    Ok(())
}

#[server(DeleteK8sAlertRule, "/api")]
pub async fn delete_k8s_alert_rule(id: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Destroy).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_k8s_alert_rule(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_k8s(&user, ActionKind::Delete, "k8s_alert_rule", &id).await;
    Ok(())
}

// ---- Templates (S-K8S-06) -------------------------------------------------

#[server(ListK8sTemplates, "/api")]
pub async fn list_k8s_templates() -> Result<Vec<K8sTemplate>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_k8s_templates()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

#[server(SaveK8sTemplate, "/api")]
pub async fn save_k8s_template(template: K8sTemplate) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::k8s::validate::check_template;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    check_template(&template.name, &template.manifest_yaml).map_err(ServerFnError::new)?;
    let is_create = template.id.is_empty();
    let state = expect_context::<AppState>();
    let saved = state
        .db
        .save_k8s_template(&template)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_k8s(
        &user,
        if is_create {
            ActionKind::Create
        } else {
            ActionKind::Update
        },
        "k8s_template",
        &saved.name,
    )
    .await;
    Ok(())
}

#[server(DeleteK8sTemplate, "/api")]
pub async fn delete_k8s_template(id: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Destroy).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_k8s_template(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_k8s(&user, ActionKind::Delete, "k8s_template", &id).await;
    Ok(())
}

// ---- Live cluster client (kube API) ---------------------------------------

/// Set (or update) a cluster's kube-API connection: its API-server endpoint and,
/// optionally, a bearer token. An empty `token` keeps the stored one (so the endpoint
/// can be edited without re-entering it). The token is never returned to the browser.
#[server(SetClusterApi, "/api")]
pub async fn set_cluster_api(
    id: String,
    endpoint: String,
    token: String,
) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let endpoint = endpoint.trim().to_string();
    if !(endpoint.starts_with("https://") || endpoint.starts_with("http://")) {
        return Err(ServerFnError::new(
            "API サーバの URL は http(s):// で始めてください。",
        ));
    }
    let state = expect_context::<AppState>();
    let token = token.trim();
    state
        .db
        .set_cluster_api(&id, &endpoint, (!token.is_empty()).then_some(token))
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_k8s(&user, ActionKind::Update, "k8s_cluster_api", &id).await;
    Ok(())
}

/// List the live Deployments / Services / Pods of a cluster by querying its kube API
/// server (requires the cluster's endpoint + token to be configured).
#[server(ListClusterWorkloads, "/api")]
pub async fn list_cluster_workloads(
    cluster_id: String,
    namespace: String,
) -> Result<K8sWorkloads, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    let (endpoint, token) = state
        .db
        .cluster_api_config(&cluster_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| {
            ServerFnError::new(
                "このクラスタには API 接続（エンドポイント + トークン）が設定されていません。",
            )
        })?;
    let client = magnetite_k8s::KubeClient::new(&endpoint, &token);
    client
        .workloads(namespace.trim())
        .await
        .map_err(|e| ServerFnError::new(format!("クラスタへの接続に失敗しました: {e:#}")))
}

/// Fetch the last lines of a pod's log from the cluster's kube API server.
#[server(GetPodLogs, "/api")]
pub async fn get_pod_logs(
    cluster_id: String,
    namespace: String,
    pod: String,
    tail_lines: u32,
) -> Result<String, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    let (endpoint, token) = state
        .db
        .cluster_api_config(&cluster_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| ServerFnError::new("このクラスタには API 接続が設定されていません。"))?;
    let client = magnetite_k8s::KubeClient::new(&endpoint, &token);
    client
        .pod_logs(namespace.trim(), pod.trim(), tail_lines.min(2000))
        .await
        .map_err(|e| ServerFnError::new(format!("ログの取得に失敗しました: {e:#}")))
}
