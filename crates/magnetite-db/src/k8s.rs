//! K8s (container) domain repository (07_data_k8s / screen_k8s): hosts,
//! clusters, alert rules and manifest templates. Backup uses the cross-cutting
//! S-Backup mechanism (added later).

use crate::error::{DbError, DbResult};
use crate::records::{parse_rfc3339, record_key, to_rfc3339};
use crate::store::Db;
use chrono::Utc;
use magnetite_core::domains::k8s::model::{
    AlertConditionKind, AlertRule, AlertTargetKind, Cluster, ClusterNode, ClusterState, Comparator,
    Host, HostAuthMethod, HostRole, HostState, K8sResourceKind, K8sTemplate,
};
use magnetite_core::models::common::Severity;
use serde::{Deserialize, Serialize};
use surrealdb::types::{RecordId, SurrealValue};

const MSG_HOST_DUP: &str = "同じホスト名が既に存在します。";
const MSG_HOST_IN_CLUSTER: &str = "他の設定から参照されているため削除できません。";

fn host_state_from(s: &str) -> HostState {
    match s {
        "ready" => HostState::Ready,
        "online" => HostState::Online,
        "error" => HostState::Error,
        _ => HostState::Offline,
    }
}
fn role_str(r: HostRole) -> &'static str {
    match r {
        HostRole::ControlPlane => "control_plane",
        HostRole::Worker => "worker",
    }
}
fn role_from(s: &str) -> HostRole {
    if s == "control_plane" {
        HostRole::ControlPlane
    } else {
        HostRole::Worker
    }
}
fn severity_str(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::Warning => "warning",
        Severity::Info => "info",
    }
}
fn severity_from(s: &str) -> Severity {
    match s {
        "critical" => Severity::Critical,
        "info" => Severity::Info,
        _ => Severity::Warning,
    }
}

// ---- Records --------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct HostRecord {
    id: Option<RecordId>,
    hostname: String,
    address: String,
    ssh_port: u16,
    ssh_user: String,
    auth_method: String,
    credential: String,
    role: Option<String>,
    cluster_ref: Option<String>,
    state: String,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl HostRecord {
    fn into_model(self) -> Host {
        Host {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            hostname: self.hostname,
            address: self.address,
            ssh_port: self.ssh_port,
            ssh_user: self.ssh_user,
            auth_method: if self.auth_method == "key" {
                HostAuthMethod::Key
            } else {
                HostAuthMethod::Password
            },
            role: self.role.as_deref().map(role_from),
            cluster_ref: self.cluster_ref,
            state: host_state_from(&self.state),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct ClusterRecord {
    id: Option<RecordId>,
    name: String,
    k8s_version: String,
    api_server_endpoint: Option<String>,
    /// Bearer token for the cluster's kube API (write-only; never projected). Absent
    /// on clusters created before the live-client fields existed.
    #[serde(default)]
    api_token: Option<String>,
    pod_cidr: String,
    service_cidr: String,
    cni: String,
    /// JSON-encoded `Vec<ClusterNode>`.
    nodes: String,
    node_count: u64,
    state: String,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl ClusterRecord {
    fn into_model(self) -> Cluster {
        Cluster {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            name: self.name,
            k8s_version: self.k8s_version,
            api_server_endpoint: self.api_server_endpoint,
            pod_cidr: self.pod_cidr,
            service_cidr: self.service_cidr,
            cni: self.cni,
            nodes: serde_json::from_str(&self.nodes).unwrap_or_default(),
            node_count: self.node_count,
            state: match self.state.as_str() {
                "ready" => ClusterState::Ready,
                "failed" => ClusterState::Failed,
                _ => ClusterState::Error,
            },
            api_token_set: self
                .api_token
                .as_deref()
                .map(|t| !t.is_empty())
                .unwrap_or(false),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct RuleRecord {
    id: Option<RecordId>,
    name: String,
    target_ref: String,
    target_kind: String,
    condition: String,
    comparator: String,
    threshold: f64,
    severity: String,
    enabled: bool,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl RuleRecord {
    fn into_model(self) -> AlertRule {
        AlertRule {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            name: self.name,
            target_ref: self.target_ref,
            target_kind: if self.target_kind == "host" {
                AlertTargetKind::Host
            } else {
                AlertTargetKind::Cluster
            },
            condition: AlertConditionKind::from_str(&self.condition),
            comparator: Comparator::from_str(&self.comparator),
            threshold: self.threshold,
            severity: severity_from(&self.severity),
            enabled: self.enabled,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct TemplateRecord {
    id: Option<RecordId>,
    name: String,
    description: Option<String>,
    resource_kind: String,
    manifest_yaml: String,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl TemplateRecord {
    fn into_model(self) -> K8sTemplate {
        K8sTemplate {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            name: self.name,
            description: self.description,
            resource_kind: K8sResourceKind::from_str(&self.resource_kind),
            manifest_yaml: self.manifest_yaml,
        }
    }
}

impl Db {
    // ---- Hosts ------------------------------------------------------------

    pub async fn list_k8s_hosts(&self) -> DbResult<Vec<Host>> {
        let recs: Vec<HostRecord> = self
            .inner
            .query("SELECT * FROM k8s_host ORDER BY hostname ASC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(HostRecord::into_model).collect())
    }

    async fn find_host(&self, hostname: &str) -> DbResult<Option<HostRecord>> {
        let recs: Vec<HostRecord> = self
            .inner
            .query("SELECT * FROM k8s_host WHERE hostname = $h LIMIT 1")
            .bind(("h", hostname.to_string()))
            .await?
            .take(0)?;
        Ok(recs.into_iter().next())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_k8s_host(
        &self,
        hostname: &str,
        address: &str,
        ssh_port: u16,
        ssh_user: &str,
        auth_method: HostAuthMethod,
        credential: &str,
        actor: &str,
    ) -> DbResult<Host> {
        if self.find_host(hostname).await?.is_some() {
            return Err(DbError::Constraint(MSG_HOST_DUP.into()));
        }
        let now = to_rfc3339(Utc::now());
        let rec = HostRecord {
            id: None,
            hostname: hostname.to_string(),
            address: address.to_string(),
            ssh_port,
            ssh_user: ssh_user.to_string(),
            auth_method: match auth_method {
                HostAuthMethod::Key => "key".into(),
                HostAuthMethod::Password => "password".into(),
            },
            credential: credential.to_string(),
            role: None,
            cluster_ref: None,
            state: "offline".into(),
            created_at: now.clone(),
            updated_at: now,
            created_by: actor.to_string(),
        };
        let created: Option<HostRecord> = self.inner.create("k8s_host").content(rec).await?;
        created
            .map(HostRecord::into_model)
            .ok_or_else(|| DbError::Constraint("host creation failed".into()))
    }

    /// Delete a host. Refused when it is part of a cluster (E-K8S-02).
    pub async fn delete_k8s_host(&self, id: &str, hostname: &str) -> DbResult<()> {
        if let Some(host) = self.find_host(hostname).await? {
            if host.cluster_ref.is_some() {
                return Err(DbError::Constraint(MSG_HOST_IN_CLUSTER.into()));
            }
        }
        let _: Option<HostRecord> = self.inner.delete(("k8s_host", id)).await?;
        Ok(())
    }

    async fn set_host_cluster(
        &self,
        hostname: &str,
        cluster: Option<&str>,
        role: Option<HostRole>,
    ) -> DbResult<()> {
        self.inner
            .query("UPDATE k8s_host SET cluster_ref = $c, role = $r, updated_at = $t WHERE hostname = $h")
            .bind(("c", cluster.map(|s| s.to_string())))
            .bind(("r", role.map(|r| role_str(r).to_string())))
            .bind(("t", to_rfc3339(Utc::now())))
            .bind(("h", hostname.to_string()))
            .await?;
        Ok(())
    }

    // ---- Clusters ---------------------------------------------------------

    pub async fn list_k8s_clusters(&self) -> DbResult<Vec<Cluster>> {
        let recs: Vec<ClusterRecord> = self
            .inner
            .query("SELECT * FROM k8s_cluster ORDER BY name ASC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(ClusterRecord::into_model).collect())
    }

    /// Create a cluster from a set of member host hostnames (first = control
    /// plane). Assigns each host's `cluster_ref`/`role`.
    // The cluster's defining fields (name, versions, CIDRs, CNI, members) are all
    // required at creation; a params struct would only add ceremony.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_k8s_cluster(
        &self,
        name: &str,
        k8s_version: &str,
        pod_cidr: &str,
        service_cidr: &str,
        cni: &str,
        member_hostnames: &[String],
        actor: &str,
    ) -> DbResult<Cluster> {
        let mut nodes = Vec::new();
        for (i, hostname) in member_hostnames.iter().enumerate() {
            if let Some(host) = self.find_host(hostname).await? {
                let role = if i == 0 {
                    HostRole::ControlPlane
                } else {
                    HostRole::Worker
                };
                nodes.push(ClusterNode {
                    host_ref: host.hostname.clone(),
                    hostname: host.hostname.clone(),
                    address: host.address.clone(),
                    role,
                    state: host_state_from(&host.state),
                });
                self.set_host_cluster(&host.hostname, Some(name), Some(role))
                    .await?;
            }
        }
        let now = to_rfc3339(Utc::now());
        let rec = ClusterRecord {
            id: None,
            name: name.to_string(),
            k8s_version: k8s_version.to_string(),
            api_server_endpoint: None,
            api_token: None,
            pod_cidr: pod_cidr.to_string(),
            service_cidr: service_cidr.to_string(),
            cni: cni.to_string(),
            nodes: serde_json::to_string(&nodes).unwrap_or_else(|_| "[]".into()),
            node_count: nodes.len() as u64,
            state: "ready".into(),
            created_at: now.clone(),
            updated_at: now,
            created_by: actor.to_string(),
        };
        let created: Option<ClusterRecord> = self.inner.create("k8s_cluster").content(rec).await?;
        created
            .map(ClusterRecord::into_model)
            .ok_or_else(|| DbError::Constraint("cluster creation failed".into()))
    }

    /// Delete a cluster, releasing its member hosts' cluster references.
    pub async fn delete_k8s_cluster(&self, id: &str, name: &str) -> DbResult<()> {
        let hosts = self.list_k8s_hosts().await?;
        for host in hosts
            .into_iter()
            .filter(|h| h.cluster_ref.as_deref() == Some(name))
        {
            self.set_host_cluster(&host.hostname, None, None).await?;
        }
        let _: Option<ClusterRecord> = self.inner.delete(("k8s_cluster", id)).await?;
        Ok(())
    }

    /// Set a cluster's kube-API connection: its `api_server_endpoint` and, when
    /// `token` is `Some(non-empty)`, its bearer token. Passing `None`/empty leaves the
    /// stored token unchanged (so the endpoint can be edited without re-entering it).
    ///
    /// # Errors
    /// A store error, or [`DbError::NotFound`] if the cluster id is gone.
    pub async fn set_cluster_api(
        &self,
        id: &str,
        endpoint: &str,
        token: Option<&str>,
    ) -> DbResult<()> {
        let now = to_rfc3339(Utc::now());
        let endpoint = endpoint.trim().to_string();
        let set_token = token.map(str::trim).filter(|t| !t.is_empty());
        let updated: Vec<ClusterRecord> = if let Some(tok) = set_token {
            self.inner
                .query("UPDATE type::record('k8s_cluster', $id) SET api_server_endpoint = $e, api_token = $tok, updated_at = $t")
                .bind(("id", id.to_string()))
                .bind(("e", endpoint))
                .bind(("tok", tok.to_string()))
                .bind(("t", now))
                .await?
                .take(0)?
        } else {
            self.inner
                .query("UPDATE type::record('k8s_cluster', $id) SET api_server_endpoint = $e, updated_at = $t")
                .bind(("id", id.to_string()))
                .bind(("e", endpoint))
                .bind(("t", now))
                .await?
                .take(0)?
        };
        if updated.is_empty() {
            return Err(DbError::NotFound);
        }
        Ok(())
    }

    /// The cluster's `(api_server_endpoint, api_token)` if both are set — the material
    /// the live kube client needs. `None` when the cluster is not connectable. The
    /// token is returned only for server-side use (never projected to the browser).
    ///
    /// # Errors
    /// A store error.
    pub async fn cluster_api_config(&self, id: &str) -> DbResult<Option<(String, String)>> {
        let recs: Vec<ClusterRecord> = self
            .inner
            .query("SELECT * FROM type::record('k8s_cluster', $id)")
            .bind(("id", id.to_string()))
            .await?
            .take(0)?;
        let Some(rec) = recs.into_iter().next() else {
            return Ok(None);
        };
        match (
            rec.api_server_endpoint.filter(|e| !e.trim().is_empty()),
            rec.api_token.filter(|t| !t.trim().is_empty()),
        ) {
            (Some(endpoint), Some(token)) => Ok(Some((endpoint, token))),
            _ => Ok(None),
        }
    }

    // ---- Alert rules ------------------------------------------------------

    pub async fn list_k8s_alert_rules(&self) -> DbResult<Vec<AlertRule>> {
        let recs: Vec<RuleRecord> = self
            .inner
            .query("SELECT * FROM k8s_alert_rule ORDER BY name ASC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(RuleRecord::into_model).collect())
    }

    pub async fn save_k8s_alert_rule(&self, rule: &AlertRule) -> DbResult<AlertRule> {
        let now = to_rfc3339(Utc::now());
        let target_kind = match rule.target_kind {
            AlertTargetKind::Host => "host",
            AlertTargetKind::Cluster => "cluster",
        };
        if rule.id.is_empty() {
            let rec = RuleRecord {
                id: None,
                name: rule.name.clone(),
                target_ref: rule.target_ref.clone(),
                target_kind: target_kind.to_string(),
                condition: rule.condition.as_str().to_string(),
                comparator: rule.comparator.as_str().to_string(),
                threshold: rule.threshold,
                severity: severity_str(rule.severity).to_string(),
                enabled: rule.enabled,
                created_at: now.clone(),
                updated_at: now,
                created_by: rule.created_by.clone(),
            };
            let created: Option<RuleRecord> =
                self.inner.create("k8s_alert_rule").content(rec).await?;
            created
                .map(RuleRecord::into_model)
                .ok_or_else(|| DbError::Constraint("rule creation failed".into()))
        } else {
            let updated: Vec<RuleRecord> = self
                .inner
                .query("UPDATE type::record('k8s_alert_rule', $id) SET name = $n, target_ref = $tr, target_kind = $tk, condition = $c, comparator = $cmp, threshold = $th, severity = $s, enabled = $en, updated_at = $t")
                .bind(("id", rule.id.clone()))
                .bind(("n", rule.name.clone()))
                .bind(("tr", rule.target_ref.clone()))
                .bind(("tk", target_kind.to_string()))
                .bind(("c", rule.condition.as_str().to_string()))
                .bind(("cmp", rule.comparator.as_str().to_string()))
                .bind(("th", rule.threshold))
                .bind(("s", severity_str(rule.severity).to_string()))
                .bind(("en", rule.enabled))
                .bind(("t", now))
                .await?
                .take(0)?;
            updated
                .into_iter()
                .next()
                .map(RuleRecord::into_model)
                .ok_or(DbError::NotFound)
        }
    }

    pub async fn set_k8s_rule_enabled(&self, id: &str, enabled: bool) -> DbResult<()> {
        self.inner
            .query("UPDATE type::record('k8s_alert_rule', $id) SET enabled = $v, updated_at = $t")
            .bind(("id", id.to_string()))
            .bind(("v", enabled))
            .bind(("t", to_rfc3339(Utc::now())))
            .await?;
        Ok(())
    }

    pub async fn delete_k8s_alert_rule(&self, id: &str) -> DbResult<()> {
        let _: Option<RuleRecord> = self.inner.delete(("k8s_alert_rule", id)).await?;
        Ok(())
    }

    // ---- Templates --------------------------------------------------------

    pub async fn list_k8s_templates(&self) -> DbResult<Vec<K8sTemplate>> {
        let recs: Vec<TemplateRecord> = self
            .inner
            .query("SELECT * FROM k8s_template ORDER BY name ASC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(TemplateRecord::into_model).collect())
    }

    pub async fn save_k8s_template(&self, template: &K8sTemplate) -> DbResult<K8sTemplate> {
        let now = to_rfc3339(Utc::now());
        if template.id.is_empty() {
            let rec = TemplateRecord {
                id: None,
                name: template.name.clone(),
                description: template.description.clone(),
                resource_kind: template.resource_kind.as_str().to_string(),
                manifest_yaml: template.manifest_yaml.clone(),
                created_at: now.clone(),
                updated_at: now,
                created_by: template.created_by.clone(),
            };
            let created: Option<TemplateRecord> =
                self.inner.create("k8s_template").content(rec).await?;
            created
                .map(TemplateRecord::into_model)
                .ok_or_else(|| DbError::Constraint("template creation failed".into()))
        } else {
            let updated: Vec<TemplateRecord> = self
                .inner
                .query("UPDATE type::record('k8s_template', $id) SET name = $n, description = $d, resource_kind = $rk, manifest_yaml = $y, updated_at = $t")
                .bind(("id", template.id.clone()))
                .bind(("n", template.name.clone()))
                .bind(("d", template.description.clone()))
                .bind(("rk", template.resource_kind.as_str().to_string()))
                .bind(("y", template.manifest_yaml.clone()))
                .bind(("t", now))
                .await?
                .take(0)?;
            updated
                .into_iter()
                .next()
                .map(TemplateRecord::into_model)
                .ok_or(DbError::NotFound)
        }
    }

    pub async fn delete_k8s_template(&self, id: &str) -> DbResult<()> {
        let _: Option<TemplateRecord> = self.inner.delete(("k8s_template", id)).await?;
        Ok(())
    }

    /// Metrics: cluster count, host count, alert rule count.
    pub async fn k8s_metrics(&self) -> DbResult<(usize, usize, usize)> {
        let clusters = self.list_k8s_clusters().await?.len();
        let hosts = self.list_k8s_hosts().await?.len();
        let rules = self.list_k8s_alert_rules().await?.len();
        Ok((clusters, hosts, rules))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_db() -> (Db, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        (db, dir)
    }

    #[tokio::test]
    async fn host_crud_and_unique() {
        let (db, _dir) = test_db().await;
        db.create_k8s_host(
            "node1",
            "10.0.0.1",
            22,
            "root",
            HostAuthMethod::Password,
            "pw",
            "admin",
        )
        .await
        .unwrap();
        assert!(db
            .create_k8s_host(
                "node1",
                "10.0.0.2",
                22,
                "root",
                HostAuthMethod::Password,
                "pw",
                "admin"
            )
            .await
            .is_err());
        assert_eq!(db.list_k8s_hosts().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn cluster_assigns_and_releases_hosts() {
        let (db, _dir) = test_db().await;
        db.create_k8s_host(
            "cp",
            "10.0.0.1",
            22,
            "root",
            HostAuthMethod::Password,
            "pw",
            "admin",
        )
        .await
        .unwrap();
        db.create_k8s_host(
            "w1",
            "10.0.0.2",
            22,
            "root",
            HostAuthMethod::Password,
            "pw",
            "admin",
        )
        .await
        .unwrap();
        let cluster = db
            .create_k8s_cluster(
                "c1",
                "1.30.2",
                "10.244.0.0/16",
                "10.96.0.0/12",
                "calico",
                &["cp".into(), "w1".into()],
                "admin",
            )
            .await
            .unwrap();
        assert_eq!(cluster.node_count, 2);
        // Host in a cluster cannot be deleted.
        let cp = db
            .list_k8s_hosts()
            .await
            .unwrap()
            .into_iter()
            .find(|h| h.hostname == "cp")
            .unwrap();
        assert!(cp.cluster_ref.is_some());
        assert!(db.delete_k8s_host(&cp.id, "cp").await.is_err());
        // Deleting the cluster releases the hosts.
        db.delete_k8s_cluster(&cluster.id, "c1").await.unwrap();
        let cp2 = db
            .list_k8s_hosts()
            .await
            .unwrap()
            .into_iter()
            .find(|h| h.hostname == "cp")
            .unwrap();
        assert!(cp2.cluster_ref.is_none());
        assert!(db.delete_k8s_host(&cp2.id, "cp").await.is_ok());
    }

    #[tokio::test]
    async fn alert_rule_toggle() {
        let (db, _dir) = test_db().await;
        let rule = AlertRule {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "admin".into(),
            name: "cpu-high".into(),
            target_ref: "c1".into(),
            target_kind: AlertTargetKind::Cluster,
            condition: AlertConditionKind::Cpu,
            comparator: Comparator::Gte,
            threshold: 80.0,
            severity: Severity::Warning,
            enabled: true,
        };
        let saved = db.save_k8s_alert_rule(&rule).await.unwrap();
        db.set_k8s_rule_enabled(&saved.id, false).await.unwrap();
        assert!(!db.list_k8s_alert_rules().await.unwrap()[0].enabled);
    }
}
