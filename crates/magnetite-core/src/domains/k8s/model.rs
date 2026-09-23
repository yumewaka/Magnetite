//! K8s (container) domain data (07_data_k8s): hosts, clusters, alert rules and
//! manifest templates. Alerts/backups use the shared cross-cutting structures.

use crate::models::common::Severity;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Host SSH authentication method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostAuthMethod {
    Password,
    Key,
}

/// Node role within a cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostRole {
    ControlPlane,
    Worker,
}

/// Host operational state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostState {
    Ready,
    Online,
    Offline,
    Error,
}

/// A container host / K8s node (07_data_k8s §2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub hostname: String,
    pub address: String,
    pub ssh_port: u16,
    pub ssh_user: String,
    pub auth_method: HostAuthMethod,
    #[serde(default)]
    pub role: Option<HostRole>,
    /// Owning cluster name, if any.
    #[serde(default)]
    pub cluster_ref: Option<String>,
    pub state: HostState,
    // credential is stored server-side and never projected.
}

/// Cluster operational state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClusterState {
    Ready,
    Error,
    Failed,
}

/// A node projection embedded in a cluster (07_data_k8s §3.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNode {
    /// Host hostname (the reference key).
    pub host_ref: String,
    pub hostname: String,
    pub address: String,
    pub role: HostRole,
    pub state: HostState,
}

/// A K8s cluster (07_data_k8s §3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cluster {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub name: String,
    pub k8s_version: String,
    #[serde(default)]
    pub api_server_endpoint: Option<String>,
    pub pod_cidr: String,
    pub service_cidr: String,
    pub cni: String,
    pub nodes: Vec<ClusterNode>,
    pub node_count: u64,
    pub state: ClusterState,
    /// Whether an API bearer token is stored for this cluster (the token itself is
    /// held server-side and never projected). With an endpoint + token set, the
    /// live workload/log views can query the cluster's kube API.
    #[serde(default)]
    pub api_token_set: bool,
}

/// Live read-only view of a cluster's workloads, fetched from its kube API server.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct K8sWorkloads {
    pub deployments: Vec<K8sDeployment>,
    pub services: Vec<K8sService>,
    pub pods: Vec<K8sPod>,
}

/// A Deployment (apps/v1), projected to the fields the UI shows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sDeployment {
    pub namespace: String,
    pub name: String,
    pub replicas: i32,
    pub ready_replicas: i32,
    pub available_replicas: i32,
    pub images: Vec<String>,
}

/// A Service (v1), projected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sService {
    pub namespace: String,
    pub name: String,
    /// `ClusterIP` / `NodePort` / `LoadBalancer` / `ExternalName`.
    pub service_type: String,
    pub cluster_ip: String,
    /// `port/protocol` strings (e.g. `80/TCP`).
    pub ports: Vec<String>,
}

/// A Pod (v1), projected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sPod {
    pub namespace: String,
    pub name: String,
    pub phase: String,
    /// Ready containers over total (e.g. `1/1`).
    pub ready: String,
    pub restarts: i32,
    pub node: String,
}

/// Alert rule target kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertTargetKind {
    Cluster,
    Host,
}

/// Metric condition for an alert rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertConditionKind {
    Cpu,
    Memory,
    PodRestart,
    NodeNotReady,
}

impl AlertConditionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            AlertConditionKind::Cpu => "cpu",
            AlertConditionKind::Memory => "memory",
            AlertConditionKind::PodRestart => "pod_restart",
            AlertConditionKind::NodeNotReady => "node_not_ready",
        }
    }

    pub fn from_str(value: &str) -> Self {
        match value {
            "memory" => AlertConditionKind::Memory,
            "pod_restart" => AlertConditionKind::PodRestart,
            "node_not_ready" => AlertConditionKind::NodeNotReady,
            _ => AlertConditionKind::Cpu,
        }
    }
}

/// Threshold comparator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Comparator {
    Gt,
    Gte,
    Lt,
    Lte,
}

impl Comparator {
    pub fn as_str(self) -> &'static str {
        match self {
            Comparator::Gt => "gt",
            Comparator::Gte => "gte",
            Comparator::Lt => "lt",
            Comparator::Lte => "lte",
        }
    }

    pub fn from_str(value: &str) -> Self {
        match value {
            "gt" => Comparator::Gt,
            "lt" => Comparator::Lt,
            "lte" => Comparator::Lte,
            _ => Comparator::Gte,
        }
    }
}

/// A K8s alert rule — the Alert-generating definition (07_data_k8s §4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRule {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub name: String,
    /// Target cluster name or host hostname (per `target_kind`).
    pub target_ref: String,
    pub target_kind: AlertTargetKind,
    pub condition: AlertConditionKind,
    pub comparator: Comparator,
    pub threshold: f64,
    pub severity: Severity,
    pub enabled: bool,
}

/// K8s resource kind for a manifest template (07_data_k8s §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum K8sResourceKind {
    Deployment,
    Service,
    ConfigMap,
    Job,
}

impl K8sResourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            K8sResourceKind::Deployment => "Deployment",
            K8sResourceKind::Service => "Service",
            K8sResourceKind::ConfigMap => "ConfigMap",
            K8sResourceKind::Job => "Job",
        }
    }

    pub fn from_str(value: &str) -> Self {
        match value {
            "Service" => K8sResourceKind::Service,
            "ConfigMap" => K8sResourceKind::ConfigMap,
            "Job" => K8sResourceKind::Job,
            _ => K8sResourceKind::Deployment,
        }
    }
}

/// A K8s manifest template (07_data_k8s §5.1; stored as a domain record).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sTemplate {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub resource_kind: K8sResourceKind,
    pub manifest_yaml: String,
}
