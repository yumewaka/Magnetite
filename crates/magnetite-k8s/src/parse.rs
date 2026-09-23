//! Kube API JSON shapes and their projection into the `magnetite-core` read models.
//! Only the fields the UI shows are deserialized; everything else is ignored.

use magnetite_core::domains::k8s::model::{K8sDeployment, K8sPod, K8sService};
use serde::Deserialize;

/// A kube list response: `{ "items": [ ... ] }`.
#[derive(Debug, Deserialize)]
pub struct List<T> {
    #[serde(default = "Vec::new")]
    pub items: Vec<T>,
}

#[derive(Debug, Default, Deserialize)]
pub struct Meta {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub namespace: String,
}

// ---- Deployment -----------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Deployment {
    #[serde(default)]
    metadata: Meta,
    #[serde(default)]
    spec: DeploymentSpec,
    #[serde(default)]
    status: DeploymentStatus,
}

#[derive(Debug, Default, Deserialize)]
struct DeploymentSpec {
    #[serde(default)]
    replicas: i32,
    #[serde(default)]
    template: PodTemplate,
}

#[derive(Debug, Default, Deserialize)]
struct PodTemplate {
    #[serde(default)]
    spec: PodSpec,
}

#[derive(Debug, Default, Deserialize)]
struct DeploymentStatus {
    #[serde(rename = "readyReplicas", default)]
    ready_replicas: i32,
    #[serde(rename = "availableReplicas", default)]
    available_replicas: i32,
}

impl From<Deployment> for K8sDeployment {
    fn from(d: Deployment) -> Self {
        K8sDeployment {
            namespace: d.metadata.namespace,
            name: d.metadata.name,
            replicas: d.spec.replicas,
            ready_replicas: d.status.ready_replicas,
            available_replicas: d.status.available_replicas,
            images: d
                .spec
                .template
                .spec
                .containers
                .into_iter()
                .filter_map(|c| (!c.image.is_empty()).then_some(c.image))
                .collect(),
        }
    }
}

// ---- Service --------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Service {
    #[serde(default)]
    metadata: Meta,
    #[serde(default)]
    spec: ServiceSpec,
}

#[derive(Debug, Default, Deserialize)]
struct ServiceSpec {
    #[serde(rename = "type", default)]
    service_type: String,
    #[serde(rename = "clusterIP", default)]
    cluster_ip: String,
    #[serde(default)]
    ports: Vec<ServicePort>,
}

#[derive(Debug, Default, Deserialize)]
struct ServicePort {
    #[serde(default)]
    port: i32,
    #[serde(default)]
    protocol: String,
}

impl From<Service> for K8sService {
    fn from(s: Service) -> Self {
        K8sService {
            namespace: s.metadata.namespace,
            name: s.metadata.name,
            service_type: s.spec.service_type,
            cluster_ip: s.spec.cluster_ip,
            ports: s
                .spec
                .ports
                .into_iter()
                .map(|p| {
                    let proto = if p.protocol.is_empty() {
                        "TCP".to_string()
                    } else {
                        p.protocol
                    };
                    format!("{}/{proto}", p.port)
                })
                .collect(),
        }
    }
}

// ---- Pod ------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct Pod {
    #[serde(default)]
    metadata: Meta,
    #[serde(default)]
    spec: PodSpec,
    #[serde(default)]
    status: PodStatus,
}

#[derive(Debug, Default, Deserialize)]
struct PodSpec {
    #[serde(rename = "nodeName", default)]
    node_name: String,
    #[serde(default)]
    containers: Vec<Container>,
}

#[derive(Debug, Default, Deserialize)]
struct Container {
    #[serde(default)]
    image: String,
}

#[derive(Debug, Default, Deserialize)]
struct PodStatus {
    #[serde(default)]
    phase: String,
    #[serde(rename = "containerStatuses", default)]
    container_statuses: Vec<ContainerStatus>,
}

#[derive(Debug, Default, Deserialize)]
struct ContainerStatus {
    #[serde(default)]
    ready: bool,
    #[serde(rename = "restartCount", default)]
    restart_count: i32,
}

impl From<Pod> for K8sPod {
    fn from(p: Pod) -> Self {
        let total = p.status.container_statuses.len();
        let ready = p
            .status
            .container_statuses
            .iter()
            .filter(|c| c.ready)
            .count();
        let restarts = p
            .status
            .container_statuses
            .iter()
            .map(|c| c.restart_count)
            .sum();
        K8sPod {
            namespace: p.metadata.namespace,
            name: p.metadata.name,
            phase: p.status.phase,
            ready: format!("{ready}/{total}"),
            restarts,
            node: p.spec.node_name,
        }
    }
}
