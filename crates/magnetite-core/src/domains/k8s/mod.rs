//! K8s (container) domain: data model (07_data_k8s) and write-time validation
//! (screen_k8s §5). Pure and shared by the UI and the DB layer.

pub mod model;
pub mod validate;

pub use model::{
    AlertConditionKind, AlertRule, AlertTargetKind, Cluster, ClusterNode, ClusterState, Comparator,
    Host, HostAuthMethod, HostRole, HostState, K8sDeployment, K8sPod, K8sResourceKind, K8sService,
    K8sTemplate, K8sWorkloads,
};
