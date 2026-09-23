//! K8s (container) management screens (S-K8S). Dashboard, hosts, clusters,
//! alert rules and templates; backup (S-K8S-05) uses the cross-cutting S-Backup
//! mechanism (added later).

pub mod alert_rules;
pub mod clusters;
pub mod dashboard;
pub mod hosts;
pub mod nav;
pub mod templates;
pub mod workloads;

pub use alert_rules::AlertRulesPage;
pub use clusters::ClustersPage;
pub use dashboard::K8sDashboard;
pub use hosts::HostsPage;
pub use templates::TemplatesPage;
pub use workloads::WorkloadsPage;
