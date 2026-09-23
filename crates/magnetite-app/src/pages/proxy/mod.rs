//! Proxy management screens (S-PROXY): dashboard, vhosts, certificates, ACL, IP
//! blocks, and — backed by the embedded reverse proxy — access logs (S-PROXY-06)
//! and health (S-PROXY-07).

pub mod access_logs;
pub mod acl_rules;
pub mod certificates;
pub mod dashboard;
pub mod forward;
pub mod health;
pub mod ip_blocklist;
pub mod nav;
pub mod vhosts;

pub use access_logs::AccessLogsPage;
pub use acl_rules::AclRulesPage;
pub use certificates::CertificatesPage;
pub use dashboard::ProxyDashboard;
pub use forward::ForwardPage;
pub use health::HealthPage;
pub use ip_blocklist::IpBlocklistPage;
pub use vhosts::VhostsPage;
