//! Watch (monitoring) management screens (S-WATCH). Dashboard, hosts, rules,
//! groups, maintenance windows and the per-host metrics view. Alert viewing /
//! acknowledgement is handled by the cross-cutting S-Alerts screen (added with
//! the alerting feature).

pub mod dashboard;
pub mod groups;
pub mod hosts;
pub mod maintenance;
pub mod metrics;
pub mod nav;
pub mod rules;

pub use dashboard::WatchDashboard;
pub use groups::WatchGroupsPage;
pub use hosts::WatchHostsPage;
pub use maintenance::WatchMaintenancePage;
pub use metrics::MetricsPage;
pub use rules::WatchRulesPage;
