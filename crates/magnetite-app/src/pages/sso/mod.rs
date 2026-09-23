//! SSO management screens (S-SSO). Providers, OIDC clients and sessions;
//! audit-sink settings (S-SSO-06) edit the cross-cutting NotificationTarget
//! (added with the alerting feature).

pub mod audit_sink;
pub mod clients;
pub mod nav;
pub mod providers;
pub mod sessions;

pub use audit_sink::AuditSinkPage;
pub use clients::ClientsPage;
pub use providers::ProvidersPage;
pub use sessions::SessionsPage;
