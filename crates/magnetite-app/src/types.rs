//! Serializable view models shared between the server functions and the UI
//! (compiled for both SSR and WASM).

use magnetite_core::domain::DomainKey;
use magnetite_core::models::CurrentUser;
use serde::{Deserialize, Serialize};

/// One navigable domain in the sidebar (only enabled domains are sent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainNav {
    pub key: DomainKey,
    pub display_name: String,
    pub icon: String,
}

/// Everything the authenticated shell needs in a single round trip: the user,
/// the enabled domains, the unacknowledged alert count and the dashboard
/// refresh cadence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellInfo {
    pub user: CurrentUser,
    pub domains: Vec<DomainNav>,
    pub open_alert_count: u32,
    pub dashboard_refresh_secs: u64,
}

/// Headline DNS dashboard metrics (S-DNS-01).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DnsMetrics {
    pub zone_count: u64,
    pub record_count: u64,
}

/// Headline DHCP dashboard metrics (S-DHCP-01).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct DhcpMetrics {
    pub pool_count: u64,
    pub reservation_count: u64,
    pub active_lease_count: u64,
}

/// Headline LDAP dashboard metrics (S-LDAP-01).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapMetrics {
    pub entry_count: u64,
    pub user_count: u64,
    pub group_count: u64,
    pub ou_count: u64,
    pub base_dn: String,
}

/// LDAP syncrepl consumer status (RFC 4533), projection-safe (no credentials).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapSyncStatus {
    /// A `[domains.ldap.server.consumer]` block is present.
    pub configured: bool,
    pub enabled: bool,
    pub provider_url: Option<String>,
    pub base_dn: String,
    pub interval_secs: u64,
    /// Change-tracking mode: `"syncrepl"` (RFC 4533) or `"ad-dirsync"` (AD/Samba).
    pub mode: String,
    pub state: magnetite_core::domains::ldap::model::LdapSyncState,
}

/// Headline Mail dashboard metrics (S-MAIL-01).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MailMetrics {
    pub user_count: u64,
    pub domain_count: u64,
    pub list_count: u64,
    pub used_bytes: u64,
}

/// Mailbox replication status (Step 2 HA), projection-safe (no secret, no bodies).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailReplStatus {
    /// A `[domains.mail.server.replication]` block is present.
    pub configured: bool,
    pub enabled: bool,
    /// This instance pulls from a primary (it is a secondary).
    pub is_secondary: bool,
    pub primary_url: Option<String>,
    pub interval_secs: u64,
    pub state: magnetite_core::domains::mail::model::MailReplState,
}

/// Headline Proxy dashboard metrics (S-PROXY-01).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ProxyMetrics {
    pub vhost_count: u64,
    pub cert_count: u64,
    pub acl_count: u64,
}

/// Headline K8s dashboard metrics (S-K8S-01).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct K8sMetrics {
    pub cluster_count: u64,
    pub host_count: u64,
    pub rule_count: u64,
}

/// Headline SSO dashboard metrics (S-SSO-01).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct SsoMetrics {
    pub provider_count: u64,
    pub client_count: u64,
    pub session_count: u64,
}

/// Headline Watch dashboard metrics (S-WATCH-01).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct WatchMetrics {
    pub host_total: u64,
    pub online: u64,
    pub offline: u64,
    pub warning: u64,
    pub rule_count: u64,
}

/// A domain status card for the integrated dashboard (F-03).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainStatusCard {
    pub key: DomainKey,
    pub display_name: String,
    pub icon: String,
    /// Health as a stable string: "healthy" | "warning" | "error" | "unknown".
    pub health: String,
    /// Headline metric lines ("label: value").
    pub metrics: Vec<String>,
}
