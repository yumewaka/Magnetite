//! DHCP domain data (07_data_dhcp §1–§4): pools, reservations, leases and the
//! singleton server config.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// An address distribution pool (07_data_dhcp §1). Holds an IPv4 and/or IPv6
/// range; addresses are kept as strings and validated in [`super::validate`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pool {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub name: String,
    #[serde(default)]
    pub subnet_v4: Option<String>,
    #[serde(default)]
    pub range_start_v4: Option<String>,
    #[serde(default)]
    pub range_end_v4: Option<String>,
    #[serde(default)]
    pub subnet_v6: Option<String>,
    #[serde(default)]
    pub range_start_v6: Option<String>,
    #[serde(default)]
    pub range_end_v6: Option<String>,
    #[serde(default)]
    pub gateway: Option<String>,
    #[serde(default)]
    pub dns_servers: Vec<String>,
    #[serde(default)]
    pub domain_name: Option<String>,
    #[serde(default)]
    pub lease_duration_secs: Option<u32>,
    pub enabled: bool,
}

/// A static MAC→IP reservation bound to a pool (07_data_dhcp §2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reservation {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub pool_ref: String,
    /// Normalized `aa:bb:cc:dd:ee:ff`.
    pub mac_address: String,
    pub ip_address: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

/// Lease lifecycle state (07_data_dhcp §3 / 08_dhcp_logic §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    Active,
    Offered,
    Expired,
    Released,
}

impl LeaseState {
    pub fn as_str(self) -> &'static str {
        match self {
            LeaseState::Active => "active",
            LeaseState::Offered => "offered",
            LeaseState::Expired => "expired",
            LeaseState::Released => "released",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "active" => Some(LeaseState::Active),
            "offered" => Some(LeaseState::Offered),
            "expired" => Some(LeaseState::Expired),
            "released" => Some(LeaseState::Released),
            _ => None,
        }
    }

    /// Whether an explicit release applies (08_dhcp_logic §4.2): only active or
    /// offered leases can be released.
    pub fn is_releasable(self) -> bool {
        matches!(self, LeaseState::Active | LeaseState::Offered)
    }
}

/// IP protocol version of a lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ProtoVer {
    V4,
    V6,
}

/// A dynamic lease record (07_data_dhcp §3). Created/updated at runtime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub pool_ref: String,
    pub ip_address: String,
    #[serde(default)]
    pub mac_address: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    pub state: LeaseState,
    pub lease_start: DateTime<Utc>,
    pub lease_expiry: DateTime<Utc>,
    #[serde(default)]
    pub last_renewal: Option<DateTime<Utc>>,
    pub protocol_version: ProtoVer,
}

/// The DHCP lease-replication feed a primary serves to a peer: the leases changed
/// since the requested cursor, plus the cursor to request next. A peer applies these
/// leases into its own store so it has the full picture (renewal continuity if the
/// originating server fails, and avoids offering an address the peer already leased).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpLeaseFeed {
    /// Leases whose `updated_at` is newer than the requested cursor, oldest first.
    pub leases: Vec<Lease>,
    /// The cursor to request next (the newest `updated_at` served, RFC 3339).
    pub cursor: String,
}

impl Lease {
    /// Whether the lease is currently active (08_dhcp_logic §1: state Active and
    /// not past expiry).
    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        self.state == LeaseState::Active && now < self.lease_expiry
    }
}

/// Server-wide DHCP configuration (07_data_dhcp §4). Singleton.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpConfig {
    pub v4_enabled: bool,
    pub v6_enabled: bool,
    pub default_lease_secs: u32,
    #[serde(default)]
    pub max_lease_secs: Option<u32>,
    #[serde(default)]
    pub default_dns_servers: Vec<String>,
    #[serde(default)]
    pub default_domain_name: Option<String>,
    pub authoritative: bool,
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            v4_enabled: true,
            v6_enabled: false,
            default_lease_secs: 86_400,
            max_lease_secs: None,
            default_dns_servers: Vec::new(),
            default_domain_name: None,
            authoritative: true,
        }
    }
}
