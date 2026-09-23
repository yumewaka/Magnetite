//! Proxy domain data (07_data_proxy): virtual hosts, certificates, ACL rules
//! and IP block entries. Certificates reference by unique `name`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Backend scheme for an upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamScheme {
    Http,
    Https,
}

/// A backend target of a virtual host (07_data_proxy §2.1.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Upstream {
    pub host: String,
    pub port: u16,
    #[serde(default = "default_weight")]
    pub weight: u16,
    #[serde(default = "default_scheme")]
    pub scheme: UpstreamScheme,
}

fn default_weight() -> u16 {
    1
}
fn default_scheme() -> UpstreamScheme {
    UpstreamScheme::Http
}

/// Proxy mode: how a virtual host handles its traffic. TLS *termination* is a separate
/// per-vhost toggle (`tls_enabled` + `certificate_ref`) and the upstream scheme is
/// `Upstream.scheme`, so there is no distinct "HTTPS" mode — an HTTPS site is an `Http`
/// (L7) vhost with `tls_enabled`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyMode {
    /// L7 HTTP reverse proxy (routed by Host + path; TLS terminated when `tls_enabled`).
    Http,
    /// L4 raw TCP stream forwarding (routed by TLS SNI or listen port).
    Tcp,
}

/// Load-balancing strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LbStrategy {
    RoundRobin,
    LeastConn,
    IpHash,
    /// Weighted round-robin: each upstream is chosen in proportion to its `weight`.
    Weighted,
}

/// A virtual host (07_data_proxy §2.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualHost {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub hostname: String,
    /// Optional path prefix (nginx `location`): when set, this vhost matches only requests
    /// whose path starts with it, and the LONGEST matching prefix wins — so one hostname
    /// can route different path prefixes to different upstreams. `None`/empty ⇒ matches any
    /// path (the host's default route).
    #[serde(default)]
    pub path_prefix: Option<String>,
    pub listen_port: u16,
    pub upstream: Vec<Upstream>,
    pub tls_enabled: bool,
    /// Certificate name (07_data_proxy §2.2); required when `tls_enabled`.
    #[serde(default)]
    pub certificate_ref: Option<String>,
    pub force_https: bool,
    pub proxy_mode: ProxyMode,
    pub lb_strategy: LbStrategy,
    pub enabled: bool,
}

/// A TLS certificate (07_data_proxy §2.2). The badge state is derived from
/// `not_after`, not stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub name: String,
    pub subject: String,
    pub issuer: String,
    pub san: Vec<String>,
    #[serde(default)]
    pub serial: Option<String>,
    #[serde(default)]
    pub fingerprint_sha256: Option<String>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub key_present: bool,
    // cert_pem / chain_pem are stored server-side and never projected here.
}

/// Derived certificate expiry status (AC-17 / PX-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertStatus {
    Valid,
    ExpiringSoon,
    Expired,
}

impl CertStatus {
    /// Compute the badge state from `not_after` at `now`. `threshold_days` is
    /// the "expiring soon" window (default 30).
    pub fn from_expiry(not_after: DateTime<Utc>, now: DateTime<Utc>, threshold_days: i64) -> Self {
        if now >= not_after {
            CertStatus::Expired
        } else if (not_after - now).num_days() <= threshold_days {
            CertStatus::ExpiringSoon
        } else {
            CertStatus::Valid
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            CertStatus::Valid => "valid",
            CertStatus::ExpiringSoon => "expiring_soon",
            CertStatus::Expired => "expired",
        }
    }
}

/// ACL action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AclAction {
    Allow,
    Deny,
}

impl AclAction {
    pub fn as_str(self) -> &'static str {
        match self {
            AclAction::Allow => "allow",
            AclAction::Deny => "deny",
        }
    }

    pub fn from_str(value: &str) -> Self {
        if value == "deny" {
            AclAction::Deny
        } else {
            AclAction::Allow
        }
    }
}

/// ACL scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AclScope {
    Global,
    Vhost,
}

/// An access-control rule (07_data_proxy §2.3). Evaluated by ascending
/// `priority`, first match wins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclRule {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub cidr: String,
    pub action: AclAction,
    pub scope: AclScope,
    /// Target vhost hostname; required when `scope = Vhost`.
    #[serde(default)]
    pub vhost_ref: Option<String>,
    pub priority: i32,
    pub enabled: bool,
    #[serde(default)]
    pub description: Option<String>,
}

/// Which side a forward-proxy rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardRuleKind {
    /// Matches the client (source) IP against a CIDR.
    Source,
    /// Matches the requested target host (exact, or `.suffix` domain match).
    Destination,
}

impl ForwardRuleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ForwardRuleKind::Source => "source",
            ForwardRuleKind::Destination => "destination",
        }
    }

    pub fn from_str(value: &str) -> Self {
        if value == "destination" {
            ForwardRuleKind::Destination
        } else {
            ForwardRuleKind::Source
        }
    }
}

/// A forward-proxy access rule. `Source` rules match the client IP (CIDR);
/// `Destination` rules match the requested host — either an exact hostname or, when
/// the matcher begins with a dot (`.example.com`), that domain and its subdomains.
/// Rules are evaluated per kind by ascending `priority`, first match wins; when no
/// rule of a kind matches, the default is Allow. For an allow-list, add a
/// low-priority `Deny` catch-all (`0.0.0.0/0` or `.`) plus higher-priority `Allow`s.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardRule {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub kind: ForwardRuleKind,
    /// CIDR (for `Source`) or host / `.domain` (for `Destination`).
    pub matcher: String,
    pub action: AclAction,
    pub priority: i32,
    pub enabled: bool,
    #[serde(default)]
    pub description: Option<String>,
}

/// A forward-proxy client credential (HTTP `Proxy-Authorization: Basic`). If at least
/// one enabled user exists the proxy requires proxy authentication; with none, auth is
/// disabled and access is gated only by the source / destination rules. The password
/// hash is stored server-side and never projected here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardUser {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub username: String,
    pub enabled: bool,
    #[serde(default)]
    pub description: Option<String>,
}

/// An IP block entry (07_data_proxy §2.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpBlock {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub cidr: String,
    #[serde(default)]
    pub reason: Option<String>,
    pub order: i32,
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    pub enabled: bool,
}
