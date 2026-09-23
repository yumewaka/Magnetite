//! DNS domain data (07_data_dns §2–§4). Zones embed their SOA; records carry a
//! typed `data` payload kept as JSON so the persistence and form layers share
//! one flexible representation (validated per type in [`super::validate`]).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A DNS zone — the authoritative boundary of a namespace (07_data_dns §2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Zone {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    /// Zone apex name (FQDN, normalized).
    pub name: String,
    pub soa: Soa,
    pub enabled: bool,
    /// DNSSEC online signing for this zone (RRSIG on positive answers + DNSKEY
    /// at apex when the query carries the DO bit, plus authenticated denial of
    /// existence on negatives). Keys are generated and held server-side.
    #[serde(default)]
    pub dnssec_enabled: bool,
    /// Use hashed denial of existence (NSEC3, RFC 5155) instead of plain NSEC for
    /// this zone's negative answers. Only meaningful when `dnssec_enabled`.
    #[serde(default)]
    pub nsec3_enabled: bool,
    /// Replication role (07_data_dns replication extension). `Primary` (default)
    /// means Magnetite is authoritative and serves transfers to secondaries;
    /// `Secondary` means Magnetite mirrors the zone from an external primary.
    #[serde(default)]
    pub role: ZoneRole,
    /// Primary-side: client IPs/CIDRs allowed to AXFR/IXFR this zone. Empty means
    /// **deny all** transfers (secure by default).
    #[serde(default)]
    pub allow_transfer: Vec<String>,
    /// Primary-side: extra NOTIFY targets (`host` or `host:port`) in addition to
    /// the zone's own NS records.
    #[serde(default)]
    pub also_notify: Vec<String>,
    /// Primary-side: send DNS NOTIFY (RFC 1996) to secondaries when the zone
    /// changes (SOA serial bump).
    #[serde(default)]
    pub notify_enabled: bool,
    /// Secondary-side: primary servers to transfer from (`host` or `host:port`).
    #[serde(default)]
    pub primaries: Vec<String>,
    /// TSIG key name (RFC 8945) authenticating transfers/NOTIFY for this zone,
    /// for either role. `None` means unauthenticated (IP allow-list only).
    #[serde(default)]
    pub tsig_key_name: Option<String>,
    /// Secondary-side runtime state from the last transfer attempt. `None` until
    /// the first refresh runs.
    #[serde(default)]
    pub transfer_state: Option<ZoneTransferState>,
}

/// Whether Magnetite is the authoritative primary for a zone, or a secondary
/// mirroring it from an external primary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ZoneRole {
    #[default]
    Primary,
    Secondary,
}

/// Secondary-side transfer state, updated by the refresh task after each attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneTransferState {
    /// SOA serial of the last successfully transferred copy.
    pub last_serial: u32,
    /// When the last transfer attempt ran.
    pub last_attempt: DateTime<Utc>,
    /// Whether the last attempt succeeded.
    pub last_ok: bool,
    /// Error detail from the last failed attempt, if any.
    #[serde(default)]
    pub last_error: Option<String>,
    /// When the zone was last *successfully* transferred. Drives SOA-expire
    /// (a secondary stops serving a zone it cannot refresh within `soa.expire`).
    #[serde(default)]
    pub last_success: Option<DateTime<Utc>>,
}

/// A TSIG shared-secret key (RFC 8945) authenticating zone transfers and NOTIFY.
/// The `secret` is server-side material and is never projected to clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TsigKey {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    /// Key name (an FQDN-style label) shared with the peer.
    pub name: String,
    pub algorithm: TsigAlgorithm,
    /// Base64-encoded HMAC secret — server-side only, blanked in projections.
    #[serde(default)]
    pub secret: String,
}

/// TSIG HMAC algorithm (RFC 8945 §6). Limited to the algorithms usable for
/// cryptographic operations (SHA-256/384/512); SHA-1/MD5 are intentionally
/// excluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum TsigAlgorithm {
    #[default]
    HmacSha256,
    HmacSha384,
    HmacSha512,
}

impl TsigAlgorithm {
    /// The DNS algorithm name used on the wire (RFC 8945 §6).
    pub fn wire_name(self) -> &'static str {
        match self {
            TsigAlgorithm::HmacSha256 => "hmac-sha256",
            TsigAlgorithm::HmacSha384 => "hmac-sha384",
            TsigAlgorithm::HmacSha512 => "hmac-sha512",
        }
    }
}

/// SOA value object embedded in a [`Zone`] (07_data_dns §2.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Soa {
    /// Primary nameserver (FQDN).
    pub mname: String,
    /// Responsible party, dotted-email notation.
    pub rname: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    /// Negative-cache TTL (minimum TTL).
    pub minimum: u32,
}

impl Default for Soa {
    fn default() -> Self {
        Self {
            mname: String::new(),
            rname: String::new(),
            serial: 1,
            refresh: 3600,
            retry: 900,
            expire: 604_800,
            minimum: 86_400,
        }
    }
}

/// A resource record within a zone (07_data_dns §3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    /// Owning zone id.
    pub zone: String,
    /// Record name (FQDN under the zone; apex is the zone name itself).
    pub name: String,
    pub ttl: u32,
    pub record_type: RecordType,
    /// Type-specific value (see 07_data_dns §3.2). JSON-shaped.
    pub data: serde_json::Value,
    pub enabled: bool,
}

/// Resource record type (07_data_dns §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RecordType {
    A,
    Aaaa,
    Cname,
    Mx,
    Txt,
    Ns,
    Ptr,
    Srv,
    Caa,
}

impl RecordType {
    pub const ALL: [RecordType; 9] = [
        RecordType::A,
        RecordType::Aaaa,
        RecordType::Cname,
        RecordType::Mx,
        RecordType::Txt,
        RecordType::Ns,
        RecordType::Ptr,
        RecordType::Srv,
        RecordType::Caa,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::Aaaa => "AAAA",
            RecordType::Cname => "CNAME",
            RecordType::Mx => "MX",
            RecordType::Txt => "TXT",
            RecordType::Ns => "NS",
            RecordType::Ptr => "PTR",
            RecordType::Srv => "SRV",
            RecordType::Caa => "CAA",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        RecordType::ALL
            .into_iter()
            .find(|t| t.as_str().eq_ignore_ascii_case(value))
    }
}

/// An RPZ (Response Policy Zone) rule (07_data_dns §4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpzRule {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    /// Target name the policy applies to (FQDN, wildcard allowed).
    pub domain: String,
    pub action: RpzAction,
    /// Required only when `action = Redirect`.
    pub redirect_to: Option<String>,
    pub enabled: bool,
}

/// RPZ action (07_data_dns §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpzAction {
    Nxdomain,
    Nodata,
    Redirect,
    Drop,
}

impl RpzAction {
    pub fn as_str(self) -> &'static str {
        match self {
            RpzAction::Nxdomain => "nxdomain",
            RpzAction::Nodata => "nodata",
            RpzAction::Redirect => "redirect",
            RpzAction::Drop => "drop",
        }
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "nxdomain" => Some(RpzAction::Nxdomain),
            "nodata" => Some(RpzAction::Nodata),
            "redirect" => Some(RpzAction::Redirect),
            "drop" => Some(RpzAction::Drop),
            _ => None,
        }
    }
}

/// GeoDNS rule (subnet/region-based answer routing). A rule owns one
/// `(name, record_type)` and returns per-region data when the client IP falls
/// in a region's CIDRs, else `default_data`. This is split-horizon / client-
/// subnet routing (no external GeoIP database); country-level GeoIP is a further
/// extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoRule {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    /// Owning zone id.
    pub zone: String,
    /// Record name (FQDN under the zone).
    pub name: String,
    pub record_type: RecordType,
    pub ttl: u32,
    /// Fallback answer when no region matches (same JSON shape as `Record.data`).
    pub default_data: serde_json::Value,
    pub regions: Vec<GeoRegion>,
    pub enabled: bool,
}

/// One region within a [`GeoRule`]: a label, its CIDRs, and the answer served
/// to clients in those CIDRs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoRegion {
    /// Region label, e.g. `NA` / `EU` / `internal`.
    pub region: String,
    pub cidrs: Vec<String>,
    /// Answer data for this region (same JSON shape as `Record.data`).
    pub data: serde_json::Value,
}

/// How the dynamic-DNS *client* talks to the provider (Magnetite pushes its current public
/// IP to an external DDNS service, e.g. No-IP / DynDNS / DuckDNS).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DdnsMode {
    /// DynDNS v2 protocol: `GET <server>?hostname=<host>&myip=<ip>` with HTTP Basic auth,
    /// response `good`/`nochg`/error code. Covers No-IP, DynDNS, and most routers.
    #[default]
    Dyndns,
    /// A free-form URL template with `{host}` `{ip}` `{user}` `{pass}` placeholders (e.g.
    /// DuckDNS `https://www.duckdns.org/update?domains={host}&token={pass}&ip={ip}`).
    Template,
}

/// Dynamic-DNS client settings (a single provider target). Editable from the Web UI and
/// hot-reloaded; the scheduler pushes an update daily at `update_time` and on demand.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DdnsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: DdnsMode,
    /// DynDNS mode: the provider update endpoint — a full URL (e.g.
    /// `https://dynupdate.no-ip.com/nic/update`) or a bare host (defaulted to
    /// `https://<host>/nic/update`).
    #[serde(default)]
    pub server: String,
    /// The hostname/label to update at the provider.
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub username: String,
    /// Provider password / token — a secret; the server-fn layer scrubs it before projecting.
    #[serde(default)]
    pub password: String,
    /// Template mode: the full URL with `{host}` `{ip}` `{user}` `{pass}` placeholders.
    #[serde(default)]
    pub url_template: String,
    /// Where to get the public IP. Empty ⇒ let the provider detect it from the request
    /// source (recommended); a URL ⇒ fetch the IP from it and send it explicitly.
    #[serde(default)]
    pub public_ip_source: Option<String>,
    /// Daily update time, `HH:MM` in the server's local timezone.
    #[serde(default = "default_ddns_time")]
    pub update_time: String,
}

fn default_ddns_time() -> String {
    "03:00".to_string()
}

/// The outcome of the last dynamic-DNS update (for the Web UI). Never carries secrets.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DdnsStatus {
    /// When the last update ran (RFC3339), or `None` if never.
    pub last_run: Option<String>,
    pub last_ok: bool,
    /// A short human-readable result (provider response summary or error).
    pub last_message: String,
    /// The IP the provider accepted / we sent, if known.
    pub last_ip: Option<String>,
}
