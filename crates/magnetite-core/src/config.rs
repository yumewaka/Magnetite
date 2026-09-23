//! Application configuration (07 §3.10 / 05 §6 / 09 §7).
//!
//! `AppConfig` is the externalised source of truth for server binding, the
//! optional SSO integration, per-domain visibility, and operational policy.
//! It replaces the former process/gateway-oriented `PortalConfig`: the
//! `ServiceAuthType`, `ProcessConfig` and `api_base_url` fields are gone
//! (domains are internal modules now, 07 §1).

use crate::authz::Role;
use crate::domain::DomainKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Top-level application configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    /// Optional SSO. When absent, only local authentication is available.
    #[serde(default)]
    pub sso: Option<SsoConfig>,
    /// Per-domain display and enablement.
    #[serde(default)]
    pub domains: HashMap<DomainKey, DomainConfig>,
    #[serde(default)]
    pub policy: PolicyConfig,
    /// Optional management-plane agent API (`/mgmt/*`). When enabled, this server
    /// exposes a machine-readable identity/health API for a `magnetite-center`
    /// control plane to poll and (later) orchestrate failover. Server-to-server
    /// only, gated by the shared `token`.
    #[serde(default)]
    pub mgmt: Option<MgmtConfig>,

    /// Optional certificate-export API (`/export/certificate/<name>`). When enabled,
    /// an app behind the proxy can fetch a managed (e.g. ACME-issued) certificate's
    /// PEM + private key with the shared `token`, so it can run its own TLS from the
    /// same cert the proxy serves. Hands out a private key, so keep it token-gated and
    /// reach it only over TLS.
    #[serde(default)]
    pub cert_export: Option<CertExportConfig>,
}

/// Certificate-export API configuration (the `[cert_export]` block). Distributes a
/// named certificate's PEM + key to backend apps, gated per-token.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CertExportConfig {
    /// Master switch for the `/export/certificate/*` API.
    #[serde(default)]
    pub enabled: bool,
    /// The endpoint returns private keys, so it must be reached over TLS. The main
    /// server terminates plain HTTP (TLS is fronted by the proxy/ingress), so this is
    /// enforced by requiring the front to set `X-Forwarded-Proto: https`. Set
    /// `allow_insecure = true` ONLY for a trusted direct-TLS or test setup where that
    /// header is absent.
    #[serde(default)]
    pub allow_insecure: bool,
    /// IPs / CIDRs of the TLS-terminating fronts (proxy / ingress) allowed to speak for
    /// clients. `X-Forwarded-Proto` and `X-Forwarded-For` are trusted ONLY when the
    /// immediate TCP peer is one of these — so an attacker reaching the plaintext port
    /// directly cannot spoof `X-Forwarded-Proto: https` to bypass the TLS requirement,
    /// and the audited / rate-limited client IP is the real client (from XFF) rather than
    /// the shared proxy IP. Empty ⇒ no proxy is trusted, and (unless `allow_insecure`)
    /// every request is treated as direct/non-TLS and refused.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Per-token authorization: each token may export ONLY the certificates named in
    /// its `certs` list. There is deliberately no single all-certificate token, so a
    /// leaked token exposes only its own certificates.
    #[serde(default)]
    pub tokens: Vec<CertExportToken>,
}

/// One certificate-export credential: a bearer token scoped to specific certificates.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CertExportToken {
    /// The bearer token (constant-time compared). Keep it secret and out of version
    /// control (`${ENV}` substitution recommended).
    #[serde(default)]
    pub token: String,
    /// Certificate names this token is authorized to export.
    #[serde(default)]
    pub certs: Vec<String>,
}

/// Management-plane agent configuration (the `[mgmt]` block). Exposes the
/// `/mgmt/*` API a `magnetite-center` control plane uses to monitor and manage
/// this server. Restart-scoped.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MgmtConfig {
    /// Master switch for the `/mgmt/*` agent API.
    #[serde(default)]
    pub enabled: bool,
    /// Shared bearer token the control plane must present (constant-time compared).
    /// Keep it secret and out of version control (env-var substitution recommended).
    #[serde(default)]
    pub token: String,
}

/// HTTP listener configuration. Changing these requires a restart (09 §7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_base_url")]
    pub base_url: String,
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    4000
}

fn default_base_url() -> String {
    "http://localhost:4000".to_string()
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            base_url: default_base_url(),
        }
    }
}

/// OIDC/PKCE single sign-on configuration (F-01). The role mapping translates
/// OIDC group/role claims into the platform [`Role`] (08_authz §4.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// Claim value -> Role. Anything unmapped falls back to Viewer.
    #[serde(default)]
    pub role_mapping: HashMap<String, Role>,
}

fn default_scopes() -> Vec<String> {
    vec!["openid".into(), "profile".into(), "email".into()]
}

/// Per-domain presentation and enablement (07 §3.10). `enabled` governs UI /
/// feature visibility (hot-reloadable via S-Settings); the embedded protocol
/// server, if any, is configured under [`DomainConfig::server`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainConfig {
    pub display_name: String,
    #[serde(default)]
    pub icon: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// In-process protocol server for this domain (09b §-1). Absent ⇒ the
    /// domain serves no protocol (control-plane only). Changing this requires a
    /// restart — the socket is bound at startup (analogous to `server`, 09 §7).
    #[serde(default)]
    pub server: Option<DomainServerConfig>,
    /// LDAP: the directory's base DN / naming context (e.g. `dc=example,dc=com`).
    /// Seeds the directory root on first run; once the directory is seeded the
    /// persisted root wins (changing this would orphan the tree). Ignored for
    /// non-LDAP domains.
    #[serde(default)]
    pub base_dn: Option<String>,
    /// LDAP / AD DC: the domain SID sub-authorities after `S-1-5` (space- or
    /// dash-separated, e.g. `21-1-2-3` for `S-1-5-21-1-2-3`, or a foreign domain's real
    /// SID to inherit it). Seeded to the DB on first run as the single source of truth
    /// shared by the KDC/SAMR/LDAP/netlogon paths; once seeded the persisted value wins.
    /// Unset ⇒ the default `21-1-2-3`. Ignored for non-LDAP domains. **Finalise this
    /// before creating any object:** a group's `objectSid` is computed and stored at
    /// creation, so changing the domain SID afterwards leaves existing groups on the old
    /// prefix (users keep only a RID, so they are unaffected).
    #[serde(default)]
    pub domain_sid: Option<String>,
}

/// Embedded protocol-server binding for a domain (R5, restart-scoped). Fields
/// beyond `listen` are domain-specific and ignored where not applicable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainServerConfig {
    /// Socket to bind, `host:port` (e.g. `0.0.0.0:53`). Required by the servers
    /// that accept connections (DNS/DHCP/Proxy/Mail/LDAP); the Watch collector
    /// binds no socket and omits it.
    #[serde(default)]
    pub listen: Option<String>,
    /// Proxy: optional HTTPS/TLS listen socket (`host:port`, e.g. `0.0.0.0:443`).
    #[serde(default)]
    pub tls_listen: Option<String>,
    /// Proxy: optional **forward-proxy** listen socket (`host:port`, e.g.
    /// `0.0.0.0:3128`). When set, an HTTP forward proxy (absolute-URI + `CONNECT`
    /// tunnelling) listens here, gated by the forward-proxy source/destination rules
    /// and client credentials. Unset disables the forward proxy.
    #[serde(default)]
    pub forward_listen: Option<String>,
    /// Proxy: optional **L4/TCP stream** listen sockets — a comma-separated list of
    /// `host:port` (e.g. `0.0.0.0:3389,0.0.0.0:5432`). Each raw TCP port forwards to a
    /// `Tcp`-mode virtual host, routed by TLS SNI (ssl_preread, several hosts on one port)
    /// or by the listen port. Used for RDP / PostgreSQL / any non-HTTP stream.
    #[serde(default)]
    pub tcp_listen: Option<String>,
    /// Proxy: maximum reverse-proxy request body size in bytes (nginx
    /// `client_max_body_size`). An over-limit declared Content-Length is rejected with
    /// 413; a larger chunked body is capped mid-stream. Unset ⇒ unlimited (bodies are
    /// streamed either way, so this is a policy limit, not a memory guard).
    #[serde(default)]
    pub max_body_bytes: Option<u64>,
    /// DNS: upstream resolvers for out-of-zone names (`host:port`).
    #[serde(default)]
    pub forwarders: Vec<String>,
    /// DNS: emit a `query` LogEntry per resolution (S-Logs ingestion).
    #[serde(default = "default_true")]
    pub query_log: bool,
    /// Mail: outbound relay smarthost. When set, authenticated submissions to
    /// non-hosted domains are relayed through this host; otherwise they are
    /// delivered directly to the recipient domain (port 25, opportunistic).
    #[serde(default)]
    pub relay: Option<RelayConfig>,
    /// Watch: seconds between collector passes (probe + rule evaluation).
    #[serde(default)]
    pub interval_secs: Option<u32>,
    /// Watch: TCP port used for the per-host reachability probe.
    #[serde(default)]
    pub probe_port: Option<u16>,
    /// LDAP: name of the `Certificate` presented on StartTLS. `None` disables
    /// StartTLS (the server then rejects the upgrade request).
    #[serde(default)]
    pub tls_cert_name: Option<String>,
    /// Mail: mailbox replication to/from a peer Magnetite instance (Step 2 HA).
    #[serde(default)]
    pub replication: Option<MailReplicationConfig>,
    /// LDAP: consume directory changes from an upstream LDAP server via RFC 4533
    /// syncrepl (this instance acts as a replica).
    #[serde(default)]
    pub consumer: Option<LdapConsumerConfig>,
    /// AD DC: the Kerberos KDC / SMB / RPC listeners for the embedded Active
    /// Directory domain controller. Present only for the `addc` domain.
    #[serde(default)]
    pub addc: Option<AddcConfig>,
    /// Proxy: automatic TLS certificates from an ACME CA (Let's Encrypt) via the
    /// HTTP-01 challenge. When enabled, the proxy obtains and renews a certificate
    /// for the configured domains and stores it in the shared cert store (so a TLS
    /// vhost can reference it by `certificate_name`).
    #[serde(default)]
    pub acme: Option<AcmeConfig>,
}

impl DomainServerConfig {
    /// The parsed listen socket, or `None` when unset / unparseable.
    pub fn socket(&self) -> Option<std::net::SocketAddr> {
        self.listen.as_deref().and_then(|l| l.parse().ok())
    }
}

/// Automatic-TLS (ACME / Let's Encrypt) configuration for the reverse proxy
/// (restart-scoped). The proxy answers the HTTP-01 challenge on its plain HTTP
/// listener (port 80 must be reachable from the CA), then stores the issued
/// certificate under `certificate_name` in the shared cert store, where the
/// hot-reload SNI resolver picks it up without a restart.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AcmeConfig {
    /// Master switch. When `false` (the default) no ACME activity happens.
    #[serde(default)]
    pub enabled: bool,
    /// Use Let's Encrypt's **staging** environment (untrusted certs, high rate
    /// limits) — for testing the flow without burning production quota. Ignored
    /// when `directory_url` is set explicitly.
    #[serde(default)]
    pub staging: bool,
    /// ACME directory URL. Defaults to Let's Encrypt production (or staging when
    /// `staging = true`). Set to point at another CA (e.g. a local Pebble).
    #[serde(default)]
    pub directory_url: Option<String>,
    /// Account contact e-mail (registered with the CA as `mailto:`; used for
    /// expiry notices). Optional but recommended.
    #[serde(default)]
    pub contact_email: Option<String>,
    /// The domains to include on the certificate (the first is the subject CN,
    /// all become subject-alternative names). Each must resolve to this host and
    /// be reachable on port 80 for the HTTP-01 challenge.
    #[serde(default)]
    pub domains: Vec<String>,
    /// Name to store the issued certificate under in the cert store (a TLS vhost
    /// references it via its certificate field). Defaults to `acme`.
    #[serde(default)]
    pub certificate_name: Option<String>,
    /// Renew when fewer than this many days of validity remain. Defaults to 30.
    #[serde(default)]
    pub renew_before_days: Option<i64>,
}

/// Listener configuration for the embedded AD domain controller (restart-scoped).
/// Each socket falls back to its well-known default when unset. The Kerberos keys
/// and machine password are derived server-side and never leave the process.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AddcConfig {
    /// Kerberos realm (e.g. `EXAMPLE.COM`). Defaults to `EXAMPLE.COM`.
    #[serde(default)]
    pub realm: Option<String>,
    /// This DC's computer label — the lowercase DNS host label under the domain
    /// (e.g. `dc2` → `dc2.<domain>`) and, uppercased (≤15 chars), its NetBIOS
    /// computer name. Drives the DC-locator A/SRV targets, the FQDN service SPNs,
    /// the CLDAP netlogon response, and the RootDSE `serverName`/`dsServiceName`.
    /// Defaults to `magnetite`. Give each DC in a multi-DC deployment a distinct
    /// value so their DNS records and identities don't collide.
    #[serde(default)]
    pub dc_name: Option<String>,
    /// KDC listen socket (`host:port`). Defaults to `0.0.0.0:88`.
    #[serde(default)]
    pub kdc_listen: Option<String>,
    /// SMB (SYSVOL + `ncacn_np` pipes) listen socket. Defaults to `0.0.0.0:445`.
    #[serde(default)]
    pub smb_listen: Option<String>,
    /// RPC/SAMR (`ncacn_ip_tcp`) listen socket. Defaults to `0.0.0.0:1025`.
    #[serde(default)]
    pub rpc_listen: Option<String>,
    /// DRSUAPI (Kerberos-authenticated DCSync) listen socket. Defaults to
    /// `0.0.0.0:1027`.
    #[serde(default)]
    pub drs_listen: Option<String>,
    /// The IPv4 address published in the DC-locator DNS records (the A record a
    /// Windows client resolves the DC to). Defaults to `127.0.0.1`.
    #[serde(default)]
    pub dc_ipv4: Option<String>,
    /// CLDAP netlogon-ping listen socket (UDP, the DC-discovery responder).
    /// Defaults to `0.0.0.0:389`.
    #[serde(default)]
    pub cldap_listen: Option<String>,
    /// Kerberos Change/Set Password (`kpasswd`, RFC 3244) listen socket (UDP+TCP).
    /// Defaults to `0.0.0.0:464`.
    #[serde(default)]
    pub kpasswd_listen: Option<String>,
    /// RPC Endpoint Mapper (`ept`, MS-RPCE) listen socket — how a Windows client
    /// discovers RPC services' dynamic ports. Defaults to `0.0.0.0:135`.
    #[serde(default)]
    pub epm_listen: Option<String>,
    /// SNTP time-service listen socket (UDP) — the DC serves time so members stay
    /// within the Kerberos clock-skew window. Defaults to `0.0.0.0:123`.
    #[serde(default)]
    pub sntp_listen: Option<String>,
    /// Inbound AD DRS replication (DCSync) run from `magnetite-server`: pull directory
    /// changes from one or more upstream DCs into the shared DB, so a Web-UI deployment
    /// stays in sync without the standalone `magnetite-addc` binary. Absent ⇒ no
    /// server-side replication (the daemon can still run it).
    #[serde(default)]
    pub replication: Option<AddcReplicationConfig>,
}

/// Server-side AD DRS replication config (07 §7 restart-scoped). Credentials live only
/// in this server-side file. A keytab is preferred over a cleartext password. All
/// upstreams share these credentials + NC; each is polled on the same interval.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AddcReplicationConfig {
    /// Master switch — replication starts only when `true`.
    #[serde(default)]
    pub enabled: bool,
    /// The source KDC (`host:88`) to obtain replication service tickets from.
    pub kdc: String,
    /// The Kerberos realm to authenticate in. Defaults to the AD DC realm when unset.
    #[serde(default)]
    pub realm: Option<String>,
    /// The replication account (must hold replication rights). Defaults to `Administrator`.
    #[serde(default)]
    pub user: Option<String>,
    /// The account's password — used only when `keytab` is unset (dev/PoC). Prefer a keytab
    /// in production so no cleartext credential lives in the config.
    #[serde(default)]
    pub password: Option<String>,
    /// A keytab file holding `user`'s AES256 key (production: no cleartext password).
    #[serde(default)]
    pub keytab: Option<String>,
    /// The naming-context DN to replicate. Defaults to the realm as `dc=…` when unset.
    #[serde(default)]
    pub nc_dn: Option<String>,
    /// Extra read-only NCs (Config/Schema) to seed once. Empty ⇒ none.
    #[serde(default)]
    pub extra_ncs: Vec<String>,
    /// Seconds between replication cycles. Defaults to 300.
    #[serde(default)]
    pub interval_secs: Option<u64>,
    /// The upstream DCs to pull from (multi-upstream = redundancy / mesh).
    #[serde(default)]
    pub upstreams: Vec<AddcReplicationUpstream>,
}

/// One upstream DC for [`AddcReplicationConfig`].
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AddcReplicationUpstream {
    /// The DC's DRSUAPI endpoint (`host:port`, `ncacn_ip_tcp`).
    pub drs: String,
    /// The DRS service SPN to request a ticket for (e.g. `ldap/dc1.example.com`).
    pub spn: String,
}

fn default_true() -> bool {
    true
}

/// Mail outbound-relay smarthost (T5, restart-scoped). Secrets live only in this
/// server-side config file and are never projected to clients. Plaintext /
/// opportunistic transport only for now — TLS to the relay (STARTTLS/implicit)
/// is deferred.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Smarthost address to submit outbound mail to.
    pub host: String,
    /// Smarthost port (default 25).
    #[serde(default = "default_smtp_port")]
    pub port: u16,
    /// Optional SMTP AUTH username for the smarthost.
    #[serde(default)]
    pub username: Option<String>,
    /// Optional SMTP AUTH password for the smarthost.
    #[serde(default)]
    pub password: Option<String>,
}

fn default_smtp_port() -> u16 {
    25
}

/// Mailbox replication between Magnetite instances (Step 2 HA, restart-scoped).
/// The `secret` is a shared bearer token that authenticates the replication feed
/// on both sides; it lives only in this server-side config and is never projected
/// to clients. A *secondary* sets `primary_url` to pull the primary's mailbox
/// changes (`<primary_url>/repl/mail`); a *primary* leaves it unset and only
/// serves the feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailReplicationConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Shared bearer token gating the replication feed.
    pub secret: String,
    /// Peer to pull mailbox changes from (secondary only).
    #[serde(default)]
    pub primary_url: Option<String>,
    /// Seconds between pull passes (default 30).
    #[serde(default)]
    pub interval_secs: Option<u64>,
}

/// LDAP syncrepl consumer (RFC 4533 refreshOnly). This instance connects to an
/// upstream LDAP `provider_url` (another Magnetite or OpenLDAP), binds, and pulls
/// directory changes into its own store. Bind credentials live only in this
/// server-side config and are never projected to clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapConsumerConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Upstream provider, `ldap://host:port` (port defaults to 389).
    pub provider_url: String,
    /// Bind DN for the sync session (empty ⇒ anonymous bind).
    #[serde(default)]
    pub bind_dn: String,
    #[serde(default)]
    pub bind_password: String,
    /// Search base to replicate. Defaults to this instance's configured base DN.
    #[serde(default)]
    pub base_dn: Option<String>,
    /// Seconds between refresh passes (default 30).
    #[serde(default)]
    pub interval_secs: Option<u64>,
    /// Change-tracking mode: `"syncrepl"` (RFC 4533, OpenLDAP) — the default — or
    /// `"ad-dirsync"` (Active Directory / Samba AD DC DirSync control).
    #[serde(default)]
    pub mode: Option<String>,
    /// AD DirSync control flags (default 0). Set e.g. `8192` (PUBLIC_DATA_ONLY)
    /// when the bind account lacks the "Replicating Directory Changes" right.
    #[serde(default)]
    pub dirsync_flags: Option<i64>,
    /// AD import: add POSIX attributes (posixAccount/posixGroup, uidNumber/
    /// gidNumber/homeDirectory/loginShell) derived from the object's SID RID.
    #[serde(default)]
    pub posix_mapping: Option<bool>,
    /// Base added to the SID RID to form `uidNumber` (default 100000).
    #[serde(default)]
    pub posix_uid_base: Option<u32>,
    /// Base added to the SID RID / primaryGroupID to form `gidNumber` (default 100000).
    #[serde(default)]
    pub posix_gid_base: Option<u32>,
    /// AD import: detect deletions by periodic full-enumeration reconciliation
    /// (needs only ordinary read access, unlike reading AD tombstones). Local
    /// AD-sourced entries whose object is no longer present upstream are removed.
    #[serde(default)]
    pub reconcile_deletions: Option<bool>,
    /// How many incremental passes between reconciliation passes (default 20).
    #[serde(default)]
    pub reconcile_every: Option<u32>,
}

impl LdapConsumerConfig {
    /// Whether to track changes via the AD/Samba DirSync control instead of RFC
    /// 4533 syncrepl (which Active Directory does not implement). DirSync needs the
    /// bind account to hold the "Replicating Directory Changes" right.
    pub fn is_ad_dirsync(&self) -> bool {
        self.mode
            .as_deref()
            .map(|m| {
                let m = m.trim().to_ascii_lowercase();
                m == "ad-dirsync" || m == "ad_dirsync" || m == "dirsync"
            })
            .unwrap_or(false)
    }

    /// Whether to import from AD/Samba by **USN polling** — an ordinary paged
    /// search tracking `uSNChanged`. Works with a plain read-only account (unlike
    /// DirSync); adds/modifications only (deletions need the Show-Deleted control).
    pub fn is_ad_usn(&self) -> bool {
        self.mode
            .as_deref()
            .map(|m| {
                let m = m.trim().to_ascii_lowercase();
                m == "ad-usn" || m == "ad_usn" || m == "usn"
            })
            .unwrap_or(false)
    }

    /// DirSync control flags (default 0).
    pub fn dirsync_flags(&self) -> i64 {
        self.dirsync_flags.unwrap_or(0)
    }

    /// Whether to add POSIX attributes to imported AD users/groups (default off).
    pub fn posix_mapping(&self) -> bool {
        self.posix_mapping.unwrap_or(false)
    }

    /// Base `uidNumber` offset (default 100000).
    pub fn posix_uid_base(&self) -> u32 {
        self.posix_uid_base.unwrap_or(100_000)
    }

    /// Base `gidNumber` offset (default 100000).
    pub fn posix_gid_base(&self) -> u32 {
        self.posix_gid_base.unwrap_or(100_000)
    }

    /// Whether to reconcile deletions by full enumeration (default off).
    pub fn reconcile_deletions(&self) -> bool {
        self.reconcile_deletions.unwrap_or(false)
    }

    /// Incremental passes between reconciliation passes (default 20, min 1).
    pub fn reconcile_every(&self) -> u32 {
        self.reconcile_every.filter(|n| *n > 0).unwrap_or(20)
    }

    /// Whether the upstream is reached over implicit TLS (`ldaps://`), so the bind
    /// (carrying `bind_password`) and the replicated data never traverse plaintext.
    pub fn is_ldaps(&self) -> bool {
        self.provider_url.trim().starts_with("ldaps://")
    }

    /// The upstream host:port, parsed from `provider_url` (default port 636 for
    /// `ldaps://`, else 389).
    pub fn host_port(&self) -> String {
        let ldaps = self.is_ldaps();
        let raw = self
            .provider_url
            .trim()
            .trim_start_matches("ldap://")
            .trim_start_matches("ldaps://")
            .trim_end_matches('/');
        if raw.contains(':') {
            raw.to_string()
        } else {
            let port = if ldaps { 636 } else { 389 };
            format!("{raw}:{port}")
        }
    }

    /// The upstream hostname without the port, for TLS server-name verification.
    pub fn host(&self) -> String {
        let hp = self.host_port();
        // Split off the trailing `:port`; leave an IPv6 literal (which contains
        // colons) intact by only splitting when the tail parses as a port number.
        match hp.rsplit_once(':') {
            Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !h.is_empty() => h.to_string(),
            _ => hp,
        }
    }

    /// Refresh interval, defaulting to 30 seconds.
    pub fn interval(&self) -> u64 {
        self.interval_secs.filter(|s| *s > 0).unwrap_or(30)
    }
}

impl MailReplicationConfig {
    /// This instance pulls from a primary (it is a secondary) when replication is
    /// enabled and a non-empty `primary_url` is configured.
    pub fn is_secondary(&self) -> bool {
        self.enabled
            && self
                .primary_url
                .as_deref()
                .map(|u| !u.trim().is_empty())
                .unwrap_or(false)
    }

    /// Poll interval, defaulting to 30 seconds.
    pub fn interval(&self) -> u64 {
        self.interval_secs.filter(|s| *s > 0).unwrap_or(30)
    }
}

/// Operational policy: refresh cadence, retention and password rules (09 §7).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default = "default_refresh_secs")]
    pub dashboard_refresh_secs: u64,
    #[serde(default = "default_retention_days")]
    pub retention_days: u32,
    #[serde(default = "default_password_min_length")]
    pub password_min_length: usize,
}

fn default_refresh_secs() -> u64 {
    30
}

fn default_retention_days() -> u32 {
    90
}

fn default_password_min_length() -> usize {
    8
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            dashboard_refresh_secs: default_refresh_secs(),
            retention_days: default_retention_days(),
            password_min_length: default_password_min_length(),
        }
    }
}

/// Configuration errors surfaced during load/validation.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file '{path}': {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
    #[error("config environment substitution: {0}")]
    EnvSubstitution(String),
}

/// Expand `${VAR}` / `${VAR:-default}` references in the raw config text against the
/// process environment, so secrets (feed tokens, bind/relay passwords, SSO client
/// secrets) can live in environment variables rather than in the file on disk.
///
/// - `${VAR}` is replaced by the value of `VAR`; if `VAR` is unset it is an error
///   (a fallback must be given explicitly as `${VAR:-default}`), so a missing secret
///   fails loudly at startup instead of silently binding an empty credential.
/// - `${VAR:-default}` uses `default` when `VAR` is unset or the reference is empty.
/// - `$$` is a literal `$`; a `$` not followed by `{`/`$` is left as-is.
///
/// # Errors
/// [`ConfigError::EnvSubstitution`] on an unterminated/empty reference or an unset
/// variable with no default.
fn expand_env_vars(content: &str) -> Result<String, ConfigError> {
    let mut out = String::with_capacity(content.len());
    let mut chars = content.char_indices().peekable();
    while let Some((_, c)) = chars.next() {
        if c != '$' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            // `$$` → literal `$`.
            Some((_, '$')) => {
                chars.next();
                out.push('$');
            }
            // `${...}` → substitution.
            Some((_, '{')) => {
                chars.next(); // consume '{'
                let rest_start = chars.peek().map(|&(j, _)| j).unwrap_or(content.len());
                let Some(rel) = content[rest_start..].find('}') else {
                    return Err(ConfigError::EnvSubstitution(
                        "unterminated ${...} reference (missing '}')".into(),
                    ));
                };
                let inner = &content[rest_start..rest_start + rel];
                // Advance the iterator past `inner` and the closing '}'.
                while let Some(&(j, _)) = chars.peek() {
                    if j > rest_start + rel {
                        break;
                    }
                    chars.next();
                }
                let (name, default) = match inner.split_once(":-") {
                    Some((n, d)) => (n.trim(), Some(d)),
                    None => (inner.trim(), None),
                };
                if name.is_empty() {
                    return Err(ConfigError::EnvSubstitution(
                        "empty ${} reference in config".into(),
                    ));
                }
                match std::env::var(name)
                    .ok()
                    .or_else(|| default.map(String::from))
                {
                    Some(v) => out.push_str(&v),
                    None => {
                        return Err(ConfigError::EnvSubstitution(format!(
                            "environment variable '{name}' referenced by the config is not set \
                             (use ${{{name}:-default}} to provide a fallback)"
                        )))
                    }
                }
            }
            // A lone '$'.
            _ => out.push('$'),
        }
    }
    Ok(out)
}

impl AppConfig {
    /// Load and validate configuration from a TOML file.
    ///
    /// # Errors
    /// Returns [`ConfigError`] if the file cannot be read, parsed, or fails
    /// validation.
    pub fn load(path: &str) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_string(),
            source,
        })?;
        Self::from_toml_str(&content)
    }

    /// Parse and validate configuration from a TOML string.
    ///
    /// # Errors
    /// Returns [`ConfigError`] if parsing or validation fails.
    pub fn from_toml_str(content: &str) -> Result<Self, ConfigError> {
        let expanded = expand_env_vars(content)?;
        let config: Self = toml::from_str(&expanded)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate invariants that serde cannot express.
    ///
    /// # Errors
    /// Returns [`ConfigError::Invalid`] when a value is out of range.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server.port == 0 {
            return Err(ConfigError::Invalid(
                "server.port must be greater than 0".into(),
            ));
        }
        if self.server.host.trim().is_empty() {
            return Err(ConfigError::Invalid("server.host must not be empty".into()));
        }
        // 05 §1: dashboard refresh is configurable 5..=3600 seconds.
        if !(5..=3600).contains(&self.policy.dashboard_refresh_secs) {
            return Err(ConfigError::Invalid(
                "policy.dashboard_refresh_secs must be between 5 and 3600".into(),
            ));
        }
        if self.policy.password_min_length < 8 {
            return Err(ConfigError::Invalid(
                "policy.password_min_length must be at least 8".into(),
            ));
        }
        for (key, domain) in &self.domains {
            if domain.display_name.trim().is_empty() {
                return Err(ConfigError::Invalid(format!(
                    "domains.{}.display_name must not be empty",
                    key
                )));
            }
            if let Some(server) = &domain.server {
                if let Some(listen) = &server.listen {
                    if listen.parse::<std::net::SocketAddr>().is_err() {
                        return Err(ConfigError::Invalid(format!(
                            "domains.{}.server.listen '{}' is not a valid host:port",
                            key, listen
                        )));
                    }
                }
                if let Some(tls) = &server.tls_listen {
                    if tls.parse::<std::net::SocketAddr>().is_err() {
                        return Err(ConfigError::Invalid(format!(
                            "domains.{}.server.tls_listen '{}' is not a valid host:port",
                            key, tls
                        )));
                    }
                }
                for fwd in &server.forwarders {
                    if fwd.parse::<std::net::SocketAddr>().is_err() {
                        return Err(ConfigError::Invalid(format!(
                            "domains.{}.server.forwarders entry '{}' is not a valid host:port",
                            key, fwd
                        )));
                    }
                }
                if let Some(relay) = &server.relay {
                    if relay.host.trim().is_empty() {
                        return Err(ConfigError::Invalid(format!(
                            "domains.{}.server.relay.host must not be empty",
                            key
                        )));
                    }
                    if relay.port == 0 {
                        return Err(ConfigError::Invalid(format!(
                            "domains.{}.server.relay.port must not be 0",
                            key
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// Whether a domain is present and enabled.
    pub fn is_domain_enabled(&self, key: DomainKey) -> bool {
        self.domains.get(&key).is_some_and(|d| d.enabled)
    }

    /// Enabled domains in canonical presentation order (07 §2 / sidebar).
    pub fn enabled_domains(&self) -> Vec<DomainKey> {
        DomainKey::DOMAINS
            .into_iter()
            .filter(|&k| self.is_domain_enabled(k))
            .collect()
    }

    /// The configured LDAP base DN (naming context), or the default when unset.
    /// Only used to seed the directory root on first run.
    pub fn ldap_base_dn(&self) -> &str {
        self.domains
            .get(&DomainKey::Ldap)
            .and_then(|d| d.base_dn.as_deref())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_LDAP_BASE_DN)
    }

    /// The configured domain SID sub-authorities (after `S-1-5`), or the default
    /// `[21, 1, 2, 3]` when unset or unparseable. Used to seed the DB-persisted domain
    /// SID on first run (the single source of truth for the KDC/SAMR/LDAP/netlogon).
    pub fn domain_sid_subauth(&self) -> Vec<u32> {
        self.domains
            .get(&DomainKey::Ldap)
            .and_then(|d| d.domain_sid.as_deref())
            .map(|s| {
                s.split([' ', '-'])
                    .filter_map(|p| p.trim().parse::<u32>().ok())
                    .collect::<Vec<_>>()
            })
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| DEFAULT_DOMAIN_SID_SUBAUTH.to_vec())
    }
}

/// Default domain SID sub-authorities (`S-1-5-21-1-2-3`) when none is configured.
pub const DEFAULT_DOMAIN_SID_SUBAUTH: [u32; 4] = [21, 1, 2, 3];

/// Default LDAP naming context when none is configured.
pub const DEFAULT_LDAP_BASE_DN: &str = "dc=example,dc=com";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_substitution_default_and_literal_and_errors() {
        // A `${VAR:-default}` for an unset var uses the default.
        assert_eq!(
            expand_env_vars("token = \"${MAGNETITE_UNSET_XYZ:-fallback}\"").unwrap(),
            "token = \"fallback\""
        );
        // `$$` is a literal `$`; a lone `$` and non-`$` text pass through.
        assert_eq!(
            expand_env_vars("cost = $$5 for $x").unwrap(),
            "cost = $5 for $x"
        );
        // A bare `${VAR}` for an unset var is a hard error (no silent empty secret).
        assert!(matches!(
            expand_env_vars("secret = \"${MAGNETITE_UNSET_XYZ}\""),
            Err(ConfigError::EnvSubstitution(_))
        ));
        // An unterminated reference is an error.
        assert!(expand_env_vars("x = \"${OOPS\"").is_err());
    }

    #[test]
    fn env_substitution_reads_the_environment() {
        // Unique name so parallel tests can't collide on process-global env.
        let key = "MAGNETITE_TEST_ENV_SUBST_TOKEN";
        std::env::set_var(key, "s3cr3t-from-env");
        let out = expand_env_vars(&format!("token = \"${{{key}}}\"")).unwrap();
        std::env::remove_var(key);
        assert_eq!(out, "token = \"s3cr3t-from-env\"");
    }

    const VALID_TOML: &str = r#"
[server]
host = "0.0.0.0"
port = 8080
base_url = "http://localhost:8080"

[policy]
dashboard_refresh_secs = 30
retention_days = 90
password_min_length = 8

[domains.dns]
display_name = "DNS"
icon = "dns"
enabled = true

[domains.watch]
display_name = "Watch"
enabled = false
"#;

    #[test]
    fn parses_and_validates() {
        let config = AppConfig::from_toml_str(VALID_TOML).unwrap();
        assert_eq!(config.server.port, 8080);
        assert!(config.sso.is_none());
        assert!(config.is_domain_enabled(DomainKey::Dns));
        assert!(!config.is_domain_enabled(DomainKey::Watch));
        assert!(!config.is_domain_enabled(DomainKey::Ldap));
        assert_eq!(config.enabled_domains(), vec![DomainKey::Dns]);
    }

    #[test]
    fn addc_server_block_parses() {
        // The AD DC is configured via a nested [domains.addc.server.addc] table;
        // TOML implicitly creates the intervening `server` table.
        let toml = r#"
[server]
host = "127.0.0.1"
port = 4000

[domains.addc]
display_name = "AD DC"

[domains.addc.server.addc]
realm = "CONTOSO.COM"
kdc_listen = "0.0.0.0:8888"
"#;
        let config = AppConfig::from_toml_str(toml).unwrap();
        let server = config
            .domains
            .get(&DomainKey::Addc)
            .and_then(|d| d.server.as_ref())
            .expect("addc server block present");
        let addc = server.addc.as_ref().expect("addc config present");
        assert_eq!(addc.realm.as_deref(), Some("CONTOSO.COM"));
        assert_eq!(addc.kdc_listen.as_deref(), Some("0.0.0.0:8888"));
        // Unset listeners stay None — the service fills the well-known defaults.
        assert!(addc.smb_listen.is_none());
        assert!(addc.drs_listen.is_none());
    }

    #[test]
    fn rejects_zero_port() {
        let toml = VALID_TOML.replace("port = 8080", "port = 0");
        let err = AppConfig::from_toml_str(&toml).unwrap_err();
        assert!(err.to_string().contains("port"));
    }

    #[test]
    fn rejects_out_of_range_refresh() {
        let toml = VALID_TOML.replace("dashboard_refresh_secs = 30", "dashboard_refresh_secs = 4");
        let err = AppConfig::from_toml_str(&toml).unwrap_err();
        assert!(err.to_string().contains("dashboard_refresh_secs"));
    }

    #[test]
    fn missing_optional_sections_use_defaults() {
        let toml = r#"
[server]
port = 4000
host = "127.0.0.1"
"#;
        let config = AppConfig::from_toml_str(toml).unwrap();
        assert_eq!(config.policy.dashboard_refresh_secs, 30);
        assert_eq!(config.policy.retention_days, 90);
        assert!(config.domains.is_empty());
    }

    #[test]
    fn load_missing_file_errors() {
        let err = AppConfig::load("/nonexistent/magnetite.toml").unwrap_err();
        assert!(matches!(err, ConfigError::Io { .. }));
    }

    #[test]
    fn ships_valid_default_config() {
        // The example config shipped at the workspace root must always parse — this
        // guards every commented/uncommented domain block (incl. `addc`).
        let content = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../magnetite.toml"));
        let config = AppConfig::from_toml_str(content).expect("shipped magnetite.toml parses");
        // The AD DC domain is declared (served protocol; not a UI DOMAINS tile).
        assert!(config.domains.contains_key(&DomainKey::Addc));
    }

    const DNS_SERVER_TOML: &str = r#"
[server]
host = "127.0.0.1"
port = 4000

[domains.dns]
display_name = "DNS"
enabled = true

[domains.dns.server]
listen = "0.0.0.0:53"
forwarders = ["1.1.1.1:53", "8.8.8.8:53"]
query_log = true
"#;

    #[test]
    fn parses_domain_server_block() {
        let config = AppConfig::from_toml_str(DNS_SERVER_TOML).unwrap();
        let server = config.domains[&DomainKey::Dns].server.as_ref().unwrap();
        assert_eq!(server.listen.as_deref(), Some("0.0.0.0:53"));
        assert_eq!(server.socket().unwrap().port(), 53);
        assert_eq!(server.forwarders.len(), 2);
        assert!(server.query_log);
    }

    #[test]
    fn rejects_bad_server_listen() {
        let toml = DNS_SERVER_TOML.replace("0.0.0.0:53", "not-a-socket");
        let err = AppConfig::from_toml_str(&toml).unwrap_err();
        assert!(err.to_string().contains("listen"));
    }
}
