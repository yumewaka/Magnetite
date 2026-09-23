//! Mail domain data (07_data_mail). Domain references use the domain *name*
//! (unique) and address references use the full email, avoiding id lookups.
//!
//! Mail users are managed data, deliberately separate from Magnetite login
//! identities.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Mail-level role (distinct from the platform RBAC `Role`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MailRole {
    #[default]
    User,
    Admin,
}

/// A mail account (07_data_mail §2.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailUser {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub local_part: String,
    /// Owning domain name.
    pub domain_ref: String,
    /// `{local_part}@{domain_ref}`.
    pub email: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub mail_role: MailRole,
    /// 0 = unlimited.
    pub quota_bytes: u64,
    pub used_bytes: u64,
    pub enabled: bool,
}

/// A mail domain (07_data_mail §2.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailDomain {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub name: String,
    pub enabled: bool,
    #[serde(default)]
    pub max_users: Option<u32>,
    #[serde(default)]
    pub default_quota_bytes: Option<u64>,
}

/// A backup-MX domain (mail redundancy / interop). Magnetite acts as a secondary
/// MX for `name`: it accepts inbound mail for the domain and forwards it to the
/// primary at `primary_host:primary_port` from a durable queue, retrying while
/// the primary is unreachable. Distinct from a hosted [`MailDomain`] — no local
/// mailboxes are involved; the message is only relayed onward.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMxDomain {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    /// The domain we are a backup MX for (e.g. `example.com`).
    pub name: String,
    /// The primary server to forward queued mail to.
    pub primary_host: String,
    /// The primary's SMTP port (usually 25).
    pub primary_port: u16,
    pub enabled: bool,
}

/// A message parked in the backup-MX forwarding queue. Projection-safe metadata
/// only — the raw message body is never included, so this is safe to send to
/// browser clients for a queue view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailQueueEntry {
    pub id: String,
    pub sender: String,
    pub recipients: Vec<String>,
    pub primary_host: String,
    pub primary_port: u16,
    pub size_bytes: u64,
    pub attempts: u32,
    pub next_attempt: DateTime<Utc>,
    #[serde(default)]
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// One replicated mailbox message on the wire (Step 2 mailbox sync). Carries the
/// full raw body, so it is a **server-to-server** payload only — never projected
/// to browser clients. `repl_id` is a stable UUID assigned at store time, used
/// for idempotent apply and deletion reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplMessage {
    pub repl_id: String,
    pub recipient: String,
    pub sender: String,
    pub raw: String,
    pub received_at: DateTime<Utc>,
    /// IMAP flags at the time of the feed (so a full sync carries flag state).
    #[serde(default)]
    pub flags: Vec<String>,
    /// The IMAP folder the message lives in (so a full sync preserves folder layout).
    /// `#[serde(default)]` so a peer that predates folders replicates into `INBOX`.
    #[serde(default = "default_folder")]
    pub folder: String,
}

/// A message whose IMAP flags changed on the primary, replicated by `repl_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailFlagUpdate {
    pub repl_id: String,
    pub flags: Vec<String>,
}

/// The mailbox replication feed a primary serves to a secondary: messages added,
/// messages deleted, and flag changes since the requested cursor, plus the
/// primary's new cursor to poll from next. Server-to-server only (raw bodies).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailReplFeed {
    pub messages: Vec<ReplMessage>,
    /// `repl_id`s deleted on the primary since the cursor.
    pub deletions: Vec<String>,
    /// Flag changes on the primary since the cursor.
    #[serde(default)]
    pub flag_updates: Vec<MailFlagUpdate>,
    /// The cursor to request next (the primary's current high-water mark).
    pub cursor: String,
}

/// Secondary-side replication status (projection-safe; no message bodies), for
/// the management UI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MailReplState {
    pub cursor: String,
    #[serde(default)]
    pub last_sync: Option<DateTime<Utc>>,
    pub applied: u64,
    pub deleted: u64,
    #[serde(default)]
    pub last_error: Option<String>,
}

/// A forwarding alias (07_data_mail §2.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alias {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub source_address: String,
    pub domain_ref: String,
    pub destination_addresses: Vec<String>,
    pub enabled: bool,
}

/// Reply-to policy for a mailing list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplyPolicy {
    List,
    Sender,
    Both,
}

impl ReplyPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            ReplyPolicy::List => "list",
            ReplyPolicy::Sender => "sender",
            ReplyPolicy::Both => "both",
        }
    }

    pub fn from_str(value: &str) -> Self {
        match value {
            "sender" => ReplyPolicy::Sender,
            "both" => ReplyPolicy::Both,
            _ => ReplyPolicy::List,
        }
    }
}

/// A mailing-list subscriber (07_data_mail §2.4.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailingListMember {
    pub email: String,
    #[serde(default)]
    pub name: Option<String>,
    pub receive: bool,
    pub can_post: bool,
}

/// A mailing list (07_data_mail §2.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailingList {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    pub address: String,
    pub domain_ref: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub owner_ref: String,
    pub members: Vec<MailingListMember>,
    pub reply_policy: ReplyPolicy,
    pub enabled: bool,
}

/// SMTP/IMAP/POP protocol identifiers (07_data_mail §2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailProtocol {
    Smtp,
    SmtpSubmission,
    Smtps,
    Imap,
    Imaps,
    Pop3,
    Pop3s,
}

impl MailProtocol {
    pub const ALL: [MailProtocol; 7] = [
        MailProtocol::Smtp,
        MailProtocol::SmtpSubmission,
        MailProtocol::Smtps,
        MailProtocol::Imap,
        MailProtocol::Imaps,
        MailProtocol::Pop3,
        MailProtocol::Pop3s,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            MailProtocol::Smtp => "smtp",
            MailProtocol::SmtpSubmission => "smtp_submission",
            MailProtocol::Smtps => "smtps",
            MailProtocol::Imap => "imap",
            MailProtocol::Imaps => "imaps",
            MailProtocol::Pop3 => "pop3",
            MailProtocol::Pop3s => "pop3s",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            MailProtocol::Smtp => "SMTP",
            MailProtocol::SmtpSubmission => "SMTP Submission",
            MailProtocol::Smtps => "SMTPS",
            MailProtocol::Imap => "IMAP",
            MailProtocol::Imaps => "IMAPS",
            MailProtocol::Pop3 => "POP3",
            MailProtocol::Pop3s => "POP3S",
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            MailProtocol::Smtp => 25,
            MailProtocol::SmtpSubmission => 587,
            MailProtocol::Smtps => 465,
            MailProtocol::Imap => 143,
            MailProtocol::Imaps => 993,
            MailProtocol::Pop3 => 110,
            MailProtocol::Pop3s => 995,
        }
    }
}

/// Per-protocol settings (07_data_mail §2.5).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ProtocolConfig {
    pub enabled: bool,
    pub port: u16,
}

/// Mail server settings singleton (07_data_mail §2.6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailServerConfig {
    pub hostname: String,
    pub max_message_size_bytes: u64,
    /// Keyed by [`MailProtocol::as_str`].
    pub protocols: BTreeMap<String, ProtocolConfig>,
    pub acme_enabled: bool,
    #[serde(default)]
    pub acme_email: Option<String>,
    #[serde(default)]
    pub acme_domains: Vec<String>,
    /// Name of the [`crate::domains::proxy::model::Certificate`] presented on the
    /// TLS ports (SMTPS/IMAPS/POP3S). `None` disables implicit TLS.
    #[serde(default)]
    pub tls_cert_name: Option<String>,
}

impl Default for MailServerConfig {
    fn default() -> Self {
        let protocols = MailProtocol::ALL
            .into_iter()
            .map(|p| {
                (
                    p.as_str().to_string(),
                    ProtocolConfig {
                        enabled: !matches!(p, MailProtocol::Pop3),
                        port: p.default_port(),
                    },
                )
            })
            .collect();
        Self {
            hostname: "mail.example.com".into(),
            max_message_size_bytes: 26_214_400,
            protocols,
            acme_enabled: false,
            acme_email: None,
            acme_domains: Vec::new(),
            tls_cert_name: None,
        }
    }
}

/// Outbound SMTP relay / smarthost settings singleton, editable from the Web UI.
/// Seeded on first run from the file config's `[domains.mail.server.relay]`, then
/// owned by the DB (DB wins). The `password` is a secret: it is stored server-side
/// but scrubbed before projection to clients, and preserved on save when the client
/// submits it empty.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MailRelayConfig {
    /// When `false`, outbound mail is delivered directly to the recipient MX (no relay).
    #[serde(default)]
    pub enabled: bool,
    /// Smarthost address to submit outbound mail to.
    #[serde(default)]
    pub host: String,
    /// Smarthost port (default 25).
    #[serde(default = "default_relay_port")]
    pub port: u16,
    /// Optional SMTP AUTH username for the smarthost.
    #[serde(default)]
    pub username: Option<String>,
    /// Optional SMTP AUTH password for the smarthost (secret; never projected).
    #[serde(default)]
    pub password: Option<String>,
}

fn default_relay_port() -> u16 {
    25
}

impl Default for MailRelayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: String::new(),
            port: default_relay_port(),
            username: None,
            password: None,
        }
    }
}

/// A received message stored by the embedded SMTP server (E4). The mail data
/// model has no message entity in the spec; this is the server's delivery
/// store, surfaced read-only in the mailbox screen. `raw` is not projected here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailMessage {
    pub id: String,
    pub recipient: String,
    pub sender: String,
    pub size_bytes: u64,
    pub received_at: DateTime<Utc>,
    /// IMAP flags set on this message (e.g. `\Seen`, `\Flagged`, `\Deleted`).
    #[serde(default)]
    pub flags: Vec<String>,
    /// The IMAP folder (mailbox) this message lives in — `INBOX` for ordinary
    /// delivery, or an imported/created folder name (`/`-separated hierarchy).
    /// `#[serde(default)]` so records written before folders existed read as `INBOX`.
    #[serde(default = "default_folder")]
    pub folder: String,
}

/// The default IMAP folder — `INBOX` — for ordinary delivery and for messages/records
/// written before the folder concept existed.
#[must_use]
pub fn default_folder() -> String {
    "INBOX".to_string()
}
