//! Mail domain repository (07_data_mail / screen_mail): domains (with AC-16
//! delete guard), users, aliases (destination existence), mailing lists (with
//! membership) and the server-config singleton.

use crate::error::{DbError, DbResult};
use crate::records::{parse_rfc3339, record_key, to_rfc3339};

/// Split one mailbox-feed stream cursor `"<timestamp>,<repl_id>"` into its parts. A
/// legacy timestamp-only stream cursor (no `,`) yields an empty key, so the boundary
/// rows are re-fetched (the idempotent apply dedups them) rather than skipped.
fn split_stream_cursor(part: &str) -> (String, String) {
    match part.split_once(',') {
        Some((ts, key)) => (ts.to_string(), key.to_string()),
        None => (part.to_string(), String::new()),
    }
}
use crate::store::Db;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use chrono::{DateTime, Utc};
use magnetite_core::domains::mail::model::{
    Alias, BackupMxDomain, MailDomain, MailFlagUpdate, MailMessage, MailQueueEntry,
    MailRelayConfig, MailReplFeed, MailReplState, MailRole, MailServerConfig, MailUser,
    MailingList, MailingListMember, ReplMessage, ReplyPolicy,
};
use serde::{Deserialize, Serialize};
use surrealdb::types::{RecordId, SurrealValue};
use uuid::Uuid;

/// A received mail message stored by the embedded SMTP server (E4). The mail
/// data model (07_data_mail) has no message entity, so this is the server's own
/// delivery store — one row per accepted local recipient.
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct MailMessageRecord {
    id: Option<RecordId>,
    recipient: String,
    sender: String,
    size_bytes: i64,
    raw: String,
    received_at: String,
    /// Stable UUID for mailbox replication (Step 2). `None` on legacy rows stored
    /// before replication existed; such rows are skipped by the replication feed.
    #[serde(default)]
    repl_id: Option<String>,
    /// JSON-encoded `Vec<String>` of IMAP flags. `None` on legacy rows.
    #[serde(default)]
    flags: Option<String>,
    /// The IMAP folder this message lives in. `None`/absent on rows written before
    /// folders existed — such rows read back as `INBOX`.
    #[serde(default)]
    folder: Option<String>,
}

impl MailMessageRecord {
    fn flags_vec(&self) -> Vec<String> {
        self.flags
            .as_deref()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or_default()
    }

    fn folder_or_inbox(&self) -> String {
        self.folder
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("INBOX")
            .to_string()
    }

    fn into_model(self) -> MailMessage {
        let flags = self.flags_vec();
        let folder = self.folder_or_inbox();
        MailMessage {
            id: record_key(&self.id),
            recipient: self.recipient,
            sender: self.sender,
            size_bytes: self.size_bytes.max(0) as u64,
            received_at: parse_rfc3339(&self.received_at),
            flags,
            folder,
        }
    }
}

/// Encode a flag list as the JSON stored in `mail_message.flags`.
fn encode_flags(flags: &[String]) -> String {
    serde_json::to_string(flags).unwrap_or_else(|_| "[]".into())
}

fn hash_password(password: &str) -> DbResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| DbError::PasswordHash(e.to_string()))
}

/// Split a mailbox-replication cursor `"<msg>|<del>|<flag>"` into its three
/// independent RFC3339 high-water marks (adds, deletions, flag changes). Missing
/// components (e.g. a shorter legacy cursor) yield empty marks (a full sync of
/// that stream).
fn split_repl_cursor(cursor: &str) -> (String, String, String) {
    let mut parts = cursor.splitn(3, '|');
    let msg = parts.next().unwrap_or("").to_string();
    let del = parts.next().unwrap_or("").to_string();
    let flag = parts.next().unwrap_or("").to_string();
    (msg, del, flag)
}

// ---- Records --------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct DomainRecord {
    id: Option<RecordId>,
    name: String,
    enabled: bool,
    max_users: Option<u32>,
    default_quota_bytes: Option<u64>,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl DomainRecord {
    fn into_model(self) -> MailDomain {
        MailDomain {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            name: self.name,
            enabled: self.enabled,
            max_users: self.max_users,
            default_quota_bytes: self.default_quota_bytes,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct UserRecord {
    id: Option<RecordId>,
    local_part: String,
    domain_ref: String,
    email: String,
    display_name: Option<String>,
    mail_role: String,
    quota_bytes: u64,
    used_bytes: u64,
    enabled: bool,
    password_hash: String,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl UserRecord {
    fn into_model(self) -> MailUser {
        MailUser {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            local_part: self.local_part,
            domain_ref: self.domain_ref,
            email: self.email,
            display_name: self.display_name,
            mail_role: if self.mail_role == "admin" {
                MailRole::Admin
            } else {
                MailRole::User
            },
            quota_bytes: self.quota_bytes,
            used_bytes: self.used_bytes,
            enabled: self.enabled,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct AliasRecord {
    id: Option<RecordId>,
    source_address: String,
    domain_ref: String,
    /// JSON-encoded `Vec<String>`.
    destination_addresses: String,
    enabled: bool,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl AliasRecord {
    fn into_model(self) -> Alias {
        Alias {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            source_address: self.source_address,
            domain_ref: self.domain_ref,
            destination_addresses: serde_json::from_str(&self.destination_addresses)
                .unwrap_or_default(),
            enabled: self.enabled,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct ListRecord {
    id: Option<RecordId>,
    address: String,
    domain_ref: String,
    name: String,
    description: Option<String>,
    owner_ref: String,
    /// JSON-encoded `Vec<MailingListMember>`.
    members: String,
    reply_policy: String,
    enabled: bool,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl ListRecord {
    fn members_vec(&self) -> Vec<MailingListMember> {
        serde_json::from_str(&self.members).unwrap_or_default()
    }

    fn into_model(self) -> MailingList {
        let members = self.members_vec();
        MailingList {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            address: self.address,
            domain_ref: self.domain_ref,
            name: self.name,
            description: self.description,
            owner_ref: self.owner_ref,
            members,
            reply_policy: ReplyPolicy::from_str(&self.reply_policy),
            enabled: self.enabled,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct ConfigRecord {
    id: Option<RecordId>,
    /// JSON-encoded `MailServerConfig`.
    config: String,
}

impl Db {
    // ---- Domains ----------------------------------------------------------

    pub async fn list_mail_domains(&self) -> DbResult<Vec<MailDomain>> {
        let recs: Vec<DomainRecord> = self
            .inner
            .query("SELECT * FROM maildomain ORDER BY name ASC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(DomainRecord::into_model).collect())
    }

    async fn find_domain(&self, name: &str) -> DbResult<Option<DomainRecord>> {
        let recs: Vec<DomainRecord> = self
            .inner
            .query("SELECT * FROM maildomain WHERE name = $n LIMIT 1")
            .bind(("n", name.to_string()))
            .await?
            .take(0)?;
        Ok(recs.into_iter().next())
    }

    pub async fn save_mail_domain(&self, domain: &MailDomain) -> DbResult<MailDomain> {
        let now = to_rfc3339(Utc::now());
        if domain.id.is_empty() {
            if self.find_domain(&domain.name).await?.is_some() {
                return Err(DbError::Constraint("同じ名称が既に存在します。".into()));
            }
            let rec = DomainRecord {
                id: None,
                name: domain.name.clone(),
                enabled: domain.enabled,
                max_users: domain.max_users,
                default_quota_bytes: domain.default_quota_bytes,
                created_at: now.clone(),
                updated_at: now,
                created_by: domain.created_by.clone(),
            };
            let created: Option<DomainRecord> =
                self.inner.create("maildomain").content(rec).await?;
            created
                .map(DomainRecord::into_model)
                .ok_or_else(|| DbError::Constraint("domain creation failed".into()))
        } else {
            let updated: Vec<DomainRecord> = self
                .inner
                .query("UPDATE type::record('maildomain', $id) SET enabled = $en, max_users = $mu, default_quota_bytes = $q, updated_at = $t")
                .bind(("id", domain.id.clone()))
                .bind(("en", domain.enabled))
                .bind(("mu", domain.max_users))
                .bind(("q", domain.default_quota_bytes))
                .bind(("t", now))
                .await?
                .take(0)?;
            updated
                .into_iter()
                .next()
                .map(DomainRecord::into_model)
                .ok_or(DbError::NotFound)
        }
    }

    /// Accounts (users + aliases) referencing a domain, for the AC-16 guard.
    pub async fn count_domain_accounts(&self, name: &str) -> DbResult<usize> {
        let users: Vec<UserRecord> = self
            .inner
            .query("SELECT * FROM mailuser WHERE domain_ref = $n")
            .bind(("n", name.to_string()))
            .await?
            .take(0)?;
        let aliases: Vec<AliasRecord> = self
            .inner
            .query("SELECT * FROM alias WHERE domain_ref = $n")
            .bind(("n", name.to_string()))
            .await?
            .take(0)?;
        Ok(users.len() + aliases.len())
    }

    /// Delete a domain, refused when accounts still reference it (AC-16).
    pub async fn delete_mail_domain(&self, id: &str, name: &str) -> DbResult<()> {
        let count = self.count_domain_accounts(name).await?;
        if count > 0 {
            return Err(DbError::Constraint(format!(
                "このドメインには {count} 件のアカウントがあります。"
            )));
        }
        let _: Option<DomainRecord> = self.inner.delete(("maildomain", id)).await?;
        Ok(())
    }

    // ---- Users ------------------------------------------------------------

    pub async fn list_mail_users(&self) -> DbResult<Vec<MailUser>> {
        let recs: Vec<UserRecord> = self
            .inner
            .query("SELECT * FROM mailuser ORDER BY email ASC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(UserRecord::into_model).collect())
    }

    async fn mail_user_exists(&self, email: &str) -> DbResult<bool> {
        let recs: Vec<UserRecord> = self
            .inner
            .query("SELECT * FROM mailuser WHERE email = $e LIMIT 1")
            .bind(("e", email.to_string()))
            .await?
            .take(0)?;
        Ok(!recs.is_empty())
    }

    /// Create a mail user (email derived, password hashed).
    pub async fn create_mail_user(
        &self,
        local_part: &str,
        domain: &str,
        display_name: Option<&str>,
        quota_bytes: u64,
        password: &str,
        actor: &str,
    ) -> DbResult<MailUser> {
        if self.find_domain(domain).await?.is_none() {
            return Err(DbError::Constraint("いずれかを選択してください。".into()));
        }
        let email = format!("{local_part}@{domain}");
        if self.mail_user_exists(&email).await? {
            return Err(DbError::Constraint("同じ名称が既に存在します。".into()));
        }
        let now = to_rfc3339(Utc::now());
        let rec = UserRecord {
            id: None,
            local_part: local_part.to_string(),
            domain_ref: domain.to_string(),
            email,
            display_name: display_name
                .filter(|d| !d.is_empty())
                .map(|d| d.to_string()),
            mail_role: "user".into(),
            quota_bytes,
            used_bytes: 0,
            enabled: true,
            password_hash: hash_password(password)?,
            created_at: now.clone(),
            updated_at: now,
            created_by: actor.to_string(),
        };
        let created: Option<UserRecord> = self.inner.create("mailuser").content(rec).await?;
        created
            .map(UserRecord::into_model)
            .ok_or_else(|| DbError::Constraint("user creation failed".into()))
    }

    pub async fn set_mail_user_enabled(&self, id: &str, enabled: bool) -> DbResult<()> {
        self.inner
            .query("UPDATE type::record('mailuser', $id) SET enabled = $v, updated_at = $t")
            .bind(("id", id.to_string()))
            .bind(("v", enabled))
            .bind(("t", to_rfc3339(Utc::now())))
            .await?;
        Ok(())
    }

    /// Reset a mail user's login password (Argon2-hashed, for POP3/IMAP AUTH). Used by the
    /// admin password-reset path and to set a real password on accounts a Maildir import
    /// created with a temporary one.
    ///
    /// # Errors
    /// A password-hash failure or a store error.
    pub async fn set_mail_user_password(&self, id: &str, password: &str) -> DbResult<()> {
        let hash = hash_password(password)?;
        self.inner
            .query("UPDATE type::record('mailuser', $id) SET password_hash = $h, updated_at = $t")
            .bind(("id", id.to_string()))
            .bind(("h", hash))
            .bind(("t", to_rfc3339(Utc::now())))
            .await?;
        Ok(())
    }

    pub async fn delete_mail_user(&self, id: &str) -> DbResult<()> {
        let _: Option<UserRecord> = self.inner.delete(("mailuser", id)).await?;
        Ok(())
    }

    // ---- Aliases ----------------------------------------------------------

    pub async fn list_aliases(&self) -> DbResult<Vec<Alias>> {
        let recs: Vec<AliasRecord> = self
            .inner
            .query("SELECT * FROM alias ORDER BY source_address ASC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(AliasRecord::into_model).collect())
    }

    /// Create or update an alias; every destination must be an existing mail
    /// user (AC-16).
    pub async fn save_alias(&self, alias: &Alias) -> DbResult<()> {
        for dest in &alias.destination_addresses {
            if !self.mail_user_exists(dest).await? {
                return Err(DbError::Constraint(
                    "宛先のアカウントが存在しません。".into(),
                ));
            }
        }
        let dests = serde_json::to_string(&alias.destination_addresses).unwrap_or_default();
        let now = to_rfc3339(Utc::now());
        if alias.id.is_empty() {
            let rec = AliasRecord {
                id: None,
                source_address: alias.source_address.clone(),
                domain_ref: alias.domain_ref.clone(),
                destination_addresses: dests,
                enabled: alias.enabled,
                created_at: now.clone(),
                updated_at: now,
                created_by: alias.created_by.clone(),
            };
            let _: Option<AliasRecord> = self.inner.create("alias").content(rec).await?;
        } else {
            self.inner
                .query("UPDATE type::record('alias', $id) SET destination_addresses = $d, enabled = $en, updated_at = $t")
                .bind(("id", alias.id.clone()))
                .bind(("d", dests))
                .bind(("en", alias.enabled))
                .bind(("t", now))
                .await?;
        }
        Ok(())
    }

    pub async fn delete_alias(&self, id: &str) -> DbResult<()> {
        let _: Option<AliasRecord> = self.inner.delete(("alias", id)).await?;
        Ok(())
    }

    // ---- Mailing lists ----------------------------------------------------

    pub async fn list_mailing_lists(&self) -> DbResult<Vec<MailingList>> {
        let recs: Vec<ListRecord> = self
            .inner
            .query("SELECT * FROM mailinglist ORDER BY address ASC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(ListRecord::into_model).collect())
    }

    async fn find_list(&self, id: &str) -> DbResult<Option<ListRecord>> {
        let rec: Option<ListRecord> = self.inner.select(("mailinglist", id)).await?;
        Ok(rec)
    }

    /// Create a mailing list (owner must be an existing mail user).
    pub async fn create_mailing_list(
        &self,
        address: &str,
        domain: &str,
        name: &str,
        owner: &str,
        reply_policy: ReplyPolicy,
        actor: &str,
    ) -> DbResult<MailingList> {
        if !self.mail_user_exists(owner).await? {
            return Err(DbError::Constraint(
                "オーナーのアカウントが存在しません。".into(),
            ));
        }
        let now = to_rfc3339(Utc::now());
        let rec = ListRecord {
            id: None,
            address: address.to_string(),
            domain_ref: domain.to_string(),
            name: name.to_string(),
            description: None,
            owner_ref: owner.to_string(),
            members: "[]".into(),
            reply_policy: reply_policy.as_str().to_string(),
            enabled: true,
            created_at: now.clone(),
            updated_at: now,
            created_by: actor.to_string(),
        };
        let created: Option<ListRecord> = self.inner.create("mailinglist").content(rec).await?;
        created
            .map(ListRecord::into_model)
            .ok_or_else(|| DbError::Constraint("list creation failed".into()))
    }

    pub async fn delete_mailing_list(&self, id: &str) -> DbResult<()> {
        let _: Option<ListRecord> = self.inner.delete(("mailinglist", id)).await?;
        Ok(())
    }

    async fn write_members(&self, id: &str, members: &[MailingListMember]) -> DbResult<()> {
        let json = serde_json::to_string(members).unwrap_or_default();
        self.inner
            .query("UPDATE type::record('mailinglist', $id) SET members = $m, updated_at = $t")
            .bind(("id", id.to_string()))
            .bind(("m", json))
            .bind(("t", to_rfc3339(Utc::now())))
            .await?;
        Ok(())
    }

    pub async fn add_list_member(&self, id: &str, member: MailingListMember) -> DbResult<()> {
        let list = self.find_list(id).await?.ok_or(DbError::NotFound)?;
        let mut members = list.members_vec();
        if members
            .iter()
            .any(|m| m.email.eq_ignore_ascii_case(&member.email))
        {
            return Err(DbError::Constraint("同じ名称が既に存在します。".into()));
        }
        members.push(member);
        self.write_members(id, &members).await
    }

    pub async fn remove_list_member(&self, id: &str, email: &str) -> DbResult<()> {
        let list = self.find_list(id).await?.ok_or(DbError::NotFound)?;
        let mut members = list.members_vec();
        members.retain(|m| !m.email.eq_ignore_ascii_case(email));
        self.write_members(id, &members).await
    }

    // ---- Server config ----------------------------------------------------

    pub async fn get_mail_config(&self) -> DbResult<MailServerConfig> {
        let recs: Vec<ConfigRecord> = self
            .inner
            .query("SELECT * FROM mailserverconfig LIMIT 1")
            .await?
            .take(0)?;
        if let Some(rec) = recs.into_iter().next() {
            if let Ok(cfg) = serde_json::from_str(&rec.config) {
                return Ok(cfg);
            }
        }
        let default = MailServerConfig::default();
        self.save_mail_config(&default).await?;
        Ok(default)
    }

    pub async fn save_mail_config(&self, config: &MailServerConfig) -> DbResult<()> {
        let json = serde_json::to_string(config).unwrap_or_default();
        let recs: Vec<ConfigRecord> = self
            .inner
            .query("SELECT * FROM mailserverconfig LIMIT 1")
            .await?
            .take(0)?;
        if recs.is_empty() {
            let rec = ConfigRecord {
                id: None,
                config: json,
            };
            let _: Option<ConfigRecord> =
                self.inner.create("mailserverconfig").content(rec).await?;
        } else {
            self.inner
                .query("UPDATE mailserverconfig SET config = $c")
                .bind(("c", json))
                .await?;
        }
        Ok(())
    }

    // ---- Outbound relay (smarthost) settings ------------------------------

    /// The stored outbound-relay (smarthost) settings, or `None` when never seeded
    /// (⇒ direct MX delivery). Includes the secret password for server-side use; the
    /// server-fn layer scrubs it before projecting to clients.
    pub async fn get_mail_relay(&self) -> DbResult<Option<MailRelayConfig>> {
        let recs: Vec<ConfigRecord> = self
            .inner
            .query("SELECT * FROM mailrelayconfig LIMIT 1")
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .next()
            .and_then(|rec| serde_json::from_str(&rec.config).ok()))
    }

    /// Seed the relay settings from `seed` (the file config) on first run and return
    /// the effective value. If a row already exists (operator-edited), it wins and
    /// `seed` is ignored. `seed` `None` with no row leaves relaying disabled.
    pub async fn ensure_mail_relay(
        &self,
        seed: Option<MailRelayConfig>,
    ) -> DbResult<Option<MailRelayConfig>> {
        if let Some(existing) = self.get_mail_relay().await? {
            return Ok(Some(existing));
        }
        match seed {
            Some(cfg) => {
                self.save_mail_relay(&cfg).await?;
                Ok(Some(cfg))
            }
            None => Ok(None),
        }
    }

    /// Create or replace the relay settings (upsert the singleton). Applied without a
    /// restart — the mail server re-reads them per connection.
    pub async fn save_mail_relay(&self, config: &MailRelayConfig) -> DbResult<()> {
        let json = serde_json::to_string(config).unwrap_or_default();
        let recs: Vec<ConfigRecord> = self
            .inner
            .query("SELECT * FROM mailrelayconfig LIMIT 1")
            .await?
            .take(0)?;
        if recs.is_empty() {
            let rec = ConfigRecord {
                id: None,
                config: json,
            };
            let _: Option<ConfigRecord> = self.inner.create("mailrelayconfig").content(rec).await?;
        } else {
            self.inner
                .query("UPDATE mailrelayconfig SET config = $c")
                .bind(("c", json))
                .await?;
        }
        Ok(())
    }

    /// Metrics: user / domain / list counts + total used bytes.
    pub async fn mail_metrics(&self) -> DbResult<(usize, usize, usize, u64)> {
        let users = self.list_mail_users().await?;
        let domains = self.list_mail_domains().await?.len();
        let lists = self.list_mailing_lists().await?.len();
        let used: u64 = users.iter().map(|u| u.used_bytes).sum();
        Ok((users.len(), domains, lists, used))
    }

    // ---- Received-message store (E4 SMTP server) --------------------------

    /// Store one received message for a local `recipient` in `INBOX`, assigning a fresh
    /// replication id (Step 2 mailbox sync).
    pub async fn store_mail_message(
        &self,
        recipient: &str,
        sender: &str,
        raw: &str,
    ) -> DbResult<()> {
        self.store_message_record(recipient, "INBOX", sender, raw, &[], Utc::now())
            .await
    }

    /// Store one imported message with full fidelity — its original **folder**, IMAP
    /// **flags** and **received date** preserved. Used by the Maildir importer so a
    /// migrated mailbox keeps its layout, read/unread state and dates. Assigns a fresh
    /// replication id so the message also replicates to a secondary.
    ///
    /// # Errors
    /// A store error.
    pub async fn store_imported_message(
        &self,
        recipient: &str,
        folder: &str,
        sender: &str,
        raw: &str,
        flags: &[String],
        received_at: DateTime<Utc>,
    ) -> DbResult<()> {
        self.store_message_record(recipient, folder, sender, raw, flags, received_at)
            .await
    }

    /// The shared writer behind [`Self::store_mail_message`] and
    /// [`Self::store_imported_message`].
    async fn store_message_record(
        &self,
        recipient: &str,
        folder: &str,
        sender: &str,
        raw: &str,
        flags: &[String],
        received_at: DateTime<Utc>,
    ) -> DbResult<()> {
        let folder = if folder.trim().is_empty() {
            "INBOX"
        } else {
            folder
        };
        let rec = MailMessageRecord {
            id: None,
            recipient: recipient.to_string(),
            sender: sender.to_string(),
            size_bytes: raw.len() as i64,
            raw: raw.to_string(),
            received_at: to_rfc3339(received_at),
            repl_id: Some(Uuid::new_v4().to_string()),
            flags: Some(encode_flags(flags)),
            folder: Some(folder.to_string()),
        };
        let _: Option<MailMessageRecord> = self.inner.create("mail_message").content(rec).await?;
        Ok(())
    }

    /// Total number of stored messages. Projects only the id so the (potentially large)
    /// RFC822 bodies are not loaded just to count rows.
    pub async fn count_mail_messages(&self) -> DbResult<usize> {
        let ids: Vec<serde_json::Value> = self
            .inner
            .query("SELECT VALUE id FROM mail_message")
            .await?
            .take(0)?;
        Ok(ids.len())
    }

    /// Number of stored messages for a recipient (mailbox size). Projects only the id
    /// so message bodies are not loaded.
    pub async fn count_mail_messages_for(&self, recipient: &str) -> DbResult<usize> {
        let ids: Vec<serde_json::Value> = self
            .inner
            .query("SELECT VALUE id FROM mail_message WHERE recipient = $r")
            .bind(("r", recipient.to_string()))
            .await?
            .take(0)?;
        Ok(ids.len())
    }

    /// Deliver a message to a local mailbox, enforcing the user's quota
    /// (08_dhcp_logic-style: refuse when over quota). Increments `used_bytes`.
    /// Returns whether the message was stored (`false` = mailbox full).
    pub async fn deliver_to_mailbox(&self, email: &str, sender: &str, raw: &str) -> DbResult<bool> {
        let users: Vec<UserRecord> = self
            .inner
            .query("SELECT * FROM mailuser WHERE email = $e LIMIT 1")
            .bind(("e", email.to_string()))
            .await?
            .take(0)?;
        let size = raw.len() as u64;
        if let Some(user) = users.first() {
            if user.quota_bytes > 0 && user.used_bytes.saturating_add(size) > user.quota_bytes {
                return Ok(false);
            }
            self.store_mail_message(email, sender, raw).await?;
            self.inner
                .query("UPDATE mailuser SET used_bytes = used_bytes + $s WHERE email = $e")
                .bind(("s", size as i64))
                .bind(("e", email.to_string()))
                .await?;
            Ok(true)
        } else {
            // No matching mailbox (shouldn't happen post-validation) — store anyway.
            self.store_mail_message(email, sender, raw).await?;
            Ok(true)
        }
    }

    /// Verify a mail user's credentials (POP3/IMAP AUTH). Returns the user on
    /// success; performs a dummy hash on a missing user to avoid a timing oracle.
    pub async fn verify_mail_login(
        &self,
        email: &str,
        password: &str,
    ) -> DbResult<Option<MailUser>> {
        let users: Vec<UserRecord> = self
            .inner
            .query("SELECT * FROM mailuser WHERE email = $e LIMIT 1")
            .bind(("e", email.to_string()))
            .await?
            .take(0)?;
        let Some(user) = users.into_iter().next() else {
            let salt = SaltString::generate(&mut OsRng);
            let _ = Argon2::default().hash_password(password.as_bytes(), &salt);
            return Ok(None);
        };
        if !user.enabled {
            return Ok(None);
        }
        let Ok(parsed) = PasswordHash::new(&user.password_hash) else {
            return Ok(None);
        };
        if Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
        {
            Ok(Some(user.into_model()))
        } else {
            Ok(None)
        }
    }

    /// Fetch a mailbox's messages oldest-first as `(id, raw)` for POP3/IMAP
    /// retrieval.
    pub async fn fetch_mailbox_raw(&self, recipient: &str) -> DbResult<Vec<(String, String)>> {
        let recs: Vec<MailMessageRecord> = self
            .inner
            .query("SELECT * FROM mail_message WHERE recipient = $r ORDER BY received_at ASC")
            .bind(("r", recipient.to_string()))
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .map(|r| (record_key(&r.id), r.raw))
            .collect())
    }

    /// The raw body of a stored message by id (webmail read).
    pub async fn get_mail_message_raw(&self, id: &str) -> DbResult<Option<String>> {
        let rec: Option<MailMessageRecord> = self.inner.select(("mail_message", id)).await?;
        Ok(rec.map(|r| r.raw))
    }

    /// List a recipient's messages in one IMAP `folder`, newest-first (metadata only).
    /// `INBOX` is matched case-insensitively (and covers legacy rows that predate
    /// folders); any other folder is matched exactly.
    ///
    /// # Errors
    /// A store error.
    pub async fn list_mailbox_folder(
        &self,
        recipient: &str,
        folder: &str,
        limit: usize,
    ) -> DbResult<Vec<MailMessage>> {
        let recs: Vec<MailMessageRecord> = self
            .inner
            .query("SELECT * FROM mail_message WHERE recipient = $r ORDER BY received_at DESC")
            .bind(("r", recipient.to_string()))
            .await?
            .take(0)?;
        let is_inbox = folder.eq_ignore_ascii_case("INBOX");
        Ok(recs
            .into_iter()
            .filter(|m| {
                let mf = m.folder_or_inbox();
                if is_inbox {
                    mf.eq_ignore_ascii_case("INBOX")
                } else {
                    mf == folder
                }
            })
            .take(limit)
            .map(MailMessageRecord::into_model)
            .collect())
    }

    /// The distinct IMAP folder names in a recipient's mailbox (always including
    /// `INBOX`), for the IMAP `LIST` response and the mailbox UI.
    ///
    /// # Errors
    /// A store error.
    pub async fn list_folders(&self, recipient: &str) -> DbResult<Vec<String>> {
        // Project only the folder column so message bodies are not loaded just to
        // collect the distinct folder names.
        let folders: Vec<Option<String>> = self
            .inner
            .query("SELECT VALUE folder FROM mail_message WHERE recipient = $r")
            .bind(("r", recipient.to_string()))
            .await?
            .take(0)?;
        let mut set: std::collections::BTreeSet<String> = folders
            .into_iter()
            .map(|f| {
                f.filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "INBOX".to_string())
            })
            .collect();
        set.insert("INBOX".to_string());
        Ok(set.into_iter().collect())
    }

    /// Delete a stored message by id (POP3 DELE on QUIT / IMAP expunge). Records a
    /// replication tombstone by `repl_id` so a secondary can mirror the deletion.
    pub async fn delete_mail_message(&self, id: &str) -> DbResult<()> {
        let existing: Option<MailMessageRecord> = self.inner.select(("mail_message", id)).await?;
        let _: Option<MailMessageRecord> = self.inner.delete(("mail_message", id)).await?;
        if let Some(repl_id) = existing.and_then(|m| m.repl_id) {
            let rec = MailChangeRecord {
                id: None,
                repl_id,
                csn: to_rfc3339(Utc::now()),
            };
            let _: Option<MailChangeRecord> =
                self.inner.create("mail_changelog").content(rec).await?;
        }
        Ok(())
    }

    /// List stored messages, newest-first, optionally for one recipient
    /// (metadata only; the raw body is not projected).
    pub async fn list_mail_messages(
        &self,
        recipient: Option<&str>,
        limit: usize,
    ) -> DbResult<Vec<MailMessage>> {
        let recs: Vec<MailMessageRecord> = match recipient {
            Some(r) => self
                .inner
                .query(
                    "SELECT * FROM mail_message WHERE recipient = $r \
                         ORDER BY received_at DESC LIMIT $l",
                )
                .bind(("r", r.to_string()))
                .bind(("l", limit as i64))
                .await?
                .take(0)?,
            None => self
                .inner
                .query("SELECT * FROM mail_message ORDER BY received_at DESC LIMIT $l")
                .bind(("l", limit as i64))
                .await?
                .take(0)?,
        };
        Ok(recs
            .into_iter()
            .map(MailMessageRecord::into_model)
            .collect())
    }
}

// ---- Backup MX (secondary MX) + durable forwarding queue ------------------

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct BackupMxRecord {
    id: Option<RecordId>,
    name: String,
    primary_host: String,
    primary_port: u32,
    enabled: bool,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl BackupMxRecord {
    fn into_model(self) -> BackupMxDomain {
        BackupMxDomain {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            name: self.name,
            primary_host: self.primary_host,
            primary_port: self.primary_port.min(u16::MAX as u32) as u16,
            enabled: self.enabled,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct MailQueueRecord {
    id: Option<RecordId>,
    sender: String,
    /// JSON-encoded `Vec<String>`.
    recipients: String,
    primary_host: String,
    primary_port: u32,
    /// The complete RFC 5322 message to forward.
    raw: String,
    size_bytes: i64,
    attempts: u32,
    next_attempt: String,
    last_error: Option<String>,
    created_at: String,
}

impl MailQueueRecord {
    fn recipients_vec(&self) -> Vec<String> {
        serde_json::from_str(&self.recipients).unwrap_or_default()
    }

    fn into_entry(self) -> MailQueueEntry {
        let recipients = self.recipients_vec();
        MailQueueEntry {
            id: record_key(&self.id),
            sender: self.sender,
            recipients,
            primary_host: self.primary_host,
            primary_port: self.primary_port.min(u16::MAX as u32) as u16,
            size_bytes: self.size_bytes.max(0) as u64,
            attempts: self.attempts,
            next_attempt: parse_rfc3339(&self.next_attempt),
            last_error: self.last_error,
            created_at: parse_rfc3339(&self.created_at),
        }
    }
}

/// A queued message ready to forward, carried to the retry task (includes the
/// raw body, unlike the projection-safe [`MailQueueEntry`]).
#[derive(Debug, Clone)]
pub struct QueuedForward {
    pub id: String,
    pub sender: String,
    pub recipients: Vec<String>,
    pub primary_host: String,
    pub primary_port: u16,
    pub raw: String,
    pub attempts: u32,
}

impl Db {
    // ---- Backup MX domains ------------------------------------------------

    /// All configured backup-MX domains (enabled and disabled), name-ordered.
    pub async fn list_backup_mx(&self) -> DbResult<Vec<BackupMxDomain>> {
        let recs: Vec<BackupMxRecord> = self
            .inner
            .query("SELECT * FROM backup_mx ORDER BY name ASC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(BackupMxRecord::into_model).collect())
    }

    async fn find_backup_mx(&self, name: &str) -> DbResult<Option<BackupMxRecord>> {
        let recs: Vec<BackupMxRecord> = self
            .inner
            .query("SELECT * FROM backup_mx WHERE name = $n LIMIT 1")
            .bind(("n", name.to_string()))
            .await?
            .take(0)?;
        Ok(recs.into_iter().next())
    }

    /// Create (empty id) or update a backup-MX domain. A hosted domain and a
    /// backup domain of the same name are mutually exclusive (one is authoritative,
    /// the other is a relay), so creation is refused when the name is hosted.
    pub async fn save_backup_mx(&self, domain: &BackupMxDomain) -> DbResult<BackupMxDomain> {
        let now = to_rfc3339(Utc::now());
        if domain.id.is_empty() {
            if self.find_backup_mx(&domain.name).await?.is_some() {
                return Err(DbError::Constraint("同じ名称が既に存在します。".into()));
            }
            if self.find_domain(&domain.name).await?.is_some() {
                return Err(DbError::Constraint(
                    "このドメインはローカルにホストされています。バックアップ MX にはできません。"
                        .into(),
                ));
            }
            let rec = BackupMxRecord {
                id: None,
                name: domain.name.clone(),
                primary_host: domain.primary_host.clone(),
                primary_port: domain.primary_port as u32,
                enabled: domain.enabled,
                created_at: now.clone(),
                updated_at: now,
                created_by: domain.created_by.clone(),
            };
            let created: Option<BackupMxRecord> =
                self.inner.create("backup_mx").content(rec).await?;
            created
                .map(BackupMxRecord::into_model)
                .ok_or_else(|| DbError::Constraint("backup MX creation failed".into()))
        } else {
            let updated: Vec<BackupMxRecord> = self
                .inner
                .query("UPDATE type::record('backup_mx', $id) SET primary_host = $h, primary_port = $p, enabled = $en, updated_at = $t")
                .bind(("id", domain.id.clone()))
                .bind(("h", domain.primary_host.clone()))
                .bind(("p", domain.primary_port as u32))
                .bind(("en", domain.enabled))
                .bind(("t", now))
                .await?
                .take(0)?;
            updated
                .into_iter()
                .next()
                .map(BackupMxRecord::into_model)
                .ok_or(DbError::NotFound)
        }
    }

    /// Delete a backup-MX domain by id.
    pub async fn delete_backup_mx(&self, id: &str) -> DbResult<()> {
        let _: Option<BackupMxRecord> = self.inner.delete(("backup_mx", id)).await?;
        Ok(())
    }

    // ---- Forwarding queue -------------------------------------------------

    /// Park a message in the backup-MX queue for forwarding to the primary. The
    /// first attempt is due immediately.
    pub async fn enqueue_backup_mail(
        &self,
        sender: &str,
        recipients: &[String],
        primary_host: &str,
        primary_port: u16,
        raw: &str,
    ) -> DbResult<()> {
        let now = to_rfc3339(Utc::now());
        let rec = MailQueueRecord {
            id: None,
            sender: sender.to_string(),
            recipients: serde_json::to_string(recipients).unwrap_or_else(|_| "[]".into()),
            primary_host: primary_host.to_string(),
            primary_port: primary_port as u32,
            raw: raw.to_string(),
            size_bytes: raw.len() as i64,
            attempts: 0,
            next_attempt: now.clone(),
            last_error: None,
            created_at: now,
        };
        let _: Option<MailQueueRecord> = self.inner.create("mail_queue").content(rec).await?;
        Ok(())
    }

    /// Queued messages whose next attempt is due at or before now, oldest-first.
    pub async fn due_backup_queue(&self, limit: usize) -> DbResult<Vec<QueuedForward>> {
        let now = to_rfc3339(Utc::now());
        let recs: Vec<MailQueueRecord> = self
            .inner
            .query(
                "SELECT * FROM mail_queue WHERE next_attempt <= $now \
                     ORDER BY next_attempt ASC LIMIT $l",
            )
            .bind(("now", now))
            .bind(("l", limit as i64))
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .map(|r| {
                let recipients = r.recipients_vec();
                QueuedForward {
                    id: record_key(&r.id),
                    sender: r.sender,
                    recipients,
                    primary_host: r.primary_host,
                    primary_port: r.primary_port.min(u16::MAX as u32) as u16,
                    raw: r.raw,
                    attempts: r.attempts,
                }
            })
            .collect())
    }

    /// Reschedule a failed forward: bump the attempt count, set the next-attempt
    /// time and record the error.
    pub async fn reschedule_backup_mail(
        &self,
        id: &str,
        attempts: u32,
        next_attempt: chrono::DateTime<Utc>,
        last_error: &str,
    ) -> DbResult<()> {
        self.inner
            .query("UPDATE type::record('mail_queue', $id) SET attempts = $a, next_attempt = $n, last_error = $e")
            .bind(("id", id.to_string()))
            .bind(("a", attempts))
            .bind(("n", to_rfc3339(next_attempt)))
            .bind(("e", last_error.to_string()))
            .await?;
        Ok(())
    }

    /// Remove a queued message (delivered to the primary, or given up).
    pub async fn delete_backup_queue(&self, id: &str) -> DbResult<()> {
        let _: Option<MailQueueRecord> = self.inner.delete(("mail_queue", id)).await?;
        Ok(())
    }

    /// The current forwarding queue as projection-safe metadata, oldest-first.
    pub async fn list_backup_queue(&self, limit: usize) -> DbResult<Vec<MailQueueEntry>> {
        let recs: Vec<MailQueueRecord> = self
            .inner
            .query("SELECT * FROM mail_queue ORDER BY created_at ASC LIMIT $l")
            .bind(("l", limit as i64))
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(MailQueueRecord::into_entry).collect())
    }

    /// Number of messages currently in the forwarding queue. Projects only the id so
    /// queued message bodies are not loaded.
    pub async fn count_backup_queue(&self) -> DbResult<usize> {
        let ids: Vec<serde_json::Value> = self
            .inner
            .query("SELECT VALUE id FROM mail_queue")
            .await?
            .take(0)?;
        Ok(ids.len())
    }
}

// ---- Mailbox replication (Step 2: Magnetite-to-Magnetite HA) --------------

/// A deletion tombstone for mailbox replication: the `repl_id` of a message that
/// was removed, and the change sequence number (an RFC3339 timestamp) so a
/// secondary can mirror deletions since its cursor.
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct MailChangeRecord {
    id: Option<RecordId>,
    repl_id: String,
    csn: String,
}

/// A flag-change record for mailbox replication: a message's `repl_id`, its new
/// flag set (JSON-encoded `Vec<String>`), and the change sequence number.
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct MailFlagChangeRecord {
    id: Option<RecordId>,
    repl_id: String,
    flags: String,
    csn: String,
}

/// Persisted secondary-side replication state (singleton row).
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct MailReplStateRecord {
    id: Option<RecordId>,
    cursor: String,
    last_sync: Option<String>,
    applied: u64,
    deleted: u64,
    last_error: Option<String>,
}

impl Db {
    // ---- Provider side (primary serves the feed) --------------------------

    /// Build the replication feed for a secondary. The `cursor` is an opaque
    /// `"<msg>|<del>|<flag>"` triple of per-stream cursors (empty ⇒ full sync). Adds,
    /// deletions and flag changes advance on **independent** cursors so a late change
    /// in one stream can never skip un-synced items in another. Each stream cursor is a
    /// compound `"<timestamp>,<repl_id>"` (the `repl_id` breaks ties so a page filled
    /// exactly at a shared timestamp does not skip the rest) — legacy timestamp-only
    /// stream cursors are still accepted. Legacy messages without a `repl_id` are excluded.
    pub async fn mail_repl_feed(&self, cursor: &str, limit: usize) -> DbResult<MailReplFeed> {
        let (msg_part, del_part, flag_part) = split_repl_cursor(cursor);
        let (msg_ts, msg_key) = split_stream_cursor(&msg_part);
        let (del_ts, del_key) = split_stream_cursor(&del_part);
        let (flag_ts, flag_key) = split_stream_cursor(&flag_part);

        let recs: Vec<MailMessageRecord> = self
            .inner
            .query(
                "SELECT * FROM mail_message \
                 WHERE (received_at > $ts OR (received_at = $ts AND repl_id > $k)) \
                    AND repl_id != NONE \
                 ORDER BY received_at ASC, repl_id ASC LIMIT $l",
            )
            .bind(("ts", msg_ts.clone()))
            .bind(("k", msg_key.clone()))
            .bind(("l", limit as i64))
            .await?
            .take(0)?;
        let new_msg = recs
            .last()
            .and_then(|r| {
                r.repl_id
                    .as_ref()
                    .map(|id| format!("{},{}", r.received_at, id))
            })
            .unwrap_or(msg_part);
        let messages: Vec<ReplMessage> = recs
            .into_iter()
            .filter_map(|r| {
                let flags = r.flags_vec();
                let folder = r.folder_or_inbox();
                r.repl_id.map(|repl_id| ReplMessage {
                    repl_id,
                    recipient: r.recipient,
                    sender: r.sender,
                    raw: r.raw,
                    received_at: parse_rfc3339(&r.received_at),
                    flags,
                    folder,
                })
            })
            .collect();

        let dels: Vec<MailChangeRecord> = self
            .inner
            .query(
                "SELECT * FROM mail_changelog \
                 WHERE csn > $ts OR (csn = $ts AND repl_id > $k) \
                 ORDER BY csn ASC, repl_id ASC LIMIT $l",
            )
            .bind(("ts", del_ts))
            .bind(("k", del_key))
            .bind(("l", limit as i64))
            .await?
            .take(0)?;
        let new_del = dels
            .last()
            .map(|d| format!("{},{}", d.csn, d.repl_id))
            .unwrap_or(del_part);
        let deletions: Vec<String> = dels.iter().map(|d| d.repl_id.clone()).collect();

        let flag_recs: Vec<MailFlagChangeRecord> = self
            .inner
            .query(
                "SELECT * FROM mail_flags_changelog \
                 WHERE csn > $ts OR (csn = $ts AND repl_id > $k) \
                 ORDER BY csn ASC, repl_id ASC LIMIT $l",
            )
            .bind(("ts", flag_ts))
            .bind(("k", flag_key))
            .bind(("l", limit as i64))
            .await?
            .take(0)?;
        let new_flag = flag_recs
            .last()
            .map(|f| format!("{},{}", f.csn, f.repl_id))
            .unwrap_or(flag_part);
        let flag_updates: Vec<MailFlagUpdate> = flag_recs
            .iter()
            .map(|f| MailFlagUpdate {
                repl_id: f.repl_id.clone(),
                flags: serde_json::from_str(&f.flags).unwrap_or_default(),
            })
            .collect();

        Ok(MailReplFeed {
            messages,
            deletions,
            flag_updates,
            cursor: format!("{new_msg}|{new_del}|{new_flag}"),
        })
    }

    // ---- Consumer side (secondary applies the feed) -----------------------

    /// Apply a replicated message idempotently: insert it under the primary's
    /// `repl_id` unless a message with that id already exists. Returns whether a
    /// new row was inserted.
    pub async fn apply_replicated_message(&self, msg: &ReplMessage) -> DbResult<bool> {
        let existing: Vec<MailMessageRecord> = self
            .inner
            .query("SELECT * FROM mail_message WHERE repl_id = $r LIMIT 1")
            .bind(("r", msg.repl_id.clone()))
            .await?
            .take(0)?;
        if !existing.is_empty() {
            return Ok(false);
        }
        let rec = MailMessageRecord {
            id: None,
            recipient: msg.recipient.clone(),
            sender: msg.sender.clone(),
            size_bytes: msg.raw.len() as i64,
            raw: msg.raw.clone(),
            received_at: to_rfc3339(msg.received_at),
            repl_id: Some(msg.repl_id.clone()),
            flags: Some(encode_flags(&msg.flags)),
            folder: Some(msg.folder.clone()),
        };
        let _: Option<MailMessageRecord> = self.inner.create("mail_message").content(rec).await?;
        Ok(true)
    }

    /// Apply a replicated flag change: set the flags of the message with `repl_id`
    /// if present. Returns whether a row was updated. Does **not** write a local
    /// changelog entry (avoids a replication feedback loop).
    pub async fn apply_replicated_flags(&self, repl_id: &str, flags: &[String]) -> DbResult<bool> {
        let existing: Vec<MailMessageRecord> = self
            .inner
            .query("SELECT * FROM mail_message WHERE repl_id = $r LIMIT 1")
            .bind(("r", repl_id.to_string()))
            .await?
            .take(0)?;
        if existing.is_empty() {
            return Ok(false);
        }
        self.inner
            .query("UPDATE mail_message SET flags = $f WHERE repl_id = $r")
            .bind(("f", encode_flags(flags)))
            .bind(("r", repl_id.to_string()))
            .await?;
        Ok(true)
    }

    /// Set the IMAP flags of a stored message by id (IMAP STORE / `\Seen` on
    /// fetch), recording a replication flag change by `repl_id` so a secondary
    /// can mirror it.
    pub async fn set_mail_flags(&self, id: &str, flags: &[String]) -> DbResult<()> {
        let Some(rec): Option<MailMessageRecord> = self.inner.select(("mail_message", id)).await?
        else {
            return Ok(());
        };
        let encoded = encode_flags(flags);
        self.inner
            .query("UPDATE type::record('mail_message', $id) SET flags = $f")
            .bind(("id", id.to_string()))
            .bind(("f", encoded.clone()))
            .await?;
        if let Some(repl_id) = rec.repl_id {
            let change = MailFlagChangeRecord {
                id: None,
                repl_id,
                flags: encoded,
                csn: to_rfc3339(Utc::now()),
            };
            let _: Option<MailFlagChangeRecord> = self
                .inner
                .create("mail_flags_changelog")
                .content(change)
                .await?;
        }
        Ok(())
    }

    /// Apply a replicated deletion: remove the message with `repl_id` if present.
    /// Returns whether a row was removed.
    pub async fn apply_replicated_deletion(&self, repl_id: &str) -> DbResult<bool> {
        let existing: Vec<MailMessageRecord> = self
            .inner
            .query("SELECT * FROM mail_message WHERE repl_id = $r")
            .bind(("r", repl_id.to_string()))
            .await?
            .take(0)?;
        if existing.is_empty() {
            return Ok(false);
        }
        self.inner
            .query("DELETE mail_message WHERE repl_id = $r")
            .bind(("r", repl_id.to_string()))
            .await?;
        Ok(true)
    }

    /// The secondary's persisted replication state (defaults when never synced).
    pub async fn get_mail_repl_state(&self) -> DbResult<MailReplState> {
        let recs: Vec<MailReplStateRecord> = self
            .inner
            .query("SELECT * FROM mail_repl_state LIMIT 1")
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .next()
            .map(|r| MailReplState {
                cursor: r.cursor,
                last_sync: r.last_sync.as_deref().map(parse_rfc3339),
                applied: r.applied,
                deleted: r.deleted,
                last_error: r.last_error,
            })
            .unwrap_or_default())
    }

    /// Persist the secondary's replication state after a pull pass. `applied` /
    /// `deleted` are added to the running totals.
    pub async fn record_mail_repl_sync(
        &self,
        cursor: &str,
        applied: u64,
        deleted: u64,
        last_error: Option<&str>,
    ) -> DbResult<()> {
        let prev = self.get_mail_repl_state().await?;
        let now = to_rfc3339(Utc::now());
        let applied_total = prev.applied + applied;
        let deleted_total = prev.deleted + deleted;
        let err = last_error.map(|s| s.to_string());
        // Singleton upsert without DELETE (DELETE errors on a not-yet-created
        // table in SurrealDB 3.x): create the row on first sync, else update it.
        let existing: Vec<MailReplStateRecord> = self
            .inner
            .query("SELECT * FROM mail_repl_state LIMIT 1")
            .await?
            .take(0)?;
        if existing.is_empty() {
            let rec = MailReplStateRecord {
                id: None,
                cursor: cursor.to_string(),
                last_sync: Some(now),
                applied: applied_total,
                deleted: deleted_total,
                last_error: err,
            };
            let _: Option<MailReplStateRecord> =
                self.inner.create("mail_repl_state").content(rec).await?;
        } else {
            self.inner
                .query(
                    "UPDATE mail_repl_state SET cursor = $c, last_sync = $t, \
                         applied = $a, deleted = $d, last_error = $e",
                )
                .bind(("c", cursor.to_string()))
                .bind(("t", now))
                .bind(("a", applied_total))
                .bind(("d", deleted_total))
                .bind(("e", err))
                .await?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct MailDkimRecord {
    id: Option<RecordId>,
    domain: String,
    selector: String,
    /// PKCS#8 PEM private key — server-side material, never projected.
    private_key_pem: String,
    enabled: bool,
}

impl Db {
    // ---- DKIM (outbound signing keys) -------------------------------------

    /// The DKIM selector + private key (PKCS#8 PEM) for a domain, when signing
    /// is enabled. Server-side secret; never projected to clients.
    pub async fn get_mail_dkim(&self, domain: &str) -> DbResult<Option<(String, String)>> {
        let recs: Vec<MailDkimRecord> = self
            .inner
            .query("SELECT * FROM mail_dkim WHERE domain = $d AND enabled = true LIMIT 1")
            .bind(("d", domain.to_ascii_lowercase()))
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .next()
            .map(|r| (r.selector, r.private_key_pem)))
    }

    /// DKIM config for a domain regardless of enabled state: the selector, the
    /// enabled flag, and the PKCS#8 PEM private key. The private key is
    /// server-side material (used to re-derive the public TXT record) and must
    /// never be projected to clients.
    pub async fn get_mail_dkim_any(
        &self,
        domain: &str,
    ) -> DbResult<Option<(String, bool, String)>> {
        let recs: Vec<MailDkimRecord> = self
            .inner
            .query("SELECT * FROM mail_dkim WHERE domain = $d LIMIT 1")
            .bind(("d", domain.to_ascii_lowercase()))
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .next()
            .map(|r| (r.selector, r.enabled, r.private_key_pem)))
    }

    /// Enable or disable DKIM signing for a domain, preserving its stored key.
    pub async fn set_mail_dkim_enabled(&self, domain: &str, enabled: bool) -> DbResult<()> {
        self.inner
            .query("UPDATE mail_dkim SET enabled = $e WHERE domain = $d")
            .bind(("d", domain.to_ascii_lowercase()))
            .bind(("e", enabled))
            .await?;
        Ok(())
    }

    /// Store (or replace) a domain's DKIM signing config.
    pub async fn save_mail_dkim(
        &self,
        domain: &str,
        selector: &str,
        private_key_pem: &str,
        enabled: bool,
    ) -> DbResult<()> {
        let domain = domain.to_ascii_lowercase();
        self.inner
            .query("DELETE mail_dkim WHERE domain = $d")
            .bind(("d", domain.clone()))
            .await?;
        self.inner
            .query(
                "CREATE mail_dkim CONTENT { domain: $d, selector: $s, private_key_pem: $k, enabled: $e }",
            )
            .bind(("d", domain))
            .bind(("s", selector.to_string()))
            .bind(("k", private_key_pem.to_string()))
            .bind(("e", enabled))
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_db() -> (Db, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        (db, dir)
    }

    #[tokio::test]
    async fn mail_relay_seed_and_upsert() {
        let (db, _dir) = test_db().await;
        // Unseeded ⇒ None (direct MX).
        assert!(db.get_mail_relay().await.unwrap().is_none());
        // ensure with None seed leaves it unset.
        assert!(db.ensure_mail_relay(None).await.unwrap().is_none());
        // Seed from the file config on first run.
        let seed = MailRelayConfig {
            enabled: true,
            host: "smtp.example.com".into(),
            port: 587,
            username: Some("user".into()),
            password: Some("secret".into()),
        };
        let effective = db.ensure_mail_relay(Some(seed.clone())).await.unwrap();
        assert_eq!(effective, Some(seed.clone()));
        // A later ensure (e.g. next restart) does not overwrite the stored value.
        let other = MailRelayConfig {
            host: "other.example.com".into(),
            ..seed.clone()
        };
        assert_eq!(
            db.ensure_mail_relay(Some(other)).await.unwrap(),
            Some(seed.clone())
        );
        // A UI save replaces it (secret included).
        let updated = MailRelayConfig {
            host: "relay2.example.com".into(),
            password: Some("newsecret".into()),
            ..seed
        };
        db.save_mail_relay(&updated).await.unwrap();
        assert_eq!(db.get_mail_relay().await.unwrap(), Some(updated));
    }

    fn new_domain(name: &str) -> MailDomain {
        MailDomain {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "admin".into(),
            name: name.into(),
            enabled: true,
            max_users: None,
            default_quota_bytes: None,
        }
    }

    #[tokio::test]
    async fn domain_delete_guarded_by_users() {
        let (db, _dir) = test_db().await;
        db.save_mail_domain(&new_domain("example.com"))
            .await
            .unwrap();
        let d = db.list_mail_domains().await.unwrap().remove(0);
        db.create_mail_user("alice", "example.com", None, 0, "pw", "admin")
            .await
            .unwrap();
        assert!(db.delete_mail_domain(&d.id, "example.com").await.is_err());
    }

    #[tokio::test]
    async fn alias_requires_existing_destination() {
        let (db, _dir) = test_db().await;
        db.save_mail_domain(&new_domain("example.com"))
            .await
            .unwrap();
        db.create_mail_user("bob", "example.com", None, 0, "pw", "admin")
            .await
            .unwrap();
        let ok_alias = Alias {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "admin".into(),
            source_address: "sales@example.com".into(),
            domain_ref: "example.com".into(),
            destination_addresses: vec!["bob@example.com".into()],
            enabled: true,
        };
        assert!(db.save_alias(&ok_alias).await.is_ok());
        let bad_alias = Alias {
            destination_addresses: vec!["ghost@example.com".into()],
            source_address: "info@example.com".into(),
            ..ok_alias
        };
        assert!(db.save_alias(&bad_alias).await.is_err());
    }

    #[tokio::test]
    async fn mailing_list_membership() {
        let (db, _dir) = test_db().await;
        db.save_mail_domain(&new_domain("example.com"))
            .await
            .unwrap();
        db.create_mail_user("owner", "example.com", None, 0, "pw", "admin")
            .await
            .unwrap();
        let list = db
            .create_mailing_list(
                "team@example.com",
                "example.com",
                "Team",
                "owner@example.com",
                ReplyPolicy::List,
                "admin",
            )
            .await
            .unwrap();
        db.add_list_member(
            &list.id,
            MailingListMember {
                email: "x@ext.com".into(),
                name: None,
                receive: true,
                can_post: true,
            },
        )
        .await
        .unwrap();
        assert_eq!(db.list_mailing_lists().await.unwrap()[0].members.len(), 1);
        db.remove_list_member(&list.id, "x@ext.com").await.unwrap();
        assert_eq!(db.list_mailing_lists().await.unwrap()[0].members.len(), 0);
    }

    #[tokio::test]
    async fn config_roundtrip() {
        let (db, _dir) = test_db().await;
        let cfg = db.get_mail_config().await.unwrap();
        assert_eq!(cfg.protocols.len(), 7);
        let mut updated = cfg;
        updated.hostname = "smtp.example.org".into();
        db.save_mail_config(&updated).await.unwrap();
        assert_eq!(
            db.get_mail_config().await.unwrap().hostname,
            "smtp.example.org"
        );
    }

    #[tokio::test]
    async fn imported_message_preserves_folder_flags_and_date() {
        let (db, _dir) = test_db().await;
        let when = DateTime::parse_from_rfc2822("Tue, 01 Jan 2019 10:00:00 +0000")
            .unwrap()
            .with_timezone(&Utc);

        // A full-fidelity import into a subfolder, and an ordinary INBOX delivery.
        db.store_imported_message(
            "bob@example.com",
            "Lists/dev",
            "list@x.test",
            "Subject: hi\r\n\r\nbody",
            &["\\Seen".to_string(), "\\Flagged".to_string()],
            when,
        )
        .await
        .unwrap();
        db.store_mail_message("bob@example.com", "a@x.test", "Subject: inbox\r\n\r\nx")
            .await
            .unwrap();

        // Folder enumeration includes INBOX + the imported subfolder.
        let folders = db.list_folders("bob@example.com").await.unwrap();
        assert_eq!(folders, vec!["INBOX".to_string(), "Lists/dev".to_string()]);

        // Count projections (SELECT VALUE ...) count rows without loading bodies.
        assert_eq!(db.count_mail_messages().await.unwrap(), 2);
        assert_eq!(
            db.count_mail_messages_for("bob@example.com").await.unwrap(),
            2
        );

        // The subfolder view carries the imported message with its flags + date.
        let sub = db
            .list_mailbox_folder("bob@example.com", "Lists/dev", 100)
            .await
            .unwrap();
        assert_eq!(sub.len(), 1);
        assert_eq!(sub[0].folder, "Lists/dev");
        assert_eq!(sub[0].flags, vec!["\\Seen", "\\Flagged"]);
        assert_eq!(sub[0].received_at, when);

        // INBOX shows only the ordinary delivery (not the subfolder message).
        let inbox = db
            .list_mailbox_folder("bob@example.com", "INBOX", 100)
            .await
            .unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].folder, "INBOX");
    }

    #[tokio::test]
    async fn mail_repl_feed_paginates_past_same_received_at() {
        let (db, _dir) = test_db().await;
        // Three messages sharing the exact same received_at (a bulk import within one
        // clock tick), each with a distinct repl_id.
        let when = DateTime::parse_from_rfc3339("2026-01-01T00:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc);
        for i in 0..3 {
            db.store_imported_message(
                "bob@x.test",
                "INBOX",
                "a@x.test",
                &format!("Subject: m{i}\r\n\r\nbody"),
                &[],
                when,
            )
            .await
            .unwrap();
        }
        // Page the message stream with limit 1: the compound (received_at, repl_id)
        // cursor must serve all three rather than skipping the ones past the first page.
        let mut seen = std::collections::BTreeSet::new();
        let mut cursor = String::new();
        for _ in 0..6 {
            let feed = db.mail_repl_feed(&cursor, 1).await.unwrap();
            if feed.messages.is_empty() {
                break;
            }
            for m in &feed.messages {
                seen.insert(m.repl_id.clone());
            }
            cursor = feed.cursor;
        }
        assert_eq!(seen.len(), 3);
    }
}
