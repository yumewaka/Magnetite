//! Proxy domain repository (07_data_proxy / screen_proxy): virtual hosts,
//! certificates (with reference guard), ACL rules and IP blocks (priority +
//! toggle). Access logs and health arrive with daemon/log integration.

use crate::error::{DbError, DbResult};
use crate::records::{parse_rfc3339, record_key, to_rfc3339};
use crate::store::Db;
use chrono::Utc;
use magnetite_core::config::AcmeConfig;
use magnetite_core::domains::proxy::model::{
    AclAction, AclRule, AclScope, Certificate, IpBlock, LbStrategy, ProxyMode, VirtualHost,
};
use serde::{Deserialize, Serialize};
use surrealdb::types::{RecordId, SurrealValue};

const MSG_HOSTNAME_DUP: &str = "同じホスト名とパスの組み合わせが既に存在します。";

/// The comparable path-prefix key for vhost uniqueness: an absent prefix and an empty one
/// both mean the whole-host default route, so they collide; any other prefix is distinct.
fn path_key(path_prefix: &Option<String>) -> &str {
    path_prefix.as_deref().unwrap_or("")
}
const MSG_CERT_DUP: &str = "同じ証明書名が既に存在します。";
const MSG_REFERENCED: &str = "他の設定から参照されているため削除できません。";

fn proxy_mode_str(m: ProxyMode) -> &'static str {
    match m {
        ProxyMode::Http => "http",
        ProxyMode::Tcp => "tcp",
    }
}
fn proxy_mode_from(s: &str) -> ProxyMode {
    match s {
        "tcp" => ProxyMode::Tcp,
        // Legacy "https" rows (the removed mode) load as HTTP — TLS is governed by
        // `tls_enabled`, not the mode — so they route again and re-save as "http".
        _ => ProxyMode::Http,
    }
}
fn lb_str(s: LbStrategy) -> &'static str {
    match s {
        LbStrategy::RoundRobin => "round_robin",
        LbStrategy::LeastConn => "least_conn",
        LbStrategy::IpHash => "ip_hash",
        LbStrategy::Weighted => "weighted",
    }
}
fn lb_from(s: &str) -> LbStrategy {
    match s {
        "least_conn" => LbStrategy::LeastConn,
        "ip_hash" => LbStrategy::IpHash,
        "weighted" => LbStrategy::Weighted,
        _ => LbStrategy::RoundRobin,
    }
}

// ---- Records --------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct VhostRecord {
    id: Option<RecordId>,
    hostname: String,
    /// Optional path prefix (nginx `location`); absent on rows predating path routing.
    #[serde(default)]
    path_prefix: Option<String>,
    listen_port: u16,
    /// JSON-encoded `Vec<Upstream>`.
    upstream: String,
    tls_enabled: bool,
    certificate_ref: Option<String>,
    force_https: bool,
    proxy_mode: String,
    lb_strategy: String,
    enabled: bool,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl VhostRecord {
    fn into_model(self) -> VirtualHost {
        VirtualHost {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            hostname: self.hostname,
            path_prefix: self.path_prefix,
            listen_port: self.listen_port,
            upstream: serde_json::from_str(&self.upstream).unwrap_or_default(),
            tls_enabled: self.tls_enabled,
            certificate_ref: self.certificate_ref,
            force_https: self.force_https,
            proxy_mode: proxy_mode_from(&self.proxy_mode),
            lb_strategy: lb_from(&self.lb_strategy),
            enabled: self.enabled,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct CertRecord {
    id: Option<RecordId>,
    name: String,
    subject: String,
    issuer: String,
    /// JSON-encoded `Vec<String>`.
    san: String,
    serial: Option<String>,
    fingerprint_sha256: Option<String>,
    not_before: String,
    not_after: String,
    cert_pem: String,
    chain_pem: Option<String>,
    /// PEM-encoded private key. Stored server-side, never projected to clients
    /// (05 §5). At-rest encryption is deferred (09 §12 R8).
    #[serde(default)]
    key_pem: Option<String>,
    key_present: bool,
    created_at: String,
    updated_at: String,
    created_by: String,
}

/// A small internal proxy setting (key/value). Backs [`Db::get_proxy_kv`] /
/// [`Db::set_proxy_kv`]; used to persist the ACME account credentials.
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct ProxyKvRecord {
    id: Option<RecordId>,
    key: String,
    value: String,
    updated_at: String,
}

/// Singleton row holding the JSON-serialised ACME settings (DB-backed so they can be edited
/// from the Web UI and hot-reloaded by the ACME manager without a restart).
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct AcmeConfigRecord {
    id: Option<RecordId>,
    config: String,
}

/// TLS material for a certificate, loaded by the embedded servers to terminate
/// TLS. Never leaves the server process.
#[derive(Debug, Clone)]
pub struct CertMaterial {
    /// Leaf certificate (PEM), followed by any chain PEM.
    pub cert_chain_pem: String,
    /// Private key (PEM).
    pub key_pem: String,
}

impl CertRecord {
    fn into_model(self) -> Certificate {
        Certificate {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            name: self.name,
            subject: self.subject,
            issuer: self.issuer,
            san: serde_json::from_str(&self.san).unwrap_or_default(),
            serial: self.serial,
            fingerprint_sha256: self.fingerprint_sha256,
            not_before: parse_rfc3339(&self.not_before),
            not_after: parse_rfc3339(&self.not_after),
            key_present: self.key_present,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct AclRecord {
    id: Option<RecordId>,
    cidr: String,
    action: String,
    scope: String,
    vhost_ref: Option<String>,
    priority: i32,
    enabled: bool,
    description: Option<String>,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl AclRecord {
    fn into_model(self) -> AclRule {
        AclRule {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            cidr: self.cidr,
            action: AclAction::from_str(&self.action),
            scope: if self.scope == "vhost" {
                AclScope::Vhost
            } else {
                AclScope::Global
            },
            vhost_ref: self.vhost_ref,
            priority: self.priority,
            enabled: self.enabled,
            description: self.description,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct IpBlockRecord {
    id: Option<RecordId>,
    cidr: String,
    reason: Option<String>,
    ord: i32,
    expires_at: Option<String>,
    enabled: bool,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl IpBlockRecord {
    fn into_model(self) -> IpBlock {
        IpBlock {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            cidr: self.cidr,
            reason: self.reason,
            order: self.ord,
            expires_at: self.expires_at.as_deref().map(parse_rfc3339),
            enabled: self.enabled,
        }
    }
}

impl Db {
    // ---- Virtual hosts ----------------------------------------------------

    pub async fn list_vhosts(&self) -> DbResult<Vec<VirtualHost>> {
        let recs: Vec<VhostRecord> = self
            .inner
            .query("SELECT * FROM vhost ORDER BY hostname ASC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(VhostRecord::into_model).collect())
    }

    /// An existing vhost with the same (hostname, path_prefix) as the arguments, if any.
    /// Uniqueness is per (host, path): the same host may hold several path-routed vhosts
    /// (e.g. `/` and `/export`), so only an identical (hostname, path_prefix) collides.
    /// An absent and an empty path_prefix both mean the whole-host default route.
    async fn find_vhost_by_host_and_path(
        &self,
        hostname: &str,
        path_prefix: &Option<String>,
    ) -> DbResult<Option<VhostRecord>> {
        let recs: Vec<VhostRecord> = self
            .inner
            .query("SELECT * FROM vhost WHERE hostname = $h")
            .bind(("h", hostname.to_ascii_lowercase()))
            .await?
            .take(0)?;
        let want = path_key(path_prefix);
        Ok(recs.into_iter().find(|r| path_key(&r.path_prefix) == want))
    }

    pub async fn save_vhost(&self, vhost: &VirtualHost) -> DbResult<VirtualHost> {
        let now = to_rfc3339(Utc::now());
        let upstream = serde_json::to_string(&vhost.upstream).unwrap_or_default();
        if vhost.id.is_empty() {
            if self
                .find_vhost_by_host_and_path(&vhost.hostname, &vhost.path_prefix)
                .await?
                .is_some()
            {
                return Err(DbError::Constraint(MSG_HOSTNAME_DUP.into()));
            }
            let rec = VhostRecord {
                id: None,
                hostname: vhost.hostname.to_ascii_lowercase(),
                path_prefix: vhost.path_prefix.clone(),
                listen_port: vhost.listen_port,
                upstream,
                tls_enabled: vhost.tls_enabled,
                certificate_ref: vhost.certificate_ref.clone(),
                force_https: vhost.force_https,
                proxy_mode: proxy_mode_str(vhost.proxy_mode).into(),
                lb_strategy: lb_str(vhost.lb_strategy).into(),
                enabled: vhost.enabled,
                created_at: now.clone(),
                updated_at: now,
                created_by: vhost.created_by.clone(),
            };
            let created: Option<VhostRecord> = self.inner.create("vhost").content(rec).await?;
            created
                .map(VhostRecord::into_model)
                .ok_or_else(|| DbError::Constraint("vhost creation failed".into()))
        } else {
            let updated: Vec<VhostRecord> = self
                .inner
                .query("UPDATE type::record('vhost', $id) SET path_prefix = $pp, listen_port = $p, upstream = $u, tls_enabled = $tls, certificate_ref = $cert, force_https = $fh, proxy_mode = $pm, lb_strategy = $lb, enabled = $en, updated_at = $t")
                .bind(("id", vhost.id.clone()))
                .bind(("pp", vhost.path_prefix.clone()))
                .bind(("p", vhost.listen_port))
                .bind(("u", upstream))
                .bind(("tls", vhost.tls_enabled))
                .bind(("cert", vhost.certificate_ref.clone()))
                .bind(("fh", vhost.force_https))
                .bind(("pm", proxy_mode_str(vhost.proxy_mode).to_string()))
                .bind(("lb", lb_str(vhost.lb_strategy).to_string()))
                .bind(("en", vhost.enabled))
                .bind(("t", now))
                .await?
                .take(0)?;
            updated
                .into_iter()
                .next()
                .map(VhostRecord::into_model)
                .ok_or(DbError::NotFound)
        }
    }

    /// Delete a vhost. Refused when a vhost-scoped ACL references it (E-P09).
    pub async fn delete_vhost(&self, id: &str, hostname: &str) -> DbResult<()> {
        let referencing = self
            .list_acl_rules()
            .await?
            .into_iter()
            .any(|r| r.vhost_ref.as_deref() == Some(hostname));
        if referencing {
            return Err(DbError::Constraint(MSG_REFERENCED.into()));
        }
        let _: Option<VhostRecord> = self.inner.delete(("vhost", id)).await?;
        Ok(())
    }

    pub async fn set_vhost_enabled(&self, id: &str, enabled: bool) -> DbResult<()> {
        self.inner
            .query("UPDATE type::record('vhost', $id) SET enabled = $v, updated_at = $t")
            .bind(("id", id.to_string()))
            .bind(("v", enabled))
            .bind(("t", to_rfc3339(Utc::now())))
            .await?;
        Ok(())
    }

    // ---- Certificates -----------------------------------------------------

    pub async fn list_certificates(&self) -> DbResult<Vec<Certificate>> {
        let recs: Vec<CertRecord> = self
            .inner
            .query("SELECT * FROM certificate ORDER BY name ASC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(CertRecord::into_model).collect())
    }

    async fn find_cert(&self, name: &str) -> DbResult<Option<CertRecord>> {
        let recs: Vec<CertRecord> = self
            .inner
            .query("SELECT * FROM certificate WHERE name = $n LIMIT 1")
            .bind(("n", name.to_string()))
            .await?
            .take(0)?;
        Ok(recs.into_iter().next())
    }

    /// Register a certificate. Parses validity from the caller (PEM decode is a
    /// later concern); stores the PEM but never projects it.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_certificate(
        &self,
        name: &str,
        subject: &str,
        issuer: &str,
        san: &[String],
        not_before: chrono::DateTime<Utc>,
        not_after: chrono::DateTime<Utc>,
        cert_pem: &str,
        chain_pem: Option<&str>,
        key_pem: Option<&str>,
        actor: &str,
    ) -> DbResult<Certificate> {
        if self.find_cert(name).await?.is_some() {
            return Err(DbError::Constraint(MSG_CERT_DUP.into()));
        }
        let key_pem = key_pem.filter(|k| !k.trim().is_empty());
        let now = to_rfc3339(Utc::now());
        let rec = CertRecord {
            id: None,
            name: name.to_string(),
            subject: subject.to_string(),
            issuer: issuer.to_string(),
            san: serde_json::to_string(san).unwrap_or_else(|_| "[]".into()),
            serial: None,
            fingerprint_sha256: None,
            not_before: to_rfc3339(not_before),
            not_after: to_rfc3339(not_after),
            cert_pem: cert_pem.to_string(),
            chain_pem: chain_pem.filter(|c| !c.is_empty()).map(|c| c.to_string()),
            key_pem: key_pem.map(|k| k.to_string()),
            key_present: key_pem.is_some(),
            created_at: now.clone(),
            updated_at: now,
            created_by: actor.to_string(),
        };
        let created: Option<CertRecord> = self.inner.create("certificate").content(rec).await?;
        created
            .map(CertRecord::into_model)
            .ok_or_else(|| DbError::Constraint("certificate creation failed".into()))
    }

    /// Create or replace a certificate by name, storing the leaf/chain PEM, private key
    /// and validity. Unlike [`create_certificate`](Self::create_certificate) this does
    /// not error when the name already exists — it overwrites the existing material.
    /// Used by the ACME renewal path, which re-issues the same-named certificate.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_certificate(
        &self,
        name: &str,
        subject: &str,
        issuer: &str,
        san: &[String],
        not_before: chrono::DateTime<Utc>,
        not_after: chrono::DateTime<Utc>,
        cert_pem: &str,
        chain_pem: Option<&str>,
        key_pem: Option<&str>,
        actor: &str,
    ) -> DbResult<Certificate> {
        let Some(existing) = self.find_cert(name).await? else {
            return self
                .create_certificate(
                    name, subject, issuer, san, not_before, not_after, cert_pem, chain_pem,
                    key_pem, actor,
                )
                .await;
        };
        let id = record_key(&existing.id);
        let key_pem = key_pem.filter(|k| !k.trim().is_empty());
        let updated: Vec<CertRecord> = self
            .inner
            .query(
                "UPDATE type::record('certificate', $id) SET subject = $subj, issuer = $iss, \
                 san = $san, not_before = $nb, not_after = $na, cert_pem = $cert, \
                 chain_pem = $chain, key_pem = $key, key_present = $kp, updated_at = $t",
            )
            .bind(("id", id))
            .bind(("subj", subject.to_string()))
            .bind(("iss", issuer.to_string()))
            .bind((
                "san",
                serde_json::to_string(san).unwrap_or_else(|_| "[]".into()),
            ))
            .bind(("nb", to_rfc3339(not_before)))
            .bind(("na", to_rfc3339(not_after)))
            .bind(("cert", cert_pem.to_string()))
            .bind((
                "chain",
                chain_pem.filter(|c| !c.is_empty()).map(|c| c.to_string()),
            ))
            .bind(("key", key_pem.map(|k| k.to_string())))
            .bind(("kp", key_pem.is_some()))
            .bind(("t", to_rfc3339(Utc::now())))
            .await?
            .take(0)?;
        updated
            .into_iter()
            .next()
            .map(CertRecord::into_model)
            .ok_or_else(|| DbError::Constraint("certificate update failed".into()))
    }

    /// Load a certificate's TLS material (leaf+chain PEM and private key) by
    /// name, for the embedded servers to terminate TLS. Returns `None` when the
    /// certificate is unknown or has no stored private key.
    pub async fn get_certificate_material(&self, name: &str) -> DbResult<Option<CertMaterial>> {
        let Some(rec) = self.find_cert(name).await? else {
            return Ok(None);
        };
        let Some(key_pem) = rec.key_pem.filter(|k| !k.trim().is_empty()) else {
            return Ok(None);
        };
        let mut cert_chain_pem = rec.cert_pem;
        if let Some(chain) = rec.chain_pem.filter(|c| !c.trim().is_empty()) {
            if !cert_chain_pem.ends_with('\n') {
                cert_chain_pem.push('\n');
            }
            cert_chain_pem.push_str(&chain);
        }
        Ok(Some(CertMaterial {
            cert_chain_pem,
            key_pem,
        }))
    }

    /// Delete a certificate. Refused when a TLS vhost references it by name.
    pub async fn delete_certificate(&self, id: &str, name: &str) -> DbResult<()> {
        let in_use = self
            .list_vhosts()
            .await?
            .into_iter()
            .any(|v| v.tls_enabled && v.certificate_ref.as_deref() == Some(name));
        if in_use {
            return Err(DbError::Constraint(MSG_REFERENCED.into()));
        }
        let _: Option<CertRecord> = self.inner.delete(("certificate", id)).await?;
        Ok(())
    }

    // ---- Proxy key/value store -------------------------------------------

    /// Read a small internal proxy setting by key (e.g. the persisted ACME
    /// account credentials). Returns `None` when the key is unset.
    pub async fn get_proxy_kv(&self, key: &str) -> DbResult<Option<String>> {
        let recs: Vec<ProxyKvRecord> = self
            .inner
            .query("SELECT * FROM proxy_kv WHERE key = $k LIMIT 1")
            .bind(("k", key.to_string()))
            .await?
            .take(0)?;
        Ok(recs.into_iter().next().map(|r| r.value))
    }

    /// Create or replace a small internal proxy setting by key. Used to persist
    /// the ACME account credentials across restarts (so renewals reuse the same
    /// account instead of registering a new one each boot).
    pub async fn set_proxy_kv(&self, key: &str, value: &str) -> DbResult<()> {
        let now = to_rfc3339(Utc::now());
        let existing: Vec<ProxyKvRecord> = self
            .inner
            .query("SELECT * FROM proxy_kv WHERE key = $k LIMIT 1")
            .bind(("k", key.to_string()))
            .await?
            .take(0)?;
        if let Some(rec) = existing.into_iter().next() {
            let _: Vec<ProxyKvRecord> = self
                .inner
                .query("UPDATE type::record('proxy_kv', $id) SET value = $v, updated_at = $t")
                .bind(("id", record_key(&rec.id)))
                .bind(("v", value.to_string()))
                .bind(("t", now))
                .await?
                .take(0)?;
        } else {
            let rec = ProxyKvRecord {
                id: None,
                key: key.to_string(),
                value: value.to_string(),
                updated_at: now,
            };
            let _: Option<ProxyKvRecord> = self.inner.create("proxy_kv").content(rec).await?;
        }
        Ok(())
    }

    // ---- ACME settings (DB-backed, hot-reloadable) ------------------------

    /// The stored ACME settings, or `None` when never seeded. Includes everything the
    /// manager needs; the server-fn layer projects it to the Web UI as-is (no secrets).
    pub async fn get_acme_config(&self) -> DbResult<Option<AcmeConfig>> {
        let recs: Vec<AcmeConfigRecord> = self
            .inner
            .query("SELECT * FROM acmeconfig LIMIT 1")
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .next()
            .and_then(|rec| serde_json::from_str(&rec.config).ok()))
    }

    /// Seed the ACME settings from `seed` (the file config `[domains.proxy.server.acme]`) on
    /// first run and return the effective value. Once a row exists (operator-edited via the
    /// Web UI) it wins and `seed` is ignored. `seed` `None` with no row leaves ACME unset.
    pub async fn ensure_acme_config(
        &self,
        seed: Option<AcmeConfig>,
    ) -> DbResult<Option<AcmeConfig>> {
        if let Some(existing) = self.get_acme_config().await? {
            return Ok(Some(existing));
        }
        match seed {
            Some(cfg) => {
                self.save_acme_config(&cfg).await?;
                Ok(Some(cfg))
            }
            None => Ok(None),
        }
    }

    /// Create or replace the ACME settings (upsert the singleton). Applied without a restart
    /// — the ACME manager re-reads them on its next poll and re-issues on SAN drift.
    pub async fn save_acme_config(&self, config: &AcmeConfig) -> DbResult<()> {
        let json = serde_json::to_string(config).unwrap_or_default();
        let recs: Vec<AcmeConfigRecord> = self
            .inner
            .query("SELECT * FROM acmeconfig LIMIT 1")
            .await?
            .take(0)?;
        if recs.is_empty() {
            let rec = AcmeConfigRecord {
                id: None,
                config: json,
            };
            let _: Option<AcmeConfigRecord> = self.inner.create("acmeconfig").content(rec).await?;
        } else {
            self.inner
                .query("UPDATE acmeconfig SET config = $c")
                .bind(("c", json))
                .await?;
        }
        Ok(())
    }

    // ---- ACL rules --------------------------------------------------------

    pub async fn list_acl_rules(&self) -> DbResult<Vec<AclRule>> {
        let recs: Vec<AclRecord> = self
            .inner
            .query("SELECT * FROM acl_rule ORDER BY priority ASC, created_at ASC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(AclRecord::into_model).collect())
    }

    pub async fn save_acl_rule(&self, rule: &AclRule) -> DbResult<AclRule> {
        let now = to_rfc3339(Utc::now());
        let scope = match rule.scope {
            AclScope::Vhost => "vhost",
            AclScope::Global => "global",
        };
        if rule.id.is_empty() {
            let rec = AclRecord {
                id: None,
                cidr: rule.cidr.clone(),
                action: rule.action.as_str().to_string(),
                scope: scope.to_string(),
                vhost_ref: rule.vhost_ref.clone(),
                priority: rule.priority,
                enabled: rule.enabled,
                description: rule.description.clone(),
                created_at: now.clone(),
                updated_at: now,
                created_by: rule.created_by.clone(),
            };
            let created: Option<AclRecord> = self.inner.create("acl_rule").content(rec).await?;
            created
                .map(AclRecord::into_model)
                .ok_or_else(|| DbError::Constraint("acl creation failed".into()))
        } else {
            let updated: Vec<AclRecord> = self
                .inner
                .query("UPDATE type::record('acl_rule', $id) SET cidr = $c, action = $a, scope = $s, vhost_ref = $v, priority = $p, enabled = $en, description = $d, updated_at = $t")
                .bind(("id", rule.id.clone()))
                .bind(("c", rule.cidr.clone()))
                .bind(("a", rule.action.as_str().to_string()))
                .bind(("s", scope.to_string()))
                .bind(("v", rule.vhost_ref.clone()))
                .bind(("p", rule.priority))
                .bind(("en", rule.enabled))
                .bind(("d", rule.description.clone()))
                .bind(("t", now))
                .await?
                .take(0)?;
            updated
                .into_iter()
                .next()
                .map(AclRecord::into_model)
                .ok_or(DbError::NotFound)
        }
    }

    pub async fn set_acl_priority(&self, id: &str, priority: i32) -> DbResult<()> {
        self.inner
            .query("UPDATE type::record('acl_rule', $id) SET priority = $p, updated_at = $t")
            .bind(("id", id.to_string()))
            .bind(("p", priority))
            .bind(("t", to_rfc3339(Utc::now())))
            .await?;
        Ok(())
    }

    pub async fn set_acl_enabled(&self, id: &str, enabled: bool) -> DbResult<()> {
        self.inner
            .query("UPDATE type::record('acl_rule', $id) SET enabled = $v, updated_at = $t")
            .bind(("id", id.to_string()))
            .bind(("v", enabled))
            .bind(("t", to_rfc3339(Utc::now())))
            .await?;
        Ok(())
    }

    pub async fn delete_acl_rule(&self, id: &str) -> DbResult<()> {
        let _: Option<AclRecord> = self.inner.delete(("acl_rule", id)).await?;
        Ok(())
    }

    // ---- IP blocks --------------------------------------------------------

    pub async fn list_ip_blocks(&self) -> DbResult<Vec<IpBlock>> {
        let recs: Vec<IpBlockRecord> = self
            .inner
            .query("SELECT * FROM ip_block ORDER BY ord ASC, created_at ASC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(IpBlockRecord::into_model).collect())
    }

    pub async fn save_ip_block(&self, block: &IpBlock) -> DbResult<IpBlock> {
        let now = to_rfc3339(Utc::now());
        let expires = block.expires_at.map(to_rfc3339);
        if block.id.is_empty() {
            let rec = IpBlockRecord {
                id: None,
                cidr: block.cidr.clone(),
                reason: block.reason.clone(),
                ord: block.order,
                expires_at: expires,
                enabled: block.enabled,
                created_at: now.clone(),
                updated_at: now,
                created_by: block.created_by.clone(),
            };
            let created: Option<IpBlockRecord> = self.inner.create("ip_block").content(rec).await?;
            created
                .map(IpBlockRecord::into_model)
                .ok_or_else(|| DbError::Constraint("ip_block creation failed".into()))
        } else {
            let updated: Vec<IpBlockRecord> = self
                .inner
                .query("UPDATE type::record('ip_block', $id) SET cidr = $c, reason = $r, ord = $o, expires_at = $e, enabled = $en, updated_at = $t")
                .bind(("id", block.id.clone()))
                .bind(("c", block.cidr.clone()))
                .bind(("r", block.reason.clone()))
                .bind(("o", block.order))
                .bind(("e", expires))
                .bind(("en", block.enabled))
                .bind(("t", now))
                .await?
                .take(0)?;
            updated
                .into_iter()
                .next()
                .map(IpBlockRecord::into_model)
                .ok_or(DbError::NotFound)
        }
    }

    pub async fn set_ip_block_order(&self, id: &str, order: i32) -> DbResult<()> {
        self.inner
            .query("UPDATE type::record('ip_block', $id) SET ord = $o, updated_at = $t")
            .bind(("id", id.to_string()))
            .bind(("o", order))
            .bind(("t", to_rfc3339(Utc::now())))
            .await?;
        Ok(())
    }

    pub async fn set_ip_block_enabled(&self, id: &str, enabled: bool) -> DbResult<()> {
        self.inner
            .query("UPDATE type::record('ip_block', $id) SET enabled = $v, updated_at = $t")
            .bind(("id", id.to_string()))
            .bind(("v", enabled))
            .bind(("t", to_rfc3339(Utc::now())))
            .await?;
        Ok(())
    }

    pub async fn delete_ip_block(&self, id: &str) -> DbResult<()> {
        let _: Option<IpBlockRecord> = self.inner.delete(("ip_block", id)).await?;
        Ok(())
    }

    /// Metrics: vhost count, certificate count, ACL rule count.
    pub async fn proxy_metrics(&self) -> DbResult<(usize, usize, usize)> {
        let vhosts = self.list_vhosts().await?.len();
        let certs = self.list_certificates().await?.len();
        let acls = self.list_acl_rules().await?.len();
        Ok((vhosts, certs, acls))
    }
}

// ---- Config replication (Tier C) ------------------------------------------

/// A certificate with its full material, for the proxy config-replication feed.
/// This is a server-to-server channel behind the shared bearer secret (like the
/// mail-body feed), so it carries the private key so a peer can terminate TLS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplCertificate {
    pub name: String,
    pub subject: String,
    pub issuer: String,
    pub san: Vec<String>,
    /// RFC 3339 validity bounds (kept as strings — the feed only relays them).
    pub not_before: String,
    pub not_after: String,
    pub cert_pem: String,
    pub chain_pem: Option<String>,
    pub key_pem: Option<String>,
}

/// A full snapshot of the reverse-proxy configuration for Tier-C replication: a
/// secondary replaces its whole proxy config with this. `serial` is the newest
/// `updated_at` across all proxy tables, so a peer skips re-applying an unchanged
/// snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyReplFeed {
    pub serial: String,
    pub vhosts: Vec<VirtualHost>,
    pub certificates: Vec<ReplCertificate>,
    pub acls: Vec<AclRule>,
    pub ip_blocks: Vec<IpBlock>,
}

/// Singleton row holding the last-applied proxy-config replication serial.
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct ProxyReplStateRecord {
    id: Option<RecordId>,
    serial: String,
    last_sync: Option<String>,
}

impl Db {
    /// Gather the full proxy-config snapshot for the replication feed (vhosts,
    /// certificates with material, ACL rules and IP blocks), plus a `serial` = the
    /// newest `updated_at` across those tables.
    pub async fn proxy_repl_feed(&self) -> DbResult<ProxyReplFeed> {
        let vhosts = self.list_vhosts().await?;
        let acls = self.list_acl_rules().await?;
        let ip_blocks = self.list_ip_blocks().await?;
        let cert_recs: Vec<CertRecord> = self
            .inner
            .query("SELECT * FROM certificate ORDER BY name ASC")
            .await?
            .take(0)?;

        let mut times: Vec<chrono::DateTime<Utc>> = Vec::new();
        times.extend(vhosts.iter().map(|v| v.updated_at));
        times.extend(acls.iter().map(|a| a.updated_at));
        times.extend(ip_blocks.iter().map(|b| b.updated_at));
        times.extend(cert_recs.iter().map(|c| parse_rfc3339(&c.updated_at)));
        let serial = times.into_iter().max().map(to_rfc3339).unwrap_or_default();

        let certificates = cert_recs
            .into_iter()
            .map(|c| ReplCertificate {
                name: c.name,
                subject: c.subject,
                issuer: c.issuer,
                san: serde_json::from_str(&c.san).unwrap_or_default(),
                not_before: c.not_before,
                not_after: c.not_after,
                cert_pem: c.cert_pem,
                chain_pem: c.chain_pem,
                key_pem: c.key_pem,
            })
            .collect();

        Ok(ProxyReplFeed {
            serial,
            vhosts,
            certificates,
            acls,
            ip_blocks,
        })
    }

    /// Apply a proxy-config snapshot on a secondary: if the serial differs from the
    /// last applied, replace the whole proxy config (vhosts / certificates / ACLs /
    /// IP blocks) with the primary's. Replica semantics — local-only proxy config is
    /// not preserved. Returns whether it applied.
    pub async fn apply_proxy_repl(&self, feed: &ProxyReplFeed) -> DbResult<bool> {
        // Skip when the serial is unchanged. An empty serial (the primary has no proxy
        // config) also matches the initial empty state, so a fresh secondary does not
        // pointlessly wipe-and-rebuild empty tables on every poll.
        if self.get_proxy_repl_serial().await? == feed.serial {
            return Ok(false);
        }
        let vhosts: Vec<VhostRecord> = feed
            .vhosts
            .iter()
            .map(|v| VhostRecord {
                id: None,
                hostname: v.hostname.to_ascii_lowercase(),
                path_prefix: v.path_prefix.clone(),
                listen_port: v.listen_port,
                upstream: serde_json::to_string(&v.upstream).unwrap_or_default(),
                tls_enabled: v.tls_enabled,
                certificate_ref: v.certificate_ref.clone(),
                force_https: v.force_https,
                proxy_mode: proxy_mode_str(v.proxy_mode).into(),
                lb_strategy: lb_str(v.lb_strategy).into(),
                enabled: v.enabled,
                created_at: to_rfc3339(v.created_at),
                updated_at: to_rfc3339(v.updated_at),
                created_by: v.created_by.clone(),
            })
            .collect();
        let now = to_rfc3339(Utc::now());
        let certs: Vec<CertRecord> = feed
            .certificates
            .iter()
            .map(|c| CertRecord {
                id: None,
                name: c.name.clone(),
                subject: c.subject.clone(),
                issuer: c.issuer.clone(),
                san: serde_json::to_string(&c.san).unwrap_or_else(|_| "[]".into()),
                serial: None,
                fingerprint_sha256: None,
                not_before: c.not_before.clone(),
                not_after: c.not_after.clone(),
                cert_pem: c.cert_pem.clone(),
                chain_pem: c.chain_pem.clone(),
                key_pem: c.key_pem.clone(),
                key_present: c.key_pem.as_deref().is_some_and(|k| !k.trim().is_empty()),
                created_at: now.clone(),
                updated_at: now.clone(),
                created_by: "replication".into(),
            })
            .collect();
        let acls: Vec<AclRecord> = feed
            .acls
            .iter()
            .map(|a| AclRecord {
                id: None,
                cidr: a.cidr.clone(),
                action: a.action.as_str().to_string(),
                scope: match a.scope {
                    AclScope::Vhost => "vhost",
                    AclScope::Global => "global",
                }
                .to_string(),
                vhost_ref: a.vhost_ref.clone(),
                priority: a.priority,
                enabled: a.enabled,
                description: a.description.clone(),
                created_at: to_rfc3339(a.created_at),
                updated_at: to_rfc3339(a.updated_at),
                created_by: a.created_by.clone(),
            })
            .collect();
        let ips: Vec<IpBlockRecord> = feed
            .ip_blocks
            .iter()
            .map(|b| IpBlockRecord {
                id: None,
                cidr: b.cidr.clone(),
                reason: b.reason.clone(),
                ord: b.order,
                expires_at: b.expires_at.map(to_rfc3339),
                enabled: b.enabled,
                created_at: to_rfc3339(b.created_at),
                updated_at: to_rfc3339(b.updated_at),
                created_by: b.created_by.clone(),
            })
            .collect();

        // Replace the whole proxy config atomically: readers (the request path / TLS
        // resolver) never observe a half-applied or momentarily-empty config, and a
        // crash mid-apply rolls back rather than leaving the tables wiped.
        self.inner
            .query(
                "BEGIN TRANSACTION; \
                 DELETE vhost; DELETE certificate; DELETE acl_rule; DELETE ip_block; \
                 INSERT INTO vhost $vhosts; \
                 INSERT INTO certificate $certs; \
                 INSERT INTO acl_rule $acls; \
                 INSERT INTO ip_block $ips; \
                 COMMIT TRANSACTION;",
            )
            .bind(("vhosts", vhosts))
            .bind(("certs", certs))
            .bind(("acls", acls))
            .bind(("ips", ips))
            .await?
            // Surface per-statement failures (a failed INSERT/COMMIT inside the
            // transaction): without this the apply would look successful and the serial
            // would advance below, silently pinning the secondary to its stale config.
            .check()?;
        self.set_proxy_repl_serial(&feed.serial).await?;
        Ok(true)
    }

    /// The last-applied proxy-config replication serial (empty when never synced).
    async fn get_proxy_repl_serial(&self) -> DbResult<String> {
        let recs: Vec<ProxyReplStateRecord> = self
            .inner
            .query("SELECT * FROM proxy_repl_state LIMIT 1")
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .next()
            .map(|r| r.serial)
            .unwrap_or_default())
    }

    /// Persist the applied proxy-config replication serial (singleton).
    async fn set_proxy_repl_serial(&self, serial: &str) -> DbResult<()> {
        let now = to_rfc3339(Utc::now());
        let existing: Vec<ProxyReplStateRecord> = self
            .inner
            .query("SELECT * FROM proxy_repl_state LIMIT 1")
            .await?
            .take(0)?;
        if existing.is_empty() {
            let rec = ProxyReplStateRecord {
                id: None,
                serial: serial.to_string(),
                last_sync: Some(now),
            };
            let _: Option<ProxyReplStateRecord> =
                self.inner.create("proxy_repl_state").content(rec).await?;
        } else {
            self.inner
                .query("UPDATE proxy_repl_state SET serial = $s, last_sync = $t")
                .bind(("s", serial.to_string()))
                .bind(("t", now))
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetite_core::domains::proxy::model::Upstream as U;

    async fn test_db() -> (Db, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        (db, dir)
    }

    fn vhost(hostname: &str, cert: Option<&str>) -> VirtualHost {
        VirtualHost {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "admin".into(),
            hostname: hostname.into(),
            path_prefix: None,
            listen_port: 443,
            upstream: vec![U {
                host: "10.0.0.1".into(),
                port: 8080,
                weight: 1,
                scheme: magnetite_core::domains::proxy::model::UpstreamScheme::Http,
            }],
            tls_enabled: cert.is_some(),
            certificate_ref: cert.map(|c| c.to_string()),
            force_https: false,
            proxy_mode: ProxyMode::Http,
            lb_strategy: LbStrategy::RoundRobin,
            enabled: true,
        }
    }

    #[test]
    fn legacy_https_mode_maps_to_http() {
        // The removed "https" mode (TLS is governed by tls_enabled, not the mode) loads as
        // HTTP so existing rows route again; unknown values also default to HTTP.
        assert_eq!(proxy_mode_from("https"), ProxyMode::Http);
        assert_eq!(proxy_mode_from("http"), ProxyMode::Http);
        assert_eq!(proxy_mode_from("tcp"), ProxyMode::Tcp);
        assert_eq!(proxy_mode_from("garbage"), ProxyMode::Http);
    }

    #[tokio::test]
    async fn vhost_crud_and_unique() {
        let (db, _dir) = test_db().await;
        let v = db.save_vhost(&vhost("a.example.com", None)).await.unwrap();
        assert_eq!(v.hostname, "a.example.com");
        assert!(db.save_vhost(&vhost("a.example.com", None)).await.is_err());
        assert_eq!(db.list_vhosts().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn vhost_uniqueness_is_per_host_and_path() {
        let (db, _dir) = test_db().await;
        let with_path = |p: Option<&str>| {
            let mut v = vhost("mag-center.example.com", None);
            v.path_prefix = p.map(str::to_string);
            v
        };
        // Same host, different path_prefix → BOTH save (path-routed vhosts).
        db.save_vhost(&with_path(None)).await.unwrap();
        db.save_vhost(&with_path(Some("/export"))).await.unwrap();
        assert_eq!(db.list_vhosts().await.unwrap().len(), 2);

        // The SAME (host, path) is still rejected.
        assert!(
            db.save_vhost(&with_path(Some("/export"))).await.is_err(),
            "a duplicate (hostname, path_prefix) is rejected"
        );
        // An empty prefix collides with the whole-host default (absent) route.
        assert!(
            db.save_vhost(&with_path(Some(""))).await.is_err(),
            "empty path_prefix is the default route and collides with the None vhost"
        );
        assert_eq!(db.list_vhosts().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn acme_config_seed_then_db_wins_and_edits_persist() {
        let (db, _dir) = test_db().await;
        // Unseeded: none.
        assert!(db.get_acme_config().await.unwrap().is_none());
        // First run seeds from the file config.
        let seed = AcmeConfig {
            enabled: true,
            domains: vec!["a.example.com".into()],
            certificate_name: Some("proxy-acme".into()),
            ..Default::default()
        };
        let eff = db
            .ensure_acme_config(Some(seed.clone()))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(eff.domains, vec!["a.example.com".to_string()]);
        // A Web-UI edit (add a host) persists and wins over the seed thereafter.
        let mut edited = seed.clone();
        edited.domains.push("b.example.com".into());
        db.save_acme_config(&edited).await.unwrap();
        let after = db.ensure_acme_config(Some(seed)).await.unwrap().unwrap();
        assert_eq!(
            after.domains,
            vec!["a.example.com".to_string(), "b.example.com".to_string()]
        );
    }

    #[tokio::test]
    async fn proxy_kv_persists_and_upserts() {
        // The `proxy_kv` table must exist after init_schema (it backs the ACME account
        // credentials); previously it was never defined, so set_proxy_kv errored and the
        // account was re-registered on every restart.
        let (db, _dir) = test_db().await;
        assert!(db
            .get_proxy_kv("acme_account_credentials")
            .await
            .unwrap()
            .is_none());
        db.set_proxy_kv("acme_account_credentials", "creds-v1")
            .await
            .unwrap();
        assert_eq!(
            db.get_proxy_kv("acme_account_credentials")
                .await
                .unwrap()
                .as_deref(),
            Some("creds-v1")
        );
        // Upsert in place: same key updates rather than duplicating.
        db.set_proxy_kv("acme_account_credentials", "creds-v2")
            .await
            .unwrap();
        assert_eq!(
            db.get_proxy_kv("acme_account_credentials")
                .await
                .unwrap()
                .as_deref(),
            Some("creds-v2")
        );
    }

    #[tokio::test]
    async fn proxy_repl_snapshot_applies_to_peer_and_dedups() {
        let (primary, _d1) = test_db().await;
        let now = Utc::now();
        primary
            .create_certificate(
                "star",
                "CN=*.example.com",
                "ACME",
                &["*.example.com".to_string()],
                now,
                now + chrono::Duration::days(89),
                "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----",
                None,
                Some("-----BEGIN PRIVATE KEY-----\nKKKK\n-----END PRIVATE KEY-----"),
                "admin",
            )
            .await
            .unwrap();
        primary
            .save_vhost(&vhost("a.example.com", Some("star")))
            .await
            .unwrap();

        let feed = primary.proxy_repl_feed().await.unwrap();
        assert_eq!(feed.vhosts.len(), 1);
        assert_eq!(feed.certificates.len(), 1);
        assert!(!feed.serial.is_empty());

        // A peer applies the snapshot and ends up with the same config + cert material.
        let (peer, _d2) = test_db().await;
        assert!(peer.apply_proxy_repl(&feed).await.unwrap());
        assert_eq!(peer.list_vhosts().await.unwrap().len(), 1);
        let material = peer
            .get_certificate_material("star")
            .await
            .unwrap()
            .expect("replicated cert has key material");
        assert!(material.key_pem.contains("PRIVATE KEY"));

        // Re-applying the same (unchanged) snapshot is a no-op.
        assert!(!peer.apply_proxy_repl(&feed).await.unwrap());

        // A change on the primary bumps the serial and re-applies.
        primary
            .save_vhost(&vhost("b.example.com", None))
            .await
            .unwrap();
        let feed2 = primary.proxy_repl_feed().await.unwrap();
        assert_ne!(feed2.serial, feed.serial);
        assert!(peer.apply_proxy_repl(&feed2).await.unwrap());
        assert_eq!(peer.list_vhosts().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn cert_delete_guarded_by_vhost() {
        let (db, _dir) = test_db().await;
        let now = Utc::now();
        let cert = db
            .create_certificate(
                "star",
                "CN=*.ex",
                "CA",
                &[],
                now,
                now + chrono::Duration::days(90),
                "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----",
                None,
                Some("-----BEGIN PRIVATE KEY-----\nk\n-----END PRIVATE KEY-----"),
                "admin",
            )
            .await
            .unwrap();
        assert!(cert.key_present);
        db.save_vhost(&vhost("a.example.com", Some("star")))
            .await
            .unwrap();
        assert!(db.delete_certificate(&cert.id, "star").await.is_err());
    }

    #[tokio::test]
    async fn cert_material_round_trips_key() {
        let (db, _dir) = test_db().await;
        let now = Utc::now();
        db.create_certificate(
            "web",
            "CN=ex",
            "CA",
            &[],
            now,
            now + chrono::Duration::days(90),
            "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----",
            Some("-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----"),
            Some("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"),
            "admin",
        )
        .await
        .unwrap();

        let material = db.get_certificate_material("web").await.unwrap().unwrap();
        assert!(material.cert_chain_pem.contains("leaf"));
        assert!(material.cert_chain_pem.contains("chain"));
        assert!(material.key_pem.contains("secret"));

        // The private key is never part of the projected Certificate model.
        let listed = db.list_certificates().await.unwrap();
        let json = serde_json::to_string(&listed[0]).unwrap();
        assert!(!json.contains("secret"));

        // A cert with no key has no material.
        db.create_certificate(
            "nokey",
            "CN=ex2",
            "CA",
            &[],
            now,
            now + chrono::Duration::days(90),
            "-----BEGIN CERTIFICATE-----\nc\n-----END CERTIFICATE-----",
            None,
            None,
            "admin",
        )
        .await
        .unwrap();
        assert!(db
            .get_certificate_material("nokey")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn vhost_delete_guarded_by_acl() {
        let (db, _dir) = test_db().await;
        db.save_vhost(&vhost("a.example.com", None)).await.unwrap();
        let v = db.list_vhosts().await.unwrap().remove(0);
        let rule = AclRule {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "admin".into(),
            cidr: "10.0.0.0/8".into(),
            action: AclAction::Deny,
            scope: AclScope::Vhost,
            vhost_ref: Some("a.example.com".into()),
            priority: 10,
            enabled: true,
            description: None,
        };
        db.save_acl_rule(&rule).await.unwrap();
        assert!(db.delete_vhost(&v.id, "a.example.com").await.is_err());
    }

    #[tokio::test]
    async fn acl_priority_update() {
        let (db, _dir) = test_db().await;
        let rule = AclRule {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "admin".into(),
            cidr: "10.0.0.0/8".into(),
            action: AclAction::Allow,
            scope: AclScope::Global,
            vhost_ref: None,
            priority: 10,
            enabled: true,
            description: None,
        };
        let saved = db.save_acl_rule(&rule).await.unwrap();
        db.set_acl_priority(&saved.id, 5).await.unwrap();
        assert_eq!(db.list_acl_rules().await.unwrap()[0].priority, 5);
    }
}
