//! SSO domain repository (07_data_sso / screen_sso): providers, OIDC clients
//! (with secret regeneration) and issued sessions (list + revoke). Secrets are
//! stored server-side and never projected (only `has_secret`).

use crate::error::{DbError, DbResult};
use crate::records::{parse_rfc3339, record_key, to_rfc3339};
use crate::store::Db;
use chrono::{DateTime, Utc};
use magnetite_core::domains::sso::model::{OidcClient, Provider, SsoSession};
use serde::{Deserialize, Serialize};
use surrealdb::types::{RecordId, SurrealValue};

fn gen_token() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "[]".into())
}

fn from_json<T: serde::de::DeserializeOwned + Default>(s: &str) -> T {
    serde_json::from_str(s).unwrap_or_default()
}

// ---- Records --------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct ProviderRecord {
    id: Option<RecordId>,
    name: String,
    provider_type: String,
    issuer: Option<String>,
    client_id: String,
    client_secret: String,
    authorize_url: Option<String>,
    token_url: Option<String>,
    userinfo_url: Option<String>,
    scopes: String,
    redirect_uri: String,
    auto_provision: bool,
    enabled: bool,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl ProviderRecord {
    fn into_model(self) -> Provider {
        Provider {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            name: self.name,
            provider_type: self.provider_type,
            issuer: self.issuer,
            client_id: self.client_id,
            has_secret: !self.client_secret.is_empty(),
            authorize_url: self.authorize_url,
            token_url: self.token_url,
            userinfo_url: self.userinfo_url,
            scopes: from_json(&self.scopes),
            redirect_uri: self.redirect_uri,
            auto_provision: self.auto_provision,
            enabled: self.enabled,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct ClientRecord {
    id: Option<RecordId>,
    client_name: String,
    client_id: String,
    client_secret: String,
    client_type: String,
    grant_types: String,
    response_types: String,
    redirect_uris: String,
    scopes: String,
    token_endpoint_auth_method: String,
    provider_ref: Option<String>,
    enabled: bool,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl ClientRecord {
    fn into_model(self) -> OidcClient {
        OidcClient {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            client_name: self.client_name,
            client_id: self.client_id,
            has_secret: !self.client_secret.is_empty(),
            client_type: self.client_type,
            grant_types: from_json(&self.grant_types),
            response_types: from_json(&self.response_types),
            redirect_uris: from_json(&self.redirect_uris),
            scopes: from_json(&self.scopes),
            token_endpoint_auth_method: self.token_endpoint_auth_method,
            provider_ref: self.provider_ref,
            enabled: self.enabled,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct SessionRecord {
    id: Option<RecordId>,
    session_ref: String,
    subject: String,
    client_ref: Option<String>,
    provider_ref: Option<String>,
    scopes: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
    issued_at: String,
    expires_at: String,
    revoked_at: Option<String>,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl SessionRecord {
    fn into_model(self) -> SsoSession {
        SsoSession {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            session_ref: self.session_ref,
            subject: self.subject,
            client_ref: self.client_ref,
            provider_ref: self.provider_ref,
            scopes: from_json(&self.scopes),
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            issued_at: parse_rfc3339(&self.issued_at),
            expires_at: parse_rfc3339(&self.expires_at),
            revoked_at: self.revoked_at.as_deref().map(parse_rfc3339),
        }
    }
}

/// A persisted issuer signing key (server-internal secret material — never
/// projected to the API; only the public half is published via the JWKS).
#[derive(Debug, Clone)]
pub struct StoredSigningKey {
    pub kid: String,
    /// The RSA private key as a PKCS#8 PEM.
    pub private_pem: String,
    /// Whether this is the current active signer (vs a retired verifier).
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub retired_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct SigningKeyRecord {
    id: Option<RecordId>,
    kid: String,
    private_pem: String,
    /// `"active"` (the single current signer) or `"retired"` (verify-only).
    state: String,
    created_at: String,
    retired_at: Option<String>,
}

impl SigningKeyRecord {
    fn into_model(self) -> StoredSigningKey {
        StoredSigningKey {
            kid: self.kid,
            private_pem: self.private_pem,
            active: self.state == "active",
            created_at: parse_rfc3339(&self.created_at),
            retired_at: self.retired_at.as_deref().map(parse_rfc3339),
        }
    }
}

impl Db {
    // ---- Providers --------------------------------------------------------

    pub async fn list_sso_providers(&self) -> DbResult<Vec<Provider>> {
        let recs: Vec<ProviderRecord> = self
            .inner
            .query("SELECT * FROM sso_provider ORDER BY name ASC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(ProviderRecord::into_model).collect())
    }

    async fn find_provider_by_name(&self, name: &str) -> DbResult<Option<ProviderRecord>> {
        let recs: Vec<ProviderRecord> = self
            .inner
            .query("SELECT * FROM sso_provider WHERE name = $n LIMIT 1")
            .bind(("n", name.to_string()))
            .await?
            .take(0)?;
        Ok(recs.into_iter().next())
    }

    /// The full login configuration (including the client secret) for the enabled
    /// provider `name`, for the federation flow. Returns `None` if there is no such
    /// provider or it is disabled. The secret never leaves the server.
    ///
    /// # Errors
    /// A store error.
    pub async fn provider_login_config(
        &self,
        name: &str,
    ) -> DbResult<Option<magnetite_core::domains::sso::model::ProviderLoginConfig>> {
        use magnetite_core::domains::sso::model::ProviderLoginConfig;
        let Some(rec) = self.find_provider_by_name(name).await? else {
            return Ok(None);
        };
        if !rec.enabled {
            return Ok(None);
        }
        Ok(Some(ProviderLoginConfig {
            name: rec.name,
            provider_type: rec.provider_type,
            client_id: rec.client_id,
            client_secret: rec.client_secret,
            authorize_url: rec.authorize_url,
            token_url: rec.token_url,
            userinfo_url: rec.userinfo_url,
            scopes: from_json(&rec.scopes),
            redirect_uri: rec.redirect_uri,
            auto_provision: rec.auto_provision,
            enabled: rec.enabled,
        }))
    }

    /// The names + types of the enabled upstream providers, for rendering login
    /// buttons on the (unauthenticated) login page. No secrets or URLs.
    ///
    /// # Errors
    /// A store error.
    pub async fn list_enabled_provider_logins(&self) -> DbResult<Vec<(String, String)>> {
        let recs: Vec<ProviderRecord> = self
            .inner
            .query("SELECT * FROM sso_provider WHERE enabled = true ORDER BY name ASC")
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .map(|r| (r.name, r.provider_type))
            .collect())
    }

    /// Create or update a provider. `secret = Some` sets it; `None` keeps the
    /// stored value on update.
    pub async fn save_provider(
        &self,
        provider: &Provider,
        secret: Option<&str>,
    ) -> DbResult<Provider> {
        let now = to_rfc3339(Utc::now());
        if provider.id.is_empty() {
            if self.find_provider_by_name(&provider.name).await?.is_some() {
                return Err(DbError::Constraint("同じ名称が既に存在します。".into()));
            }
            let rec = ProviderRecord {
                id: None,
                name: provider.name.clone(),
                provider_type: provider.provider_type.clone(),
                issuer: provider.issuer.clone(),
                client_id: provider.client_id.clone(),
                client_secret: secret.unwrap_or("").to_string(),
                authorize_url: provider.authorize_url.clone(),
                token_url: provider.token_url.clone(),
                userinfo_url: provider.userinfo_url.clone(),
                scopes: json(&provider.scopes),
                redirect_uri: provider.redirect_uri.clone(),
                auto_provision: provider.auto_provision,
                enabled: provider.enabled,
                created_at: now.clone(),
                updated_at: now,
                created_by: provider.created_by.clone(),
            };
            let created: Option<ProviderRecord> =
                self.inner.create("sso_provider").content(rec).await?;
            created
                .map(ProviderRecord::into_model)
                .ok_or_else(|| DbError::Constraint("provider creation failed".into()))
        } else {
            // Keep the existing secret unless a new one is provided.
            let updated: Vec<ProviderRecord> = self
                .inner
                .query("UPDATE type::record('sso_provider', $id) SET provider_type = $pt, issuer = $iss, client_id = $cid, authorize_url = $au, token_url = $tu, userinfo_url = $uu, scopes = $sc, redirect_uri = $ru, auto_provision = $ap, enabled = $en, updated_at = $t")
                .bind(("id", provider.id.clone()))
                .bind(("pt", provider.provider_type.clone()))
                .bind(("iss", provider.issuer.clone()))
                .bind(("cid", provider.client_id.clone()))
                .bind(("au", provider.authorize_url.clone()))
                .bind(("tu", provider.token_url.clone()))
                .bind(("uu", provider.userinfo_url.clone()))
                .bind(("sc", json(&provider.scopes)))
                .bind(("ru", provider.redirect_uri.clone()))
                .bind(("ap", provider.auto_provision))
                .bind(("en", provider.enabled))
                .bind(("t", now.clone()))
                .await?
                .take(0)?;
            if let Some(new_secret) = secret {
                self.inner
                    .query("UPDATE type::record('sso_provider', $id) SET client_secret = $s")
                    .bind(("id", provider.id.clone()))
                    .bind(("s", new_secret.to_string()))
                    .await?;
            }
            updated
                .into_iter()
                .next()
                .map(ProviderRecord::into_model)
                .ok_or(DbError::NotFound)
        }
    }

    /// Delete a provider and revoke its sessions (AC-19).
    pub async fn delete_provider(&self, id: &str, name: &str) -> DbResult<()> {
        self.revoke_sessions_where("provider_ref", name).await?;
        let _: Option<ProviderRecord> = self.inner.delete(("sso_provider", id)).await?;
        Ok(())
    }

    // ---- OIDC clients -----------------------------------------------------

    pub async fn list_oidc_clients(&self) -> DbResult<Vec<OidcClient>> {
        let recs: Vec<ClientRecord> = self
            .inner
            .query("SELECT * FROM sso_client ORDER BY client_name ASC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(ClientRecord::into_model).collect())
    }

    /// Create a client (generates client_id and secret for confidential ones).
    pub async fn create_oidc_client(&self, client: &OidcClient) -> DbResult<OidcClient> {
        let secret = if client.client_type == "public" {
            String::new()
        } else {
            gen_token()
        };
        let now = to_rfc3339(Utc::now());
        let rec = ClientRecord {
            id: None,
            client_name: client.client_name.clone(),
            client_id: format!("mag-{}", gen_token()),
            client_secret: secret,
            client_type: client.client_type.clone(),
            grant_types: json(&client.grant_types),
            response_types: json(&client.response_types),
            redirect_uris: json(&client.redirect_uris),
            scopes: json(&client.scopes),
            token_endpoint_auth_method: client.token_endpoint_auth_method.clone(),
            provider_ref: client.provider_ref.clone(),
            enabled: client.enabled,
            created_at: now.clone(),
            updated_at: now,
            created_by: client.created_by.clone(),
        };
        let created: Option<ClientRecord> = self.inner.create("sso_client").content(rec).await?;
        created
            .map(ClientRecord::into_model)
            .ok_or_else(|| DbError::Constraint("client creation failed".into()))
    }

    /// Look up a client by its issued `client_id`, returning the model plus the
    /// stored secret (empty for public clients) for token-endpoint
    /// authentication by the embedded OIDC issuer.
    pub async fn get_oidc_client_auth(
        &self,
        client_id: &str,
    ) -> DbResult<Option<(OidcClient, String)>> {
        let recs: Vec<ClientRecord> = self
            .inner
            .query("SELECT * FROM sso_client WHERE client_id = $cid LIMIT 1")
            .bind(("cid", client_id.to_string()))
            .await?
            .take(0)?;
        Ok(recs.into_iter().next().map(|r| {
            let secret = r.client_secret.clone();
            (r.into_model(), secret)
        }))
    }

    /// Update a client's mutable fields (id/secret preserved).
    pub async fn update_oidc_client(&self, client: &OidcClient) -> DbResult<Option<OidcClient>> {
        let now = to_rfc3339(Utc::now());
        let updated: Vec<ClientRecord> = self
            .inner
            .query("UPDATE type::record('sso_client', $id) SET client_name = $n, client_type = $ct, grant_types = $g, response_types = $rt, redirect_uris = $r, scopes = $s, token_endpoint_auth_method = $m, provider_ref = $p, enabled = $en, updated_at = $t")
            .bind(("id", client.id.clone()))
            .bind(("n", client.client_name.clone()))
            .bind(("ct", client.client_type.clone()))
            .bind(("g", json(&client.grant_types)))
            .bind(("rt", json(&client.response_types)))
            .bind(("r", json(&client.redirect_uris)))
            .bind(("s", json(&client.scopes)))
            .bind(("m", client.token_endpoint_auth_method.clone()))
            .bind(("p", client.provider_ref.clone()))
            .bind(("en", client.enabled))
            .bind(("t", now))
            .await?
            .take(0)?;
        Ok(updated.into_iter().next().map(ClientRecord::into_model))
    }

    /// Regenerate a client's secret and return the new plaintext once (E-S05).
    pub async fn regenerate_client_secret(&self, id: &str) -> DbResult<String> {
        let secret = gen_token();
        self.inner
            .query("UPDATE type::record('sso_client', $id) SET client_secret = $s, updated_at = $t")
            .bind(("id", id.to_string()))
            .bind(("s", secret.clone()))
            .bind(("t", to_rfc3339(Utc::now())))
            .await?;
        Ok(secret)
    }

    /// Delete a client and revoke its sessions (AC-19). `client_id` is the
    /// issued OAuth client id used as the session reference.
    pub async fn delete_oidc_client(&self, id: &str, client_id: &str) -> DbResult<()> {
        self.revoke_sessions_where("client_ref", client_id).await?;
        let _: Option<ClientRecord> = self.inner.delete(("sso_client", id)).await?;
        Ok(())
    }

    // ---- Sessions ---------------------------------------------------------

    /// List currently active SSO sessions.
    pub async fn list_active_sso_sessions(&self) -> DbResult<Vec<SsoSession>> {
        let recs: Vec<SessionRecord> = self
            .inner
            .query("SELECT * FROM sso_session ORDER BY issued_at DESC")
            .await?
            .take(0)?;
        let now = Utc::now();
        Ok(recs
            .into_iter()
            .map(SessionRecord::into_model)
            .filter(|s| s.is_active_at(now))
            .collect())
    }

    /// Revoke a single session by its record id.
    pub async fn revoke_sso_session(&self, id: &str) -> DbResult<()> {
        self.inner
            .query("UPDATE type::record('sso_session', $id) SET revoked_at = $t, updated_at = $t WHERE revoked_at IS NONE")
            .bind(("id", id.to_string()))
            .bind(("t", to_rfc3339(Utc::now())))
            .await?;
        Ok(())
    }

    async fn revoke_sessions_where(&self, field: &str, value: &str) -> DbResult<()> {
        let now = to_rfc3339(Utc::now());
        let stmt = format!(
            "UPDATE sso_session SET revoked_at = $t, updated_at = $t WHERE {field} = $v AND revoked_at IS NONE"
        );
        self.inner
            .query(stmt)
            .bind(("t", now))
            .bind(("v", value.to_string()))
            .await?;
        Ok(())
    }

    /// Revoke all active sessions for a subject.
    pub async fn revoke_sso_sessions_for_subject(&self, subject: &str) -> DbResult<()> {
        self.revoke_sessions_where("subject", subject).await
    }

    /// Create an SSO session (for the SSO login flow; also used by tests).
    #[allow(clippy::too_many_arguments)]
    pub async fn create_sso_session(
        &self,
        subject: &str,
        client_ref: Option<&str>,
        provider_ref: Option<&str>,
        scopes: &[String],
        ttl_hours: i64,
        actor: &str,
    ) -> DbResult<SsoSession> {
        let now = Utc::now();
        let now_s = to_rfc3339(now);
        let rec = SessionRecord {
            id: None,
            session_ref: gen_token(),
            subject: subject.to_string(),
            client_ref: client_ref.map(|s| s.to_string()),
            provider_ref: provider_ref.map(|s| s.to_string()),
            scopes: json(&scopes.to_vec()),
            ip_address: None,
            user_agent: None,
            issued_at: now_s.clone(),
            expires_at: to_rfc3339(now + chrono::Duration::hours(ttl_hours)),
            revoked_at: None,
            created_at: now_s.clone(),
            updated_at: now_s,
            created_by: actor.to_string(),
        };
        let created: Option<SessionRecord> = self.inner.create("sso_session").content(rec).await?;
        created
            .map(SessionRecord::into_model)
            .ok_or_else(|| DbError::Constraint("session creation failed".into()))
    }

    /// Metrics: provider count, client count, active session count.
    pub async fn sso_metrics(&self) -> DbResult<(usize, usize, usize)> {
        let providers = self.list_sso_providers().await?.len();
        let clients = self.list_oidc_clients().await?.len();
        let sessions = self.list_active_sso_sessions().await?.len();
        Ok((providers, clients, sessions))
    }

    // ---- OIDC signing keys ------------------------------------------------

    /// Load every stored issuer signing key (the one active signing key plus any
    /// retired keys still published for verification), the active key first.
    pub async fn load_sso_signing_keys(&self) -> DbResult<Vec<StoredSigningKey>> {
        let recs: Vec<SigningKeyRecord> = self
            .inner
            .query("SELECT * FROM sso_signing_key ORDER BY created_at DESC")
            .await?
            .take(0)?;
        let mut keys: Vec<StoredSigningKey> =
            recs.into_iter().map(SigningKeyRecord::into_model).collect();
        // Active first, then most-recently-created; a running issuer signs with
        // `keys[0]` and verifies against the whole set.
        keys.sort_by(|a, b| {
            b.active
                .cmp(&a.active)
                .then(b.created_at.cmp(&a.created_at))
        });
        Ok(keys)
    }

    /// Persist a fresh signing key as the sole active one. Used on first-ever
    /// startup when no key exists yet.
    pub async fn insert_active_signing_key(&self, kid: &str, private_pem: &str) -> DbResult<()> {
        let now = to_rfc3339(Utc::now());
        let rec = SigningKeyRecord {
            id: None,
            kid: kid.to_string(),
            private_pem: private_pem.to_string(),
            state: "active".to_string(),
            created_at: now,
            retired_at: None,
        };
        let _: Option<SigningKeyRecord> = self.inner.create("sso_signing_key").content(rec).await?;
        Ok(())
    }

    /// Rotate the signing key: retire whatever is currently active (kept for
    /// verification) and install `new_kid` as the new active signer.
    pub async fn rotate_signing_key(&self, new_kid: &str, private_pem: &str) -> DbResult<()> {
        let now = to_rfc3339(Utc::now());
        self.inner
            .query("UPDATE sso_signing_key SET state = 'retired', retired_at = $t WHERE state = 'active'")
            .bind(("t", now.clone()))
            .await?;
        let rec = SigningKeyRecord {
            id: None,
            kid: new_kid.to_string(),
            private_pem: private_pem.to_string(),
            state: "active".to_string(),
            created_at: now,
            retired_at: None,
        };
        let _: Option<SigningKeyRecord> = self.inner.create("sso_signing_key").content(rec).await?;
        Ok(())
    }

    /// Drop retired keys whose `retired_at` is older than `cutoff` (their tokens
    /// have long expired, so they no longer need to be published). Returns how
    /// many were pruned.
    pub async fn prune_retired_signing_keys(&self, cutoff: DateTime<Utc>) -> DbResult<usize> {
        let cutoff_s = to_rfc3339(cutoff);
        let stale: Vec<SigningKeyRecord> = self
            .inner
            .query("SELECT * FROM sso_signing_key WHERE state = 'retired' AND retired_at != NONE AND retired_at < $c")
            .bind(("c", cutoff_s.clone()))
            .await?
            .take(0)?;
        self.inner
            .query("DELETE sso_signing_key WHERE state = 'retired' AND retired_at != NONE AND retired_at < $c")
            .bind(("c", cutoff_s))
            .await?;
        Ok(stale.len())
    }
}

// ---- Config replication (Tier C) ------------------------------------------

/// An SSO identity provider with its full config incl. the OAuth `client_secret`,
/// for the replication feed (server-to-server behind the bearer secret).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplProvider {
    pub name: String,
    pub provider_type: String,
    pub issuer: Option<String>,
    pub client_id: String,
    pub client_secret: String,
    pub authorize_url: Option<String>,
    pub token_url: Option<String>,
    pub userinfo_url: Option<String>,
    /// JSON-encoded `Vec<String>` (relayed verbatim).
    pub scopes: String,
    pub redirect_uri: String,
    pub auto_provision: bool,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
    pub created_by: String,
}

/// An OIDC client with its full config incl. the `client_secret`, for the feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplClient {
    pub client_name: String,
    pub client_id: String,
    pub client_secret: String,
    pub client_type: String,
    pub grant_types: String,
    pub response_types: String,
    pub redirect_uris: String,
    pub scopes: String,
    pub token_endpoint_auth_method: String,
    pub provider_ref: Option<String>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
    pub created_by: String,
}

/// An issuer signing key with its PKCS#8 private PEM, for the feed. Replicating
/// these keeps the JWKS consistent across nodes so a token signed by one verifies
/// on another.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplSigningKey {
    pub kid: String,
    pub private_pem: String,
    /// `"active"` (the single current signer) or `"retired"` (verify-only).
    pub state: String,
    pub created_at: String,
    pub retired_at: Option<String>,
}

/// A full snapshot of the SSO configuration for Tier-C replication: providers,
/// OIDC clients and issuer signing keys (all secret-bearing). Sessions are NOT
/// replicated (high-churn; they re-establish on failover). `serial` is the newest
/// `updated_at` (or key created/retired time), so a peer skips an unchanged snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoReplFeed {
    pub serial: String,
    pub providers: Vec<ReplProvider>,
    pub clients: Vec<ReplClient>,
    pub signing_keys: Vec<ReplSigningKey>,
}

/// Singleton row holding the last-applied SSO replication serial.
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct SsoReplStateRecord {
    id: Option<RecordId>,
    serial: String,
    last_sync: Option<String>,
}

impl Db {
    /// Gather the full SSO config snapshot for the replication feed (providers,
    /// clients and signing keys, all with secrets), plus a `serial`.
    pub async fn sso_repl_feed(&self) -> DbResult<SsoReplFeed> {
        let provs: Vec<ProviderRecord> = self
            .inner
            .query("SELECT * FROM sso_provider ORDER BY name ASC")
            .await?
            .take(0)?;
        let clis: Vec<ClientRecord> = self
            .inner
            .query("SELECT * FROM sso_client ORDER BY client_name ASC")
            .await?
            .take(0)?;
        let keys: Vec<SigningKeyRecord> = self
            .inner
            .query("SELECT * FROM sso_signing_key ORDER BY kid ASC")
            .await?
            .take(0)?;

        let mut times: Vec<DateTime<Utc>> = Vec::new();
        times.extend(provs.iter().map(|p| parse_rfc3339(&p.updated_at)));
        times.extend(clis.iter().map(|c| parse_rfc3339(&c.updated_at)));
        for k in &keys {
            times.push(parse_rfc3339(&k.created_at));
            if let Some(r) = &k.retired_at {
                times.push(parse_rfc3339(r));
            }
        }
        let serial = times.into_iter().max().map(to_rfc3339).unwrap_or_default();

        let providers = provs
            .into_iter()
            .map(|p| ReplProvider {
                name: p.name,
                provider_type: p.provider_type,
                issuer: p.issuer,
                client_id: p.client_id,
                client_secret: p.client_secret,
                authorize_url: p.authorize_url,
                token_url: p.token_url,
                userinfo_url: p.userinfo_url,
                scopes: p.scopes,
                redirect_uri: p.redirect_uri,
                auto_provision: p.auto_provision,
                enabled: p.enabled,
                created_at: p.created_at,
                updated_at: p.updated_at,
                created_by: p.created_by,
            })
            .collect();
        let clients = clis
            .into_iter()
            .map(|c| ReplClient {
                client_name: c.client_name,
                client_id: c.client_id,
                client_secret: c.client_secret,
                client_type: c.client_type,
                grant_types: c.grant_types,
                response_types: c.response_types,
                redirect_uris: c.redirect_uris,
                scopes: c.scopes,
                token_endpoint_auth_method: c.token_endpoint_auth_method,
                provider_ref: c.provider_ref,
                enabled: c.enabled,
                created_at: c.created_at,
                updated_at: c.updated_at,
                created_by: c.created_by,
            })
            .collect();
        let signing_keys = keys
            .into_iter()
            .map(|k| ReplSigningKey {
                kid: k.kid,
                private_pem: k.private_pem,
                state: k.state,
                created_at: k.created_at,
                retired_at: k.retired_at,
            })
            .collect();

        Ok(SsoReplFeed {
            serial,
            providers,
            clients,
            signing_keys,
        })
    }

    /// Apply an SSO config snapshot on a secondary: when the serial changed, replace
    /// providers / clients / signing keys with the primary's (verbatim, preserving
    /// kid/state/timestamps). Sessions are left untouched. Replica semantics. Returns
    /// whether it applied.
    pub async fn apply_sso_repl(&self, feed: &SsoReplFeed) -> DbResult<bool> {
        // Skip when the serial is unchanged. An empty serial (the primary has no SSO
        // config) also matches the initial empty state, so a fresh secondary does not
        // pointlessly wipe-and-rebuild empty tables on every poll.
        if self.get_sso_repl_serial().await? == feed.serial {
            return Ok(false);
        }
        let providers: Vec<ProviderRecord> = feed
            .providers
            .iter()
            .map(|p| ProviderRecord {
                id: None,
                name: p.name.clone(),
                provider_type: p.provider_type.clone(),
                issuer: p.issuer.clone(),
                client_id: p.client_id.clone(),
                client_secret: p.client_secret.clone(),
                authorize_url: p.authorize_url.clone(),
                token_url: p.token_url.clone(),
                userinfo_url: p.userinfo_url.clone(),
                scopes: p.scopes.clone(),
                redirect_uri: p.redirect_uri.clone(),
                auto_provision: p.auto_provision,
                enabled: p.enabled,
                created_at: p.created_at.clone(),
                updated_at: p.updated_at.clone(),
                created_by: p.created_by.clone(),
            })
            .collect();
        let clients: Vec<ClientRecord> = feed
            .clients
            .iter()
            .map(|c| ClientRecord {
                id: None,
                client_name: c.client_name.clone(),
                client_id: c.client_id.clone(),
                client_secret: c.client_secret.clone(),
                client_type: c.client_type.clone(),
                grant_types: c.grant_types.clone(),
                response_types: c.response_types.clone(),
                redirect_uris: c.redirect_uris.clone(),
                scopes: c.scopes.clone(),
                token_endpoint_auth_method: c.token_endpoint_auth_method.clone(),
                provider_ref: c.provider_ref.clone(),
                enabled: c.enabled,
                created_at: c.created_at.clone(),
                updated_at: c.updated_at.clone(),
                created_by: c.created_by.clone(),
            })
            .collect();
        let keys: Vec<SigningKeyRecord> = feed
            .signing_keys
            .iter()
            .map(|k| SigningKeyRecord {
                id: None,
                kid: k.kid.clone(),
                private_pem: k.private_pem.clone(),
                state: k.state.clone(),
                created_at: k.created_at.clone(),
                retired_at: k.retired_at.clone(),
            })
            .collect();

        // Replace the whole SSO config atomically so a secondary that also serves as an
        // issuer never observes a momentarily-empty provider/client/key set, and a crash
        // mid-apply rolls back rather than leaving the tables wiped.
        self.inner
            .query(
                "BEGIN TRANSACTION; \
                 DELETE sso_provider; DELETE sso_client; DELETE sso_signing_key; \
                 INSERT INTO sso_provider $providers; \
                 INSERT INTO sso_client $clients; \
                 INSERT INTO sso_signing_key $keys; \
                 COMMIT TRANSACTION;",
            )
            .bind(("providers", providers))
            .bind(("clients", clients))
            .bind(("keys", keys))
            .await?
            // Surface per-statement failures (a failed INSERT/COMMIT inside the
            // transaction): without this the apply would look successful and the serial
            // would advance below, silently pinning the secondary to its stale config.
            .check()?;
        self.set_sso_repl_serial(&feed.serial).await?;
        Ok(true)
    }

    /// The last-applied SSO replication serial (empty when never synced).
    async fn get_sso_repl_serial(&self) -> DbResult<String> {
        let recs: Vec<SsoReplStateRecord> = self
            .inner
            .query("SELECT * FROM sso_repl_state LIMIT 1")
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .next()
            .map(|r| r.serial)
            .unwrap_or_default())
    }

    /// Persist the applied SSO replication serial (singleton).
    async fn set_sso_repl_serial(&self, serial: &str) -> DbResult<()> {
        let now = to_rfc3339(Utc::now());
        let existing: Vec<SsoReplStateRecord> = self
            .inner
            .query("SELECT * FROM sso_repl_state LIMIT 1")
            .await?
            .take(0)?;
        if existing.is_empty() {
            let rec = SsoReplStateRecord {
                id: None,
                serial: serial.to_string(),
                last_sync: Some(now),
            };
            let _: Option<SsoReplStateRecord> =
                self.inner.create("sso_repl_state").content(rec).await?;
        } else {
            self.inner
                .query("UPDATE sso_repl_state SET serial = $s, last_sync = $t")
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

    async fn test_db() -> (Db, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        (db, dir)
    }

    fn provider(name: &str) -> Provider {
        Provider {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "admin".into(),
            name: name.into(),
            provider_type: "google".into(),
            issuer: None,
            client_id: "cid".into(),
            has_secret: false,
            authorize_url: None,
            token_url: None,
            userinfo_url: None,
            scopes: vec!["openid".into()],
            redirect_uri: "https://mag.example.com/cb".into(),
            auto_provision: false,
            enabled: true,
        }
    }

    #[tokio::test]
    async fn sso_repl_snapshot_applies_to_peer_and_dedups() {
        let (primary, _d1) = test_db().await;
        primary
            .save_provider(&provider("Google"), Some("provsecret"))
            .await
            .unwrap();
        primary
            .create_oidc_client(&OidcClient {
                id: String::new(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                created_by: "admin".into(),
                client_name: "webapp".into(),
                client_id: String::new(),
                has_secret: false,
                client_type: "confidential".into(),
                grant_types: vec!["authorization_code".into()],
                response_types: vec!["code".into()],
                redirect_uris: vec!["https://app.example.com/cb".into()],
                scopes: vec!["openid".into()],
                token_endpoint_auth_method: "client_secret_basic".into(),
                provider_ref: None,
                enabled: true,
            })
            .await
            .unwrap();
        primary
            .insert_active_signing_key(
                "kid-1",
                "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----",
            )
            .await
            .unwrap();

        let feed = primary.sso_repl_feed().await.unwrap();
        assert_eq!(feed.providers.len(), 1);
        assert_eq!(feed.clients.len(), 1);
        assert_eq!(feed.signing_keys.len(), 1);
        // Secrets are carried on the server-to-server feed.
        assert_eq!(feed.providers[0].client_secret, "provsecret");
        assert!(feed.signing_keys[0].private_pem.contains("PRIVATE KEY"));
        assert!(!feed.serial.is_empty());

        // A peer applies the snapshot and ends up with the same config + key material.
        let (peer, _d2) = test_db().await;
        assert!(peer.apply_sso_repl(&feed).await.unwrap());
        assert_eq!(peer.list_sso_providers().await.unwrap().len(), 1);
        assert_eq!(peer.list_oidc_clients().await.unwrap().len(), 1);
        let keys = peer.load_sso_signing_keys().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].kid, "kid-1");
        assert!(keys[0].active);

        // Re-applying the unchanged snapshot is a no-op.
        assert!(!peer.apply_sso_repl(&feed).await.unwrap());

        // A change on the primary bumps the serial and re-applies.
        primary
            .save_provider(&provider("GitHub"), Some("s2"))
            .await
            .unwrap();
        let feed2 = primary.sso_repl_feed().await.unwrap();
        assert_ne!(feed2.serial, feed.serial);
        assert!(peer.apply_sso_repl(&feed2).await.unwrap());
        assert_eq!(peer.list_sso_providers().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn provider_masks_secret() {
        let (db, _dir) = test_db().await;
        let p = db
            .save_provider(&provider("Google"), Some("s3cr3t"))
            .await
            .unwrap();
        assert!(p.has_secret);
        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("s3cr3t"));
    }

    #[tokio::test]
    async fn provider_delete_revokes_sessions() {
        let (db, _dir) = test_db().await;
        db.save_provider(&provider("Google"), Some("x"))
            .await
            .unwrap();
        let p = db.list_sso_providers().await.unwrap().remove(0);
        db.create_sso_session(
            "alice",
            None,
            Some("Google"),
            &["openid".into()],
            24,
            "admin",
        )
        .await
        .unwrap();
        assert_eq!(db.list_active_sso_sessions().await.unwrap().len(), 1);
        db.delete_provider(&p.id, "Google").await.unwrap();
        assert_eq!(db.list_active_sso_sessions().await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn client_secret_regenerates() {
        let (db, _dir) = test_db().await;
        let client = OidcClient {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "admin".into(),
            client_name: "app".into(),
            client_id: String::new(),
            has_secret: false,
            client_type: "confidential".into(),
            grant_types: vec!["authorization_code".into()],
            response_types: vec!["code".into()],
            redirect_uris: vec!["https://app.example.com/cb".into()],
            scopes: vec!["openid".into()],
            token_endpoint_auth_method: "client_secret_basic".into(),
            provider_ref: None,
            enabled: true,
        };
        let created = db.create_oidc_client(&client).await.unwrap();
        assert!(created.has_secret);
        assert!(created.client_id.starts_with("mag-"));
        let s1 = db.regenerate_client_secret(&created.id).await.unwrap();
        let s2 = db.regenerate_client_secret(&created.id).await.unwrap();
        assert_ne!(s1, s2);
    }

    #[tokio::test]
    async fn single_session_revoke() {
        let (db, _dir) = test_db().await;
        let s = db
            .create_sso_session("bob", None, None, &[], 24, "admin")
            .await
            .unwrap();
        db.revoke_sso_session(&s.id).await.unwrap();
        assert!(db.list_active_sso_sessions().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn signing_key_persists_rotates_and_prunes() {
        let (db, _dir) = test_db().await;
        // Empty to start; first startup installs an active key.
        assert!(db.load_sso_signing_keys().await.unwrap().is_empty());
        db.insert_active_signing_key("kid-1", "PEM-1")
            .await
            .unwrap();
        let keys = db.load_sso_signing_keys().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys[0].active && keys[0].kid == "kid-1");

        // Rotation: kid-1 retires (still present for verification), kid-2 signs.
        db.rotate_signing_key("kid-2", "PEM-2").await.unwrap();
        let keys = db.load_sso_signing_keys().await.unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys[0].active && keys[0].kid == "kid-2"); // active sorted first
        let retired = &keys[1];
        assert!(!retired.active && retired.kid == "kid-1" && retired.retired_at.is_some());

        // Prune with a future cutoff drops the retired key; the active stays.
        let pruned = db
            .prune_retired_signing_keys(Utc::now() + chrono::Duration::hours(1))
            .await
            .unwrap();
        assert_eq!(pruned, 1);
        let keys = db.load_sso_signing_keys().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].kid, "kid-2");
    }
}
