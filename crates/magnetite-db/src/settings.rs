//! Runtime system-settings singleton (07 §3.10 / F-09 / screen_settings).
//!
//! A single `app_settings` row overlays the editable subset of the TOML
//! [`AppConfig`]: per-domain enablement, dashboard refresh cadence, retention
//! and the SSO connection. When absent, the settings mirror the loaded config
//! so behaviour is unchanged until an admin saves. The SSO client secret is
//! stored here but never returned to the client (only `has_secret`).

use crate::error::DbResult;
use crate::records::to_rfc3339;
use crate::store::Db;
use chrono::Utc;
use magnetite_core::config::AppConfig;
use magnetite_core::domain::DomainKey;
use magnetite_core::models::{DomainToggle, SsoSettings, SystemSettings};
use serde::{Deserialize, Serialize};
use surrealdb::types::{RecordId, SurrealValue};

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct SettingsRecord {
    id: Option<RecordId>,
    /// Domain keys explicitly turned OFF (everything else is enabled).
    disabled_domains: Vec<String>,
    dashboard_refresh_secs: i64,
    retention_days: i64,
    sso_enabled: bool,
    issuer_url: String,
    client_id: String,
    redirect_uri: String,
    client_secret: Option<String>,
    updated_at: String,
}

impl Db {
    async fn settings_record(&self) -> DbResult<Option<SettingsRecord>> {
        let rows: Vec<SettingsRecord> = self
            .inner
            .query("SELECT * FROM app_settings LIMIT 1")
            .await?
            .take(0)?;
        Ok(rows.into_iter().next())
    }

    /// Read the effective system settings, overlaying the stored row on the
    /// config defaults. Never returns the SSO secret value.
    pub async fn get_system_settings(&self, config: &AppConfig) -> DbResult<SystemSettings> {
        let rec = self.settings_record().await?;

        let domains = DomainKey::DOMAINS
            .into_iter()
            .map(|key| {
                let display_name = config
                    .domains
                    .get(&key)
                    .map(|d| d.display_name.clone())
                    .unwrap_or_else(|| key.as_str().to_uppercase());
                let enabled = match &rec {
                    Some(r) => !r.disabled_domains.iter().any(|d| d == key.as_str()),
                    None => config.domains.get(&key).map(|d| d.enabled).unwrap_or(true),
                };
                DomainToggle {
                    key,
                    display_name,
                    enabled,
                }
            })
            .collect();

        let (dashboard_refresh_secs, retention_days, sso) = match &rec {
            Some(r) => (
                r.dashboard_refresh_secs.max(0) as u64,
                r.retention_days.max(0) as u32,
                SsoSettings {
                    enabled: r.sso_enabled,
                    issuer_url: r.issuer_url.clone(),
                    client_id: r.client_id.clone(),
                    redirect_uri: r.redirect_uri.clone(),
                    has_secret: r.client_secret.as_deref().is_some_and(|s| !s.is_empty()),
                },
            ),
            None => (
                config.policy.dashboard_refresh_secs,
                config.policy.retention_days,
                match &config.sso {
                    Some(s) => SsoSettings {
                        enabled: true,
                        issuer_url: s.issuer_url.clone(),
                        client_id: s.client_id.clone(),
                        redirect_uri: s.redirect_uri.clone(),
                        has_secret: !s.client_secret.is_empty(),
                    },
                    None => SsoSettings::default(),
                },
            ),
        };

        Ok(SystemSettings {
            domains,
            dashboard_refresh_secs,
            retention_days,
            sso,
        })
    }

    /// Persist system settings (replace the singleton row). A blank
    /// `new_secret` preserves the previously stored SSO secret.
    #[allow(clippy::too_many_arguments)]
    pub async fn save_system_settings(
        &self,
        enabled_domains: &[DomainKey],
        dashboard_refresh_secs: u64,
        retention_days: u32,
        sso_enabled: bool,
        issuer_url: &str,
        client_id: &str,
        redirect_uri: &str,
        new_secret: Option<&str>,
    ) -> DbResult<()> {
        let prev_secret = self.settings_record().await?.and_then(|r| r.client_secret);
        let client_secret = match new_secret {
            Some(s) if !s.trim().is_empty() => Some(s.to_string()),
            _ => prev_secret,
        };
        let disabled_domains = DomainKey::DOMAINS
            .into_iter()
            .filter(|k| !enabled_domains.contains(k))
            .map(|k| k.as_str().to_string())
            .collect();

        let rec = SettingsRecord {
            id: None,
            disabled_domains,
            dashboard_refresh_secs: dashboard_refresh_secs as i64,
            retention_days: retention_days as i64,
            sso_enabled,
            issuer_url: issuer_url.to_string(),
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            client_secret,
            updated_at: to_rfc3339(Utc::now()),
        };
        self.inner.query("DELETE app_settings").await?;
        let _: Option<SettingsRecord> = self.inner.create("app_settings").content(rec).await?;
        Ok(())
    }
}

/// Singleton row holding this server's stable identity (a UUID minted on first run),
/// so a `magnetite-center` control plane can address the server by a durable id rather
/// than a mutable host:port.
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct ServerIdentityRecord {
    id: Option<RecordId>,
    server_id: String,
    created_at: String,
}

impl Db {
    /// This server's stable id, minting and persisting a fresh UUID on first call.
    /// Idempotent — the same id is returned on every subsequent call (and restart).
    pub async fn get_or_create_server_id(&self) -> DbResult<String> {
        let recs: Vec<ServerIdentityRecord> = self
            .inner
            .query("SELECT * FROM server_identity LIMIT 1")
            .await?
            .take(0)?;
        if let Some(rec) = recs.into_iter().next() {
            return Ok(rec.server_id);
        }
        let server_id = uuid::Uuid::new_v4().to_string();
        let rec = ServerIdentityRecord {
            id: None,
            server_id: server_id.clone(),
            created_at: to_rfc3339(Utc::now()),
        };
        let _: Option<ServerIdentityRecord> =
            self.inner.create("server_identity").content(rec).await?;
        Ok(server_id)
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
    async fn server_id_is_minted_once_and_stable() {
        let (db, _dir) = test_db().await;
        let a = db.get_or_create_server_id().await.unwrap();
        assert!(!a.is_empty());
        // Idempotent: the same id is returned on subsequent calls.
        let b = db.get_or_create_server_id().await.unwrap();
        assert_eq!(a, b);
    }

    fn config() -> AppConfig {
        AppConfig::from_toml_str(
            r#"
[server]
host = "127.0.0.1"
port = 4000

[policy]
dashboard_refresh_secs = 30
retention_days = 90
password_min_length = 8

[domains.dns]
display_name = "DNS"
enabled = true

[domains.watch]
display_name = "Watch"
enabled = true
"#,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn defaults_mirror_config_then_persist() {
        let (db, _dir) = test_db().await;
        let cfg = config();

        // No row yet: mirror the config.
        let s = db.get_system_settings(&cfg).await.unwrap();
        assert_eq!(s.dashboard_refresh_secs, 30);
        assert_eq!(s.retention_days, 90);
        assert_eq!(s.domains.len(), 8);
        assert!(!s.sso.enabled);
        // dns present+enabled in config -> on; ldap absent -> default on.
        assert!(
            s.domains
                .iter()
                .find(|d| d.key == DomainKey::Dns)
                .unwrap()
                .enabled
        );

        // Save: disable Watch, change numbers, set SSO with a secret.
        let enabled: Vec<DomainKey> = DomainKey::DOMAINS
            .into_iter()
            .filter(|k| *k != DomainKey::Watch)
            .collect();
        db.save_system_settings(
            &enabled,
            60,
            30,
            true,
            "https://idp.example.com",
            "mag-app",
            "https://localhost:4000/auth/callback",
            Some("s3cr3t"),
        )
        .await
        .unwrap();

        let s = db.get_system_settings(&cfg).await.unwrap();
        assert_eq!(s.dashboard_refresh_secs, 60);
        assert_eq!(s.retention_days, 30);
        assert!(
            !s.domains
                .iter()
                .find(|d| d.key == DomainKey::Watch)
                .unwrap()
                .enabled
        );
        assert!(s.sso.enabled);
        assert!(s.sso.has_secret);
        assert_eq!(s.sso.client_id, "mag-app");

        // Saving again with a blank secret keeps the stored one.
        db.save_system_settings(
            &enabled,
            60,
            30,
            true,
            "https://idp.example.com",
            "mag-app",
            "https://localhost:4000/auth/callback",
            None,
        )
        .await
        .unwrap();
        let s = db.get_system_settings(&cfg).await.unwrap();
        assert!(s.sso.has_secret);
    }
}
