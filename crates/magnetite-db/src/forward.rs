//! Forward-proxy repository: access rules (source / destination, priority-ordered
//! allow/deny) and client credentials (HTTP proxy Basic auth). Mirrors the reverse
//! proxy's ACL/IP-block storage style — `SurrealValue` records converted to the
//! shared `magnetite-core` models; the credential hash never leaves this layer.

use crate::error::{DbError, DbResult};
use crate::records::{parse_rfc3339, record_key, to_rfc3339};
use crate::store::Db;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use chrono::Utc;
use magnetite_core::domains::proxy::model::{AclAction, ForwardRule, ForwardRuleKind, ForwardUser};
use serde::{Deserialize, Serialize};
use surrealdb::types::{RecordId, SurrealValue};

const MSG_USER_DUP: &str = "同じユーザ名が既に存在します。";

fn hash_password(password: &str) -> DbResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| DbError::PasswordHash(e.to_string()))
}

// ---- Records --------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct ForwardRuleRecord {
    id: Option<RecordId>,
    kind: String,
    matcher: String,
    action: String,
    priority: i32,
    enabled: bool,
    description: Option<String>,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl ForwardRuleRecord {
    fn into_model(self) -> ForwardRule {
        ForwardRule {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            kind: ForwardRuleKind::from_str(&self.kind),
            matcher: self.matcher,
            action: AclAction::from_str(&self.action),
            priority: self.priority,
            enabled: self.enabled,
            description: self.description,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct ForwardUserRecord {
    id: Option<RecordId>,
    username: String,
    password_hash: String,
    enabled: bool,
    description: Option<String>,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl ForwardUserRecord {
    fn into_model(self) -> ForwardUser {
        ForwardUser {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            username: self.username,
            enabled: self.enabled,
            description: self.description,
        }
    }
}

impl Db {
    // ---- Forward-proxy rules ----------------------------------------------

    /// List forward-proxy access rules, priority-ascending (source then destination
    /// interleave by priority; callers filter by `kind`).
    pub async fn list_forward_rules(&self) -> DbResult<Vec<ForwardRule>> {
        let recs: Vec<ForwardRuleRecord> = self
            .inner
            .query("SELECT * FROM forward_rule ORDER BY priority ASC, created_at ASC")
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .map(ForwardRuleRecord::into_model)
            .collect())
    }

    /// Create (empty `id`) or update a forward-proxy access rule.
    ///
    /// # Errors
    /// A store error, or (on update) [`DbError::NotFound`] if the id is gone.
    pub async fn save_forward_rule(&self, rule: &ForwardRule) -> DbResult<ForwardRule> {
        let now = to_rfc3339(Utc::now());
        if rule.id.is_empty() {
            let rec = ForwardRuleRecord {
                id: None,
                kind: rule.kind.as_str().to_string(),
                matcher: rule.matcher.clone(),
                action: rule.action.as_str().to_string(),
                priority: rule.priority,
                enabled: rule.enabled,
                description: rule.description.clone(),
                created_at: now.clone(),
                updated_at: now,
                created_by: rule.created_by.clone(),
            };
            let created: Option<ForwardRuleRecord> =
                self.inner.create("forward_rule").content(rec).await?;
            created
                .map(ForwardRuleRecord::into_model)
                .ok_or_else(|| DbError::Constraint("forward rule creation failed".into()))
        } else {
            let updated: Vec<ForwardRuleRecord> = self
                .inner
                .query("UPDATE type::record('forward_rule', $id) SET kind = $k, matcher = $m, action = $a, priority = $p, enabled = $en, description = $d, updated_at = $t")
                .bind(("id", rule.id.clone()))
                .bind(("k", rule.kind.as_str().to_string()))
                .bind(("m", rule.matcher.clone()))
                .bind(("a", rule.action.as_str().to_string()))
                .bind(("p", rule.priority))
                .bind(("en", rule.enabled))
                .bind(("d", rule.description.clone()))
                .bind(("t", now))
                .await?
                .take(0)?;
            updated
                .into_iter()
                .next()
                .map(ForwardRuleRecord::into_model)
                .ok_or(DbError::NotFound)
        }
    }

    /// Enable / disable a forward-proxy rule.
    pub async fn set_forward_rule_enabled(&self, id: &str, enabled: bool) -> DbResult<()> {
        self.inner
            .query("UPDATE type::record('forward_rule', $id) SET enabled = $v, updated_at = $t")
            .bind(("id", id.to_string()))
            .bind(("v", enabled))
            .bind(("t", to_rfc3339(Utc::now())))
            .await?;
        Ok(())
    }

    /// Delete a forward-proxy rule.
    pub async fn delete_forward_rule(&self, id: &str) -> DbResult<()> {
        let _: Option<ForwardRuleRecord> = self.inner.delete(("forward_rule", id)).await?;
        Ok(())
    }

    // ---- Forward-proxy users (Basic auth) ---------------------------------

    /// List forward-proxy client credentials (no hash), username-ordered.
    pub async fn list_forward_users(&self) -> DbResult<Vec<ForwardUser>> {
        let recs: Vec<ForwardUserRecord> = self
            .inner
            .query("SELECT * FROM forward_user ORDER BY username ASC")
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .map(ForwardUserRecord::into_model)
            .collect())
    }

    /// Create a forward-proxy client credential, hashing the password.
    ///
    /// # Errors
    /// [`DbError::Constraint`] if the username already exists.
    pub async fn create_forward_user(
        &self,
        username: &str,
        password: &str,
        description: Option<&str>,
        created_by: &str,
    ) -> DbResult<ForwardUser> {
        if self.find_forward_user(username).await?.is_some() {
            return Err(DbError::Constraint(MSG_USER_DUP.into()));
        }
        let now = to_rfc3339(Utc::now());
        let rec = ForwardUserRecord {
            id: None,
            username: username.to_string(),
            password_hash: hash_password(password)?,
            enabled: true,
            description: description.map(str::to_string),
            created_at: now.clone(),
            updated_at: now,
            created_by: created_by.to_string(),
        };
        let created: Option<ForwardUserRecord> =
            self.inner.create("forward_user").content(rec).await?;
        created
            .map(ForwardUserRecord::into_model)
            .ok_or_else(|| DbError::Constraint("forward user creation failed".into()))
    }

    async fn find_forward_user(&self, username: &str) -> DbResult<Option<ForwardUserRecord>> {
        let recs: Vec<ForwardUserRecord> = self
            .inner
            .query("SELECT * FROM forward_user WHERE username = $u LIMIT 1")
            .bind(("u", username.to_string()))
            .await?
            .take(0)?;
        Ok(recs.into_iter().next())
    }

    /// Enable / disable a forward-proxy user.
    pub async fn set_forward_user_enabled(&self, id: &str, enabled: bool) -> DbResult<()> {
        self.inner
            .query("UPDATE type::record('forward_user', $id) SET enabled = $v, updated_at = $t")
            .bind(("id", id.to_string()))
            .bind(("v", enabled))
            .bind(("t", to_rfc3339(Utc::now())))
            .await?;
        Ok(())
    }

    /// Delete a forward-proxy user.
    pub async fn delete_forward_user(&self, id: &str) -> DbResult<()> {
        let _: Option<ForwardUserRecord> = self.inner.delete(("forward_user", id)).await?;
        Ok(())
    }

    /// Whether at least one *enabled* forward-proxy user exists — i.e. whether the
    /// forward proxy must require `Proxy-Authorization`.
    pub async fn has_enabled_forward_users(&self) -> DbResult<bool> {
        let recs: Vec<ForwardUserRecord> = self
            .inner
            .query("SELECT * FROM forward_user WHERE enabled = true LIMIT 1")
            .await?
            .take(0)?;
        Ok(!recs.is_empty())
    }

    /// Verify a forward-proxy Basic credential. Returns `true` only for an enabled
    /// user whose password matches. Runs a dummy hash on a miss to blunt timing.
    pub async fn verify_forward_user(&self, username: &str, password: &str) -> DbResult<bool> {
        let Some(user) = self.find_forward_user(username).await? else {
            let salt = SaltString::generate(&mut OsRng);
            let _ = Argon2::default().hash_password(password.as_bytes(), &salt);
            return Ok(false);
        };
        if !user.enabled {
            return Ok(false);
        }
        let Ok(parsed) = PasswordHash::new(&user.password_hash) else {
            return Ok(false);
        };
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetite_core::domains::proxy::model::{AclAction, ForwardRuleKind};

    async fn test_db() -> (Db, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        (db, dir)
    }

    fn new_rule(kind: ForwardRuleKind, matcher: &str, action: AclAction) -> ForwardRule {
        ForwardRule {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "tester".into(),
            kind,
            matcher: matcher.into(),
            action,
            priority: 10,
            enabled: true,
            description: None,
        }
    }

    #[tokio::test]
    async fn forward_rule_crud() {
        let (db, _dir) = test_db().await;
        let saved = db
            .save_forward_rule(&new_rule(
                ForwardRuleKind::Source,
                "10.0.0.0/8",
                AclAction::Allow,
            ))
            .await
            .unwrap();
        assert!(!saved.id.is_empty());
        db.save_forward_rule(&new_rule(
            ForwardRuleKind::Destination,
            ".example.com",
            AclAction::Deny,
        ))
        .await
        .unwrap();

        let rules = db.list_forward_rules().await.unwrap();
        assert_eq!(rules.len(), 2);

        db.set_forward_rule_enabled(&saved.id, false).await.unwrap();
        let after = db.list_forward_rules().await.unwrap();
        assert!(after.iter().any(|r| r.id == saved.id && !r.enabled));

        db.delete_forward_rule(&saved.id).await.unwrap();
        assert_eq!(db.list_forward_rules().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn forward_user_auth() {
        let (db, _dir) = test_db().await;
        assert!(!db.has_enabled_forward_users().await.unwrap());

        db.create_forward_user("alice", "s3cret", Some("test"), "admin")
            .await
            .unwrap();
        assert!(db.has_enabled_forward_users().await.unwrap());
        assert!(db.verify_forward_user("alice", "s3cret").await.unwrap());
        assert!(!db.verify_forward_user("alice", "wrong").await.unwrap());
        assert!(!db.verify_forward_user("bob", "s3cret").await.unwrap());

        // Duplicate username rejected.
        assert!(db
            .create_forward_user("alice", "x", None, "admin")
            .await
            .is_err());

        let users = db.list_forward_users().await.unwrap();
        assert_eq!(users.len(), 1);
        let id = users[0].id.clone();
        db.set_forward_user_enabled(&id, false).await.unwrap();
        assert!(!db.has_enabled_forward_users().await.unwrap());
        assert!(!db.verify_forward_user("alice", "s3cret").await.unwrap());

        db.delete_forward_user(&id).await.unwrap();
        assert_eq!(db.list_forward_users().await.unwrap().len(), 0);
    }
}
