//! Local account repository: hashing, credential verification, CRUD and the
//! last-admin guard (07 §3.7 / AC-03 / AC-05 / 08_authz §6).

use crate::error::{DbError, DbResult};
use crate::records::{to_rfc3339, AccountRecord};
use crate::store::Db;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use chrono::Utc;
use magnetite_core::authz::Role;
use magnetite_core::models::LocalAccount;

fn hash_password(password: &str) -> DbResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| DbError::PasswordHash(e.to_string()))
}

impl Db {
    /// Number of local accounts. Used to detect the first-run state (AC-03).
    pub async fn count_accounts(&self) -> DbResult<usize> {
        let accounts: Vec<AccountRecord> =
            self.inner.query("SELECT * FROM account").await?.take(0)?;
        Ok(accounts.len())
    }

    /// Whether any local account exists.
    pub async fn has_accounts(&self) -> DbResult<bool> {
        Ok(self.count_accounts().await? > 0)
    }

    /// Create an account with the given role, hashing the password.
    ///
    /// # Errors
    /// [`DbError::Constraint`] if the username already exists.
    pub async fn create_account(
        &self,
        username: &str,
        password: &str,
        role: Role,
    ) -> DbResult<LocalAccount> {
        if self.find_account_by_username(username).await?.is_some() {
            return Err(DbError::Constraint("同じユーザ名が既に存在します。".into()));
        }
        let now = to_rfc3339(Utc::now());
        let record = AccountRecord {
            id: None,
            username: username.to_string(),
            password_hash: hash_password(password)?,
            role: role.as_str().to_string(),
            enabled: true,
            created_at: now.clone(),
            updated_at: now,
            last_login_at: None,
        };
        let created: Option<AccountRecord> = self.inner.create("account").content(record).await?;
        created
            .map(AccountRecord::into_model)
            .ok_or(DbError::Constraint(
                "account creation returned nothing".into(),
            ))
    }

    /// Atomically create the first admin during initial setup (TOCTOU-safe).
    ///
    /// # Errors
    /// [`DbError::Constraint`] if setup was already completed.
    pub async fn create_first_admin(
        &self,
        username: &str,
        password: &str,
    ) -> DbResult<LocalAccount> {
        let _guard = self.setup_lock.lock().await;
        if self.has_accounts().await? {
            return Err(DbError::Constraint("setup already completed".into()));
        }
        self.create_account(username, password, Role::Admin).await
    }

    /// Look up an account by username.
    pub async fn find_account_by_username(&self, username: &str) -> DbResult<Option<LocalAccount>> {
        let records: Vec<AccountRecord> = self
            .inner
            .query("SELECT * FROM account WHERE username = $u LIMIT 1")
            .bind(("u", username.to_string()))
            .await?
            .take(0)?;
        Ok(records.into_iter().next().map(AccountRecord::into_model))
    }

    /// Verify credentials, returning the account on success. Performs a dummy
    /// hash on a missing user to avoid a timing oracle.
    pub async fn verify_login(
        &self,
        username: &str,
        password: &str,
    ) -> DbResult<Option<LocalAccount>> {
        let account = self.find_account_by_username(username).await?;
        let Some(account) = account else {
            let salt = SaltString::generate(&mut OsRng);
            let _ = Argon2::default().hash_password(password.as_bytes(), &salt);
            return Ok(None);
        };
        if !account.enabled {
            return Ok(None);
        }
        let parsed = match PasswordHash::new(&account.password_hash) {
            Ok(p) => p,
            Err(_) => return Ok(None),
        };
        if Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
        {
            Ok(Some(account))
        } else {
            Ok(None)
        }
    }

    /// List all accounts ordered by creation time.
    pub async fn list_accounts(&self) -> DbResult<Vec<LocalAccount>> {
        let records: Vec<AccountRecord> = self
            .inner
            .query("SELECT * FROM account ORDER BY created_at ASC")
            .await?
            .take(0)?;
        Ok(records.into_iter().map(AccountRecord::into_model).collect())
    }

    /// Count enabled accounts holding the Admin role (last-admin guard).
    pub async fn count_enabled_admins(&self) -> DbResult<usize> {
        let count = self
            .list_accounts()
            .await?
            .into_iter()
            .filter(|a| a.enabled && a.role == Role::Admin)
            .count();
        Ok(count)
    }

    /// Record a successful login timestamp.
    pub async fn touch_last_login(&self, username: &str) -> DbResult<()> {
        let now = to_rfc3339(Utc::now());
        self.inner
            .query("UPDATE account SET last_login_at = $t WHERE username = $u")
            .bind(("t", now))
            .bind(("u", username.to_string()))
            .await?;
        Ok(())
    }

    /// Whether removing this account's admin capability (delete/disable/demote)
    /// would leave zero enabled admins (last-admin guard, AC-05).
    async fn is_last_enabled_admin(&self, account: &LocalAccount) -> DbResult<bool> {
        Ok(account.enabled
            && account.role == Role::Admin
            && self.count_enabled_admins().await? <= 1)
    }

    /// Change an account's role. Demoting the last enabled admin is refused.
    pub async fn set_account_role(&self, username: &str, role: Role) -> DbResult<()> {
        let account = self
            .find_account_by_username(username)
            .await?
            .ok_or(DbError::NotFound)?;
        if role != Role::Admin && self.is_last_enabled_admin(&account).await? {
            return Err(DbError::Constraint(
                "最後の管理者アカウントは変更できません。".into(),
            ));
        }
        self.inner
            .query("UPDATE account SET role = $r, updated_at = $t WHERE username = $u")
            .bind(("r", role.as_str().to_string()))
            .bind(("t", to_rfc3339(Utc::now())))
            .bind(("u", username.to_string()))
            .await?;
        Ok(())
    }

    /// Enable/disable an account. Disabling revokes its sessions; disabling the
    /// last enabled admin is refused.
    pub async fn set_account_enabled(&self, username: &str, enabled: bool) -> DbResult<()> {
        let account = self
            .find_account_by_username(username)
            .await?
            .ok_or(DbError::NotFound)?;
        if !enabled && self.is_last_enabled_admin(&account).await? {
            return Err(DbError::Constraint(
                "最後の管理者アカウントは無効化できません。".into(),
            ));
        }
        self.inner
            .query("UPDATE account SET enabled = $e, updated_at = $t WHERE username = $u")
            .bind(("e", enabled))
            .bind(("t", to_rfc3339(Utc::now())))
            .bind(("u", username.to_string()))
            .await?;
        if !enabled {
            self.revoke_sessions_for_subject(username).await?;
        }
        Ok(())
    }

    /// Delete an account (and revoke its sessions). Deleting the last enabled
    /// admin is refused (AC-05).
    pub async fn delete_account(&self, username: &str) -> DbResult<()> {
        let account = self
            .find_account_by_username(username)
            .await?
            .ok_or(DbError::NotFound)?;
        if self.is_last_enabled_admin(&account).await? {
            return Err(DbError::Constraint(
                "最後の管理者アカウントは削除できません。".into(),
            ));
        }
        self.inner
            .query("DELETE account WHERE username = $u")
            .bind(("u", username.to_string()))
            .await?;
        self.revoke_sessions_for_subject(username).await?;
        Ok(())
    }

    /// Reset an account's password (Argon2-hashed).
    pub async fn reset_account_password(&self, username: &str, new_password: &str) -> DbResult<()> {
        self.find_account_by_username(username)
            .await?
            .ok_or(DbError::NotFound)?;
        let hash = hash_password(new_password)?;
        self.inner
            .query("UPDATE account SET password_hash = $h, updated_at = $t WHERE username = $u")
            .bind(("h", hash))
            .bind(("t", to_rfc3339(Utc::now())))
            .bind(("u", username.to_string()))
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
    async fn first_admin_setup_is_single_shot() {
        let (db, _dir) = test_db().await;
        assert!(!db.has_accounts().await.unwrap());
        db.create_first_admin("admin", "abcd1234").await.unwrap();
        assert!(db.has_accounts().await.unwrap());
        // Second attempt must fail.
        assert!(db.create_first_admin("root", "abcd1234").await.is_err());
    }

    #[tokio::test]
    async fn verify_login_roundtrip() {
        let (db, _dir) = test_db().await;
        db.create_account("bob", "secret12", Role::Operator)
            .await
            .unwrap();
        assert!(db.verify_login("bob", "secret12").await.unwrap().is_some());
        assert!(db.verify_login("bob", "wrong").await.unwrap().is_none());
        assert!(db
            .verify_login("ghost", "secret12")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn duplicate_username_rejected() {
        let (db, _dir) = test_db().await;
        db.create_account("dup", "abcd1234", Role::Viewer)
            .await
            .unwrap();
        assert!(db
            .create_account("dup", "abcd1234", Role::Viewer)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn counts_enabled_admins() {
        let (db, _dir) = test_db().await;
        db.create_account("a1", "abcd1234", Role::Admin)
            .await
            .unwrap();
        db.create_account("a2", "abcd1234", Role::Admin)
            .await
            .unwrap();
        db.create_account("op", "abcd1234", Role::Operator)
            .await
            .unwrap();
        assert_eq!(db.count_enabled_admins().await.unwrap(), 2);
    }

    #[tokio::test]
    async fn last_admin_is_protected() {
        let (db, _dir) = test_db().await;
        db.create_first_admin("admin", "abcd1234").await.unwrap();
        // Sole admin cannot be deleted, disabled or demoted.
        assert!(db.delete_account("admin").await.is_err());
        assert!(db.set_account_enabled("admin", false).await.is_err());
        assert!(db.set_account_role("admin", Role::Operator).await.is_err());
        // A second admin lifts the guard.
        db.create_account("admin2", "abcd1234", Role::Admin)
            .await
            .unwrap();
        assert!(db.set_account_role("admin", Role::Operator).await.is_ok());
        assert_eq!(db.count_enabled_admins().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn password_reset_changes_login() {
        let (db, _dir) = test_db().await;
        db.create_account("carol", "oldpass12", Role::Viewer)
            .await
            .unwrap();
        db.reset_account_password("carol", "newpass34")
            .await
            .unwrap();
        assert!(db
            .verify_login("carol", "oldpass12")
            .await
            .unwrap()
            .is_none());
        assert!(db
            .verify_login("carol", "newpass34")
            .await
            .unwrap()
            .is_some());
    }
}
