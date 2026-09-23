//! Logon-script management — the store side of the NETLOGON share. Scripts live in
//! the replicated SYSVOL store under `<domain>\scripts\<name>` (so they replicate to
//! peer DCs like any GPT file); the AD DC SMB server serves them at the NETLOGON
//! share root, and a user runs one by naming it in its `scriptPath` attribute.

use crate::error::{DbError, DbResult};
use crate::gpo::base_dn_to_domain;
use crate::store::Db;
use magnetite_core::domains::addc::model::LogonScript;

impl Db {
    /// The SYSVOL path a logon script `name` is stored at for `base_dn`'s domain.
    fn logon_script_path(base_dn: &str, name: &str) -> String {
        format!("{}\\scripts\\{name}", base_dn_to_domain(base_dn))
    }

    /// Reject a script name that is empty or carries a path separator (it must be a
    /// single file name under the scripts directory).
    fn validate_script_name(name: &str) -> DbResult<()> {
        if name.is_empty() || name.contains(['\\', '/']) || name.contains("..") {
            return Err(DbError::Constraint(format!(
                "invalid logon-script name: {name:?}"
            )));
        }
        Ok(())
    }

    /// Create or replace a logon script `name` with `content`, storing it in the
    /// replicated SYSVOL store under `<domain>\scripts\<name>` (served over NETLOGON
    /// after the next refresh).
    ///
    /// # Errors
    /// An invalid name, or a store error.
    pub async fn create_logon_script(
        &self,
        base_dn: &str,
        name: &str,
        content: Vec<u8>,
    ) -> DbResult<()> {
        Self::validate_script_name(name)?;
        let path = Self::logon_script_path(base_dn, name);
        self.upsert_sysvol_file(&path, &content).await?;
        Ok(())
    }

    /// List the domain's logon scripts (name + size), name-sorted.
    ///
    /// # Errors
    /// A store error.
    pub async fn list_logon_scripts(&self, base_dn: &str) -> DbResult<Vec<LogonScript>> {
        let prefix = format!("{}\\scripts\\", base_dn_to_domain(base_dn)).to_lowercase();
        let mut out: Vec<LogonScript> = self
            .list_sysvol_files()
            .await?
            .into_iter()
            .filter(|(p, _)| p.to_lowercase().starts_with(&prefix))
            .map(|(p, content)| LogonScript {
                name: p[prefix.len()..].to_string(),
                size: content.len() as u64,
            })
            // A nested path under scripts\ is not a top-level script; keep only leaves.
            .filter(|s| !s.name.contains('\\'))
            .collect();
        out.sort_by_key(|s| s.name.to_lowercase());
        Ok(out)
    }

    /// Delete a logon script by name (tombstones it in SYSVOL). A no-op if absent.
    ///
    /// # Errors
    /// An invalid name, or a store error.
    pub async fn delete_logon_script(&self, base_dn: &str, name: &str) -> DbResult<()> {
        Self::validate_script_name(name)?;
        self.delete_sysvol_file(&Self::logon_script_path(base_dn, name))
            .await?;
        Ok(())
    }

    /// The NETLOGON share's files: the domain's logon scripts, each keyed by its bare
    /// name (the `<domain>\scripts\` prefix stripped) so it is served at the share root
    /// (`\\<dc>\NETLOGON\<name>`). Feeds `magnetite_smb::Vfs::from_files`.
    ///
    /// # Errors
    /// A store error.
    pub async fn netlogon_files(&self, base_dn: &str) -> DbResult<Vec<(String, Vec<u8>)>> {
        let prefix = format!("{}\\scripts\\", base_dn_to_domain(base_dn)).to_lowercase();
        Ok(self
            .list_sysvol_files()
            .await?
            .into_iter()
            .filter(|(p, _)| p.to_lowercase().starts_with(&prefix))
            .map(|(p, content)| (p[prefix.len()..].to_string(), content))
            .collect())
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
    async fn logon_script_crud_and_netlogon_view() {
        let (db, _dir) = test_db().await;
        let base = "dc=example,dc=com";
        db.create_logon_script(base, "logon.bat", b"@echo on\r\n".to_vec())
            .await
            .unwrap();
        db.create_logon_script(base, "map.cmd", b"net use\r\n".to_vec())
            .await
            .unwrap();

        let scripts = db.list_logon_scripts(base).await.unwrap();
        assert_eq!(scripts.len(), 2);
        assert!(scripts.iter().any(|s| s.name == "logon.bat" && s.size > 0));

        // NETLOGON serves them at the share root (bare names).
        let files = db.netlogon_files(base).await.unwrap();
        assert!(files.iter().any(|(n, _)| n == "logon.bat"));
        assert!(files.iter().all(|(n, _)| !n.contains('\\')));

        // A name with a separator is rejected.
        assert!(db
            .create_logon_script(base, "a\\b.bat", vec![])
            .await
            .is_err());

        db.delete_logon_script(base, "logon.bat").await.unwrap();
        let after = db.list_logon_scripts(base).await.unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].name, "map.cmd");
    }
}
