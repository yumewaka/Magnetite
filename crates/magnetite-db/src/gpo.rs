//! Group Policy Object (GPO) management — the store side of the AD DC web
//! control-plane. A GPO has two halves that must stay in lock-step: the
//! `groupPolicyContainer` (GPC) object in the LDAP directory (how a member
//! *discovers* the policy) and the GPT files in the replicated SYSVOL store (how a
//! member *fetches* it over SMB). [`Db::create_gpo`] provisions both from a
//! [`magnetite_gpo`] spec; [`Db::list_gpos`]/[`Db::delete_gpo`] manage the set.
//!
//! This is the single production caller of `magnetite-gpo`; `magnetite-ldap`'s
//! `seed_group_policy` is the same seeding used by tests.

use crate::error::DbResult;
use crate::store::Db;
use magnetite_core::domains::addc::model::{GpoRegKind, GpoSettingInput, GpoSummary};
use magnetite_gpo::{provision, GpoSpec, RegValue, RegistrySetting};
use std::collections::BTreeMap;
use surrealdb::types::SurrealValue;
use uuid::Uuid;

/// A projection of the columns [`Db::list_gpos`] needs from an `entry` row.
#[derive(serde::Deserialize, SurrealValue)]
struct GpcRow {
    dn: String,
    /// The entry's attributes, stored as a JSON object of `name -> [values]`.
    attributes: String,
}

/// Derive the AD DNS domain (e.g. `example.com`) from a base DN
/// (`dc=example,dc=com`). Non-`dc=` components are ignored.
pub(crate) fn base_dn_to_domain(base_dn: &str) -> String {
    base_dn
        .split(',')
        .filter_map(|c| {
            c.trim()
                .strip_prefix("dc=")
                .or_else(|| c.trim().strip_prefix("DC="))
        })
        .collect::<Vec<_>>()
        .join(".")
}

/// The braced, upper-case GUID form AD uses for a GPO, e.g.
/// `{31B2F340-016D-11D2-945F-00C04FB984F9}`.
fn new_gpo_guid() -> String {
    format!("{{{}}}", Uuid::new_v4().to_string().to_uppercase())
}

impl Db {
    /// Provision a new GPO from `display_name` + machine registry `settings`, seeding
    /// its GPC into the directory and its GPT files into the replicated SYSVOL store
    /// (served over SMB after the next SYSVOL refresh). Returns the created summary.
    /// A fresh random GUID is assigned.
    ///
    /// # Errors
    /// A store error, or an invalid `Dword` setting (`data` not a `u32`).
    pub async fn create_gpo(
        &self,
        base_dn: &str,
        display_name: &str,
        settings: &[GpoSettingInput],
    ) -> DbResult<GpoSummary> {
        let domain = base_dn_to_domain(base_dn);
        let guid = new_gpo_guid();
        let machine_settings = settings
            .iter()
            .map(|s| {
                let data = match s.kind {
                    GpoRegKind::Dword => {
                        RegValue::Dword(s.data.trim().parse::<u32>().map_err(|_| {
                            crate::error::DbError::Constraint(format!(
                                "GPO setting {}\\{}: '{}' is not a valid DWORD",
                                s.key, s.value_name, s.data
                            ))
                        })?)
                    }
                    GpoRegKind::Sz => RegValue::Sz(s.data.clone()),
                };
                Ok(RegistrySetting {
                    key: s.key.clone(),
                    value: s.value_name.clone(),
                    data,
                })
            })
            .collect::<DbResult<Vec<_>>>()?;

        let gpo = provision(&GpoSpec {
            display_name: display_name.to_string(),
            guid: guid.clone(),
            domain,
            machine_settings,
        });
        self.seed_provisioned_gpo(base_dn, &gpo).await?;
        Ok(GpoSummary {
            guid,
            display_name: display_name.to_string(),
            version: gpo.version,
            gpc_path: gpo
                .gpc_attributes
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("gPCFileSysPath"))
                .map(|(_, v)| v.clone())
                .unwrap_or_default(),
        })
    }

    /// Seed a provisioned GPO's GPC (directory) + GPT (SYSVOL) halves. Idempotent.
    async fn seed_provisioned_gpo(
        &self,
        base_dn: &str,
        gpo: &magnetite_gpo::ProvisionedGpo,
    ) -> DbResult<()> {
        let system = format!("CN=System,{base_dn}");
        let policies = format!("CN=Policies,{system}");
        let gpc = format!("CN={},{policies}", gpo.guid);
        self.seed_gpo_container(&system, "System").await?;
        self.seed_gpo_container(&policies, "Policies").await?;

        let mut object_classes = Vec::new();
        let mut attributes: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (key, value) in &gpo.gpc_attributes {
            if key.eq_ignore_ascii_case("objectClass") {
                object_classes.push(value.clone());
            } else {
                attributes
                    .entry(key.clone())
                    .or_default()
                    .push(value.clone());
            }
        }
        self.apply_ldap_sync_entry(&gpc, &gpo.guid, object_classes, &attributes, true)
            .await?;
        self.seed_gpo_container(&format!("CN=Machine,{gpc}"), "Machine")
            .await?;
        self.seed_gpo_container(&format!("CN=User,{gpc}"), "User")
            .await?;
        self.seed_sysvol_files(&gpo.sysvol_files).await?;
        Ok(())
    }

    /// Seed a plain `container` object with a `cn` (idempotent).
    async fn seed_gpo_container(&self, dn: &str, cn: &str) -> DbResult<()> {
        let mut attributes = BTreeMap::new();
        attributes.insert("cn".to_string(), vec![cn.to_string()]);
        self.apply_ldap_sync_entry(
            dn,
            dn,
            vec!["top".to_string(), "container".to_string()],
            &attributes,
            true,
        )
        .await?;
        Ok(())
    }

    /// List every provisioned GPO (its `groupPolicyContainer` object), newest name
    /// order irrelevant — sorted by display name.
    ///
    /// # Errors
    /// A store error.
    pub async fn list_gpos(&self, _base_dn: &str) -> DbResult<Vec<GpoSummary>> {
        let rows: Vec<GpcRow> = match self
            .inner
            .query(
                "SELECT dn, attributes FROM entry WHERE structural_class = 'groupPolicyContainer'",
            )
            .await
        {
            Ok(mut r) => r.take(0).unwrap_or_default(),
            Err(e) if e.to_string().contains("does not exist") => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        let mut out: Vec<GpoSummary> = rows
            .into_iter()
            .map(|r| {
                let attrs: BTreeMap<String, Vec<String>> =
                    serde_json::from_str(&r.attributes).unwrap_or_default();
                let first = |k: &str| {
                    attrs
                        .iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case(k))
                        .and_then(|(_, v)| v.first())
                        .cloned()
                        .unwrap_or_default()
                };
                // The GUID comes from the `cn` attribute (case-preserved), not the
                // DN's RDN — `normalize_dn` lower-cases the stored DN.
                let guid = {
                    let cn = first("cn");
                    if cn.is_empty() {
                        r.dn.split(',')
                            .next()
                            .and_then(|rdn| rdn.split_once('='))
                            .map(|(_, v)| v.to_string())
                            .unwrap_or_default()
                    } else {
                        cn
                    }
                };
                GpoSummary {
                    guid,
                    display_name: first("displayName"),
                    version: first("versionNumber").parse().unwrap_or(0),
                    gpc_path: first("gPCFileSysPath"),
                }
            })
            .collect();
        out.sort_by_key(|g| g.display_name.to_lowercase());
        Ok(out)
    }

    /// Delete a GPO by GUID: remove its GPC object + `CN=Machine`/`CN=User`
    /// sub-containers from the directory, and tombstone its GPT files from the SYSVOL
    /// store (so it stops being served + the deletion replicates). A no-op if absent.
    ///
    /// # Errors
    /// A store error.
    pub async fn delete_gpo(&self, base_dn: &str, guid: &str) -> DbResult<()> {
        let gpc = format!("CN={guid},CN=Policies,CN=System,{base_dn}");
        let gpc = magnetite_core::domains::ldap::validate::normalize_dn(&gpc);
        // Remove the GPC and any child (Machine/User) in one transaction.
        self.inner
            .query("DELETE entry WHERE dn = $dn OR parent_dn = $dn")
            .bind(("dn", gpc))
            .await?;
        // Tombstone the GPT files under this GUID's SYSVOL path (…\Policies\{GUID}\…).
        let needle = format!("\\Policies\\{guid}\\").to_lowercase();
        for (path, _) in self.list_sysvol_files().await? {
            if path.to_lowercase().contains(&needle) {
                self.delete_sysvol_file(&path).await?;
            }
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

    #[test]
    fn base_dn_to_domain_maps_dc_components() {
        assert_eq!(base_dn_to_domain("dc=example,dc=com"), "example.com");
        assert_eq!(base_dn_to_domain("DC=magtest,DC=local"), "magtest.local");
    }

    #[tokio::test]
    async fn create_list_delete_gpo_round_trips() {
        let (db, _dir) = test_db().await;
        let base = "dc=example,dc=com";
        let settings = vec![
            GpoSettingInput {
                key: "Software\\Policies\\Test".into(),
                value_name: "EnableFoo".into(),
                kind: GpoRegKind::Dword,
                data: "1".into(),
            },
            GpoSettingInput {
                key: "Software\\Policies\\Test".into(),
                value_name: "Banner".into(),
                kind: GpoRegKind::Sz,
                data: "hello".into(),
            },
        ];
        let created = db.create_gpo(base, "Test Policy", &settings).await.unwrap();
        assert!(created.guid.starts_with('{') && created.guid.ends_with('}'));
        assert!(created.gpc_path.contains(&created.guid));

        // Listed with its GPC attributes.
        let gpos = db.list_gpos(base).await.unwrap();
        let g = gpos
            .iter()
            .find(|g| g.guid == created.guid)
            .expect("GPO listed");
        assert_eq!(g.display_name, "Test Policy");
        assert!(g.version > 0);

        // The GPT files landed in the SYSVOL store (GPT.INI + Machine/Registry.pol).
        let sysvol = db.list_sysvol_files().await.unwrap();
        let guid = &created.guid;
        assert!(sysvol
            .iter()
            .any(|(p, _)| p.contains(guid) && p.ends_with("GPT.INI")));
        assert!(sysvol
            .iter()
            .any(|(p, _)| p.contains(guid) && p.ends_with("Registry.pol")));

        // A bad DWORD is rejected.
        let bad = vec![GpoSettingInput {
            key: "K".into(),
            value_name: "V".into(),
            kind: GpoRegKind::Dword,
            data: "not-a-number".into(),
        }];
        assert!(db.create_gpo(base, "Bad", &bad).await.is_err());

        // Delete removes the GPC and its GPT files.
        db.delete_gpo(base, &created.guid).await.unwrap();
        assert!(!db
            .list_gpos(base)
            .await
            .unwrap()
            .iter()
            .any(|g| g.guid == created.guid));
        let sysvol2 = db.list_sysvol_files().await.unwrap();
        assert!(!sysvol2.iter().any(|(p, _)| p.contains(guid)));
    }
}
