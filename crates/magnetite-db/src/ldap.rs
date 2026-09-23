//! LDAP (directory) domain repository (07_data_ldap / 08_ldap_logic): DIT tree
//! nodes, typed user/group/OU projections, the OU delete guard (AC-15) and
//! group membership. Rename (modrdn) chains, ACL, schema and LDIF are layered
//! on in a later increment.

use crate::error::{DbError, DbResult};
use crate::records::{parse_rfc3339, record_key, to_rfc3339};
use crate::store::Db;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use chrono::Utc;
use magnetite_core::domains::ldap::model::{
    DirectoryEntry, LdapAclEffect, LdapAclOperation, LdapAclRule, LdapAclSubject, LdapGroup,
    LdapOu, LdapSyncState, LdapUser, TreeNode, OC_CONTAINER, OC_DOMAIN, OC_GROUP, OC_OU, OC_USER,
};
use magnetite_core::domains::ldap::validate::{build_dn, normalize_dn};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use surrealdb::types::{RecordId, SurrealValue};

/// Lowercase hex of raw bytes (the `objectSid` storage form, decoded to binary on
/// serving — see the LDAP service's AD-import path).
fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The RID (last sub-authority) of a binary SID given as a lowercase-hex string, or
/// `None` if it is malformed / too short. SID layout: `revision`, `subauth count`, a
/// 6-byte identifier authority, then `count` little-endian `u32` sub-authorities.
fn rid_from_sid_hex(sid_hex: &str) -> Option<u32> {
    if sid_hex.len() < 2 || !sid_hex.len().is_multiple_of(2) {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..sid_hex.len() / 2)
        .map(|i| u8::from_str_radix(&sid_hex[i * 2..i * 2 + 2], 16).ok())
        .collect();
    let bytes = bytes?;
    let count = *bytes.get(1)? as usize;
    let last = 8 + count.checked_sub(1)? * 4;
    Some(u32::from_le_bytes(
        bytes.get(last..last + 4)?.try_into().ok()?,
    ))
}

/// Per-role FSMO owner overrides, each the owning DC's server/NetBIOS name (which is
/// its nTDSDSA parent CN). A role left `None` defaults to the local DC. Used by
/// [`Db::seed_fsmo_roles_owned`] so a multi-DC domain reports the real holder of each
/// role rather than always the local DC.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FsmoOwners {
    /// Schema Master owner (forest-wide).
    pub schema: Option<String>,
    /// Domain Naming Master owner (forest-wide).
    pub domain_naming: Option<String>,
    /// RID Master owner.
    pub rid: Option<String>,
    /// Infrastructure Master owner.
    pub infrastructure: Option<String>,
    /// PDC Emulator owner.
    pub pdc: Option<String>,
    /// DomainDnsZones Infrastructure owner.
    pub domain_dns: Option<String>,
    /// ForestDnsZones Infrastructure owner.
    pub forest_dns: Option<String>,
}

impl FsmoOwners {
    /// Parse a `role=owner` spec (comma-separated) into per-role overrides. Role keys
    /// (case-insensitive): `schema`, `naming`/`domain-naming`, `rid`, `pdc`,
    /// `infra`/`infrastructure`, `domaindns`/`domain-dns`, `forestdns`/`forest-dns`.
    /// Unknown keys and empty owners are ignored.
    pub fn from_spec(spec: &str) -> Self {
        let mut o = FsmoOwners::default();
        for entry in spec.split(',') {
            let Some((key, owner)) = entry.split_once('=') else {
                continue;
            };
            let owner = owner.trim();
            if owner.is_empty() {
                continue;
            }
            let slot = match key.trim().to_ascii_lowercase().as_str() {
                "schema" => &mut o.schema,
                "naming" | "domain-naming" => &mut o.domain_naming,
                "rid" => &mut o.rid,
                "pdc" => &mut o.pdc,
                "infra" | "infrastructure" => &mut o.infrastructure,
                "domaindns" | "domain-dns" => &mut o.domain_dns,
                "forestdns" | "forest-dns" => &mut o.forest_dns,
                _ => continue,
            };
            *slot = Some(owner.to_string());
        }
        o
    }
}

const MSG_OU_GUARD: &str = "この OU には配下エントリがあります。先に移動または削除してください。";
const MSG_DN_DUP: &str = "同じ DN のエントリが既に存在します。";

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct EntryRecord {
    id: Option<RecordId>,
    dn: String,
    rdn: String,
    parent_dn: Option<String>,
    object_classes: Vec<String>,
    structural_class: String,
    /// JSON-encoded `BTreeMap<String, Vec<String>>`.
    attributes: String,
    enabled: bool,
    /// Argon2 hash; never projected to clients.
    password_ref: Option<String>,
    has_children: bool,
    created_at: String,
    updated_at: String,
    created_by: String,
    /// Upstream syncrepl entryUUID for entries pulled by the consumer (RFC 4533),
    /// used to apply deletes by UUID. `None` for locally-created entries.
    #[serde(default)]
    source_uuid: Option<String>,
}

/// An LDAP modify operation (RFC 4511 §4.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LdapModifyOp {
    /// Add the given values to the attribute (creating it if absent).
    Add,
    /// Remove the given values (or the whole attribute if none are given).
    Delete,
    /// Replace all of the attribute's values (or delete it if none are given).
    Replace,
}

/// A single attribute change within an LDAP modify.
#[derive(Clone, Debug)]
pub struct LdapAttrChange {
    pub op: LdapModifyOp,
    pub attr: String,
    pub values: Vec<String>,
}

impl EntryRecord {
    fn attributes_map(&self) -> BTreeMap<String, Vec<String>> {
        serde_json::from_str(&self.attributes).unwrap_or_default()
    }

    fn into_entry(self) -> DirectoryEntry {
        let attributes = self.attributes_map();
        DirectoryEntry {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            dn: self.dn,
            rdn: self.rdn,
            parent_dn: self.parent_dn,
            object_classes: self.object_classes,
            structural_class: self.structural_class,
            attributes,
            has_children: self.has_children,
        }
    }
}

fn hash_password(password: &str) -> DbResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| DbError::PasswordHash(e.to_string()))
}

/// Add `value` to attribute `attr` (case-insensitive key match), avoiding a
/// duplicate value. Used to keep the RDN attribute present after a rename.
fn add_attr_value(attrs: &mut BTreeMap<String, Vec<String>>, attr: &str, value: &str) {
    let key = attrs
        .keys()
        .find(|k| k.eq_ignore_ascii_case(attr))
        .cloned()
        .unwrap_or_else(|| attr.to_string());
    let values = attrs.entry(key).or_default();
    if !values.iter().any(|v| v.eq_ignore_ascii_case(value)) {
        values.push(value.to_string());
    }
}

/// Remove `value` from attribute `attr` (case-insensitive), dropping the
/// attribute entirely if it becomes empty. Used for `deleteOldRDN`.
fn remove_attr_value(attrs: &mut BTreeMap<String, Vec<String>>, attr: &str, value: &str) {
    let Some(key) = attrs.keys().find(|k| k.eq_ignore_ascii_case(attr)).cloned() else {
        return;
    };
    if let Some(values) = attrs.get_mut(&key) {
        values.retain(|v| !v.eq_ignore_ascii_case(value));
        if values.is_empty() {
            attrs.remove(&key);
        }
    }
}

/// A directory-change tombstone for LDAP content sync (RFC 4533): records a
/// deleted entry's DN and the change sequence number (CSN, an RFC3339 timestamp)
/// so a consumer can be told what disappeared since its cookie.
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct LdapChangeRecord {
    id: Option<RecordId>,
    dn: String,
    csn: String,
}

/// Persisted consumer-side syncrepl state (singleton row).
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct LdapSyncStateRecord {
    id: Option<RecordId>,
    cookie: String,
    last_sync: Option<String>,
    applied: u64,
    deleted: u64,
    last_error: Option<String>,
}

impl Db {
    /// Seed the directory root entry if none exists yet, and return the base DN
    /// (naming context). `base_dn` is the configured value used only for the
    /// first seed; once the directory is seeded the persisted root DN is returned
    /// (changing the base DN would orphan the existing tree).
    pub async fn ensure_ldap_base(&self, base_dn: &str, actor: &str) -> DbResult<String> {
        if let Some(existing) = self.ldap_root_dn().await? {
            return Ok(existing);
        }
        let base_dn = normalize_dn(base_dn);
        let now = to_rfc3339(Utc::now());
        let rec = EntryRecord {
            id: None,
            dn: base_dn.clone(),
            rdn: base_dn.split(',').next().unwrap_or(&base_dn).to_string(),
            parent_dn: None,
            object_classes: vec!["top".into(), OC_DOMAIN.into()],
            structural_class: OC_DOMAIN.into(),
            attributes: "{}".into(),
            enabled: true,
            password_ref: None,
            has_children: false,
            created_at: now.clone(),
            updated_at: now,
            created_by: actor.to_string(),
            source_uuid: None,
        };
        let _: Option<EntryRecord> = self.inner.create("entry").content(rec).await?;
        Ok(base_dn)
    }

    /// Seed the AD well-known containers under the domain root so a domain-join
    /// client has somewhere to create its `computer` object. Creates (idempotently)
    /// `CN=Users`, `CN=Computers`, `CN=System` (objectClass `container`) and
    /// `OU=Domain Controllers`. Ensures the base first; safe to call on every start.
    ///
    /// # Errors
    /// Propagates base/entry store failures.
    pub async fn seed_domain_containers(&self, base_dn: &str, actor: &str) -> DbResult<()> {
        let base = self.ensure_ldap_base(base_dn, actor).await?;
        for cn in ["Users", "Computers", "System"] {
            self.ensure_container(&format!("CN={cn},{base}"), OC_CONTAINER, actor)
                .await?;
        }
        // Domain Controllers is an OU in AD, not a plain container.
        self.ensure_container(&format!("OU=Domain Controllers,{base}"), OC_OU, actor)
            .await?;
        Ok(())
    }

    /// Create a structural container entry (`container` or `organizationalUnit`) at
    /// `dn` if it does not already exist. Idempotent.
    async fn ensure_container(&self, dn: &str, structural: &str, actor: &str) -> DbResult<()> {
        let norm = normalize_dn(dn);
        if self.find_entry(&norm).await?.is_some() {
            return Ok(());
        }
        let rdn = norm.split(',').next().unwrap_or(&norm).to_string();
        let parent_dn = norm.split_once(',').map(|(_, p)| p.to_string());
        let (now, by) = Self::now_meta(actor);
        let rec = EntryRecord {
            id: None,
            dn: norm,
            rdn,
            parent_dn,
            object_classes: vec!["top".into(), structural.to_string()],
            structural_class: structural.to_string(),
            attributes: "{}".into(),
            enabled: true,
            password_ref: None,
            has_children: false,
            created_at: now.clone(),
            updated_at: now,
            created_by: by,
            source_uuid: None,
        };
        self.insert_entry(rec).await?;
        Ok(())
    }

    /// Create a structural object with `attrs` at `dn` if it does not exist.
    /// Idempotent (a present object is left untouched).
    async fn ensure_object(
        &self,
        dn: &str,
        structural: &str,
        attrs: &[(&str, &str)],
        actor: &str,
    ) -> DbResult<()> {
        let norm = normalize_dn(dn);
        if self.find_entry(&norm).await?.is_some() {
            return Ok(());
        }
        let rdn = norm.split(',').next().unwrap_or(&norm).to_string();
        let parent_dn = norm.split_once(',').map(|(_, p)| p.to_string());
        let attributes: BTreeMap<String, Vec<String>> = attrs
            .iter()
            .map(|(k, v)| (k.to_string(), vec![v.to_string()]))
            .collect();
        let (now, by) = Self::now_meta(actor);
        let rec = EntryRecord {
            id: None,
            dn: norm,
            rdn,
            parent_dn,
            object_classes: vec!["top".into(), structural.to_string()],
            structural_class: structural.to_string(),
            attributes: serde_json::to_string(&attributes).unwrap_or_else(|_| "{}".into()),
            enabled: true,
            password_ref: None,
            has_children: false,
            created_at: now.clone(),
            updated_at: now,
            created_by: by,
            source_uuid: None,
        };
        self.insert_entry(rec).await?;
        Ok(())
    }

    /// Seed the AD Configuration/Schema partitions, this DC's `nTDSDSA` object, and
    /// the five FSMO role objects — each with `fSMORoleOwner` pointing at this DC —
    /// so a single-DC forest correctly reports itself as the holder of all five
    /// roles (`netdom query fsmo`, `Get-ADForest`/`Get-ADDomain`). Idempotent; safe
    /// to call on every start.
    ///
    /// # Errors
    /// Propagates base/entry store failures.
    pub async fn seed_fsmo_roles(
        &self,
        base_dn: &str,
        dc_netbios: &str,
        actor: &str,
    ) -> DbResult<()> {
        self.seed_fsmo_roles_owned(base_dn, dc_netbios, &FsmoOwners::default(), actor)
            .await
    }

    /// Like [`seed_fsmo_roles`](Self::seed_fsmo_roles) but each role's `fSMORoleOwner`
    /// follows `owners`: a role assigned to a peer DC points at THAT DC's nTDSDSA
    /// (`CN=NTDS Settings,CN=<peer>,...`) rather than the local DC, so a multi-DC domain
    /// reports the true holder. A role left unset in `owners` defaults to `dc_netbios`.
    ///
    /// # Errors
    /// Propagates base/entry store failures.
    pub async fn seed_fsmo_roles_owned(
        &self,
        base_dn: &str,
        dc_netbios: &str,
        owners: &FsmoOwners,
        actor: &str,
    ) -> DbResult<()> {
        let base = self.ensure_ldap_base(base_dn, actor).await?;
        let config = format!("CN=Configuration,{base}");
        let sites = format!("CN=Sites,{config}");
        let site1 = format!("CN=Default-First-Site-Name,{sites}");
        let servers = format!("CN=Servers,{site1}");
        let server = format!("CN={dc_netbios},{servers}");
        let ntds = format!("CN=NTDS Settings,{server}");
        // The local DC's directory-service (nTDSDSA) object — the default role owner.
        let owner = normalize_dn(&ntds);
        // Resolve a role's owner DN: the assigned peer's nTDSDSA, or the local DC.
        let owner_of = |peer: &Option<String>| -> String {
            match peer {
                Some(nb) if nb != dc_netbios => normalize_dn(&format!(
                    "CN=NTDS Settings,CN={nb},CN=Servers,CN=Default-First-Site-Name,CN=Sites,{config}"
                )),
                _ => owner.clone(),
            }
        };
        let o_schema = owner_of(&owners.schema);
        let o_naming = owner_of(&owners.domain_naming);
        let o_rid = owner_of(&owners.rid);
        let o_infra = owner_of(&owners.infrastructure);
        let o_pdc = owner_of(&owners.pdc);
        let o_ddns = owner_of(&owners.domain_dns);
        let o_fdns = owner_of(&owners.forest_dns);

        // The Configuration partition path down to this DC's NTDS Settings object.
        self.ensure_object(&config, "container", &[], actor).await?;
        self.ensure_object(&sites, "container", &[], actor).await?;
        self.ensure_object(&site1, "site", &[], actor).await?;
        self.ensure_object(&servers, "container", &[], actor)
            .await?;
        self.ensure_object(&server, "server", &[], actor).await?;
        self.ensure_object(&ntds, "nTDSDSA", &[], actor).await?;

        // Forest roles: Schema Master + Domain Naming Master.
        let schema = format!("CN=Schema,{config}");
        let partitions = format!("CN=Partitions,{config}");
        self.ensure_object(&schema, "dMD", &[("fSMORoleOwner", &o_schema)], actor)
            .await?;
        self.ensure_object(
            &partitions,
            "crossRefContainer",
            &[("fSMORoleOwner", &o_naming)],
            actor,
        )
        .await?;

        // The domain crossRef under CN=Partitions. A domain-join client reads
        // `nETBIOSName` here to learn the flat (NetBIOS) domain name; without this
        // object the join aborts with "the parameter is incorrect" (INVALID_PARAMETER)
        // after the machine account is created. Derive the DNS root + NetBIOS name
        // from the base DN (e.g. dc=yumewaka,dc=local → yumewaka.local / YUMEWAKA).
        let dc_labels: Vec<String> = base
            .split(',')
            .filter_map(|c| {
                let c = c.trim();
                c.strip_prefix("dc=").or_else(|| c.strip_prefix("DC="))
            })
            .map(|s| s.to_string())
            .collect();
        let dns_root = dc_labels.join(".");
        let domain_netbios: String = dc_labels
            .first()
            .map(|s| s.to_ascii_uppercase().chars().take(15).collect())
            .unwrap_or_default();
        if !domain_netbios.is_empty() {
            let crossref = format!("CN={domain_netbios},{partitions}");
            self.ensure_object(
                &crossref,
                "crossRef",
                &[
                    ("nCName", base.as_str()),
                    ("nETBIOSName", domain_netbios.as_str()),
                    ("dnsRoot", dns_root.as_str()),
                    // FLAG_CR_NTDS_NC (1) | FLAG_CR_NTDS_DOMAIN (2): a writable domain NC.
                    ("systemFlags", "3"),
                ],
                actor,
            )
            .await?;
        }
        // Domain roles: RID Master + Infrastructure Master. RID Manager$ lives under
        // CN=System, so ensure that container exists (seed_domain_containers also
        // creates it, but keep this self-contained).
        self.ensure_object(&format!("CN=System,{base}"), OC_CONTAINER, &[], actor)
            .await?;
        let rid_manager = format!("CN=RID Manager$,CN=System,{base}");
        let infrastructure = format!("CN=Infrastructure,{base}");
        self.ensure_object(
            &rid_manager,
            "rIDManager",
            &[("fSMORoleOwner", &o_rid)],
            actor,
        )
        .await?;
        self.ensure_object(
            &infrastructure,
            "infrastructureUpdate",
            &[("fSMORoleOwner", &o_infra)],
            actor,
        )
        .await?;

        // DNS application-partition FSMO roles. `samba-tool fsmo show` (and AD's own
        // DNS-integrated zones) reads the Infrastructure object under the
        // DomainDnsZones and ForestDnsZones partitions; without them samba-tool raises
        // `IndexError` on the empty search result. In a single-domain forest both
        // partitions hang off the domain base. Seed each partition head plus its
        // Infrastructure role object pointing at this DC.
        for (partition, dns_owner) in [("DomainDnsZones", &o_ddns), ("ForestDnsZones", &o_fdns)] {
            let part_head = format!("DC={partition},{base}");
            self.ensure_object(&part_head, "domainDNS", &[], actor)
                .await?;
            let dns_infra = format!("CN=Infrastructure,{part_head}");
            self.ensure_object(
                &dns_infra,
                "infrastructureUpdate",
                &[("fSMORoleOwner", dns_owner.as_str())],
                actor,
            )
            .await?;
        }

        // The PDC Emulator role is held on the domain root itself.
        let root_has_owner = self
            .find_entry(&base)
            .await?
            .map(|e| e.into_entry().attr("fSMORoleOwner").is_some())
            .unwrap_or(false);
        if !root_has_owner {
            self.modify_entry(
                &base,
                &[LdapAttrChange {
                    op: LdapModifyOp::Replace,
                    attr: "fSMORoleOwner".to_string(),
                    values: vec![o_pdc],
                }],
            )
            .await?;
        }
        Ok(())
    }

    /// Seize a FSMO role to this DC in response to a rootDSE `become<X>Master`
    /// request (what `ntdsutil` / `Move-ADDirectoryServerOperationMasterRole` /
    /// `samba-tool fsmo seize` write): rewrite the role object's `fSMORoleOwner` to
    /// this DC's nTDSDSA. `role_attr` is the seize trigger attribute
    /// (case-insensitive); returns the role object DN rewritten, or `None` if
    /// `role_attr` is not a recognized FSMO seize. Idempotent, and uses the same DN
    /// shape [`seed_fsmo_roles_owned`](Self::seed_fsmo_roles_owned) serves so a later
    /// `fsmo show` stays consistent.
    ///
    /// # Errors
    /// Propagates base/entry store failures.
    pub async fn seize_fsmo_role(
        &self,
        base_dn: &str,
        dc_netbios: &str,
        role_attr: &str,
    ) -> DbResult<Option<String>> {
        let base = self.ensure_ldap_base(base_dn, "system").await?;
        let config = format!("CN=Configuration,{base}");
        let role_dn = match role_attr.to_ascii_lowercase().as_str() {
            "becomeschemamaster" => format!("CN=Schema,{config}"),
            "becomedomainmaster" => format!("CN=Partitions,{config}"),
            "becomeridmaster" => format!("CN=RID Manager$,CN=System,{base}"),
            "becomeinfrastructuremaster" => format!("CN=Infrastructure,{base}"),
            "becomepdc" => base.clone(),
            _ => return Ok(None),
        };
        let owner = normalize_dn(&format!(
            "CN=NTDS Settings,CN={dc_netbios},CN=Servers,CN=Default-First-Site-Name,CN=Sites,{config}"
        ));
        self.modify_entry(
            &role_dn,
            &[LdapAttrChange {
                op: LdapModifyOp::Replace,
                attr: "fSMORoleOwner".to_string(),
                values: vec![owner],
            }],
        )
        .await?;
        Ok(Some(role_dn))
    }

    /// The current `fSMORoleOwner` of each of the five FSMO role objects, in a fixed
    /// order: `(role_key, role_object_dn, owner_dn)`. `owner_dn` is `None` when the
    /// role object or its owner attribute is absent. `role_key` is the stable key the
    /// Web layer maps to a seize trigger (`schema`/`domain_naming`/`rid`/
    /// `infrastructure`/`pdc`).
    ///
    /// # Errors
    /// Propagates entry store failures.
    pub async fn fsmo_owners(
        &self,
        base_dn: &str,
    ) -> DbResult<Vec<(&'static str, String, Option<String>)>> {
        let base = normalize_dn(base_dn);
        let config = format!("CN=Configuration,{base}");
        let roles: [(&'static str, String); 5] = [
            ("schema", format!("CN=Schema,{config}")),
            ("domain_naming", format!("CN=Partitions,{config}")),
            ("rid", format!("CN=RID Manager$,CN=System,{base}")),
            ("infrastructure", format!("CN=Infrastructure,{base}")),
            ("pdc", base.clone()),
        ];
        let mut out = Vec::with_capacity(roles.len());
        for (key, dn) in roles {
            let owner = self.get_entry(&dn).await?.and_then(|e| {
                e.attributes
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("fSMORoleOwner"))
                    .and_then(|(_, v)| v.first().cloned())
            });
            out.push((key, dn, owner));
        }
        Ok(out)
    }

    /// The persisted directory root DN (the domain-class entry), if the directory
    /// has been seeded.
    pub async fn ldap_root_dn(&self) -> DbResult<Option<String>> {
        let recs: Vec<String> = self
            .inner
            .query("SELECT VALUE dn FROM entry WHERE structural_class = $sc LIMIT 1")
            .bind(("sc", OC_DOMAIN.to_string()))
            .await?
            .take(0)?;
        Ok(recs.into_iter().next())
    }

    // ---- Content synchronization (RFC 4533 provider) ----------------------

    /// The directory's current context CSN (the RFC 4533 sync cookie value): the
    /// latest change timestamp across live entries and deletion tombstones.
    pub async fn ldap_context_csn(&self) -> DbResult<String> {
        let mut max = String::new();
        let entries: Vec<String> = self
            .inner
            .query("SELECT VALUE updated_at FROM entry ORDER BY updated_at DESC LIMIT 1")
            .await?
            .take(0)?;
        if let Some(v) = entries.into_iter().next() {
            if v > max {
                max = v;
            }
        }
        let deletes: Vec<String> = self
            .inner
            .query("SELECT VALUE csn FROM ldap_changelog ORDER BY csn DESC LIMIT 1")
            .await?
            .take(0)?;
        if let Some(v) = deletes.into_iter().next() {
            if v > max {
                max = v;
            }
        }
        Ok(max)
    }

    /// Live entries changed strictly after `since` (an RFC3339 CSN), or all live
    /// entries when `since` is empty (add/modify phase of content sync).
    pub async fn ldap_entries_since(&self, since: &str) -> DbResult<Vec<DirectoryEntry>> {
        let recs: Vec<EntryRecord> = if since.is_empty() {
            self.inner
                .query("SELECT * FROM entry ORDER BY dn ASC")
                .await?
                .take(0)?
        } else {
            self.inner
                .query("SELECT * FROM entry WHERE updated_at > $s ORDER BY dn ASC")
                .bind(("s", since.to_string()))
                .await?
                .take(0)?
        };
        Ok(recs.into_iter().map(EntryRecord::into_entry).collect())
    }

    /// DNs of entries deleted strictly after `since` (delete phase of content
    /// sync).
    pub async fn ldap_deletions_since(&self, since: &str) -> DbResult<Vec<String>> {
        let recs: Vec<String> = self
            .inner
            .query("SELECT VALUE dn FROM ldap_changelog WHERE csn > $s ORDER BY csn ASC")
            .bind(("s", since.to_string()))
            .await?
            .take(0)?;
        Ok(recs)
    }

    // ---- Consumer side (RFC 4533 syncrepl replica) ------------------------

    /// Apply a replicated entry from an upstream provider: upsert it by DN,
    /// recording the source `entry_uuid` so a later delete-by-UUID can find it.
    /// Consumed entries are read replicas — no password is stored, so they cannot
    /// be used to bind locally.
    pub async fn apply_ldap_sync_entry(
        &self,
        dn: &str,
        entry_uuid: &str,
        object_classes: Vec<String>,
        attributes: &BTreeMap<String, Vec<String>>,
        enabled: bool,
    ) -> DbResult<bool> {
        let norm = normalize_dn(dn);
        let rdn = norm.split(',').next().unwrap_or(&norm).to_string();
        let parent_dn = norm.split_once(',').map(|(_, p)| p.to_string());
        let structural = object_classes
            .iter()
            .rev()
            .find(|c| !c.eq_ignore_ascii_case("top"))
            .cloned()
            .unwrap_or_else(|| "top".to_string());
        let attrs_json = serde_json::to_string(attributes).unwrap_or_else(|_| "{}".into());
        let now = to_rfc3339(Utc::now());

        let existing = self.find_entry(&norm).await?;
        if existing.is_some() {
            self.inner
                .query(
                    "UPDATE entry SET object_classes = $oc, structural_class = $sc, \
                         attributes = $at, source_uuid = $uuid, enabled = $en, updated_at = $t \
                         WHERE dn = $dn",
                )
                .bind(("oc", object_classes))
                .bind(("sc", structural))
                .bind(("at", attrs_json))
                .bind(("uuid", entry_uuid.to_string()))
                .bind(("en", enabled))
                .bind(("t", now))
                .bind(("dn", norm))
                .await?;
            Ok(false)
        } else {
            let rec = EntryRecord {
                id: None,
                dn: norm,
                rdn,
                parent_dn: parent_dn.clone(),
                object_classes,
                structural_class: structural,
                attributes: attrs_json,
                enabled,
                password_ref: None,
                has_children: false,
                created_at: now.clone(),
                updated_at: now,
                created_by: "syncrepl".to_string(),
                source_uuid: Some(entry_uuid.to_string()),
            };
            let _: Option<EntryRecord> = self.inner.create("entry").content(rec).await?;
            if let Some(parent) = parent_dn {
                // Best-effort: mark the parent as having children (ignore if the
                // parent hasn't been replicated yet).
                let _ = self.set_has_children(&parent, true).await;
            }
            Ok(true)
        }
    }

    /// All upstream `source_uuid`s of entries imported from a replication/AD
    /// source (used for deletion reconciliation: any local id no longer present
    /// upstream is a deletion).
    pub async fn ldap_imported_uuids(&self) -> DbResult<Vec<String>> {
        let uuids: Vec<String> = self
            .inner
            .query("SELECT VALUE source_uuid FROM entry WHERE source_uuid != NONE")
            .await?
            .take(0)?;
        Ok(uuids)
    }

    /// Apply a replicated deletion by the upstream `entry_uuid`. Returns whether a
    /// row was removed.
    pub async fn apply_ldap_sync_delete(&self, entry_uuid: &str) -> DbResult<bool> {
        let dns: Vec<String> = self
            .inner
            .query("SELECT VALUE dn FROM entry WHERE source_uuid = $u")
            .bind(("u", entry_uuid.to_string()))
            .await?
            .take(0)?;
        if dns.is_empty() {
            return Ok(false);
        }
        self.inner
            .query("DELETE entry WHERE source_uuid = $u")
            .bind(("u", entry_uuid.to_string()))
            .await?;
        Ok(true)
    }

    /// The consumer's persisted syncrepl state (defaults when never synced).
    pub async fn get_ldap_sync_state(&self) -> DbResult<LdapSyncState> {
        let recs: Vec<LdapSyncStateRecord> = self
            .inner
            .query("SELECT * FROM ldap_sync_state LIMIT 1")
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .next()
            .map(|r| LdapSyncState {
                cookie: r.cookie,
                last_sync: r.last_sync.as_deref().map(parse_rfc3339),
                applied: r.applied,
                deleted: r.deleted,
                last_error: r.last_error,
            })
            .unwrap_or_default())
    }

    /// Persist the consumer's syncrepl state after a refresh pass. `applied` /
    /// `deleted` are added to the running totals.
    pub async fn record_ldap_sync(
        &self,
        cookie: &str,
        applied: u64,
        deleted: u64,
        last_error: Option<&str>,
    ) -> DbResult<()> {
        let prev = self.get_ldap_sync_state().await?;
        let now = to_rfc3339(Utc::now());
        let applied_total = prev.applied + applied;
        let deleted_total = prev.deleted + deleted;
        let err = last_error.map(|s| s.to_string());
        let existing: Vec<LdapSyncStateRecord> = self
            .inner
            .query("SELECT * FROM ldap_sync_state LIMIT 1")
            .await?
            .take(0)?;
        if existing.is_empty() {
            let rec = LdapSyncStateRecord {
                id: None,
                cookie: cookie.to_string(),
                last_sync: Some(now),
                applied: applied_total,
                deleted: deleted_total,
                last_error: err,
            };
            let _: Option<LdapSyncStateRecord> =
                self.inner.create("ldap_sync_state").content(rec).await?;
        } else {
            self.inner
                .query(
                    "UPDATE ldap_sync_state SET cookie = $c, last_sync = $t, \
                         applied = $a, deleted = $d, last_error = $e",
                )
                .bind(("c", cookie.to_string()))
                .bind(("t", now))
                .bind(("a", applied_total))
                .bind(("d", deleted_total))
                .bind(("e", err))
                .await?;
        }
        Ok(())
    }

    async fn find_entry(&self, dn: &str) -> DbResult<Option<EntryRecord>> {
        let recs: Vec<EntryRecord> = self
            .inner
            .query("SELECT * FROM entry WHERE dn = $dn LIMIT 1")
            .bind(("dn", normalize_dn(dn)))
            .await?
            .take(0)?;
        Ok(recs.into_iter().next())
    }

    /// Fetch an entry by DN, with sensitive attributes stripped.
    pub async fn get_entry(&self, dn: &str) -> DbResult<Option<DirectoryEntry>> {
        Ok(self
            .find_entry(dn)
            .await?
            .map(|r| r.into_entry().redacted()))
    }

    /// Verify a simple-bind DN + password against the stored Argon2 hash
    /// (embedded LDAP server). `true` only for an existing, enabled entry whose
    /// password matches. Missing entry / disabled / no password ⇒ `false`.
    pub async fn verify_ldap_bind(&self, dn: &str, password: &str) -> DbResult<bool> {
        let Some(rec) = self.find_entry(dn).await? else {
            return Ok(false);
        };
        if !rec.enabled {
            return Ok(false);
        }
        let Some(hash) = rec.password_ref.as_deref() else {
            return Ok(false);
        };
        let Ok(parsed) = PasswordHash::new(hash) else {
            return Ok(false);
        };
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    }

    /// All directory entries, for the embedded LDAP search server to filter by
    /// scope and search filter. `DirectoryEntry` never carries the password
    /// (it lives in a separate column), so this projection is safe.
    pub async fn list_all_entries(&self) -> DbResult<Vec<DirectoryEntry>> {
        let recs: Vec<EntryRecord> = self
            .inner
            .query("SELECT * FROM entry ORDER BY dn ASC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(EntryRecord::into_entry).collect())
    }

    /// One entry by DN, non-redacted (for the LDAP `base`-scope search — same projection
    /// as [`list_all_entries`], unlike [`get_entry`] which redacts).
    pub async fn get_entry_full(&self, dn: &str) -> DbResult<Option<DirectoryEntry>> {
        Ok(self.find_entry(dn).await?.map(EntryRecord::into_entry))
    }

    /// The immediate children of `parent_dn` (LDAP `one-level`/`children` scope), pushing
    /// the scope filter into the DB (indexed `parent_dn`) instead of scanning every entry.
    pub async fn list_entries_by_parent(&self, parent_dn: &str) -> DbResult<Vec<DirectoryEntry>> {
        let recs: Vec<EntryRecord> = self
            .inner
            .query("SELECT * FROM entry WHERE parent_dn = $p ORDER BY dn ASC")
            .bind(("p", normalize_dn(parent_dn)))
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(EntryRecord::into_entry).collect())
    }

    /// `base_dn` and all its descendants (LDAP `subtree` scope), scoped in the DB by the
    /// normalized-DN suffix instead of loading the whole directory.
    pub async fn list_entries_subtree(&self, base_dn: &str) -> DbResult<Vec<DirectoryEntry>> {
        let base = normalize_dn(base_dn);
        let suffix = format!(",{base}");
        let recs: Vec<EntryRecord> = self
            .inner
            .query("SELECT * FROM entry WHERE dn = $b OR string::ends_with(dn, $s) ORDER BY dn ASC")
            .bind(("b", base))
            .bind(("s", suffix))
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(EntryRecord::into_entry).collect())
    }

    /// List all `computer` entries (DN-ordered), redacted (no credential). For the
    /// LDAP computers management screen.
    ///
    /// # Errors
    /// A store error.
    pub async fn list_computers(&self) -> DbResult<Vec<DirectoryEntry>> {
        let recs: Vec<EntryRecord> = self
            .inner
            .query("SELECT * FROM entry WHERE structural_class = 'computer' ORDER BY dn ASC")
            .await?
            .take(0)?;
        Ok(recs
            .into_iter()
            .map(|r| r.into_entry().redacted())
            .collect())
    }

    /// List direct children of `parent_dn` (or the roots when `None`) as tree
    /// nodes (S-LDAP-02 lazy expansion).
    pub async fn list_children(&self, parent_dn: Option<&str>) -> DbResult<Vec<TreeNode>> {
        let recs: Vec<EntryRecord> = match parent_dn {
            Some(p) => self
                .inner
                .query("SELECT * FROM entry WHERE parent_dn = $p ORDER BY dn ASC")
                .bind(("p", normalize_dn(p)))
                .await?
                .take(0)?,
            None => self
                .inner
                .query("SELECT * FROM entry WHERE parent_dn IS NONE ORDER BY dn ASC")
                .await?
                .take(0)?,
        };
        Ok(recs
            .into_iter()
            .map(|r| TreeNode::from(&r.into_entry()))
            .collect())
    }

    async fn list_by_structural(&self, class: &str) -> DbResult<Vec<EntryRecord>> {
        let recs: Vec<EntryRecord> = self
            .inner
            .query("SELECT * FROM entry WHERE structural_class = $c ORDER BY dn ASC")
            .bind(("c", class.to_string()))
            .await?
            .take(0)?;
        Ok(recs)
    }

    async fn parent_exists(&self, parent_dn: &str) -> DbResult<bool> {
        Ok(self.find_entry(parent_dn).await?.is_some())
    }

    async fn insert_entry(&self, rec: EntryRecord) -> DbResult<DirectoryEntry> {
        if self.find_entry(&rec.dn).await?.is_some() {
            return Err(DbError::Constraint(MSG_DN_DUP.into()));
        }
        if let Some(parent) = rec.parent_dn.clone() {
            if !self.parent_exists(&parent).await? {
                return Err(DbError::Constraint("親 DN が存在しません。".into()));
            }
        }
        let parent = rec.parent_dn.clone();
        let created: Option<EntryRecord> = self.inner.create("entry").content(rec).await?;
        let entry = created
            .map(EntryRecord::into_entry)
            .ok_or_else(|| DbError::Constraint("entry creation returned nothing".into()))?;
        if let Some(parent) = parent {
            self.set_has_children(&parent, true).await?;
        }
        Ok(entry)
    }

    /// Create a directory entry from a raw DN, object classes and attributes — the
    /// LDAP `AddRequest` path (e.g. a domain join adding a `computer` object). The
    /// RDN/parent are derived from the DN, the structural class is the last
    /// non-`top` object class, and `userPassword` is routed to the Argon2 credential
    /// column (never the attribute map). The parent must already exist.
    ///
    /// # Errors
    /// [`DbError::Constraint`] if the DN already exists or the parent is missing.
    pub async fn create_entry(
        &self,
        dn: &str,
        object_classes: Vec<String>,
        attributes: &BTreeMap<String, Vec<String>>,
        actor: &str,
    ) -> DbResult<DirectoryEntry> {
        let norm = normalize_dn(dn);
        let rdn = norm.split(',').next().unwrap_or(&norm).to_string();
        let parent_dn = norm.split_once(',').map(|(_, p)| p.to_string());
        let structural = object_classes
            .iter()
            .rev()
            .find(|c| !c.eq_ignore_ascii_case("top"))
            .cloned()
            .unwrap_or_else(|| "top".to_string());

        // Extract userPassword (case-insensitive) — it goes to the credential column.
        let mut attrs = attributes.clone();
        let pw_key = attrs
            .keys()
            .find(|k| k.eq_ignore_ascii_case("userPassword"))
            .cloned();
        let password = pw_key
            .and_then(|k| attrs.remove(&k))
            .and_then(|v| v.into_iter().next());

        let (now, by) = Self::now_meta(actor);
        let record = EntryRecord {
            id: None,
            dn: norm,
            rdn,
            parent_dn,
            object_classes,
            structural_class: structural,
            attributes: serde_json::to_string(&attrs).unwrap_or_else(|_| "{}".into()),
            enabled: true,
            password_ref: None,
            has_children: false,
            created_at: now.clone(),
            updated_at: now,
            created_by: by,
            source_uuid: None,
        };
        let entry = self.insert_entry(record).await?;
        if let Some(pw) = password {
            self.reset_password(&entry.dn, &pw).await?;
        }
        Ok(entry)
    }

    /// Ensure an LDAP `computer` object exists for a machine account created via
    /// SAMR — unifying the two stores so the account is consistent over LDAP too.
    /// Idempotent: creates the entry (seeding the base if needed) on the first call,
    /// updates its attributes on later calls. The entry is `cn=<name>,<base>` (the
    /// trailing `$` dropped from the CN).
    ///
    /// # Errors
    /// Propagates base/entry store failures.
    pub async fn ensure_computer_entry(
        &self,
        base_dn: &str,
        sam_account_name: &str,
        dns_host_name: &str,
        user_account_control: u32,
        actor: &str,
    ) -> DbResult<()> {
        let base = self.ensure_ldap_base(base_dn, actor).await?;
        let cn = sam_account_name.trim_end_matches('$');
        let dn = normalize_dn(&format!("cn={cn},{base}"));
        let mut attributes: BTreeMap<String, Vec<String>> = BTreeMap::new();
        attributes.insert("sAMAccountName".into(), vec![sam_account_name.to_string()]);
        attributes.insert("dNSHostName".into(), vec![dns_host_name.to_string()]);
        attributes.insert(
            "userAccountControl".into(),
            vec![user_account_control.to_string()],
        );
        if self.find_entry(&dn).await?.is_some() {
            let changes: Vec<LdapAttrChange> = attributes
                .into_iter()
                .map(|(attr, values)| LdapAttrChange {
                    op: LdapModifyOp::Replace,
                    attr,
                    values,
                })
                .collect();
            self.modify_entry(&dn, &changes).await?;
        } else {
            self.create_entry(
                &dn,
                vec!["top".into(), "computer".into()],
                &attributes,
                actor,
            )
            .await?;
        }
        Ok(())
    }

    /// Project a replicated AD **user** into the LDAP `entry` tree so the directory
    /// server (which reads only `entry`) serves it — the bridge from the `ad_principal`
    /// store the DRS-replication path writes to (B1). The entry is
    /// `CN=<sam>,CN=Users,<base>` with `objectClass: user`, `sAMAccountName`, the
    /// hex-encoded `objectSid` (the AD-import convention the server decodes to binary on
    /// serving) and `userAccountControl`. Idempotent: created once, its attributes
    /// refreshed on later replication cycles.
    ///
    /// # Errors
    /// Propagates base/entry store failures.
    pub async fn ensure_user_entry(
        &self,
        base_dn: &str,
        sam_account_name: &str,
        object_sid: &[u8],
        user_account_control: u32,
        actor: &str,
    ) -> DbResult<()> {
        let base = self.ensure_ldap_base(base_dn, actor).await?;
        let users = format!("CN=Users,{base}");
        self.ensure_container(&users, OC_CONTAINER, actor).await?;
        let dn = normalize_dn(&format!("CN={sam_account_name},{users}"));
        let mut attributes: BTreeMap<String, Vec<String>> = BTreeMap::new();
        attributes.insert("sAMAccountName".into(), vec![sam_account_name.to_string()]);
        attributes.insert("objectSid".into(), vec![hex_lower(object_sid)]);
        attributes.insert(
            "userAccountControl".into(),
            vec![user_account_control.to_string()],
        );
        self.upsert_projected_entry(
            &dn,
            vec![
                "top".into(),
                "person".into(),
                "organizationalPerson".into(),
                "user".into(),
            ],
            attributes,
            actor,
        )
        .await
    }

    /// Project a replicated AD **group** into the LDAP `entry` tree (B1): the bridge from
    /// the `ad_group` store. The entry is `CN=<sam>,CN=Users,<base>` with
    /// `objectClass: group`, `sAMAccountName`, the hex-encoded `objectSid`, and `member`
    /// = the DNs of its members (each member SID resolved to a `CN=…,CN=Users,<base>` DN
    /// via the `ad_principal`/`ad_group` stores; an unresolvable member is skipped — a
    /// later cycle re-projects once it exists). Idempotent.
    ///
    /// # Errors
    /// Propagates base/entry store failures.
    pub async fn ensure_group_entry(
        &self,
        base_dn: &str,
        sam_account_name: &str,
        object_sid: &[u8],
        member_sids_hex: &[String],
        actor: &str,
    ) -> DbResult<()> {
        let base = self.ensure_ldap_base(base_dn, actor).await?;
        let users = format!("CN=Users,{base}");
        self.ensure_container(&users, OC_CONTAINER, actor).await?;
        let member_dns = self.member_dns_for_sids(&base, member_sids_hex).await?;
        let dn = normalize_dn(&format!("CN={sam_account_name},{users}"));
        let mut attributes: BTreeMap<String, Vec<String>> = BTreeMap::new();
        attributes.insert("sAMAccountName".into(), vec![sam_account_name.to_string()]);
        attributes.insert("objectSid".into(), vec![hex_lower(object_sid)]);
        attributes.insert("member".into(), member_dns);
        self.upsert_projected_entry(&dn, vec!["top".into(), "group".into()], attributes, actor)
            .await
    }

    /// Resolve many members' `objectSid`s (hex) to their projected DNs under
    /// `CN=Users,<base>` in **two batched queries** (a group match by exact SID, else a
    /// principal match by the SID's RID) instead of two queries per member (N+1). Input
    /// order is preserved; SIDs neither store holds yet are skipped.
    async fn member_dns_for_sids(
        &self,
        base: &str,
        member_sids_hex: &[String],
    ) -> DbResult<Vec<String>> {
        if member_sids_hex.is_empty() {
            return Ok(Vec::new());
        }
        // A group can be a member of another group — match those by exact SID first.
        let sids: Vec<String> = member_sids_hex.to_vec();
        let group_recs: Vec<crate::ad::AdGroupRecord> = self
            .inner
            .query("SELECT * FROM ad_group WHERE sid IN $sids")
            .bind(("sids", sids))
            .await?
            .take(0)
            .unwrap_or_default();
        let group_by_sid: std::collections::HashMap<String, String> = group_recs
            .into_iter()
            .map(|g| (g.sid, g.sam_account_name))
            .collect();
        // The rest resolve to principals by RID (the SID's last sub-authority).
        let rids: Vec<u32> = member_sids_hex
            .iter()
            .filter_map(|s| rid_from_sid_hex(s))
            .collect();
        let principal_recs: Vec<crate::ad::AdPrincipalRecord> = if rids.is_empty() {
            Vec::new()
        } else {
            self.inner
                .query("SELECT * FROM ad_principal WHERE rid IN $rids")
                .bind(("rids", rids))
                .await?
                .take(0)
                .unwrap_or_default()
        };
        let principal_by_rid: std::collections::HashMap<u32, String> = principal_recs
            .into_iter()
            .map(|p| (p.rid, p.sam_account_name))
            .collect();

        let mut out = Vec::new();
        for sid_hex in member_sids_hex {
            if let Some(sam) = group_by_sid.get(sid_hex) {
                out.push(normalize_dn(&format!("CN={sam},CN=Users,{base}")));
            } else if let Some(sam) =
                rid_from_sid_hex(sid_hex).and_then(|r| principal_by_rid.get(&r))
            {
                out.push(normalize_dn(&format!("CN={sam},CN=Users,{base}")));
            }
        }
        Ok(out)
    }

    /// Create the projected `entry` at `dn`, or refresh its attributes if it already
    /// exists (Replace each). Shared by [`ensure_user_entry`](Self::ensure_user_entry)
    /// and [`ensure_group_entry`](Self::ensure_group_entry), and the entry point for
    /// **generic** replicated-object projection (Config/Schema NC objects, OUs): any DN
    /// with an object-class list and attribute map lands in the LDAP-servable `entry`
    /// tree. Schema validation is intentionally skipped, since the source AD is
    /// authoritative for the classes/attributes of a replicated object.
    ///
    /// # Errors
    /// Propagates store failures.
    pub async fn upsert_projected_entry(
        &self,
        dn: &str,
        object_classes: Vec<String>,
        attributes: BTreeMap<String, Vec<String>>,
        actor: &str,
    ) -> DbResult<()> {
        // A replicated object can arrive before an ancestor container was created (or its
        // parent is un-seeded), and `create_entry` requires the parent to exist — so
        // synthesize any missing ancestor as a plain container first.
        self.ensure_ancestors(dn, actor).await?;
        if self.find_entry(dn).await?.is_some() {
            let changes: Vec<LdapAttrChange> = attributes
                .into_iter()
                .map(|(attr, values)| LdapAttrChange {
                    op: LdapModifyOp::Replace,
                    attr,
                    values,
                })
                .collect();
            self.modify_entry(dn, &changes).await?;
        } else {
            self.create_entry(dn, object_classes, &attributes, actor)
                .await?;
        }
        Ok(())
    }

    /// Ensure every ancestor of `dn` exists, synthesizing any missing one as a plain
    /// `container` (top-down, so each has an existing parent). Stops at the first existing
    /// ancestor. In the live DC the Config skeleton is already seeded, so this only fills
    /// gaps; it lets a generically-projected object be stored even if an intermediate
    /// container was not itself replicated (its real class arrives — and Replaces — later
    /// only if it is a classifiable object).
    async fn ensure_ancestors(&self, dn: &str, actor: &str) -> DbResult<()> {
        let mut missing = Vec::new();
        let mut parent = dn.split_once(',').map(|(_, p)| normalize_dn(p));
        while let Some(p) = parent {
            if p.is_empty() || self.find_entry(&p).await?.is_some() {
                break;
            }
            parent = p.split_once(',').map(|(_, pp)| normalize_dn(pp));
            missing.push(p);
        }
        // `missing` is deep→shallow; create shallow→deep so each parent exists first.
        for anc in missing.into_iter().rev() {
            self.ensure_container(&anc, OC_CONTAINER, actor).await?;
        }
        Ok(())
    }

    /// Delete a projected `entry` by DN if it exists — the LDAP-tree side of applying a
    /// tombstone (B4b), so a deleted user/group also disappears from the directory
    /// server. A no-op if the entry was never projected.
    ///
    /// # Errors
    /// Propagates store failures.
    pub async fn delete_projected_entry(
        &self,
        base_dn: &str,
        sam_account_name: &str,
    ) -> DbResult<()> {
        let base = normalize_dn(base_dn);
        let dn = normalize_dn(&format!("CN={sam_account_name},CN=Users,{base}"));
        if self.find_entry(&dn).await?.is_some() {
            self.inner
                .query("DELETE entry WHERE dn = $dn")
                .bind(("dn", dn))
                .await?;
        }
        Ok(())
    }

    async fn set_has_children(&self, dn: &str, value: bool) -> DbResult<()> {
        self.inner
            .query("UPDATE entry SET has_children = $v WHERE dn = $dn")
            .bind(("v", value))
            .bind(("dn", normalize_dn(dn)))
            .await?;
        Ok(())
    }

    fn now_meta(actor: &str) -> (String, String) {
        (to_rfc3339(Utc::now()), actor.to_string())
    }

    /// Create a user entry under `parent_dn`.
    pub async fn create_user(
        &self,
        parent_dn: &str,
        uid: &str,
        cn: &str,
        sn: &str,
        mail: Option<&str>,
        actor: &str,
    ) -> DbResult<LdapUser> {
        let rdn = format!("uid={uid}");
        let dn = normalize_dn(&build_dn(&rdn, parent_dn));
        let mut attributes: BTreeMap<String, Vec<String>> = BTreeMap::new();
        attributes.insert("uid".into(), vec![uid.to_string()]);
        attributes.insert("cn".into(), vec![cn.to_string()]);
        attributes.insert("sn".into(), vec![sn.to_string()]);
        if let Some(m) = mail.filter(|m| !m.is_empty()) {
            attributes.insert("mail".into(), vec![m.to_string()]);
        }
        let (now, by) = Self::now_meta(actor);
        let rec = EntryRecord {
            id: None,
            dn,
            rdn,
            parent_dn: Some(normalize_dn(parent_dn)),
            object_classes: vec![
                "top".into(),
                "person".into(),
                "organizationalPerson".into(),
                OC_USER.into(),
            ],
            structural_class: OC_USER.into(),
            attributes: serde_json::to_string(&attributes).unwrap_or_default(),
            enabled: true,
            password_ref: None,
            has_children: false,
            created_at: now.clone(),
            updated_at: now,
            created_by: by,
            source_uuid: None,
        };
        let entry = self.insert_entry(rec).await?;
        Ok(LdapUser {
            dn: entry.dn,
            uid: uid.to_string(),
            cn: cn.to_string(),
            sn: sn.to_string(),
            mail: mail.filter(|m| !m.is_empty()).map(|m| m.to_string()),
            enabled: true,
        })
    }

    /// Create a group entry under `parent_dn`.
    pub async fn create_group(
        &self,
        parent_dn: &str,
        cn: &str,
        description: Option<&str>,
        actor: &str,
    ) -> DbResult<LdapGroup> {
        let rdn = format!("cn={cn}");
        let dn = normalize_dn(&build_dn(&rdn, parent_dn));
        let mut attributes: BTreeMap<String, Vec<String>> = BTreeMap::new();
        attributes.insert("cn".into(), vec![cn.to_string()]);
        if let Some(d) = description.filter(|d| !d.is_empty()) {
            attributes.insert("description".into(), vec![d.to_string()]);
        }
        attributes.insert("member".into(), Vec::new());
        let (now, by) = Self::now_meta(actor);
        let rec = EntryRecord {
            id: None,
            dn,
            rdn,
            parent_dn: Some(normalize_dn(parent_dn)),
            object_classes: vec!["top".into(), OC_GROUP.into()],
            structural_class: OC_GROUP.into(),
            attributes: serde_json::to_string(&attributes).unwrap_or_default(),
            enabled: true,
            password_ref: None,
            has_children: false,
            created_at: now.clone(),
            updated_at: now,
            created_by: by,
            source_uuid: None,
        };
        let entry = self.insert_entry(rec).await?;
        Ok(LdapGroup {
            dn: entry.dn,
            cn: cn.to_string(),
            description: description.filter(|d| !d.is_empty()).map(|d| d.to_string()),
            members: Vec::new(),
        })
    }

    /// Create an OU entry under `parent_dn`.
    pub async fn create_ou(
        &self,
        parent_dn: &str,
        ou: &str,
        description: Option<&str>,
        actor: &str,
    ) -> DbResult<LdapOu> {
        let rdn = format!("ou={ou}");
        let dn = normalize_dn(&build_dn(&rdn, parent_dn));
        let mut attributes: BTreeMap<String, Vec<String>> = BTreeMap::new();
        attributes.insert("ou".into(), vec![ou.to_string()]);
        if let Some(d) = description.filter(|d| !d.is_empty()) {
            attributes.insert("description".into(), vec![d.to_string()]);
        }
        let (now, by) = Self::now_meta(actor);
        let rec = EntryRecord {
            id: None,
            dn,
            rdn,
            parent_dn: Some(normalize_dn(parent_dn)),
            object_classes: vec!["top".into(), OC_OU.into()],
            structural_class: OC_OU.into(),
            attributes: serde_json::to_string(&attributes).unwrap_or_default(),
            enabled: true,
            password_ref: None,
            has_children: false,
            created_at: now.clone(),
            updated_at: now,
            created_by: by,
            source_uuid: None,
        };
        let entry = self.insert_entry(rec).await?;
        Ok(LdapOu {
            dn: entry.dn,
            ou: ou.to_string(),
            description: description.filter(|d| !d.is_empty()).map(|d| d.to_string()),
            has_children: false,
        })
    }

    /// Delete an entry (08_ldap_logic §2.4). Entries with children are refused
    /// (OU guard, AC-15); the deleted DN is stripped from all group members.
    pub async fn delete_entry(&self, dn: &str) -> DbResult<()> {
        let entry = self.find_entry(dn).await?.ok_or(DbError::NotFound)?;
        if entry.has_children {
            return Err(DbError::Constraint(MSG_OU_GUARD.into()));
        }
        let target = normalize_dn(dn);
        // Strip the DN from any group members.
        for mut group in self.list_by_structural(OC_GROUP).await? {
            let mut attrs = group.attributes_map();
            if let Some(members) = attrs.get_mut("member") {
                let before = members.len();
                members.retain(|m| normalize_dn(m) != target);
                if members.len() != before {
                    group.attributes = serde_json::to_string(&attrs).unwrap_or_default();
                    self.write_attributes(&group.dn, &group.attributes).await?;
                }
            }
        }
        self.inner
            .query("DELETE entry WHERE dn = $dn")
            .bind(("dn", target.clone()))
            .await?;
        // Tombstone for content sync (RFC 4533).
        let rec = LdapChangeRecord {
            id: None,
            dn: target,
            csn: to_rfc3339(Utc::now()),
        };
        let _: Option<LdapChangeRecord> = self.inner.create("ldap_changelog").content(rec).await?;
        // Recompute the parent's has_children.
        if let Some(parent) = entry.parent_dn {
            let remaining = self.list_children(Some(&parent)).await?;
            self.set_has_children(&parent, !remaining.is_empty())
                .await?;
        }
        Ok(())
    }

    /// Rename or move an entry (RFC 4511 §4.9 ModifyDN): replace the leaf RDN with
    /// `new_rdn`, optionally reparent under `new_superior`, and — when
    /// `delete_old_rdn` — drop the old RDN's attribute value (the new RDN value is
    /// always ensured present). Only leaf entries move (entries with children are
    /// refused, like [`Self::delete_entry`]); group `member` references are rewritten
    /// to the new DN, and the old DN is tombstoned for content sync.
    ///
    /// # Errors
    /// [`DbError::NotFound`] if absent; [`DbError::Constraint`] if it has children,
    /// the target DN already exists, or the new parent is missing.
    pub async fn rename_entry(
        &self,
        dn: &str,
        new_rdn: &str,
        delete_old_rdn: bool,
        new_superior: Option<&str>,
    ) -> DbResult<DirectoryEntry> {
        let mut record = self.find_entry(dn).await?.ok_or(DbError::NotFound)?;
        if record.has_children {
            return Err(DbError::Constraint(MSG_OU_GUARD.into()));
        }
        let old_dn = normalize_dn(dn);
        let old_rdn = record.rdn.clone();
        let new_rdn = normalize_dn(new_rdn);
        let new_parent = match new_superior {
            Some(sup) => Some(normalize_dn(sup)),
            None => record.parent_dn.clone(),
        };
        let new_dn = match &new_parent {
            Some(parent) => format!("{new_rdn},{parent}"),
            None => new_rdn.clone(),
        };
        if new_dn != old_dn && self.find_entry(&new_dn).await?.is_some() {
            return Err(DbError::Constraint(MSG_DN_DUP.into()));
        }
        if let Some(parent) = &new_parent {
            if record.parent_dn.as_ref() != Some(parent) && !self.parent_exists(parent).await? {
                return Err(DbError::Constraint("親 DN が存在しません。".into()));
            }
        }

        // Keep the RDN attribute consistent: the new RDN value must be present; the
        // old one is removed only when deleteOldRDN is set (RFC 4511 §4.9).
        let mut attrs = record.attributes_map();
        if delete_old_rdn {
            if let Some((attr, value)) = old_rdn.split_once('=') {
                remove_attr_value(&mut attrs, attr, value);
            }
        }
        if let Some((attr, value)) = new_rdn.split_once('=') {
            add_attr_value(&mut attrs, attr, value);
        }
        let attributes_json = serde_json::to_string(&attrs).unwrap_or_else(|_| "{}".into());

        // Rewrite group members that referenced the old DN.
        for mut group in self.list_by_structural(OC_GROUP).await? {
            let mut gattrs = group.attributes_map();
            if let Some(members) = gattrs.get_mut("member") {
                let mut changed = false;
                for member in members.iter_mut() {
                    if normalize_dn(member) == old_dn {
                        *member = new_dn.clone();
                        changed = true;
                    }
                }
                if changed {
                    group.attributes = serde_json::to_string(&gattrs).unwrap_or_default();
                    self.write_attributes(&group.dn, &group.attributes).await?;
                }
            }
        }

        let old_parent = record.parent_dn.clone();
        self.inner
            .query("UPDATE entry SET dn = $ndn, rdn = $rdn, parent_dn = $pdn, attributes = $a, updated_at = $t WHERE dn = $odn")
            .bind(("ndn", new_dn.clone()))
            .bind(("rdn", new_rdn.clone()))
            .bind(("pdn", new_parent.clone()))
            .bind(("a", attributes_json.clone()))
            .bind(("t", to_rfc3339(Utc::now())))
            .bind(("odn", old_dn.clone()))
            .await?;

        // Content sync: the old DN reads as disappeared (tombstone); the new DN
        // reappears on the next refresh (RFC 4533).
        let rec = LdapChangeRecord {
            id: None,
            dn: old_dn.clone(),
            csn: to_rfc3339(Utc::now()),
        };
        let _: Option<LdapChangeRecord> = self.inner.create("ldap_changelog").content(rec).await?;

        // has_children bookkeeping when reparenting.
        if old_parent != new_parent {
            if let Some(parent) = &old_parent {
                let remaining = self.list_children(Some(parent)).await?;
                self.set_has_children(parent, !remaining.is_empty()).await?;
            }
            if let Some(parent) = &new_parent {
                self.set_has_children(parent, true).await?;
            }
        }

        record.dn = new_dn;
        record.rdn = new_rdn;
        record.parent_dn = new_parent;
        record.attributes = attributes_json;
        Ok(record.into_entry())
    }

    async fn write_attributes(&self, dn: &str, attributes_json: &str) -> DbResult<()> {
        self.inner
            .query("UPDATE entry SET attributes = $a, updated_at = $t WHERE dn = $dn")
            .bind(("a", attributes_json.to_string()))
            .bind(("t", to_rfc3339(Utc::now())))
            .bind(("dn", normalize_dn(dn)))
            .await?;
        Ok(())
    }

    /// Apply an LDAP modify (RFC 4511 §4.6) to an existing entry's attributes,
    /// persisting the result. `userPassword` is routed to the Argon2 credential
    /// column (never the attribute map). Returns `false` if the entry doesn't exist.
    ///
    /// # Errors
    /// A store error, or a password-hash failure for a `userPassword` change.
    pub async fn modify_entry(&self, dn: &str, changes: &[LdapAttrChange]) -> DbResult<bool> {
        let Some(record) = self.find_entry(dn).await? else {
            return Ok(false);
        };
        let mut attributes = record.attributes_map();
        let mut new_password: Option<String> = None;
        for change in changes {
            if change.attr.eq_ignore_ascii_case("userPassword") {
                if !matches!(change.op, LdapModifyOp::Delete) {
                    new_password = change.values.first().cloned();
                }
                continue;
            }
            match change.op {
                LdapModifyOp::Add => attributes
                    .entry(change.attr.clone())
                    .or_default()
                    .extend(change.values.iter().cloned()),
                LdapModifyOp::Replace => {
                    if change.values.is_empty() {
                        attributes.remove(&change.attr);
                    } else {
                        attributes.insert(change.attr.clone(), change.values.clone());
                    }
                }
                LdapModifyOp::Delete => {
                    if change.values.is_empty() {
                        attributes.remove(&change.attr);
                    } else if let Some(existing) = attributes.get_mut(&change.attr) {
                        existing.retain(|v| !change.values.contains(v));
                        if existing.is_empty() {
                            attributes.remove(&change.attr);
                        }
                    }
                }
            }
        }
        let json = serde_json::to_string(&attributes).unwrap_or_else(|_| "{}".to_string());
        self.write_attributes(dn, &json).await?;
        if let Some(password) = new_password {
            self.reset_password(dn, &password).await?;
        }
        Ok(true)
    }

    /// Stamp a Web-created entry with its AD identity attributes — `sAMAccountName` and
    /// the hex-encoded `objectSid` — so a client reading LDAP directly (e.g. sssd in AD
    /// mode) sees it as a real AD object, the same shape replication projects via
    /// [`Self::ensure_user_entry`]. Windows itself resolves membership through the PAC and
    /// is unaffected either way. Returns `false` if the entry no longer exists.
    ///
    /// # Errors
    /// A store error.
    pub async fn set_entry_ad_identity(
        &self,
        dn: &str,
        sam_account_name: &str,
        object_sid_hex: &str,
    ) -> DbResult<bool> {
        let changes = [
            LdapAttrChange {
                op: LdapModifyOp::Replace,
                attr: "sAMAccountName".into(),
                values: vec![sam_account_name.to_string()],
            },
            LdapAttrChange {
                op: LdapModifyOp::Replace,
                attr: "objectSid".into(),
                values: vec![object_sid_hex.to_string()],
            },
        ];
        self.modify_entry(dn, &changes).await
    }

    /// List users (07_data_ldap §2.2).
    pub async fn list_users(&self) -> DbResult<Vec<LdapUser>> {
        Ok(self
            .list_by_structural(OC_USER)
            .await?
            .into_iter()
            .map(|r| {
                let enabled = r.enabled;
                let e = r.into_entry();
                LdapUser {
                    dn: e.dn.clone(),
                    uid: e.attr("uid").unwrap_or_default().to_string(),
                    cn: e.attr("cn").unwrap_or_default().to_string(),
                    sn: e.attr("sn").unwrap_or_default().to_string(),
                    mail: e.attr("mail").map(|m| m.to_string()),
                    enabled,
                }
            })
            .collect())
    }

    /// Resolve a login account name (the user part of a Kerberos principal, e.g.
    /// `alice` from `alice@EXAMPLE.COM`) to its directory DN, matching `uid`,
    /// `sAMAccountName`, or `cn` case-insensitively. Used to bind a GSS-authenticated
    /// principal to a real DN so ACLs apply under its directory identity. Returns
    /// `None` when no entry matches.
    ///
    /// # Errors
    /// Propagates a store read failure.
    pub async fn resolve_account_dn(&self, account: &str) -> DbResult<Option<String>> {
        for entry in self.list_all_entries().await? {
            let matched = ["uid", "sAMAccountName", "cn"]
                .iter()
                .filter_map(|attr| entry.attr(attr))
                .any(|value| value.eq_ignore_ascii_case(account));
            if matched {
                return Ok(Some(entry.dn));
            }
        }
        Ok(None)
    }

    /// List groups (07_data_ldap §2.3).
    pub async fn list_groups(&self) -> DbResult<Vec<LdapGroup>> {
        Ok(self
            .list_by_structural(OC_GROUP)
            .await?
            .into_iter()
            .map(|r| {
                let e = r.into_entry();
                LdapGroup {
                    dn: e.dn.clone(),
                    cn: e.attr("cn").unwrap_or_default().to_string(),
                    description: e.attr("description").map(|d| d.to_string()),
                    members: e.attrs("member").to_vec(),
                }
            })
            .collect())
    }

    /// List OUs (07_data_ldap §2.4).
    pub async fn list_ous(&self) -> DbResult<Vec<LdapOu>> {
        Ok(self
            .list_by_structural(OC_OU)
            .await?
            .into_iter()
            .map(|r| {
                let has_children = r.has_children;
                let e = r.into_entry();
                LdapOu {
                    dn: e.dn.clone(),
                    ou: e.attr("ou").unwrap_or_default().to_string(),
                    description: e.attr("description").map(|d| d.to_string()),
                    has_children,
                }
            })
            .collect())
    }

    /// Toggle a user's enabled flag (LE-03).
    pub async fn set_user_enabled(&self, dn: &str, enabled: bool) -> DbResult<()> {
        self.find_entry(dn).await?.ok_or(DbError::NotFound)?;
        self.inner
            .query("UPDATE entry SET enabled = $v, updated_at = $t WHERE dn = $dn")
            .bind(("v", enabled))
            .bind(("t", to_rfc3339(Utc::now())))
            .bind(("dn", normalize_dn(dn)))
            .await?;
        Ok(())
    }

    /// Reset a user's password (Admin only — LE-05). Stores an Argon2 hash.
    pub async fn reset_password(&self, dn: &str, new_password: &str) -> DbResult<()> {
        self.find_entry(dn).await?.ok_or(DbError::NotFound)?;
        let hash = hash_password(new_password)?;
        self.inner
            .query("UPDATE entry SET password_ref = $p, updated_at = $t WHERE dn = $dn")
            .bind(("p", hash))
            .bind(("t", to_rfc3339(Utc::now())))
            .bind(("dn", normalize_dn(dn)))
            .await?;
        Ok(())
    }

    /// Add a member DN to a group (LE-06). The member must exist.
    pub async fn add_member(&self, group_dn: &str, member_dn: &str) -> DbResult<()> {
        if self.find_entry(member_dn).await?.is_none() {
            return Err(DbError::Constraint(
                "指定した DN のエントリが存在しません。".into(),
            ));
        }
        let group = self.find_entry(group_dn).await?.ok_or(DbError::NotFound)?;
        let mut attrs = group.attributes_map();
        let members = attrs.entry("member".into()).or_default();
        let target = normalize_dn(member_dn);
        if !members.iter().any(|m| normalize_dn(m) == target) {
            members.push(member_dn.to_string());
        }
        self.write_attributes(
            &group.dn,
            &serde_json::to_string(&attrs).unwrap_or_default(),
        )
        .await
    }

    /// Remove a member DN from a group (LE-07).
    pub async fn remove_member(&self, group_dn: &str, member_dn: &str) -> DbResult<()> {
        let group = self.find_entry(group_dn).await?.ok_or(DbError::NotFound)?;
        let mut attrs = group.attributes_map();
        if let Some(members) = attrs.get_mut("member") {
            let target = normalize_dn(member_dn);
            members.retain(|m| normalize_dn(m) != target);
        }
        self.write_attributes(
            &group.dn,
            &serde_json::to_string(&attrs).unwrap_or_default(),
        )
        .await
    }

    /// Headline LDAP metrics: entry / user / group / OU counts.
    pub async fn ldap_metrics(&self) -> DbResult<(usize, usize, usize, usize)> {
        let entries: Vec<EntryRecord> = self.inner.query("SELECT * FROM entry").await?.take(0)?;
        let mut users = 0;
        let mut groups = 0;
        let mut ous = 0;
        for e in &entries {
            match e.structural_class.as_str() {
                OC_USER => users += 1,
                OC_GROUP => groups += 1,
                OC_OU => ous += 1,
                _ => {}
            }
        }
        Ok((entries.len(), users, groups, ous))
    }

    // ---- Access control (S-LDAP-07) ---------------------------------------

    /// List ACL rules, evaluation order (priority ascending).
    pub async fn list_ldap_acls(&self) -> DbResult<Vec<LdapAclRule>> {
        let recs: Vec<AclRecord> = self
            .inner
            .query("SELECT * FROM ldap_acl ORDER BY priority ASC")
            .await?
            .take(0)?;
        Ok(recs.into_iter().map(AclRecord::into_model).collect())
    }

    /// Create an ACL rule.
    pub async fn create_ldap_acl(&self, rule: &LdapAclRule) -> DbResult<LdapAclRule> {
        let now = to_rfc3339(Utc::now());
        let rec = AclRecord {
            id: None,
            priority: rule.priority,
            target_dn: normalize_dn(&rule.target_dn),
            operations: serde_json::to_string(&rule.operations).unwrap_or_else(|_| "[]".into()),
            subject: serde_json::to_string(&rule.subject).unwrap_or_else(|_| "null".into()),
            effect: serde_json::to_string(&rule.effect).unwrap_or_else(|_| "\"deny\"".into()),
            enabled: rule.enabled,
            created_at: now.clone(),
            updated_at: now,
            created_by: rule.created_by.clone(),
        };
        let created: Option<AclRecord> = self.inner.create("ldap_acl").content(rec).await?;
        created
            .map(AclRecord::into_model)
            .ok_or_else(|| DbError::Constraint("ACL creation returned nothing".into()))
    }

    /// Delete an ACL rule.
    pub async fn delete_ldap_acl(&self, id: &str) -> DbResult<()> {
        let _: Option<AclRecord> = self.inner.delete(("ldap_acl", id)).await?;
        Ok(())
    }

    /// Toggle an ACL rule.
    pub async fn set_ldap_acl_enabled(&self, id: &str, enabled: bool) -> DbResult<()> {
        self.inner
            .query("UPDATE type::record('ldap_acl', $id) SET enabled = $en, updated_at = $t")
            .bind(("id", id.to_string()))
            .bind(("en", enabled))
            .bind(("t", to_rfc3339(Utc::now())))
            .await?;
        Ok(())
    }

    /// Whether `bound_dn` (`None` = anonymous) may perform `op` on `target_dn`.
    /// With no ACL rules configured the directory is fully open; once any
    /// enabled rule exists, the first matching rule decides and an unmatched
    /// request is denied.
    pub async fn evaluate_ldap_acl(
        &self,
        bound_dn: Option<&str>,
        op: LdapAclOperation,
        target_dn: &str,
    ) -> DbResult<bool> {
        let rules: Vec<LdapAclRule> = self
            .list_ldap_acls()
            .await?
            .into_iter()
            .filter(|r| r.enabled)
            .collect();
        if rules.is_empty() {
            return Ok(true);
        }
        let target = normalize_dn(target_dn);
        for rule in &rules {
            if !rule.operations.contains(&op) || !dn_in_scope(&rule.target_dn, &target) {
                continue;
            }
            if self.acl_subject_matches(&rule.subject, bound_dn).await? {
                return Ok(rule.effect == LdapAclEffect::Allow);
            }
        }
        Ok(false)
    }

    async fn acl_subject_matches(
        &self,
        subject: &LdapAclSubject,
        bound_dn: Option<&str>,
    ) -> DbResult<bool> {
        Ok(match subject {
            LdapAclSubject::Anyone => true,
            LdapAclSubject::Anonymous => bound_dn.is_none(),
            LdapAclSubject::Authenticated => bound_dn.is_some(),
            LdapAclSubject::Dn(dn) => {
                bound_dn.map(normalize_dn).as_deref() == Some(normalize_dn(dn).as_str())
            }
            LdapAclSubject::GroupMember(group) => match bound_dn {
                Some(dn) => self.group_has_member(group, dn).await?,
                None => false,
            },
        })
    }

    /// Whether `member_dn` is listed in `group_dn`'s `member` attribute.
    async fn group_has_member(&self, group_dn: &str, member_dn: &str) -> DbResult<bool> {
        let Some(group) = self.find_entry(group_dn).await? else {
            return Ok(false);
        };
        let target = normalize_dn(member_dn);
        Ok(group
            .attributes_map()
            .get("member")
            .map(|members| members.iter().any(|m| normalize_dn(m) == target))
            .unwrap_or(false))
    }
}

/// Whether `dn` is `target` or beneath it (`*` matches everything).
fn dn_in_scope(target_pattern: &str, dn: &str) -> bool {
    if target_pattern == "*" {
        return true;
    }
    let target = normalize_dn(target_pattern);
    dn == target || dn.ends_with(&format!(",{target}"))
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct AclRecord {
    id: Option<RecordId>,
    priority: u32,
    target_dn: String,
    /// JSON-encoded `Vec<LdapAclOperation>`.
    operations: String,
    /// JSON-encoded `LdapAclSubject`.
    subject: String,
    /// JSON-encoded `LdapAclEffect`.
    effect: String,
    enabled: bool,
    created_at: String,
    updated_at: String,
    created_by: String,
}

impl AclRecord {
    fn into_model(self) -> LdapAclRule {
        LdapAclRule {
            id: record_key(&self.id),
            created_at: parse_rfc3339(&self.created_at),
            updated_at: parse_rfc3339(&self.updated_at),
            created_by: self.created_by,
            priority: self.priority,
            target_dn: self.target_dn,
            operations: serde_json::from_str(&self.operations).unwrap_or_default(),
            subject: serde_json::from_str(&self.subject).unwrap_or(LdapAclSubject::Anyone),
            effect: serde_json::from_str(&self.effect).unwrap_or(LdapAclEffect::Deny),
            enabled: self.enabled,
        }
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
    async fn base_dn_is_configurable_and_persists() {
        let (db, _dir) = test_db().await;
        // The first seed adopts the configured base DN.
        let base = db.ensure_ldap_base("dc=acme,dc=io", "admin").await.unwrap();
        assert_eq!(base, "dc=acme,dc=io");
        // A later call with a *different* configured value keeps the persisted
        // root (changing the base DN would orphan the tree).
        let again = db
            .ensure_ldap_base("dc=other,dc=net", "admin")
            .await
            .unwrap();
        assert_eq!(again, "dc=acme,dc=io");
        assert_eq!(
            db.ldap_root_dn().await.unwrap().as_deref(),
            Some("dc=acme,dc=io")
        );
    }

    #[tokio::test]
    async fn ou_guard_blocks_delete_with_children() {
        let (db, _dir) = test_db().await;
        let base = db
            .ensure_ldap_base("dc=example,dc=com", "admin")
            .await
            .unwrap();
        let ou = db.create_ou(&base, "People", None, "admin").await.unwrap();
        db.create_user(&ou.dn, "jsmith", "John", "Smith", None, "admin")
            .await
            .unwrap();
        // OU has a child → delete refused.
        assert!(db.delete_entry(&ou.dn).await.is_err());
    }

    #[tokio::test]
    async fn acl_evaluation_by_subject_and_scope() {
        let (db, _dir) = test_db().await;
        let base = db
            .ensure_ldap_base("dc=example,dc=com", "admin")
            .await
            .unwrap();
        let people = db.create_ou(&base, "People", None, "admin").await.unwrap();
        db.create_user(&people.dn, "alice", "Alice", "A", None, "admin")
            .await
            .unwrap();
        let alice_dn = format!("uid=alice,{}", people.dn);
        let group = db
            .create_group(&base, "admins", None, "admin")
            .await
            .unwrap();
        db.add_member(&group.dn, &alice_dn).await.unwrap();

        // No rules configured → fully open.
        assert!(db
            .evaluate_ldap_acl(None, LdapAclOperation::Search, &people.dn)
            .await
            .unwrap());

        let rule =
            |priority: u32, target: String, subject: LdapAclSubject, effect: LdapAclEffect| {
                LdapAclRule {
                    id: String::new(),
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                    created_by: "admin".into(),
                    priority,
                    target_dn: target,
                    operations: vec![LdapAclOperation::Search],
                    subject,
                    effect,
                    enabled: true,
                }
            };
        db.create_ldap_acl(&rule(
            10,
            people.dn.clone(),
            LdapAclSubject::Anonymous,
            LdapAclEffect::Deny,
        ))
        .await
        .unwrap();
        db.create_ldap_acl(&rule(
            20,
            people.dn.clone(),
            LdapAclSubject::GroupMember(group.dn.clone()),
            LdapAclEffect::Allow,
        ))
        .await
        .unwrap();
        db.create_ldap_acl(&rule(
            30,
            "*".into(),
            LdapAclSubject::Anyone,
            LdapAclEffect::Deny,
        ))
        .await
        .unwrap();

        // Anonymous → denied by rule 10.
        assert!(!db
            .evaluate_ldap_acl(None, LdapAclOperation::Search, &people.dn)
            .await
            .unwrap());
        // Group member alice → allowed by rule 20.
        assert!(db
            .evaluate_ldap_acl(Some(&alice_dn), LdapAclOperation::Search, &people.dn)
            .await
            .unwrap());
        // Another bound DN → matches only the catch-all deny (rule 30).
        let bob = format!("uid=bob,{}", people.dn);
        assert!(!db
            .evaluate_ldap_acl(Some(&bob), LdapAclOperation::Search, &people.dn)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn replicated_user_and_group_project_into_the_entry_tree() {
        let (db, _dir) = test_db().await;
        let base = "dc=example,dc=com";
        // A binary SID S-1-5-21-1-2-3-<rid>.
        fn sid(rid: u32) -> Vec<u8> {
            let mut s = vec![1u8, 5, 0, 0, 0, 0, 0, 5];
            for sub in [21u32, 1, 2, 3, rid] {
                s.extend_from_slice(&sub.to_le_bytes());
            }
            s
        }

        // A replicated user is projected as CN=alice,CN=Users,<base> with objectClass
        // user, sAMAccountName, hex objectSid and userAccountControl (B1).
        db.ensure_user_entry(base, "alice", &sid(1105), 0x200, "repl")
            .await
            .unwrap();
        let alice_dn = normalize_dn("CN=alice,CN=Users,dc=example,dc=com");
        let e = db
            .get_entry(&alice_dn)
            .await
            .unwrap()
            .expect("user projected");
        assert!(e.object_classes.iter().any(|c| c == "user"));
        assert_eq!(
            e.attributes.get("sAMAccountName"),
            Some(&vec!["alice".to_string()])
        );
        assert_eq!(
            e.attributes.get("objectSid"),
            Some(&vec![hex_lower(&sid(1105))])
        );
        assert_eq!(
            e.attributes.get("userAccountControl"),
            Some(&vec!["512".to_string()])
        );

        // The member's principal must exist for its SID to resolve to a DN.
        db.upsert_ad_principal_with_hash("alice", 1105, "pw", &[0u8; 16], Some(&[]), "EXAMPLE.COM")
            .await
            .unwrap();
        // A replicated group carrying alice as a member projects her DN into `member`.
        db.ensure_group_entry(
            base,
            "Engineers",
            &sid(1200),
            &[hex_lower(&sid(1105))],
            "repl",
        )
        .await
        .unwrap();
        let grp_dn = normalize_dn("CN=Engineers,CN=Users,dc=example,dc=com");
        let g = db
            .get_entry(&grp_dn)
            .await
            .unwrap()
            .expect("group projected");
        assert!(g.object_classes.iter().any(|c| c == "group"));
        assert_eq!(g.attributes.get("member"), Some(&vec![alice_dn.clone()]));

        // Re-projecting is idempotent (Replace), not a duplicate.
        db.ensure_user_entry(base, "alice", &sid(1105), 0x202, "repl")
            .await
            .unwrap();
        let e2 = db.get_entry(&alice_dn).await.unwrap().unwrap();
        assert_eq!(
            e2.attributes.get("userAccountControl"),
            Some(&vec!["514".to_string()])
        );

        // The tombstone side removes the projected entry.
        db.delete_projected_entry(base, "alice").await.unwrap();
        assert!(db.get_entry(&alice_dn).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn generic_projected_object_lands_in_the_entry_tree() {
        let (db, _dir) = test_db().await;
        db.ensure_ldap_base("dc=ex,dc=com", "admin").await.unwrap();
        // A generic (non-user/group) replicated object: an attributeSchema.
        let dn = normalize_dn("CN=msDSCustom,CN=Schema,CN=Configuration,dc=ex,dc=com");
        let mut attrs: BTreeMap<String, Vec<String>> = BTreeMap::new();
        attrs.insert("cn".into(), vec!["msDSCustom".into()]);
        attrs.insert("lDAPDisplayName".into(), vec!["msDSCustom".into()]);
        db.upsert_projected_entry(
            &dn,
            vec!["top".into(), "attributeSchema".into()],
            attrs,
            "replication",
        )
        .await
        .unwrap();
        let e = db.get_entry(&dn).await.unwrap().expect("projected");
        assert_eq!(e.structural_class, "attributeSchema");
        assert_eq!(
            e.attributes.get("lDAPDisplayName"),
            Some(&vec!["msDSCustom".to_string()])
        );

        // Re-projecting replaces attributes (idempotent), not duplicates.
        let mut attrs2: BTreeMap<String, Vec<String>> = BTreeMap::new();
        attrs2.insert("description".into(), vec!["updated".into()]);
        db.upsert_projected_entry(
            &dn,
            vec!["top".into(), "attributeSchema".into()],
            attrs2,
            "replication",
        )
        .await
        .unwrap();
        let e2 = db.get_entry(&dn).await.unwrap().unwrap();
        assert_eq!(
            e2.attributes.get("description"),
            Some(&vec!["updated".to_string()])
        );
    }

    #[tokio::test]
    async fn leaf_delete_updates_parent_has_children() {
        let (db, _dir) = test_db().await;
        let base = db
            .ensure_ldap_base("dc=example,dc=com", "admin")
            .await
            .unwrap();
        let ou = db.create_ou(&base, "People", None, "admin").await.unwrap();
        let user = db
            .create_user(&ou.dn, "jsmith", "John", "Smith", None, "admin")
            .await
            .unwrap();
        db.delete_entry(&user.dn).await.unwrap();
        // Now the OU has no children → deletable.
        assert!(db.delete_entry(&ou.dn).await.is_ok());
    }

    #[tokio::test]
    async fn membership_add_remove() {
        let (db, _dir) = test_db().await;
        let base = db
            .ensure_ldap_base("dc=example,dc=com", "admin")
            .await
            .unwrap();
        let user = db
            .create_user(&base, "jsmith", "John", "Smith", None, "admin")
            .await
            .unwrap();
        let group = db
            .create_group(&base, "admins", None, "admin")
            .await
            .unwrap();
        db.add_member(&group.dn, &user.dn).await.unwrap();
        let groups = db.list_groups().await.unwrap();
        assert_eq!(groups[0].members.len(), 1);
        // Adding a non-existent member is rejected.
        assert!(db
            .add_member(&group.dn, "uid=ghost,dc=example,dc=com")
            .await
            .is_err());
        db.remove_member(&group.dn, &user.dn).await.unwrap();
        assert_eq!(db.list_groups().await.unwrap()[0].members.len(), 0);
    }

    #[tokio::test]
    async fn modify_entry_add_replace_delete() {
        let (db, _dir) = test_db().await;
        let base = db
            .ensure_ldap_base("dc=example,dc=com", "admin")
            .await
            .unwrap();
        let user = db
            .create_user(&base, "pc1", "PC1", "PC1", None, "admin")
            .await
            .unwrap();

        // Add two SPN values and set dNSHostName — the join's attribute writes.
        db.modify_entry(
            &user.dn,
            &[
                LdapAttrChange {
                    op: LdapModifyOp::Add,
                    attr: "servicePrincipalName".into(),
                    values: vec!["HOST/pc1".into(), "HOST/pc1.example.com".into()],
                },
                LdapAttrChange {
                    op: LdapModifyOp::Replace,
                    attr: "dNSHostName".into(),
                    values: vec!["pc1.example.com".into()],
                },
            ],
        )
        .await
        .unwrap();
        let e = db.get_entry(&user.dn).await.unwrap().unwrap();
        assert_eq!(e.attrs("servicePrincipalName").len(), 2);
        assert_eq!(e.attr("dNSHostName"), Some("pc1.example.com"));

        // Delete one SPN value.
        db.modify_entry(
            &user.dn,
            &[LdapAttrChange {
                op: LdapModifyOp::Delete,
                attr: "servicePrincipalName".into(),
                values: vec!["HOST/pc1".into()],
            }],
        )
        .await
        .unwrap();
        let e2 = db.get_entry(&user.dn).await.unwrap().unwrap();
        assert_eq!(e2.attrs("servicePrincipalName"), ["HOST/pc1.example.com"]);

        // Modifying a non-existent entry reports not-found.
        assert!(!db
            .modify_entry("uid=ghost,dc=example,dc=com", &[])
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn rename_entry_changes_rdn_and_updates_the_rdn_attribute() {
        let (db, _dir) = test_db().await;
        db.ensure_ldap_base("dc=example,dc=com", "admin")
            .await
            .unwrap();
        let attrs = BTreeMap::from([
            ("uid".to_string(), vec!["jsmith".to_string()]),
            ("cn".to_string(), vec!["John Smith".to_string()]),
        ]);
        db.create_entry(
            "uid=jsmith,dc=example,dc=com",
            vec!["top".into(), "person".into()],
            &attrs,
            "admin",
        )
        .await
        .unwrap();

        // Rename the RDN with deleteOldRDN — old value dropped, new value added.
        let renamed = db
            .rename_entry("uid=jsmith,dc=example,dc=com", "uid=jdoe", true, None)
            .await
            .unwrap();
        assert_eq!(renamed.dn, "uid=jdoe,dc=example,dc=com");
        assert!(db
            .get_entry("uid=jsmith,dc=example,dc=com")
            .await
            .unwrap()
            .is_none());
        let moved = db
            .get_entry("uid=jdoe,dc=example,dc=com")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(moved.rdn, "uid=jdoe");
        assert_eq!(moved.attrs("uid"), ["jdoe"]); // old RDN value removed, new one present
        assert_eq!(moved.attr("cn"), Some("John Smith")); // other attributes preserved
    }

    #[tokio::test]
    async fn rename_entry_moves_to_new_superior_and_fixes_has_children() {
        let (db, _dir) = test_db().await;
        let base = db
            .ensure_ldap_base("dc=example,dc=com", "admin")
            .await
            .unwrap();
        let people = db.create_ou(&base, "People", None, "admin").await.unwrap();
        let staff = db.create_ou(&base, "Staff", None, "admin").await.unwrap();
        let attrs = BTreeMap::from([("uid".to_string(), vec!["bob".to_string()])]);
        db.create_entry(
            &format!("uid=bob,{}", people.dn),
            vec!["top".into(), "person".into()],
            &attrs,
            "admin",
        )
        .await
        .unwrap();

        let moved = db
            .rename_entry(
                &format!("uid=bob,{}", people.dn),
                "uid=bob",
                false,
                Some(&staff.dn),
            )
            .await
            .unwrap();
        assert_eq!(moved.dn, format!("uid=bob,{}", staff.dn));
        // The old parent is empty again (deletable); the new parent holds the child.
        assert!(db.delete_entry(&people.dn).await.is_ok());
        assert!(db.delete_entry(&staff.dn).await.is_err()); // still has the moved child
    }

    #[tokio::test]
    async fn rename_entry_rewrites_group_membership() {
        let (db, _dir) = test_db().await;
        let base = db
            .ensure_ldap_base("dc=example,dc=com", "admin")
            .await
            .unwrap();
        let group = db
            .create_group(&base, "admins", None, "admin")
            .await
            .unwrap();
        let attrs = BTreeMap::from([("uid".to_string(), vec!["jsmith".to_string()])]);
        db.create_entry(
            "uid=jsmith,dc=example,dc=com",
            vec!["top".into(), "person".into()],
            &attrs,
            "admin",
        )
        .await
        .unwrap();
        db.add_member(&group.dn, "uid=jsmith,dc=example,dc=com")
            .await
            .unwrap();

        db.rename_entry("uid=jsmith,dc=example,dc=com", "uid=jdoe", true, None)
            .await
            .unwrap();
        let members = &db.list_groups().await.unwrap()[0].members;
        assert!(members
            .iter()
            .any(|m| normalize_dn(m) == "uid=jdoe,dc=example,dc=com"));
        assert!(!members
            .iter()
            .any(|m| normalize_dn(m) == "uid=jsmith,dc=example,dc=com"));
    }

    #[tokio::test]
    async fn rename_entry_missing_is_not_found() {
        let (db, _dir) = test_db().await;
        db.ensure_ldap_base("dc=example,dc=com", "admin")
            .await
            .unwrap();
        let err = db
            .rename_entry("uid=ghost,dc=example,dc=com", "uid=x", true, None)
            .await
            .unwrap_err();
        assert!(matches!(err, DbError::NotFound));
    }

    #[tokio::test]
    async fn scoped_entry_queries_narrow_by_dn() {
        let (db, _dir) = test_db().await;
        let base = db
            .ensure_ldap_base("dc=example,dc=com", "admin")
            .await
            .unwrap();
        let people = db.create_ou(&base, "People", None, "admin").await.unwrap();
        let attrs = BTreeMap::from([("uid".to_string(), vec!["bob".to_string()])]);
        db.create_entry(
            &format!("uid=bob,{}", people.dn),
            vec!["top".into(), "person".into()],
            &attrs,
            "admin",
        )
        .await
        .unwrap();

        // base scope: exactly the base object.
        let b = db.get_entry_full(&base).await.unwrap().unwrap();
        assert_eq!(normalize_dn(&b.dn), normalize_dn(&base));

        // one-level under base: the People OU, not the deeper user.
        let children = db.list_entries_by_parent(&base).await.unwrap();
        assert!(children
            .iter()
            .any(|e| normalize_dn(&e.dn) == normalize_dn(&people.dn)));
        assert!(!children.iter().any(|e| e.dn.contains("uid=bob")));

        // one-level under People: just the user.
        let under_people = db.list_entries_by_parent(&people.dn).await.unwrap();
        assert_eq!(under_people.len(), 1);
        assert!(under_people[0].dn.contains("uid=bob"));

        // subtree of base: base + People + the user (string::ends_with suffix match).
        let sub = db.list_entries_subtree(&base).await.unwrap();
        assert!(sub
            .iter()
            .any(|e| normalize_dn(&e.dn) == normalize_dn(&base)));
        assert!(sub.iter().any(|e| e.dn.contains("uid=bob")));
        assert!(sub.len() >= 3);
    }

    #[tokio::test]
    async fn create_entry_makes_computer_object() {
        let (db, _dir) = test_db().await;
        let base = db
            .ensure_ldap_base("dc=example,dc=com", "admin")
            .await
            .unwrap();
        let mut attributes: BTreeMap<String, Vec<String>> = BTreeMap::new();
        attributes.insert("sAMAccountName".into(), vec!["WIN10PC$".into()]);
        attributes.insert("dNSHostName".into(), vec!["win10pc.example.com".into()]);
        attributes.insert("userAccountControl".into(), vec!["4096".into()]);
        let dn = format!("cn=WIN10PC,{base}");

        let entry = db
            .create_entry(
                &dn,
                vec!["top".into(), "computer".into()],
                &attributes,
                "admin",
            )
            .await
            .unwrap();
        assert_eq!(entry.structural_class, "computer");

        let got = db.get_entry(&dn).await.unwrap().unwrap();
        assert_eq!(got.attr("sAMAccountName"), Some("WIN10PC$"));
        assert_eq!(got.attr("dNSHostName"), Some("win10pc.example.com"));
        assert!(got.object_classes.contains(&"computer".to_string()));

        // A duplicate DN is rejected.
        assert!(db
            .create_entry(&dn, vec!["computer".into()], &attributes, "admin")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn ensure_computer_entry_unifies_and_is_idempotent() {
        let (db, _dir) = test_db().await;
        // First call seeds the base and creates the computer object (UAC 0x1002).
        db.ensure_computer_entry(
            "dc=example,dc=com",
            "SRV01$",
            "srv01.example.com",
            0x1002,
            "addc",
        )
        .await
        .unwrap();
        let dn = "cn=SRV01,dc=example,dc=com";
        let e = db.get_entry(dn).await.unwrap().unwrap();
        assert_eq!(e.attr("sAMAccountName"), Some("SRV01$"));
        assert_eq!(e.attr("userAccountControl"), Some("4098")); // 0x1002
        assert!(e.object_classes.contains(&"computer".to_string()));

        // Second call updates the attributes (enabled UAC 0x1000), no duplicate.
        db.ensure_computer_entry(
            "dc=example,dc=com",
            "SRV01$",
            "srv01.example.com",
            0x1000,
            "addc",
        )
        .await
        .unwrap();
        let e2 = db.get_entry(dn).await.unwrap().unwrap();
        assert_eq!(e2.attr("userAccountControl"), Some("4096")); // 0x1000
        let matches = db
            .list_all_entries()
            .await
            .unwrap()
            .into_iter()
            .filter(|x| x.attr("sAMAccountName") == Some("SRV01$"))
            .count();
        assert_eq!(matches, 1, "no duplicate computer entry");
    }

    #[tokio::test]
    async fn seed_domain_containers_creates_well_known_containers_idempotently() {
        let (db, _dir) = test_db().await;
        db.seed_domain_containers("dc=example,dc=com", "system")
            .await
            .unwrap();

        // CN=Computers is where a domain-join client adds its machine object.
        let computers = db
            .get_entry("cn=computers,dc=example,dc=com")
            .await
            .unwrap()
            .expect("CN=Computers seeded");
        assert_eq!(computers.structural_class, "container");
        assert!(db
            .get_entry("cn=users,dc=example,dc=com")
            .await
            .unwrap()
            .is_some());
        assert!(db
            .get_entry("cn=system,dc=example,dc=com")
            .await
            .unwrap()
            .is_some());
        // Domain Controllers is an OU.
        let dcs = db
            .get_entry("ou=domain controllers,dc=example,dc=com")
            .await
            .unwrap()
            .expect("OU=Domain Controllers seeded");
        assert_eq!(dcs.structural_class, "organizationalUnit");

        // Re-seeding does not duplicate.
        db.seed_domain_containers("dc=example,dc=com", "system")
            .await
            .unwrap();
        let computers_count = db
            .list_all_entries()
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.dn == "cn=computers,dc=example,dc=com")
            .count();
        assert_eq!(computers_count, 1, "no duplicate container on re-seed");
    }

    #[tokio::test]
    async fn resolve_account_dn_matches_uid_and_sam_case_insensitively() {
        let (db, _dir) = test_db().await;
        let base = db
            .ensure_ldap_base("dc=example,dc=com", "admin")
            .await
            .unwrap();
        db.create_ou(&base, "people", None, "admin").await.unwrap();
        let people = format!("ou=people,{base}");
        db.create_user(&people, "alice", "Alice A", "A", None, "admin")
            .await
            .unwrap();
        db.ensure_computer_entry(
            "dc=example,dc=com",
            "WIN10PC$",
            "win10pc.example.com",
            0x1000,
            "addc",
        )
        .await
        .unwrap();

        // A GSS principal's user part resolves by uid, case-insensitively; the DN is
        // the normalized (lower-cased) directory DN.
        assert_eq!(
            db.resolve_account_dn("ALICE").await.unwrap().as_deref(),
            Some("uid=alice,ou=people,dc=example,dc=com")
        );
        // A machine account resolves by sAMAccountName.
        assert_eq!(
            db.resolve_account_dn("WIN10PC$").await.unwrap().as_deref(),
            Some("cn=win10pc,dc=example,dc=com")
        );
        // An unknown account resolves to None.
        assert!(db.resolve_account_dn("nobody").await.unwrap().is_none());
    }

    #[test]
    fn fsmo_owners_from_spec_parses_role_overrides() {
        let o = FsmoOwners::from_spec("rid=kether, pdc = binar ,bogus=x,schema=");
        assert_eq!(o.rid.as_deref(), Some("kether"));
        assert_eq!(o.pdc.as_deref(), Some("binar"));
        assert_eq!(o.schema, None, "empty owner ignored");
        assert_eq!(o.infrastructure, None, "unset role stays local");
        let o = FsmoOwners::from_spec("domain-naming=dc2,forestdns=dc3,infra=dc4");
        assert_eq!(o.domain_naming.as_deref(), Some("dc2"));
        assert_eq!(o.forest_dns.as_deref(), Some("dc3"));
        assert_eq!(o.infrastructure.as_deref(), Some("dc4"));
    }

    #[tokio::test]
    async fn seed_fsmo_roles_owned_points_assigned_roles_at_the_peer() {
        let (db, _dir) = test_db().await;
        // RID + PDC held by peer "kether"; the rest stay on this DC ("MAGNETITE").
        let owners = FsmoOwners {
            rid: Some("kether".to_string()),
            pdc: Some("kether".to_string()),
            ..Default::default()
        };
        db.seed_fsmo_roles_owned("dc=example,dc=com", "MAGNETITE", &owners, "system")
            .await
            .unwrap();
        let local = "cn=ntds settings,cn=magnetite,cn=servers,cn=default-first-site-name,\
                     cn=sites,cn=configuration,dc=example,dc=com";
        let peer = "cn=ntds settings,cn=kether,cn=servers,cn=default-first-site-name,\
                    cn=sites,cn=configuration,dc=example,dc=com";
        // Assigned roles name the peer's nTDSDSA.
        for dn in [
            "dc=example,dc=com",                           // PDC Emulator -> kether
            "cn=rid manager$,cn=system,dc=example,dc=com", // RID Master -> kether
        ] {
            let e = db.get_entry(dn).await.unwrap().unwrap();
            assert_eq!(e.attr("fSMORoleOwner"), Some(peer), "{dn} -> peer");
        }
        // Unassigned roles stay on this DC.
        for dn in [
            "cn=schema,cn=configuration,dc=example,dc=com",
            "cn=infrastructure,dc=example,dc=com",
        ] {
            let e = db.get_entry(dn).await.unwrap().unwrap();
            assert_eq!(e.attr("fSMORoleOwner"), Some(local), "{dn} -> local");
        }
    }

    #[tokio::test]
    async fn fsmo_seize_rewrites_role_owner_to_this_dc() {
        let (db, _dir) = test_db().await;
        // RID starts on the peer "kether".
        let owners = FsmoOwners {
            rid: Some("kether".to_string()),
            ..Default::default()
        };
        db.seed_fsmo_roles_owned("dc=example,dc=com", "MAGNETITE", &owners, "system")
            .await
            .unwrap();
        let rid_dn = "cn=rid manager$,cn=system,dc=example,dc=com";
        let peer = "cn=ntds settings,cn=kether,cn=servers,cn=default-first-site-name,\
                    cn=sites,cn=configuration,dc=example,dc=com";
        let local = "cn=ntds settings,cn=magnetite,cn=servers,cn=default-first-site-name,\
                     cn=sites,cn=configuration,dc=example,dc=com";
        assert_eq!(
            db.get_entry(rid_dn)
                .await
                .unwrap()
                .unwrap()
                .attr("fSMORoleOwner"),
            Some(peer),
            "RID role starts on the peer"
        );

        // A `becomeRidMaster` seize moves the role to THIS DC.
        let seized = db
            .seize_fsmo_role("dc=example,dc=com", "MAGNETITE", "becomeRidMaster")
            .await
            .unwrap();
        assert!(
            seized
                .as_deref()
                .is_some_and(|d| d.eq_ignore_ascii_case(rid_dn)),
            "recognized RID seize: {seized:?}"
        );
        assert_eq!(
            db.get_entry(rid_dn)
                .await
                .unwrap()
                .unwrap()
                .attr("fSMORoleOwner"),
            Some(local),
            "RID role now owned by this DC"
        );

        // A non-FSMO attribute is not a seize.
        assert_eq!(
            db.seize_fsmo_role("dc=example,dc=com", "MAGNETITE", "dNSHostName")
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn seed_fsmo_roles_places_all_five_owners_on_this_dc() {
        let (db, _dir) = test_db().await;
        db.seed_fsmo_roles("dc=example,dc=com", "MAGNETITE", "system")
            .await
            .unwrap();
        let ntds = "cn=ntds settings,cn=magnetite,cn=servers,cn=default-first-site-name,\
                    cn=sites,cn=configuration,dc=example,dc=com";
        assert!(
            db.get_entry(ntds).await.unwrap().is_some(),
            "nTDSDSA object seeded"
        );

        // All five FSMO role holders name this DC's nTDSDSA in fSMORoleOwner.
        for dn in [
            "dc=example,dc=com",                                // PDC Emulator
            "cn=rid manager$,cn=system,dc=example,dc=com",      // RID Master
            "cn=infrastructure,dc=example,dc=com",              // Infrastructure
            "cn=schema,cn=configuration,dc=example,dc=com",     // Schema Master
            "cn=partitions,cn=configuration,dc=example,dc=com", // Domain Naming
        ] {
            let e = db
                .get_entry(dn)
                .await
                .unwrap()
                .unwrap_or_else(|| panic!("{dn} missing"));
            assert_eq!(e.attr("fSMORoleOwner"), Some(ntds), "{dn} role owner");
        }

        // The domain crossRef carries the flat NetBIOS name a join client reads.
        let crossref = "cn=example,cn=partitions,cn=configuration,dc=example,dc=com";
        let cr = db
            .get_entry(crossref)
            .await
            .unwrap()
            .expect("domain crossRef seeded");
        assert_eq!(cr.structural_class, "crossRef");
        assert_eq!(cr.attr("nETBIOSName"), Some("EXAMPLE"));
        assert_eq!(cr.attr("nCName"), Some("dc=example,dc=com"));
        assert_eq!(cr.attr("dnsRoot"), Some("example.com"));

        // Idempotent: re-seeding does not duplicate or error.
        db.seed_fsmo_roles("dc=example,dc=com", "MAGNETITE", "system")
            .await
            .unwrap();
        let ntds_count = db
            .list_all_entries()
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.dn == ntds)
            .count();
        assert_eq!(ntds_count, 1, "no duplicate nTDSDSA on re-seed");
    }

    #[tokio::test]
    async fn deleting_user_strips_group_membership() {
        let (db, _dir) = test_db().await;
        let base = db
            .ensure_ldap_base("dc=example,dc=com", "admin")
            .await
            .unwrap();
        let user = db
            .create_user(&base, "jsmith", "John", "Smith", None, "admin")
            .await
            .unwrap();
        let group = db
            .create_group(&base, "admins", None, "admin")
            .await
            .unwrap();
        db.add_member(&group.dn, &user.dn).await.unwrap();
        db.delete_entry(&user.dn).await.unwrap();
        assert_eq!(db.list_groups().await.unwrap()[0].members.len(), 0);
    }
}
