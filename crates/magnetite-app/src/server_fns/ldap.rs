//! LDAP domain server functions (F-13 / S-LDAP-01..05): dashboard, tree,
//! users, groups, OUs. Authorized (08_authz / 08_ldap_logic §0.2), audited.

use crate::types::{LdapMetrics, LdapSyncStatus};
use leptos::prelude::*;
use magnetite_core::domains::ldap::model::{
    DirectoryEntry, LdapAclRule, LdapGroup, LdapOu, LdapUser, TreeNode,
};

/// The AD DC Kerberos realm (from config, e.g. `EXAMPLE.COM`) — the salt domain for
/// `ad_principal` key derivation, so a user provisioned here authenticates against the
/// same realm the KDC serves.
#[cfg(feature = "ssr")]
fn addc_realm() -> String {
    use crate::state::AppState;
    use magnetite_core::domain::DomainKey;
    let state = expect_context::<AppState>();
    state
        .config
        .domains
        .get(&DomainKey::Addc)
        .and_then(|d| d.server.as_ref())
        .and_then(|s| s.addc.as_ref())
        .and_then(|a| a.realm.clone())
        .unwrap_or_else(|| magnetite_addc::DEFAULT_REALM.to_string())
}

/// Provision (or refresh) the `ad_principal` — the RID + NT hash + Kerberos key the
/// KDC authenticates Windows logons against — for `sam`. This is what makes a Web-created
/// user able to log on to Windows (the LDAP `entry` alone only supports simple bind).
///
/// The RID is resolved as: `explicit_rid` (to inherit an old domain's exact SID) →ᵉˡˢᵉ the
/// account's existing RID →ᵉˡˢᵉ a freshly reserved one above the well-known floor. Returns
/// the RID used (so the caller can render the entry's `objectSid`).
///
/// Key material: when `nt_hash` is `Some` it is imported verbatim (a migrated account whose
/// plaintext is unknown); when `kerberos_key` is `Some` (32-byte AES256, e.g. DCSynced from
/// the old AD) it too is stored verbatim, so both NTLM AND Kerberos carry over with the
/// password fully preserved. Whatever is `None` is derived from `password` instead.
#[cfg(feature = "ssr")]
async fn provision_ad_principal(
    db: &magnetite_db::Db,
    sam: &str,
    password: &str,
    explicit_rid: Option<u32>,
    nt_hash: Option<[u8; 16]>,
    kerberos_key: Option<Vec<u8>>,
) -> Result<u32, ServerFnError> {
    let realm = addc_realm();
    let rid = match explicit_rid {
        Some(r) => r,
        None => match db
            .get_ad_principal(sam)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?
        {
            Some(existing) => existing.rid,
            None => db
                .reserve_rid_block(magnetite_addc::RID_POOL_FIRST, 1)
                .await
                .map_err(|e| ServerFnError::new(e.to_string()))?,
        },
    };
    match nt_hash {
        // Import path: store the given NT hash + (optional) Kerberos key verbatim.
        Some(h) => {
            // Never derive a Kerberos key from an empty password — it would be a known,
            // logon-able key. With no imported key and no password, store an EMPTY
            // Kerberos key so the account is NTLM-only (from the real imported NT hash)
            // until a password or key is set; the KDC skips an empty-key principal.
            let key = if kerberos_key.is_none() && password.is_empty() {
                Some(Vec::new())
            } else {
                kerberos_key
            };
            db.upsert_local_principal(sam, rid, password, &h, key.as_deref(), &realm)
                .await
                .map(|_| ())
                .map_err(|e| ServerFnError::new(e.to_string()))?
        }
        // Derive both from the password (the ordinary create / password-reset path).
        None => db
            .upsert_ad_principal(sam, rid, password, &realm)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?,
    }
    Ok(rid)
}

/// Parse a 32-hex-character NT hash into 16 bytes, or `Err` when malformed. Blank ⇒ `None`.
#[cfg(feature = "ssr")]
fn parse_nt_hash(hex: &str) -> Result<Option<[u8; 16]>, ServerFnError> {
    let hex = hex.trim();
    if hex.is_empty() {
        return Ok(None);
    }
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ServerFnError::new(
            "NTハッシュは16進32文字で指定してください。",
        ));
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| ServerFnError::new("NTハッシュが不正です。"))?;
    }
    Ok(Some(out))
}

/// Parse a 64-hex-character (32-byte) AES256 Kerberos key into bytes, or `Err` when
/// malformed. Blank ⇒ `None`.
#[cfg(feature = "ssr")]
fn parse_hex_key(hex: &str) -> Result<Option<Vec<u8>>, ServerFnError> {
    let hex = hex.trim();
    if hex.is_empty() {
        return Ok(None);
    }
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ServerFnError::new(
            "Kerberos 鍵は16進64文字（AES256）で指定してください。",
        ));
    }
    let bytes = (0..32)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|_| ServerFnError::new("Kerberos 鍵が不正です。"))?;
    Ok(Some(bytes))
}

/// The `sAMAccountName` carried in a DN's leftmost RDN value (`cn=Admins,…` ⇒ `Admins`,
/// `uid=alice,…` ⇒ `alice`).
#[cfg(feature = "ssr")]
fn rdn_sam(dn: &str) -> &str {
    let rdn = dn.split_once(',').map(|(r, _)| r).unwrap_or(dn);
    rdn.split_once('=').map(|(_, v)| v).unwrap_or(rdn).trim()
}

/// The DB-persisted domain SID sub-authorities (single source of truth), or the default.
#[cfg(feature = "ssr")]
async fn domain_subauth(db: &magnetite_db::Db) -> Vec<u32> {
    db.get_domain_sid()
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| vec![21, 1, 2, 3])
}

/// Encode an account/group `objectSid` (hex, little-endian) from the domain
/// sub-authorities + `rid` — `S-1-5-<sub…>-<rid>`. The RID is the last sub-authority, so
/// the AD DC recovers it as the last LE u32 (matching `build_directory_from_db`).
#[cfg(feature = "ssr")]
fn object_sid_hex(domain_sub: &[u32], rid: u32) -> String {
    let count = u8::try_from(domain_sub.len() + 1).unwrap_or(5);
    let mut sid: Vec<u8> = vec![0x01, count, 0, 0, 0, 0, 0, 0x05]; // rev, count, NT authority(5)
    for s in domain_sub {
        sid.extend_from_slice(&s.to_le_bytes());
    }
    sid.extend_from_slice(&rid.to_le_bytes());
    sid.iter().map(|b| format!("{b:02x}")).collect()
}

/// Provision (or fetch) the `ad_group` — the RID + `objectSid` the KDC/PAC references —
/// for group `sam`, returning its `objectSid` hex. Reuses the existing RID/SID when
/// present, else allocates a fresh RID from the pool shared with users (so RIDs never
/// collide). This is the group analog of [`provision_ad_principal`]: it makes a Web-created
/// group visible to Kerberos group-based access control, not just to LDAP.
#[cfg(feature = "ssr")]
async fn provision_ad_group(db: &magnetite_db::Db, sam: &str) -> Result<String, ServerFnError> {
    if let Some(existing) = db
        .get_ad_group(sam)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
    {
        return Ok(existing.sid);
    }
    let rid = db
        .reserve_rid_block(magnetite_addc::RID_POOL_FIRST, 1)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let sid_hex = object_sid_hex(&domain_subauth(db).await, rid);
    db.upsert_ad_group(sam, rid, &sid_hex, &[])
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(sid_hex)
}

/// Resolve a group member's `objectSid` (hex) so it can be linked into an `ad_group`: a
/// user via its `ad_principal` RID, or a nested group via its `ad_group` SID. `None` when
/// the member has no provisioned AD identity yet (e.g. a user created without a password);
/// the PAC would drop such a member anyway, so the caller skips the link.
#[cfg(feature = "ssr")]
async fn member_object_sid(
    db: &magnetite_db::Db,
    member_sam: &str,
) -> Result<Option<String>, ServerFnError> {
    if let Some(u) = db
        .get_ad_principal(member_sam)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
    {
        return Ok(Some(object_sid_hex(&domain_subauth(db).await, u.rid)));
    }
    if let Some(g) = db
        .get_ad_group(member_sam)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
    {
        return Ok(Some(g.sid));
    }
    Ok(None)
}

#[cfg(feature = "ssr")]
async fn audit_ldap(
    user: &magnetite_core::models::CurrentUser,
    action: magnetite_core::models::common::ActionKind,
    target_kind: &str,
    target_id: &str,
) {
    use crate::server_fns::auth::client_ip;
    use crate::state::AppState;
    let state = expect_context::<AppState>();
    let _ = state
        .db
        .append_audit(magnetite_core::models::NewAuditEntry {
            actor: user.subject.clone(),
            actor_role: user.role,
            domain: magnetite_core::domain::DomainKey::Ldap,
            action,
            target_kind: target_kind.to_string(),
            target_id: target_id.to_string(),
            result: magnetite_core::models::common::OpResult::Success,
            ip: client_ip().await,
            detail: None,
        })
        .await;
}

/// LDAP dashboard metrics (S-LDAP-01).
#[server(GetLdapMetrics, "/api")]
pub async fn get_ldap_metrics() -> Result<LdapMetrics, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    let user = require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    let base = state
        .db
        .ensure_ldap_base(state.config.ldap_base_dn(), &user.subject)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let (entries, users, groups, ous) = state
        .db
        .ldap_metrics()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(LdapMetrics {
        entry_count: entries as u64,
        user_count: users as u64,
        group_count: groups as u64,
        ou_count: ous as u64,
        base_dn: base,
    })
}

// ---- Tree (S-LDAP-02) -----------------------------------------------------

/// Root tree nodes (base DN). Seeds the base entry on first access.
#[server(GetTreeRoot, "/api")]
pub async fn get_tree_root() -> Result<Vec<TreeNode>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    let user = require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .ensure_ldap_base(state.config.ldap_base_dn(), &user.subject)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    state
        .db
        .list_children(None)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Children of a DN (lazy expansion).
#[server(GetTreeChildren, "/api")]
pub async fn get_tree_children(dn: String) -> Result<Vec<TreeNode>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_children(Some(&dn))
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Full entry detail for the tree's right panel (redacted).
#[server(GetEntry, "/api")]
pub async fn get_entry(dn: String) -> Result<Option<DirectoryEntry>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .get_entry(&dn)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Available parent DNs (base + OUs) for the create forms.
#[server(ListParents, "/api")]
pub async fn list_parents() -> Result<Vec<String>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    let user = require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    let base = state
        .db
        .ensure_ldap_base(state.config.ldap_base_dn(), &user.subject)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let mut parents = vec![base];
    let ous = state
        .db
        .list_ous()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    parents.extend(ous.into_iter().map(|o| o.dn));
    Ok(parents)
}

// ---- Users (S-LDAP-03) ----------------------------------------------------

/// List directory users.
#[server(ListUsers, "/api")]
pub async fn list_users() -> Result<Vec<LdapUser>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_users()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create a user (S-LDAP-03).
// The new user's attributes map one-to-one to the create-user form fields.
#[allow(clippy::too_many_arguments)]
#[server(CreateUser, "/api")]
pub async fn create_user(
    parent_dn: String,
    uid: String,
    cn: String,
    sn: String,
    mail: String,
    password: String,
    rid: Option<u32>,
    nt_hash: String,
    kerberos_key: String,
) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::ldap::validate::check_user;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    check_user(&uid, &cn, &sn, &mail).map_err(ServerFnError::new)?;
    let state = expect_context::<AppState>();
    // Optional migration inputs: an explicit RID to inherit the old domain's exact SID, an
    // NT hash to import (plaintext unknown), and the AES256 Kerberos key to import too
    // (both DCSynced from the old AD) so the password carries over for Kerberos AND NTLM.
    let imported_hash = parse_nt_hash(&nt_hash)?;
    let imported_key = parse_hex_key(&kerberos_key)?;
    // The Kerberos key rides in with the NT hash (they DCSync together); importing a key
    // without its NT hash would be an incomplete account.
    if imported_key.is_some() && imported_hash.is_none() {
        return Err(ServerFnError::new(
            "Kerberos 鍵を取り込む場合は NT ハッシュも指定してください。",
        ));
    }
    // A password makes the account log-on-able via Kerberos AND seeds the LDAP simple-bind
    // credential. It is required UNLESS an NT hash is imported (then NTLM works from the
    // hash and a password can be set later); when supplied it must meet policy.
    let has_password = !password.is_empty();
    if imported_hash.is_none() || has_password {
        let min = state.config.policy.password_min_length;
        if magnetite_core::password::check_password(&password, min).is_err() {
            return Err(ServerFnError::new(
                "パスワードがポリシーを満たしていません。",
            ));
        }
    }
    let mail_opt = if mail.trim().is_empty() {
        None
    } else {
        Some(mail.as_str())
    };
    let created = state
        .db
        .create_user(&parent_dn, &uid, &cn, &sn, mail_opt, &user.subject)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    // Set the LDAP simple-bind password when one was supplied, AND provision the
    // ad_principal (RID + NT hash + Kerberos key) so the user can actually log on to
    // Windows, not just LDAP-bind. With an imported NT hash and no password, only the
    // ad_principal is written (NTLM logon; LDAP simple bind stays unavailable until a
    // password is set).
    if has_password {
        state
            .db
            .reset_password(&created.dn, &password)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
    }
    let assigned_rid =
        provision_ad_principal(&state.db, &uid, &password, rid, imported_hash, imported_key)
            .await?;
    // Stamp the LDAP entry with objectSid + sAMAccountName so a client reading LDAP
    // directly (e.g. sssd) sees a real AD object; Windows resolves via the PAC regardless.
    let sid_hex = object_sid_hex(&domain_subauth(&state.db).await, assigned_rid);
    state
        .db
        .set_entry_ad_identity(&created.dn, &uid, &sid_hex)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    state
        .services
        .notify(magnetite_core::domain::DomainKey::Addc);
    audit_ldap(&user, ActionKind::Create, "user", &created.dn).await;
    Ok(())
}

/// Toggle a user's enabled flag (LE-03).
#[server(ToggleUser, "/api")]
pub async fn toggle_user(dn: String, enabled: bool) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .set_user_enabled(&dn, enabled)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_ldap(&user, ActionKind::Update, "user", &dn).await;
    Ok(())
}

/// Reset a user's password (Admin only — LE-05 / AC-15).
#[server(ResetPassword, "/api")]
pub async fn reset_password(dn: String, new_password: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Admin).await?;
    let state = expect_context::<AppState>();
    let min = state.config.policy.password_min_length;
    if magnetite_core::password::check_password(&new_password, min).is_err() {
        return Err(ServerFnError::new(
            "パスワードがポリシーを満たしていません。",
        ));
    }
    state
        .db
        .reset_password(&dn, &new_password)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    // Keep the ad_principal (Windows logon credential) in sync with the LDAP password
    // — the sAMAccountName is the entry's RDN value (`uid=<sam>` / `cn=<sam>`). Reuse the
    // account's existing RID and derive fresh keys from the new password.
    let sam = rdn_sam(&dn);
    if !sam.is_empty() {
        provision_ad_principal(&state.db, sam, &new_password, None, None, None).await?;
        state
            .services
            .notify(magnetite_core::domain::DomainKey::Addc);
    }
    audit_ldap(&user, ActionKind::Update, "user_password", &dn).await;
    Ok(())
}

// ---- Groups (S-LDAP-04) ---------------------------------------------------

/// List directory groups.
#[server(ListGroups, "/api")]
pub async fn list_groups() -> Result<Vec<LdapGroup>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_groups()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create a group (S-LDAP-04).
#[server(CreateGroup, "/api")]
pub async fn create_group(
    parent_dn: String,
    cn: String,
    description: String,
) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::ldap::validate::check_group;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    check_group(&cn).map_err(ServerFnError::new)?;
    let state = expect_context::<AppState>();
    let desc = if description.trim().is_empty() {
        None
    } else {
        Some(description.as_str())
    };
    let created = state
        .db
        .create_group(&parent_dn, &cn, desc, &user.subject)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    // Also provision the `ad_group` (RID + objectSid) so the group is visible to the
    // KDC/PAC for group-based access control, not just over LDAP. Notify the AD DC so it
    // picks up the new group on the next live refresh (no restart).
    let sid_hex = provision_ad_group(&state.db, &cn).await?;
    // Stamp the LDAP entry with objectSid + sAMAccountName for direct-LDAP clients.
    state
        .db
        .set_entry_ad_identity(&created.dn, &cn, &sid_hex)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    state
        .services
        .notify(magnetite_core::domain::DomainKey::Addc);
    audit_ldap(&user, ActionKind::Create, "group", &created.dn).await;
    Ok(())
}

/// Add a member DN to a group (LE-06).
#[server(AddMember, "/api")]
pub async fn add_member(group_dn: String, member_dn: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::ldap::validate::check_member_dn;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    check_member_dn(&member_dn).map_err(ServerFnError::new)?;
    let state = expect_context::<AppState>();
    state
        .db
        .add_member(&group_dn, &member_dn)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    // Mirror the membership into `ad_group` (present link) so the KDC/PAC surfaces this
    // member's group SID. Backfill the group's ad_group row if missing; skip members that
    // have no provisioned AD identity yet (the PAC would drop them anyway).
    let group_sid = provision_ad_group(&state.db, rdn_sam(&group_dn)).await?;
    if let Some(member_sid) = member_object_sid(&state.db, rdn_sam(&member_dn)).await? {
        state
            .db
            .set_group_member_local(&group_sid, &member_sid, true)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        state
            .services
            .notify(magnetite_core::domain::DomainKey::Addc);
    }
    audit_ldap(&user, ActionKind::Update, "group_member", &group_dn).await;
    Ok(())
}

/// Remove a member DN from a group (LE-07).
#[server(RemoveMember, "/api")]
pub async fn remove_member(group_dn: String, member_dn: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .remove_member(&group_dn, &member_dn)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    // Mirror the removal into `ad_group` (absent-link tombstone) so the KDC/PAC stops
    // surfacing this membership. Backfill the group's ad_group row if missing.
    let group_sid = provision_ad_group(&state.db, rdn_sam(&group_dn)).await?;
    if let Some(member_sid) = member_object_sid(&state.db, rdn_sam(&member_dn)).await? {
        state
            .db
            .set_group_member_local(&group_sid, &member_sid, false)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        state
            .services
            .notify(magnetite_core::domain::DomainKey::Addc);
    }
    audit_ldap(&user, ActionKind::Update, "group_member", &group_dn).await;
    Ok(())
}

// ---- OUs (S-LDAP-05) ------------------------------------------------------

/// List OUs.
#[server(ListOus, "/api")]
pub async fn list_ous() -> Result<Vec<LdapOu>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_ous()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create an OU (S-LDAP-05).
#[server(CreateOu, "/api")]
pub async fn create_ou(
    parent_dn: String,
    ou: String,
    description: String,
) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::ldap::validate::check_ou;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    check_ou(&ou).map_err(ServerFnError::new)?;
    let state = expect_context::<AppState>();
    let desc = if description.trim().is_empty() {
        None
    } else {
        Some(description.as_str())
    };
    let created = state
        .db
        .create_ou(&parent_dn, &ou, desc, &user.subject)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_ldap(&user, ActionKind::Create, "ou", &created.dn).await;
    Ok(())
}

/// List the directory's `computer` entries (DN + key attributes).
#[server(ListComputers, "/api")]
pub async fn list_computers() -> Result<Vec<DirectoryEntry>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_computers()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create a `computer` entry under `parent_dn` (RDN `cn=<cn>`, objectClass
/// `top`/`computer`, `sAMAccountName=<cn>$`, optional `dNSHostName`). Write and above.
#[server(CreateComputer, "/api")]
pub async fn create_computer(
    parent_dn: String,
    cn: String,
    dns_host_name: String,
) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;
    use std::collections::BTreeMap;

    let user = require(ActionClass::Write).await?;
    let cn = cn.trim().to_string();
    let parent_dn = parent_dn.trim();
    if cn.is_empty() || parent_dn.is_empty() {
        return Err(ServerFnError::new(
            "コンピュータ名と親 DN を入力してください。",
        ));
    }
    if cn.contains([',', '=', '\\', '/']) {
        return Err(ServerFnError::new(
            "コンピュータ名に使用できない文字が含まれています。",
        ));
    }
    let dn = format!("cn={cn},{parent_dn}");
    let mut attrs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    attrs.insert("cn".into(), vec![cn.clone()]);
    attrs.insert("sAMAccountName".into(), vec![format!("{cn}$")]);
    let dns_host_name = dns_host_name.trim();
    if !dns_host_name.is_empty() {
        attrs.insert("dNSHostName".into(), vec![dns_host_name.to_string()]);
    }
    let state = expect_context::<AppState>();
    let created = state
        .db
        .create_entry(
            &dn,
            vec!["top".into(), "computer".into()],
            &attrs,
            &user.subject,
        )
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_ldap(&user, ActionKind::Create, "computer", &created.dn).await;
    Ok(())
}

/// Move a leaf entry to a different parent OU (RFC 4511 ModifyDN reparent). The RDN
/// is kept; group `member` references are rewritten by the repository. Entries with
/// children are refused. Write and above.
#[server(MoveEntry, "/api")]
pub async fn move_entry(dn: String, new_parent: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let dn = dn.trim();
    let new_parent = new_parent.trim();
    if dn.is_empty() || new_parent.is_empty() {
        return Err(ServerFnError::new("移動元と移動先を指定してください。"));
    }
    // Keep the leaf RDN; only the superior changes.
    let rdn = dn
        .split_once(',')
        .map(|(rdn, _)| rdn)
        .unwrap_or(dn)
        .to_string();
    let state = expect_context::<AppState>();
    let moved = state
        .db
        .rename_entry(dn, &rdn, true, Some(new_parent))
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_ldap(&user, ActionKind::Update, "entry", &moved.dn).await;
    Ok(())
}

/// Delete an entry (user/group/OU). OU guard enforced in the repository (AC-15).
#[server(DeleteEntry, "/api")]
pub async fn delete_entry(dn: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_entry(&dn)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    // Tear down the AD identity too, so a deleted group/user can't still be resolved by
    // the KDC/PAC: remove the ad_group (by SID) or the ad_principal (by RID). A non-AD
    // entry (OU, ACL, …) matches neither and is a no-op. Notify the AD DC when touched.
    let sam = rdn_sam(&dn);
    let removed_group = state
        .db
        .get_ad_group(sam)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let mut touched_addc = false;
    if let Some(g) = removed_group {
        state
            .db
            .delete_replicated_group(&g.sid)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        touched_addc = true;
    } else if let Some(u) = state
        .db
        .get_ad_principal(sam)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
    {
        state
            .db
            .delete_replicated_principal(u.rid)
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        touched_addc = true;
    }
    if touched_addc {
        state
            .services
            .notify(magnetite_core::domain::DomainKey::Addc);
    }
    audit_ldap(&user, ActionKind::Delete, "entry", &dn).await;
    Ok(())
}

// ---- Access control (S-LDAP-07) -------------------------------------------

/// List all LDAP ACL rules, ordered by priority.
#[server(ListLdapAcls, "/api")]
pub async fn list_ldap_acls() -> Result<Vec<LdapAclRule>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_ldap_acls()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create an LDAP ACL rule. Editing is not supported — delete and recreate.
#[server(CreateLdapAcl, "/api")]
pub async fn create_ldap_acl(rule: LdapAclRule) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    if rule.target_dn.trim().is_empty() {
        return Err(ServerFnError::new(
            "対象 DN を入力してください（全体は * ）。",
        ));
    }
    if rule.operations.is_empty() {
        return Err(ServerFnError::new("操作を1つ以上選択してください。"));
    }
    let state = expect_context::<AppState>();
    let created = state
        .db
        .create_ldap_acl(&rule)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_ldap(&user, ActionKind::Create, "ldap_acl", &created.id).await;
    Ok(())
}

/// Toggle an ACL rule's enabled flag.
#[server(ToggleLdapAcl, "/api")]
pub async fn toggle_ldap_acl(id: String, enabled: bool) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .set_ldap_acl_enabled(&id, enabled)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_ldap(&user, ActionKind::Update, "ldap_acl", &id).await;
    Ok(())
}

/// Delete an ACL rule by id.
#[server(DeleteLdapAcl, "/api")]
pub async fn delete_ldap_acl(id: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::ActionKind;

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_ldap_acl(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_ldap(&user, ActionKind::Delete, "ldap_acl", &id).await;
    Ok(())
}

/// LDAP syncrepl consumer status: this instance's configured provider plus the
/// persisted sync state. Bind credentials are never included.
#[server(GetLdapSyncStatus, "/api")]
pub async fn get_ldap_sync_status() -> Result<LdapSyncStatus, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domain::DomainKey;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    let cfg = state
        .config
        .domains
        .get(&DomainKey::Ldap)
        .and_then(|d| d.server.as_ref())
        .and_then(|s| s.consumer.as_ref());
    let (configured, enabled, provider_url, interval_secs, mode) = match cfg {
        Some(c) => (
            true,
            c.enabled,
            Some(c.provider_url.clone()),
            c.interval(),
            if c.is_ad_dirsync() {
                "ad-dirsync".to_string()
            } else if c.is_ad_usn() {
                "ad-usn".to_string()
            } else {
                "syncrepl".to_string()
            },
        ),
        None => (false, false, None, 30, "syncrepl".to_string()),
    };
    let sync_state = state
        .db
        .get_ldap_sync_state()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(LdapSyncStatus {
        configured,
        enabled,
        provider_url,
        base_dn: state.config.ldap_base_dn().to_string(),
        interval_secs,
        mode,
        state: sync_state,
    })
}
