//! Normalize an Active Directory / Samba object into Magnetite's directory shape
//! so imported users and groups appear in the ordinary LDAP user/group views.
//!
//! - `objectClass`: AD `user`→ [`OC_USER`] (inetOrgPerson), `group`→ [`OC_GROUP`]
//!   (groupOfNames), `organizationalUnit`→ [`OC_OU`]; otherwise the AD classes are
//!   kept. The chosen class becomes the entry's `structural_class`.
//! - `uid` ← `sAMAccountName`; `cn`/`sn`/`mail`/`member` are kept as-is.
//! - `enabled` ← the `ACCOUNTDISABLE` bit of `userAccountControl` (users only).
//! - Optional POSIX (`AdMapOpts.posix`): add `posixAccount`/`posixGroup` and
//!   `uidNumber`/`gidNumber`/`homeDirectory`/`loginShell` derived from the SID RID.

use ldap3_proto::proto::{LdapPartialAttribute, LdapSearchResultEntry};
use magnetite_core::domains::ldap::model::{OC_GROUP, OC_OU, OC_USER};
use std::collections::BTreeMap;

/// AD `userAccountControl` bit: the account is disabled.
const UF_ACCOUNTDISABLE: u32 = 0x0002;
/// The well-known "Domain Users" primary group RID (fallback gidNumber source).
const RID_DOMAIN_USERS: u32 = 513;

/// POSIX mapping options.
pub(crate) struct AdMapOpts {
    pub posix: bool,
    pub uid_base: u32,
    pub gid_base: u32,
}

/// A normalized AD object ready for `apply_ldap_sync_entry`.
pub(crate) struct NormalizedAdEntry {
    pub guid: Option<String>,
    pub is_deleted: bool,
    pub object_classes: Vec<String>,
    pub attributes: BTreeMap<String, Vec<String>>,
    pub enabled: bool,
}

/// Lower-case hex of a byte slice (stable id for binary AD attributes).
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The RID (relative id) of an AD SID — its last 32-bit little-endian subauthority.
fn sid_rid(sid: &[u8]) -> Option<u32> {
    if sid.len() < 4 {
        return None;
    }
    let tail = &sid[sid.len() - 4..];
    Some(u32::from_le_bytes([tail[0], tail[1], tail[2], tail[3]]))
}

fn first_text(vals: &[Vec<u8>]) -> Option<String> {
    vals.first().map(|v| String::from_utf8_lossy(v).to_string())
}

pub(crate) fn normalize_ad_entry(
    entry: &LdapSearchResultEntry,
    opts: &AdMapOpts,
) -> NormalizedAdEntry {
    let mut guid = None;
    let mut sid_bytes: Option<Vec<u8>> = None;
    let mut is_deleted = false;
    let mut ad_classes: Vec<String> = Vec::new();
    let mut attributes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut uac: Option<u32> = None;
    let mut sam: Option<String> = None;
    let mut primary_gid: Option<u32> = None;

    for LdapPartialAttribute { atype, vals } in &entry.attributes {
        if atype.eq_ignore_ascii_case("objectGUID") {
            guid = vals.first().map(|b| hex_encode(b));
            continue;
        }
        if atype.eq_ignore_ascii_case("objectSid") {
            sid_bytes = vals.first().cloned();
            attributes.insert(
                "objectSid".into(),
                vec![vals.first().map(|b| hex_encode(b)).unwrap_or_default()],
            );
            continue;
        }
        if atype.eq_ignore_ascii_case("objectClass") {
            ad_classes = vals
                .iter()
                .map(|v| String::from_utf8_lossy(v).to_string())
                .collect();
            continue;
        }
        if atype.eq_ignore_ascii_case("isDeleted") {
            is_deleted = vals
                .first()
                .map(|v| v.eq_ignore_ascii_case(b"TRUE"))
                .unwrap_or(false);
        }
        if atype.eq_ignore_ascii_case("userAccountControl") {
            uac = first_text(vals).and_then(|s| s.trim().parse::<u32>().ok());
        }
        if atype.eq_ignore_ascii_case("sAMAccountName") {
            sam = first_text(vals);
        }
        if atype.eq_ignore_ascii_case("primaryGroupID") {
            primary_gid = first_text(vals).and_then(|s| s.trim().parse::<u32>().ok());
        }
        let text: Vec<String> = vals
            .iter()
            .map(|v| String::from_utf8_lossy(v).to_string())
            .collect();
        attributes.insert(atype.clone(), text);
    }

    let has = |c: &str| ad_classes.iter().any(|x| x.eq_ignore_ascii_case(c));
    let is_user = has("user") && !has("computer");
    let is_group = has("group");
    let is_ou = has("organizationalUnit");

    // The structural class (inetOrgPerson / groupOfNames) is kept LAST because the
    // apply layer derives `structural_class` from the last non-`top` class; the
    // auxiliary posixAccount / posixGroup are inserted before it.
    let object_classes = if is_user {
        let mut c = vec![
            "top".to_string(),
            "person".to_string(),
            "organizationalPerson".to_string(),
        ];
        if opts.posix {
            c.push("posixAccount".to_string());
        }
        c.push(OC_USER.to_string());
        c
    } else if is_group {
        let mut c = vec!["top".to_string()];
        if opts.posix {
            c.push("posixGroup".to_string());
        }
        c.push(OC_GROUP.to_string());
        c
    } else if is_ou {
        vec!["top".to_string(), OC_OU.to_string()]
    } else {
        ad_classes.clone()
    };

    // uid ← sAMAccountName.
    if let Some(s) = &sam {
        attributes.insert("uid".into(), vec![s.clone()]);
    }

    // enabled ← userAccountControl (users only; groups are always enabled).
    let enabled = if is_user {
        uac.map(|u| u & UF_ACCOUNTDISABLE == 0).unwrap_or(true)
    } else {
        true
    };

    // Optional POSIX numeric/path attributes from the SID RID (the posixAccount /
    // posixGroup object classes were already added, before the structural class).
    if opts.posix {
        let rid = sid_bytes.as_deref().and_then(sid_rid);
        let login = sam.clone().unwrap_or_default();
        if is_user {
            if let Some(rid) = rid {
                let uid_number = opts.uid_base.saturating_add(rid);
                let gid_number = opts
                    .gid_base
                    .saturating_add(primary_gid.unwrap_or(RID_DOMAIN_USERS));
                attributes.insert("uidNumber".into(), vec![uid_number.to_string()]);
                attributes.insert("gidNumber".into(), vec![gid_number.to_string()]);
            }
            if !login.is_empty() {
                attributes.insert("homeDirectory".into(), vec![format!("/home/{login}")]);
            }
            attributes.insert("loginShell".into(), vec!["/bin/bash".into()]);
        } else if is_group {
            if let Some(rid) = rid {
                let gid_number = opts.gid_base.saturating_add(rid);
                attributes.insert("gidNumber".into(), vec![gid_number.to_string()]);
            }
        }
    }

    NormalizedAdEntry {
        guid,
        is_deleted,
        object_classes,
        attributes,
        enabled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pa(name: &str, vals: Vec<Vec<u8>>) -> LdapPartialAttribute {
        LdapPartialAttribute {
            atype: name.into(),
            vals,
        }
    }

    /// An AD SID whose RID (last LE u32) is 1105.
    fn sid_with_rid(rid: u32) -> Vec<u8> {
        let mut sid = vec![1, 5, 0, 0, 0, 0, 0, 5]; // revision + authority (partial)
        sid.extend_from_slice(&[21, 0, 0, 0]); // one subauthority placeholder
        sid.extend_from_slice(&rid.to_le_bytes());
        sid
    }

    #[test]
    fn user_is_normalized_to_inetorgperson_with_uid_and_enabled() {
        let entry = LdapSearchResultEntry {
            dn: "CN=Bob,OU=Users,DC=corp,DC=example,DC=com".into(),
            attributes: vec![
                pa(
                    "objectClass",
                    vec![b"top".to_vec(), b"person".to_vec(), b"user".to_vec()],
                ),
                pa("sAMAccountName", vec![b"bob".to_vec()]),
                pa("cn", vec![b"Bob Smith".to_vec()]),
                pa("mail", vec![b"bob@corp.example.com".to_vec()]),
                pa("userAccountControl", vec![b"514".to_vec()]), // 512|2 → disabled
            ],
        };
        let n = normalize_ad_entry(
            &entry,
            &AdMapOpts {
                posix: false,
                uid_base: 100_000,
                gid_base: 100_000,
            },
        );
        assert_eq!(n.object_classes.last().unwrap(), OC_USER);
        assert_eq!(n.attributes.get("uid").unwrap(), &vec!["bob".to_string()]);
        assert_eq!(n.attributes.get("mail").unwrap()[0], "bob@corp.example.com");
        assert!(!n.enabled, "UAC 514 has the ACCOUNTDISABLE bit set");
    }

    #[test]
    fn posix_attributes_are_derived_from_the_sid_rid() {
        let entry = LdapSearchResultEntry {
            dn: "CN=Bob,DC=corp,DC=example,DC=com".into(),
            attributes: vec![
                pa("objectClass", vec![b"top".to_vec(), b"user".to_vec()]),
                pa("sAMAccountName", vec![b"bob".to_vec()]),
                pa("userAccountControl", vec![b"512".to_vec()]),
                pa("objectSid", vec![sid_with_rid(1105)]),
                pa("primaryGroupID", vec![b"513".to_vec()]),
            ],
        };
        let n = normalize_ad_entry(
            &entry,
            &AdMapOpts {
                posix: true,
                uid_base: 100_000,
                gid_base: 100_000,
            },
        );
        assert!(n.object_classes.iter().any(|c| c == "posixAccount"));
        assert_eq!(n.attributes.get("uidNumber").unwrap()[0], "101105"); // 100000 + 1105
        assert_eq!(n.attributes.get("gidNumber").unwrap()[0], "100513"); // 100000 + 513
        assert_eq!(n.attributes.get("homeDirectory").unwrap()[0], "/home/bob");
        assert_eq!(n.attributes.get("loginShell").unwrap()[0], "/bin/bash");
        assert!(n.enabled);
    }

    #[test]
    fn group_is_normalized_to_groupofnames() {
        let entry = LdapSearchResultEntry {
            dn: "CN=Admins,DC=corp,DC=example,DC=com".into(),
            attributes: vec![
                pa("objectClass", vec![b"top".to_vec(), b"group".to_vec()]),
                pa("cn", vec![b"Admins".to_vec()]),
                pa("member", vec![b"CN=Bob,DC=corp,DC=example,DC=com".to_vec()]),
            ],
        };
        let n = normalize_ad_entry(
            &entry,
            &AdMapOpts {
                posix: false,
                uid_base: 100_000,
                gid_base: 100_000,
            },
        );
        assert_eq!(n.object_classes.last().unwrap(), OC_GROUP);
        assert!(n.enabled);
    }
}
