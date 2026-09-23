//! A representative core Active Directory schema, rendered as RFC 4512
//! `attributeTypes` / `objectClasses` for the subschema subentry so LDAP clients
//! (ldap3, `ldp.exe`, ADSI) can *discover* the schema. This is deliberately the
//! essential classes and attributes a directory browser expects — not the full
//! ~1500-attribute AD schema — with real AD/X.500 OIDs and standard LDAP syntaxes.

use std::collections::{BTreeMap, BTreeSet};

/// Standard LDAP syntax OIDs (RFC 4517).
mod syntax {
    pub const DIRECTORY_STRING: &str = "1.3.6.1.4.1.1466.115.121.1.15";
    pub const IA5_STRING: &str = "1.3.6.1.4.1.1466.115.121.1.26";
    pub const INTEGER: &str = "1.3.6.1.4.1.1466.115.121.1.27";
    pub const OCTET_STRING: &str = "1.3.6.1.4.1.1466.115.121.1.40";
    pub const DN: &str = "1.3.6.1.4.1.1466.115.121.1.12";
    pub const GENERALIZED_TIME: &str = "1.3.6.1.4.1.1466.115.121.1.24";
    pub const OID: &str = "1.3.6.1.4.1.1466.115.121.1.38";
}

use syntax::*;

/// Core attributes: (name, OID, syntax OID, single-valued).
const ATTRIBUTES: &[(&str, &str, &str, bool)] = &[
    ("objectClass", "2.5.4.0", OID, false),
    ("cn", "2.5.4.3", DIRECTORY_STRING, false),
    ("uid", "0.9.2342.19200300.100.1.1", DIRECTORY_STRING, false),
    ("userPassword", "2.5.4.35", OCTET_STRING, false),
    ("sn", "2.5.4.4", DIRECTORY_STRING, false),
    ("name", "1.2.840.113556.1.4.1", DIRECTORY_STRING, true),
    ("description", "2.5.4.13", DIRECTORY_STRING, false),
    ("distinguishedName", "2.5.4.49", DN, true),
    ("givenName", "2.5.4.42", DIRECTORY_STRING, false),
    (
        "displayName",
        "1.2.840.113556.1.2.13",
        DIRECTORY_STRING,
        true,
    ),
    ("ou", "2.5.4.11", DIRECTORY_STRING, false),
    ("dc", "0.9.2342.19200300.100.1.25", IA5_STRING, true),
    ("mail", "0.9.2342.19200300.100.1.3", IA5_STRING, false),
    ("telephoneNumber", "2.5.4.20", DIRECTORY_STRING, false),
    ("member", "2.5.4.31", DN, false),
    ("memberOf", "1.2.840.113556.1.2.102", DN, false),
    ("objectGUID", "1.2.840.113556.1.4.2", OCTET_STRING, true),
    ("objectSid", "1.2.840.113556.1.4.146", OCTET_STRING, true),
    ("objectCategory", "1.2.840.113556.1.4.782", DN, true),
    (
        "sAMAccountName",
        "1.2.840.113556.1.4.221",
        DIRECTORY_STRING,
        true,
    ),
    ("sAMAccountType", "1.2.840.113556.1.4.302", INTEGER, true),
    ("userAccountControl", "1.2.840.113556.1.4.8", INTEGER, true),
    (
        "userPrincipalName",
        "1.2.840.113556.1.4.656",
        DIRECTORY_STRING,
        true,
    ),
    (
        "servicePrincipalName",
        "1.2.840.113556.1.4.771",
        DIRECTORY_STRING,
        false,
    ),
    (
        "dNSHostName",
        "1.2.840.113556.1.4.619",
        DIRECTORY_STRING,
        true,
    ),
    ("primaryGroupID", "1.2.840.113556.1.4.98", INTEGER, true),
    (
        "whenCreated",
        "1.2.840.113556.1.2.2",
        GENERALIZED_TIME,
        true,
    ),
    (
        "whenChanged",
        "1.2.840.113556.1.2.3",
        GENERALIZED_TIME,
        true,
    ),
    ("uSNCreated", "1.2.840.113556.1.2.19", INTEGER, true),
    ("uSNChanged", "1.2.840.113556.1.2.120", INTEGER, true),
    ("instanceType", "1.2.840.113556.1.2.1", INTEGER, true),
    ("pwdLastSet", "1.2.840.113556.1.4.96", INTEGER, true),
    ("accountExpires", "1.2.840.113556.1.4.159", INTEGER, true),
    ("lastLogon", "1.2.840.113556.1.4.52", INTEGER, true),
    ("badPwdCount", "1.2.840.113556.1.4.12", INTEGER, true),
    ("gPLink", "1.2.840.113556.1.4.891", DIRECTORY_STRING, true),
    (
        "gPCFileSysPath",
        "1.2.840.113556.1.4.894",
        DIRECTORY_STRING,
        true,
    ),
    ("versionNumber", "1.2.840.113556.1.4.876", INTEGER, true),
    (
        "nTSecurityDescriptor",
        "1.2.840.113556.1.2.281",
        OCTET_STRING,
        true,
    ),
    ("subschemaSubentry", "2.5.18.10", DN, true),
    // `o` (organizationName) — the RDN attribute of an `organization` entry.
    ("o", "2.5.4.10", DIRECTORY_STRING, false),
    // `serverReference` — a DC/server object's link to its computer account.
    ("serverReference", "1.2.840.113556.1.4.515", DN, true),
    ("attributeTypes", "2.5.21.5", DIRECTORY_STRING, false),
    ("objectClasses", "2.5.21.6", DIRECTORY_STRING, false),
    // The FSMO role holder — a DN pointing at an nTDSDSA. Writable so a client can
    // seize a role (rewrite the owner); read to answer `netdom query fsmo`.
    ("fSMORoleOwner", "1.2.840.113556.1.4.183", DN, true),
];

/// One class definition: (name, OID, superclass, kind, MUST, MAY).
type ClassDef = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static [&'static str],
    &'static [&'static str],
);

/// Core classes.
const CLASSES: &[ClassDef] = &[
    (
        "top",
        "2.5.6.0",
        "",
        "ABSTRACT",
        &["objectClass"],
        &[
            "cn",
            "description",
            "distinguishedName",
            "name",
            "objectCategory",
            "objectGUID",
            "whenCreated",
            "whenChanged",
            "uSNCreated",
            "uSNChanged",
            "instanceType",
            "nTSecurityDescriptor",
            "subschemaSubentry",
        ],
    ),
    // AD relaxes X.500 `person` MUST from (cn, sn) to just cn; sn becomes MAY.
    (
        "person",
        "2.5.6.6",
        "top",
        "STRUCTURAL",
        &["cn"],
        &["sn", "description", "telephoneNumber"],
    ),
    (
        "organizationalPerson",
        "2.5.6.7",
        "person",
        "STRUCTURAL",
        &[],
        &["ou", "displayName", "givenName", "mail"],
    ),
    (
        "inetOrgPerson",
        "2.16.840.1.113730.3.2.2",
        "organizationalPerson",
        "STRUCTURAL",
        &[],
        &["uid", "mail", "displayName", "userPassword"],
    ),
    (
        "groupOfNames",
        "2.5.6.9",
        "top",
        "STRUCTURAL",
        &["cn"],
        &["member", "description"],
    ),
    (
        "domain",
        "0.9.2342.19200300.100.4.13",
        "top",
        "STRUCTURAL",
        &[],
        &["dc", "description"],
    ),
    (
        "user",
        "1.2.840.113556.1.5.9",
        "organizationalPerson",
        "STRUCTURAL",
        &[],
        &[
            "sAMAccountName",
            "sAMAccountType",
            "userAccountControl",
            "userPrincipalName",
            "servicePrincipalName",
            "memberOf",
            "primaryGroupID",
            "objectSid",
            "pwdLastSet",
            "accountExpires",
            "lastLogon",
            "badPwdCount",
        ],
    ),
    (
        "computer",
        "1.2.840.113556.1.3.30",
        "user",
        "STRUCTURAL",
        &[],
        &["dNSHostName"],
    ),
    (
        "group",
        "1.2.840.113556.1.5.8",
        "top",
        "STRUCTURAL",
        &["cn"],
        &[
            "member",
            "memberOf",
            "sAMAccountName",
            "sAMAccountType",
            "objectSid",
            "description",
        ],
    ),
    (
        "container",
        "1.2.840.113556.1.3.23",
        "top",
        "STRUCTURAL",
        &["cn"],
        &["description"],
    ),
    (
        "organizationalUnit",
        "2.5.6.5",
        "top",
        "STRUCTURAL",
        &["ou"],
        &["description", "gPLink"],
    ),
    (
        "organization",
        "2.5.6.4",
        "top",
        "STRUCTURAL",
        &["o"],
        &["description"],
    ),
    (
        "domainController",
        "1.2.840.113556.1.5.17",
        "computer",
        "STRUCTURAL",
        &[],
        &["dNSHostName", "serverReference"],
    ),
    (
        "domainDNS",
        "1.2.840.113556.1.5.67",
        "top",
        "STRUCTURAL",
        &[],
        &["dc", "gPLink"],
    ),
    (
        "builtinDomain",
        "1.2.840.113556.1.5.24",
        "top",
        "STRUCTURAL",
        &[],
        &["cn"],
    ),
    (
        "subSchema",
        "2.5.20.1",
        "top",
        "STRUCTURAL",
        &[],
        &["attributeTypes", "objectClasses"],
    ),
];

/// RFC 4512 `attributeTypes` descriptions for the subschema subentry.
pub(crate) fn attribute_types() -> Vec<String> {
    ATTRIBUTES
        .iter()
        .map(|(name, oid, syn, single)| {
            let single = if *single { " SINGLE-VALUE" } else { "" };
            format!("( {oid} NAME '{name}' SYNTAX {syn}{single} )")
        })
        .collect()
}

/// RFC 4512 `objectClasses` descriptions for the subschema subentry.
pub(crate) fn object_classes() -> Vec<String> {
    CLASSES
        .iter()
        .map(|(name, oid, sup, kind, must, may)| {
            let sup = if sup.is_empty() {
                String::new()
            } else {
                format!(" SUP {sup}")
            };
            let must = render_list("MUST", must);
            let may = render_list("MAY", may);
            format!("( {oid} NAME '{name}'{sup} {kind}{must}{may} )")
        })
        .collect()
}

/// The LDAP syntaxes referenced above, for the subschema subentry's `ldapSyntaxes`.
pub(crate) fn ldap_syntaxes() -> Vec<String> {
    [
        (DIRECTORY_STRING, "Directory String"),
        (IA5_STRING, "IA5 String"),
        (INTEGER, "INTEGER"),
        (OCTET_STRING, "Octet String"),
        (DN, "Distinguished Name"),
        (GENERALIZED_TIME, "Generalized Time"),
        (OID, "OID"),
    ]
    .iter()
    .map(|(oid, desc)| format!("( {oid} DESC '{desc}' )"))
    .collect()
}

fn class(name: &str) -> Option<&'static ClassDef> {
    CLASSES.iter().find(|(n, ..)| n.eq_ignore_ascii_case(name))
}

/// Whether the attribute type is defined in this schema.
pub(crate) fn is_known_attribute(name: &str) -> bool {
    ATTRIBUTES
        .iter()
        .any(|(n, ..)| n.eq_ignore_ascii_case(name))
}

/// A schema-enforcement failure (the two LDAP result codes we raise).
pub(crate) enum Violation {
    ObjectClassViolation(String),
    UndefinedAttributeType(String),
}

/// The object classes plus their transitive superclasses; `Err(name)` on an
/// unknown class.
fn resolve_chain(object_classes: &[String]) -> Result<Vec<&'static ClassDef>, String> {
    let mut resolved: Vec<&ClassDef> = Vec::new();
    let mut pending: Vec<String> = object_classes.to_vec();
    pending.push("top".to_string());
    while let Some(name) = pending.pop() {
        if resolved.iter().any(|(n, ..)| n.eq_ignore_ascii_case(&name)) {
            continue;
        }
        let definition = class(&name).ok_or_else(|| name.clone())?;
        resolved.push(definition);
        if !definition.2.is_empty() {
            pending.push(definition.2.to_string());
        }
    }
    Ok(resolved)
}

/// Validate a new entry against the schema (RFC 4512 §2.4.2, AD-relaxed): object
/// classes must be defined, exactly one structural class, every MUST attribute
/// present (the RDN attribute counts as present), and every attribute both
/// defined and permitted by the classes' MUST∪MAY. `rdn_attr` is the RDN's
/// attribute name (e.g. `cn` for `cn=WIN10PC`).
pub(crate) fn validate_new_entry(
    object_classes: &[String],
    attributes: &BTreeMap<String, Vec<String>>,
    rdn_attr: &str,
) -> Result<(), Violation> {
    let chain = resolve_chain(object_classes)
        .map_err(|name| Violation::ObjectClassViolation(format!("unknown objectClass '{name}'")))?;

    // Exactly one structural "leaf" (a structural class that is not the superclass
    // of another structural class in the set).
    let structural: Vec<&str> = chain
        .iter()
        .filter(|(_, _, _, kind, _, _)| *kind == "STRUCTURAL")
        .map(|(n, ..)| *n)
        .collect();
    let superclasses: BTreeSet<String> = chain
        .iter()
        .filter(|(_, _, _, kind, _, _)| *kind == "STRUCTURAL")
        .map(|(_, _, sup, _, _, _)| sup.to_ascii_lowercase())
        .collect();
    let leaves: Vec<&str> = structural
        .iter()
        .copied()
        .filter(|n| !superclasses.contains(&n.to_ascii_lowercase()))
        .collect();
    match leaves.len() {
        1 => {}
        0 => {
            return Err(Violation::ObjectClassViolation(
                "no structural object class".into(),
            ))
        }
        _ => {
            return Err(Violation::ObjectClassViolation(format!(
                "multiple structural object classes: {}",
                leaves.join(", ")
            )))
        }
    }

    let present = |name: &str| {
        name.eq_ignore_ascii_case("objectClass")
            || name.eq_ignore_ascii_case(rdn_attr)
            || attributes.keys().any(|k| k.eq_ignore_ascii_case(name))
    };
    let mut allowed: BTreeSet<String> = BTreeSet::from(["objectclass".to_string()]);
    for (_, _, _, _, must, may) in &chain {
        for m in *must {
            if !present(m) {
                return Err(Violation::ObjectClassViolation(format!(
                    "missing required attribute '{m}'"
                )));
            }
            allowed.insert(m.to_ascii_lowercase());
        }
        for a in *may {
            allowed.insert(a.to_ascii_lowercase());
        }
    }
    for name in attributes.keys() {
        if !is_known_attribute(name) {
            return Err(Violation::UndefinedAttributeType(format!(
                "undefined attribute type '{name}'"
            )));
        }
        if !allowed.contains(&name.to_ascii_lowercase()) {
            return Err(Violation::ObjectClassViolation(format!(
                "attribute '{name}' is not permitted by the object classes"
            )));
        }
    }
    Ok(())
}

fn render_list(kind: &str, items: &[&str]) -> String {
    if items.is_empty() {
        String::new()
    } else {
        format!(" {kind} ( {} )", items.join(" $ "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribute_types_are_rfc4512_shaped() {
        let types = attribute_types();
        assert!(types
            .iter()
            .all(|t| t.starts_with("( ") && t.ends_with(" )")));
        assert!(types
            .iter()
            .any(|t| t.contains("NAME 'sAMAccountName'") && t.contains("SINGLE-VALUE")));
        assert!(types.iter().any(|t| t.contains("NAME 'objectGUID'")));
    }

    #[test]
    fn object_classes_cover_the_ad_core_with_inheritance() {
        let classes = object_classes();
        let user = classes
            .iter()
            .find(|c| c.contains("NAME 'user'"))
            .expect("user class");
        assert!(user.contains("SUP organizationalPerson"));
        assert!(user.contains("STRUCTURAL"));
        assert!(user.contains("sAMAccountName"));
        let computer = classes
            .iter()
            .find(|c| c.contains("NAME 'computer'"))
            .unwrap();
        assert!(computer.contains("SUP user") && computer.contains("dNSHostName"));
        let top = classes.iter().find(|c| c.contains("NAME 'top'")).unwrap();
        assert!(top.contains("ABSTRACT") && top.contains("MUST ( objectClass )"));
    }

    #[test]
    fn validate_new_entry_accepts_valid_and_flags_violations() {
        let oc = |names: &[&str]| names.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let attr = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), vec![v.to_string()]))
                .collect::<BTreeMap<_, _>>()
        };

        // computer with cn from the RDN + an allowed sAMAccountName → valid.
        assert!(validate_new_entry(
            &oc(&["top", "computer"]),
            &attr(&[("sAMAccountName", "PC$")]),
            "cn",
        )
        .is_ok());

        // Unknown objectClass → objectClassViolation.
        assert!(matches!(
            validate_new_entry(&oc(&["widget"]), &BTreeMap::new(), "cn"),
            Err(Violation::ObjectClassViolation(_))
        ));
        // Undefined attribute → undefinedAttributeType.
        assert!(matches!(
            validate_new_entry(&oc(&["top", "computer"]), &attr(&[("frob", "x")]), "cn"),
            Err(Violation::UndefinedAttributeType(_))
        ));
        // Missing MUST cn (RDN is sn) → objectClassViolation.
        assert!(matches!(
            validate_new_entry(&oc(&["top", "person"]), &BTreeMap::new(), "sn"),
            Err(Violation::ObjectClassViolation(_))
        ));
        // Two structural classes → objectClassViolation.
        assert!(matches!(
            validate_new_entry(&oc(&["top", "user", "group"]), &BTreeMap::new(), "cn"),
            Err(Violation::ObjectClassViolation(_))
        ));
        // A defined attribute not permitted by the classes → objectClassViolation.
        assert!(matches!(
            validate_new_entry(
                &oc(&["top", "container"]),
                &attr(&[("dNSHostName", "h")]),
                "cn"
            ),
            Err(Violation::ObjectClassViolation(_))
        ));
    }
}
