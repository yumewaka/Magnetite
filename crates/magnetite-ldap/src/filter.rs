//! LDAP search-filter evaluation (pure). Matches an RFC 4511 filter against a
//! directory entry's attribute view. Comparisons are case-insensitive (the
//! common `caseIgnoreMatch` default). Unsupported forms (extensible match) never
//! match.

use ldap3_proto::proto::{LdapFilter, LdapSubstringFilter};
use magnetite_core::domains::ldap::model::DirectoryEntry;
use std::collections::BTreeMap;

/// A lowercased-key attribute view: `objectClass` (from the entry's classes)
/// plus every stored attribute, so filters can match either uniformly.
pub(crate) fn attribute_view(entry: &DirectoryEntry) -> BTreeMap<String, Vec<String>> {
    let mut view: BTreeMap<String, Vec<String>> = BTreeMap::new();
    view.insert("objectclass".into(), entry.object_classes.clone());
    for (name, values) in &entry.attributes {
        view.entry(name.to_ascii_lowercase())
            .or_default()
            .extend(values.iter().cloned());
    }
    view
}

/// Evaluate `filter` against a lowercased attribute `view`.
pub(crate) fn matches(filter: &LdapFilter, view: &BTreeMap<String, Vec<String>>) -> bool {
    match filter {
        LdapFilter::And(fs) => fs.iter().all(|f| matches(f, view)),
        LdapFilter::Or(fs) => fs.iter().any(|f| matches(f, view)),
        LdapFilter::Not(inner) => !matches(inner, view),
        LdapFilter::Present(attr) => view.contains_key(&attr.to_ascii_lowercase()),
        LdapFilter::Equality(attr, val) => {
            values(view, attr).is_some_and(|vals| vals.iter().any(|v| v.eq_ignore_ascii_case(val)))
        }
        LdapFilter::Substring(attr, sub) => {
            values(view, attr).is_some_and(|vals| vals.iter().any(|v| substring_matches(v, sub)))
        }
        LdapFilter::GreaterOrEqual(attr, val) => {
            values(view, attr).is_some_and(|vals| vals.iter().any(|v| v.as_str() >= val.as_str()))
        }
        LdapFilter::LessOrEqual(attr, val) => {
            values(view, attr).is_some_and(|vals| vals.iter().any(|v| v.as_str() <= val.as_str()))
        }
        LdapFilter::Approx(attr, val) => {
            values(view, attr).is_some_and(|vals| vals.iter().any(|v| v.eq_ignore_ascii_case(val)))
        }
        // Extensible match and any future variants are treated as non-matching.
        _ => false,
    }
}

fn values<'a>(view: &'a BTreeMap<String, Vec<String>>, attr: &str) -> Option<&'a Vec<String>> {
    view.get(&attr.to_ascii_lowercase())
}

/// Ordered substring match: `initial` prefix, each `any` fragment in order, then
/// the `final_` suffix (all case-insensitive).
fn substring_matches(value: &str, sub: &LdapSubstringFilter) -> bool {
    let hay = value.to_ascii_lowercase();
    let mut cursor = 0usize;
    if let Some(initial) = &sub.initial {
        let needle = initial.to_ascii_lowercase();
        if !hay[cursor..].starts_with(&needle) {
            return false;
        }
        cursor += needle.len();
    }
    for any in &sub.any {
        let needle = any.to_ascii_lowercase();
        match hay[cursor..].find(&needle) {
            Some(pos) => cursor += pos + needle.len(),
            None => return false,
        }
    }
    if let Some(fin) = &sub.final_ {
        let needle = fin.to_ascii_lowercase();
        if !hay[cursor..].ends_with(&needle) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn entry(dn: &str, classes: &[&str], attrs: &[(&str, &[&str])]) -> DirectoryEntry {
        let mut attributes = BTreeMap::new();
        for (k, vs) in attrs {
            attributes.insert(
                (*k).to_string(),
                vs.iter().map(|s| (*s).to_string()).collect(),
            );
        }
        DirectoryEntry {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "t".into(),
            dn: dn.into(),
            rdn: dn.split(',').next().unwrap_or("").into(),
            parent_dn: None,
            object_classes: classes.iter().map(|s| (*s).to_string()).collect(),
            structural_class: classes.last().copied().unwrap_or("top").into(),
            attributes,
            has_children: false,
        }
    }

    fn sub(initial: Option<&str>, any: &[&str], fin: Option<&str>) -> LdapFilter {
        LdapFilter::Substring(
            "cn".into(),
            LdapSubstringFilter {
                initial: initial.map(String::from),
                any: any.iter().map(|s| (*s).to_string()).collect(),
                final_: fin.map(String::from),
            },
        )
    }

    #[test]
    fn equality_and_present_are_case_insensitive() {
        let e = entry(
            "uid=alice,dc=x",
            &["top", "inetOrgPerson"],
            &[("uid", &["alice"])],
        );
        let v = attribute_view(&e);
        assert!(matches(
            &LdapFilter::Equality("UID".into(), "Alice".into()),
            &v
        ));
        assert!(matches(
            &LdapFilter::Equality("objectClass".into(), "inetorgperson".into()),
            &v
        ));
        assert!(matches(&LdapFilter::Present("uid".into()), &v));
        assert!(!matches(&LdapFilter::Present("mail".into()), &v));
        assert!(!matches(
            &LdapFilter::Equality("uid".into(), "bob".into()),
            &v
        ));
    }

    #[test]
    fn and_or_not_compose() {
        let e = entry(
            "uid=alice,dc=x",
            &["top", "person"],
            &[("uid", &["alice"]), ("sn", &["a"])],
        );
        let v = attribute_view(&e);
        let f = LdapFilter::And(vec![
            LdapFilter::Present("uid".into()),
            LdapFilter::Not(Box::new(LdapFilter::Present("mail".into()))),
        ]);
        assert!(matches(&f, &v));
        let f = LdapFilter::Or(vec![
            LdapFilter::Equality("uid".into(), "nope".into()),
            LdapFilter::Equality("sn".into(), "a".into()),
        ]);
        assert!(matches(&f, &v));
        // Empty AND matches everything; empty OR matches nothing.
        assert!(matches(&LdapFilter::And(vec![]), &v));
        assert!(!matches(&LdapFilter::Or(vec![]), &v));
    }

    #[test]
    fn substring_initial_any_final() {
        let e = entry("cn=Alice Smith,dc=x", &["top"], &[("cn", &["Alice Smith"])]);
        let v = attribute_view(&e);
        assert!(matches(&sub(Some("ali"), &[], None), &v));
        assert!(matches(&sub(None, &["ce sm"], None), &v));
        assert!(matches(&sub(Some("ali"), &["e"], Some("smith")), &v));
        assert!(!matches(&sub(Some("bob"), &[], None), &v));
        assert!(!matches(&sub(None, &[], Some("jones")), &v));
    }
}
