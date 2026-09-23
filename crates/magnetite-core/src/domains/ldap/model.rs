//! LDAP (directory) domain data (07_data_ldap). The DIT is stored as generic
//! [`DirectoryEntry`] nodes; users/groups/OUs are typed projections over an
//! entry's `structural_class` and attributes.
//!
//! These directory users/groups are *managed data*, deliberately separate from
//! Magnetite's login identities (`LocalAccount`/`Session`).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Structural object classes used by the typed projections.
pub const OC_USER: &str = "inetOrgPerson";
pub const OC_GROUP: &str = "groupOfNames";
pub const OC_OU: &str = "organizationalUnit";
pub const OC_DOMAIN: &str = "domain";
/// The `container` class for AD well-known containers (CN=Users/Computers/System).
pub const OC_CONTAINER: &str = "container";

/// Attribute name that stores the (hashed) password. Never returned to clients.
pub const ATTR_PASSWORD: &str = "userPassword";

/// Consumer-side syncrepl status (RFC 4533), projection-safe (no credentials),
/// for the management UI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LdapSyncState {
    /// The opaque sync cookie last received from the provider.
    pub cookie: String,
    #[serde(default)]
    pub last_sync: Option<DateTime<Utc>>,
    pub applied: u64,
    pub deleted: u64,
    #[serde(default)]
    pub last_error: Option<String>,
}

/// A generic DIT node (07_data_ldap §2.1). Parent/child is expressed through
/// the DN hierarchy (`parent_dn`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryEntry {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    /// Distinguished name — globally unique, RFC 4514 form.
    pub dn: String,
    /// Relative DN (leftmost DN component).
    pub rdn: String,
    /// Parent DN; `None` only for the root (base DN).
    pub parent_dn: Option<String>,
    pub object_classes: Vec<String>,
    pub structural_class: String,
    /// Attribute name → values (multi-valued).
    pub attributes: BTreeMap<String, Vec<String>>,
    /// Whether the entry has children (tree display / delete guard).
    pub has_children: bool,
}

impl DirectoryEntry {
    /// First value of an attribute, if present.
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attributes
            .get(name)
            .and_then(|v| v.first())
            .map(|s| s.as_str())
    }

    /// All values of an attribute.
    pub fn attrs(&self, name: &str) -> &[String] {
        self.attributes
            .get(name)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Remove sensitive attributes for client-facing responses.
    pub fn redacted(mut self) -> Self {
        self.attributes.remove(ATTR_PASSWORD);
        self
    }
}

/// User projection (07_data_ldap §2.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapUser {
    pub dn: String,
    pub uid: String,
    pub cn: String,
    pub sn: String,
    #[serde(default)]
    pub mail: Option<String>,
    pub enabled: bool,
}

/// Group projection (07_data_ldap §2.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapGroup {
    pub dn: String,
    pub cn: String,
    #[serde(default)]
    pub description: Option<String>,
    pub members: Vec<String>,
}

/// OU projection (07_data_ldap §2.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapOu {
    pub dn: String,
    pub ou: String,
    #[serde(default)]
    pub description: Option<String>,
    pub has_children: bool,
}

/// A tree node for lazy DIT navigation (S-LDAP-02).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeNode {
    pub dn: String,
    pub rdn: String,
    pub structural_class: String,
    pub has_children: bool,
}

impl From<&DirectoryEntry> for TreeNode {
    fn from(e: &DirectoryEntry) -> Self {
        Self {
            dn: e.dn.clone(),
            rdn: e.rdn.clone(),
            structural_class: e.structural_class.clone(),
            has_children: e.has_children,
        }
    }
}

/// An LDAP access-control rule (S-LDAP-07). Rules are evaluated in `priority`
/// order; the first rule whose `target_dn`, `operations` and `subject` match the
/// request decides the outcome. When no rule is configured at all the directory
/// is fully open (backward-compatible); once any rule exists, a request that
/// matches no rule is denied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapAclRule {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    /// Lower priority is evaluated first.
    pub priority: u32,
    /// DN or subtree this rule applies to; `*` matches everything, otherwise a
    /// request DN matches when it equals `target_dn` or is beneath it.
    pub target_dn: String,
    pub operations: Vec<LdapAclOperation>,
    pub subject: LdapAclSubject,
    pub effect: LdapAclEffect,
    pub enabled: bool,
}

/// LDAP operations that can be access-controlled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LdapAclOperation {
    Search,
    Read,
    Add,
    Modify,
    Delete,
    ModifyDn,
    Compare,
}

/// Who an [`LdapAclRule`] applies to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LdapAclSubject {
    /// Anyone (authenticated or not).
    Anyone,
    /// Unauthenticated (anonymous) sessions.
    Anonymous,
    /// Any authenticated (bound) session.
    Authenticated,
    /// A specific bound DN.
    Dn(String),
    /// Members of a specific group DN.
    GroupMember(String),
}

/// Allow or deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LdapAclEffect {
    Allow,
    Deny,
}
