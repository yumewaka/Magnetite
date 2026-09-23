//! LDAP (directory) domain: DIT data model (07_data_ldap) and write-time
//! validation (08_ldap_logic). Pure and shared by the UI and the DB layer.

pub mod model;
pub mod validate;

pub use model::{DirectoryEntry, LdapGroup, LdapOu, LdapUser, TreeNode};
