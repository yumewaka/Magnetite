//! LDAP management screens (S-LDAP). Phase covers dashboard, tree, users,
//! groups and OUs; schema/ACL/LDIF/changelog (S-LDAP-06..09) follow next.

pub mod acl;
pub mod computers;
pub mod dashboard;
pub mod groups;
pub mod nav;
pub mod ous;
pub mod replication;
pub mod tree;
pub mod users;

pub use acl::AclPage;
pub use computers::ComputersPage;
pub use dashboard::LdapDashboard;
pub use groups::GroupsPage;
pub use ous::OusPage;
pub use replication::LdapReplicationPage;
pub use tree::TreePage;
pub use users::UsersPage;
