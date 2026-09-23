//! `magnetite-db` — the single embedded database that is the sole source of
//! truth for the platform (09 §0). Server-only: it depends on SurrealDB/RocksDB
//! and never compiles into the WASM bundle.
//!
//! Repositories are implemented as inherent methods on [`Db`], grouped by
//! subsystem (accounts, sessions, audit). Phase 0 covers the authentication and
//! audit foundation; domain repositories are layered on later.

mod accounts;
mod ad;
mod addc_dns;
mod alerts;
mod audit;
mod backups;
mod dhcp;
mod dns;
mod error;
mod forward;
mod gpo;
mod k8s;
mod ldap;
mod logon;
mod logs;
mod mail;
mod metrics;
mod migrations;
mod proxy;
mod records;
mod replication;
mod services;
mod sessions;
mod settings;
mod sso;
mod store;
mod sysvol;
mod watch;

pub use ad::{AdGroup, AdPrincipal, IncomingLink, StoredLink};
pub use addc_dns::{dc_locator_records, DcLocatorRecord};
pub use alerts::NewAlert;
pub use error::{DbError, DbResult};
pub use ldap::{FsmoOwners, LdapAttrChange, LdapModifyOp};
pub use logs::NewLogEntry;
pub use mail::QueuedForward;
pub use metrics::{spawn_health_guarded, spawn_supervised, task_panic_count};
pub use proxy::{CertMaterial, ProxyReplFeed, ReplCertificate};
pub use replication::{ReplStamp, UtdvCursor};
pub use services::{EmbeddedService, ServiceHealth, ServiceRegistry};
pub use sso::{SsoReplFeed, StoredSigningKey};
pub use store::Db;
pub use sysvol::{SysvolFeed, SysvolFile};
