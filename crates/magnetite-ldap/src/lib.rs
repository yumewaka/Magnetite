//! `magnetite-ldap` — the embedded LDAPv3 directory server (09b §-1). Speaks
//! LDAP over TCP against the shared directory (`entry` table): simple &
//! anonymous bind, search (base/one/subtree with RFC 4511 filters), the RootDSE
//! and unbind. Exposed as a [`magnetite_db::EmbeddedService`] so
//! `magnetite-server` runs it in-process.
//!
//! Wire = `ldap3_proto` (BER/ASN.1 codec); policy (bind auth, scope + filter
//! evaluation, projection, StartTLS upgrade, ACL gating) is ours. Writes
//! (Add/Modify/Delete/ModifyDN) are authenticated + ACL-gated and enforce the AD
//! schema; adding a `computer` object registers the machine account with the KDC
//! (a domain join). Deferred: implicit LDAPS, per-entry/attribute ACL, paged
//! results, and referrals.

mod ad_dirsync;
mod ad_map;
mod ad_usn;
mod client_tls;
mod codec;
mod consumer;
pub mod dc_join;
mod filter;
pub mod gpo;
mod sasl;
mod schema;
mod seclayer;
pub mod service;
mod tls;

pub use ad_usn::{ad_usn_once, ad_usn_reconcile};
pub use consumer::spawn_consumer;
pub use gpo::seed_group_policy;
pub use service::{LdapService, MachineKeyRegistrar};
