//! Per-domain data models and their write-time validation. Each domain's data
//! (07_data_<domain>) and rules (08_<domain>_logic §5) live here so both the
//! WASM UI and the server share one definition.

pub mod addc;
pub mod dhcp;
pub mod dns;
pub mod k8s;
pub mod ldap;
pub mod mail;
pub mod proxy;
pub mod sso;
pub mod watch;
