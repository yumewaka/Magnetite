//! Server functions — the SSR/browser boundary. Domain-independent auth and
//! shell functions live here; domain server functions are added per phase.

pub mod account;
pub mod addc;
pub mod alert;
pub mod audit;
pub mod auth;
pub mod backup;
pub mod dhcp;
pub mod dns;
pub mod k8s;
pub mod ldap;
pub mod logs;
pub mod mail;
pub mod proxy;
pub mod settings;
pub mod shell;
pub mod sso;
pub mod watch;
