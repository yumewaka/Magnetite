//! `magnetite-dns` — the in-process authoritative DNS server (09b §-1, Phase E1).
//!
//! Ported from the old `service-integration` dns-server onto the shared
//! magnetite-db. Built on `hickory-proto` for the wire codec; Magnetite owns the
//! answer logic. Exposed as a [`DnsService`] implementing
//! `magnetite_db::EmbeddedService`.

pub mod cache;
pub mod ddns;
pub mod dnssec;
pub mod dynupdate;
pub mod forwarder;
pub mod geo;
pub mod gss_tsig;
mod nsec;
mod nsec3;
pub mod replication;
pub mod resolver;
pub mod service;
pub mod tkey;
pub mod wire;

pub use service::DnsService;
