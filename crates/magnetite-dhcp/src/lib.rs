//! `magnetite-dhcp` — the in-process DHCPv4 server (09b §-1, Phase E2).
//!
//! Ported from the old `service-integration` dhcp-project onto the shared
//! magnetite-db. Built on `dhcproto` for the wire codec; Magnetite owns the
//! allocation policy. Exposed as a [`DhcpService`] implementing
//! `magnetite_db::EmbeddedService`.

pub mod alloc;
pub mod service;
pub mod wire;

pub use service::DhcpService;
