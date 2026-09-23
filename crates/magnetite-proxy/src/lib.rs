//! `magnetite-proxy` — the in-process HTTP reverse proxy (09b §-1, Phase E3).
//!
//! Ported from the old `service-integration` proxy-project onto the shared
//! magnetite-db. Built on `hyper` for the HTTP codec; Magnetite owns routing and
//! access control. Exposed as a [`ProxyService`] implementing
//! `magnetite_db::EmbeddedService`.

mod acme;
mod forward;
pub mod router;
pub mod service;
pub mod tls;

pub use service::ProxyService;
