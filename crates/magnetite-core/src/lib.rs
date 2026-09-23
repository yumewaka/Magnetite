//! `magnetite-core` — the domain-independent foundation shared by the server
//! and the WASM UI: configuration, shared data models, the authorization
//! engine, password policy, error taxonomy and i18n.
//!
//! Everything here must compile to `wasm32` (it is linked into the hydrate
//! bundle), so this crate stays free of tokio, the database and other
//! server-only dependencies.

// The domain enums deliberately expose an inherent `from_str(&str)` that parses a
// stored/DB string, returning `Option<Self>` (unknown → None) or `Self` (unknown →
// a documented default) rather than the `FromStr` trait's fallible `Result`. That
// convention is used pervasively across the DB, server and UI layers; the infallible
// `-> Self` variants cannot be `FromStr` at all. Opting out of this one stylistic
// lint keeps the convention consistent instead of renaming 40+ call sites.
#![allow(clippy::should_implement_trait)]

pub mod authz;
pub mod config;
pub mod domain;
pub mod domains;
pub mod error;
pub mod i18n;
pub mod models;
pub mod password;

pub use authz::{ActionClass, Decision, Role};
pub use config::{AppConfig, DomainConfig, DomainServerConfig, LdapConsumerConfig, RelayConfig};
pub use domain::DomainKey;
pub use error::{CoreError, CoreResult};
