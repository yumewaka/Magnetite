//! SSO / auth-provider management domain: data model (07_data_sso) and
//! write-time validation (screen_sso §5). Pure and shared by the UI and DB.

pub mod model;
pub mod validate;

pub use model::{OidcClient, Provider, ProviderLoginConfig, SsoSession};
