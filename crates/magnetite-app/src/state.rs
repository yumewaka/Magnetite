//! Server-side shared state (SSR only). Provided into the Leptos/server-fn
//! request context so server functions can reach the database and config.

use magnetite_core::AppConfig;
use magnetite_db::{Db, ServiceRegistry};
use std::sync::Arc;

/// Shared application state injected into every request context.
#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub config: Arc<AppConfig>,
    /// In-process protocol servers (09b §-1 / Phase E0). Empty until domains
    /// are ported; server functions read health from here.
    pub services: ServiceRegistry,
}

impl AppState {
    pub fn new(db: Db, config: Arc<AppConfig>, services: ServiceRegistry) -> Self {
        Self {
            db,
            config,
            services,
        }
    }
}
