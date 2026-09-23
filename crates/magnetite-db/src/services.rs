//! Embedded protocol-server harness (09b §-1 / Phase E0).
//!
//! Magnetite is a monolith that will run each domain's protocol server
//! **in-process** (authoritative DNS, DHCP, LDAP, mail, proxy, the SSO IdP, …),
//! porting the old `service-integration/*-project` implementations onto the
//! single shared DB — rather than driving external daemons (bind/kea/…).
//!
//! This module is the daemon-agnostic seam: an [`EmbeddedService`] trait and a
//! [`ServiceRegistry`]. Phase E0 ships the harness with **no services
//! registered**, so every domain reports [`ServiceHealth::Disabled`] and
//! behaviour is unchanged. Real servers are added one domain at a time
//! (Phase E1+ starts with DNS).

use crate::store::Db;
use magnetite_core::domain::DomainKey;
use magnetite_core::models::common::HealthState;
use std::sync::Arc;
use tokio::sync::watch;

/// Operational state of an embedded service. `Disabled` means no server is
/// registered for that domain (Magnetite is not serving that protocol).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceHealth {
    Healthy,
    Warning,
    Error,
    Unknown,
    Disabled,
}

impl ServiceHealth {
    /// Project onto the cross-cutting [`HealthState`] used by DomainStatus.
    /// `Disabled` maps to `Unknown` (nothing is being served, so health is
    /// simply not applicable/known).
    pub fn as_health_state(self) -> HealthState {
        match self {
            ServiceHealth::Healthy => HealthState::Healthy,
            ServiceHealth::Warning => HealthState::Warning,
            ServiceHealth::Error => HealthState::Error,
            ServiceHealth::Unknown | ServiceHealth::Disabled => HealthState::Unknown,
        }
    }

    /// Stable lowercase string used by the dashboard card. `Disabled` is kept
    /// distinct from `Unknown` so the UI can show "not configured" (no protocol
    /// server for that domain) rather than an ambiguous "unknown".
    pub fn as_str(self) -> &'static str {
        match self {
            ServiceHealth::Disabled => "disabled",
            _ => match self.as_health_state() {
                HealthState::Healthy => "healthy",
                HealthState::Warning => "warning",
                HealthState::Error => "error",
                HealthState::Unknown => "unknown",
            },
        }
    }
}

/// A domain's protocol server, run in-process by `magnetite-server`.
///
/// `start` is synchronous and returns immediately: an implementation spawns its
/// own background task(s) (à la `spawn_session_cleanup`) that run until
/// `shutdown` flips to `true`. `health` reads the service's own live state.
pub trait EmbeddedService: Send + Sync {
    /// Which domain this service serves.
    fn domain(&self) -> DomainKey;

    /// Current operational state (cheap, non-blocking).
    fn health(&self) -> ServiceHealth;

    /// Spawn the server's background task(s). Runs until `shutdown` is `true`.
    fn start(&self, db: Db, shutdown: watch::Receiver<bool>);

    /// Called after a committed config change for this domain, so the service
    /// can refresh its in-memory view (default: no-op — services that read the
    /// DB live need nothing here).
    fn notify_config_changed(&self) {}
}

/// The set of embedded services, shared (cheaply cloneable) into `AppState` so
/// server functions can read health, and into `magnetite-server` to start them.
#[derive(Clone, Default)]
pub struct ServiceRegistry {
    services: Arc<Vec<Arc<dyn EmbeddedService>>>,
}

impl ServiceRegistry {
    /// Build a registry from the given services.
    pub fn new(services: Vec<Arc<dyn EmbeddedService>>) -> Self {
        Self {
            services: Arc::new(services),
        }
    }

    /// An empty registry (Phase E0 default — no protocol servers yet).
    pub fn empty() -> Self {
        Self::default()
    }

    fn get(&self, domain: DomainKey) -> Option<&Arc<dyn EmbeddedService>> {
        self.services.iter().find(|s| s.domain() == domain)
    }

    /// Health of the service for `domain`, or `Disabled` if none is registered.
    pub fn health(&self, domain: DomainKey) -> ServiceHealth {
        self.get(domain)
            .map(|s| s.health())
            .unwrap_or(ServiceHealth::Disabled)
    }

    /// Whether a server is registered (and thus served) for `domain`.
    pub fn is_serving(&self, domain: DomainKey) -> bool {
        self.get(domain).is_some()
    }

    /// Live health of every *registered* service (domains with no server are
    /// omitted — they are simply not served). Backs the `/readyz` and `/metrics`
    /// endpoints, which report on what this node actually serves.
    pub fn statuses(&self) -> Vec<(DomainKey, ServiceHealth)> {
        self.services
            .iter()
            .map(|s| (s.domain(), s.health()))
            .collect()
    }

    /// Start every registered service's background task(s).
    pub fn start_all(&self, db: &Db, shutdown: &watch::Receiver<bool>) {
        for service in self.services.iter() {
            service.start(db.clone(), shutdown.clone());
        }
    }

    /// Notify the service for `domain` that its config changed (no-op if none).
    pub fn notify(&self, domain: DomainKey) {
        if let Some(service) = self.get(domain) {
            service.notify_config_changed();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeDns {
        healthy: bool,
    }
    impl EmbeddedService for FakeDns {
        fn domain(&self) -> DomainKey {
            DomainKey::Dns
        }
        fn health(&self) -> ServiceHealth {
            if self.healthy {
                ServiceHealth::Healthy
            } else {
                ServiceHealth::Error
            }
        }
        fn start(&self, _db: Db, _shutdown: watch::Receiver<bool>) {}
    }

    #[test]
    fn empty_registry_reports_disabled() {
        let reg = ServiceRegistry::empty();
        assert_eq!(reg.health(DomainKey::Dns), ServiceHealth::Disabled);
        assert!(!reg.is_serving(DomainKey::Dns));
        // Disabled is surfaced distinctly ("not configured"), not as "unknown".
        assert_eq!(reg.health(DomainKey::Dns).as_str(), "disabled");
        // It still projects to the Unknown health *state* for coloring.
        assert_eq!(
            reg.health(DomainKey::Dns).as_health_state(),
            HealthState::Unknown
        );
    }

    #[test]
    fn registered_service_reports_its_health() {
        let reg = ServiceRegistry::new(vec![Arc::new(FakeDns { healthy: true })]);
        assert!(reg.is_serving(DomainKey::Dns));
        assert_eq!(reg.health(DomainKey::Dns), ServiceHealth::Healthy);
        assert_eq!(reg.health(DomainKey::Dns).as_str(), "healthy");
        // A domain with no service stays disabled.
        assert_eq!(reg.health(DomainKey::Dhcp), ServiceHealth::Disabled);
    }
}
