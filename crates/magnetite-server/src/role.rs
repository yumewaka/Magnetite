//! Runtime replication-role control for the config-replication domains
//! (mail / dhcp / proxy / sso).
//!
//! A node configured as a *secondary* for one of these domains runs a pull loop that
//! keeps replacing its local config with the primary's snapshot. Its role is otherwise
//! fixed at startup by `[domains.<d>.server.replication]`. This controller lets the
//! management plane flip that role at runtime, without a restart:
//!
//! - **promote** pauses the pull loop, so the node stops overwriting its own config and
//!   its last-synced config becomes authoritative — it now acts as the primary.
//! - **demote** resumes pulling, returning the node to a tracking secondary.
//!
//! Only a domain that was configured as a secondary (and therefore has a running pull
//! loop) can be flipped; promoting a standalone/primary domain is a no-op the API rejects.

use magnetite_core::domain::DomainKey;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// A shared, cheaply-cloneable handle to every managed domain's pull flag.
#[derive(Clone, Default)]
pub struct RoleController {
    /// Per-domain "keep pulling" flag. Present only for domains configured as a
    /// secondary; each flag is also captured by that domain's pull loop.
    flags: Arc<Mutex<HashMap<DomainKey, Arc<AtomicBool>>>>,
}

impl RoleController {
    pub fn new() -> Self {
        Self::default()
    }

    /// Lock the flag map, tolerating a poisoned mutex (the map is tiny and only ever holds
    /// atomics, so a panic elsewhere never leaves it in a torn state).
    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<DomainKey, Arc<AtomicBool>>> {
        self.flags.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Register `key` as a runtime-flippable secondary and return its pull flag (initially
    /// `true` = pulling). The pull loop for that domain should capture the returned flag
    /// and skip its pull whenever it reads `false`.
    pub fn register_secondary(&self, key: DomainKey) -> Arc<AtomicBool> {
        let flag = Arc::new(AtomicBool::new(true));
        self.map().insert(key, flag.clone());
        flag
    }

    /// Promote `key` to primary (pause its pull loop). Returns `false` if the domain is not
    /// a managed secondary.
    pub fn promote(&self, key: DomainKey) -> bool {
        self.set_pulling(key, false)
    }

    /// Demote `key` back to a tracking secondary (resume its pull loop). Returns `false` if
    /// the domain is not a managed secondary.
    pub fn demote(&self, key: DomainKey) -> bool {
        self.set_pulling(key, true)
    }

    fn set_pulling(&self, key: DomainKey, pulling: bool) -> bool {
        match self.map().get(&key) {
            Some(flag) => {
                flag.store(pulling, Ordering::SeqCst);
                true
            }
            None => false,
        }
    }

    /// The runtime pull state of `key`: `Some(true)` = actively pulling (secondary),
    /// `Some(false)` = promoted (acting as primary), `None` = not a managed secondary.
    pub fn is_pulling(&self, key: DomainKey) -> Option<bool> {
        self.map().get(&key).map(|f| f.load(Ordering::SeqCst))
    }

    /// Every managed domain and whether it is currently pulling. Used to report runtime
    /// role and to flip all managed domains at once (whole-node failover).
    pub fn managed(&self) -> Vec<(DomainKey, bool)> {
        self.map()
            .iter()
            .map(|(k, f)| (*k, f.load(Ordering::SeqCst)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn promote_and_demote_flip_only_registered_secondaries() {
        let rc = RoleController::new();
        let flag = rc.register_secondary(DomainKey::Proxy);
        assert!(flag.load(Ordering::SeqCst)); // starts pulling
        assert_eq!(rc.is_pulling(DomainKey::Proxy), Some(true));

        assert!(rc.promote(DomainKey::Proxy));
        assert!(!flag.load(Ordering::SeqCst)); // pull loop will now skip
        assert_eq!(rc.is_pulling(DomainKey::Proxy), Some(false));

        assert!(rc.demote(DomainKey::Proxy));
        assert!(flag.load(Ordering::SeqCst));

        // An unregistered domain cannot be flipped and reports no runtime role.
        assert!(!rc.promote(DomainKey::Sso));
        assert_eq!(rc.is_pulling(DomainKey::Sso), None);

        assert_eq!(rc.managed(), vec![(DomainKey::Proxy, true)]);
    }
}
