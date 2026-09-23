//! FSMO single-master roles and RID-pool mastering.
//!
//! To be a *standalone* domain authority (not merely a replica that requests roles from
//! Samba), magnetite must MODEL who owns each of the five Flexible Single Master
//! Operations roles and, for the RID Master, actually hand out RID pools to the DCs in
//! the domain. This module is that server-side model:
//!
//! * [`FsmoOwnership`] tracks the owner (by DSA id) of each [`FsmoRole`], with graceful
//!   transfer and (ungraceful) seizure.
//! * [`RidAllocator`] is the RID Master's allocation state -- a global watermark plus a
//!   record of the pools handed to each DC. It replaces static `NODE_INDEX` coordination:
//!   a DC requests a pool and the master hands it the next free range, advancing the
//!   watermark, so ranges never overlap without operators hand-assigning indices.

use std::collections::BTreeMap;

/// The five Active Directory FSMO roles: two forest-wide, three per-domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FsmoRole {
    /// Forest-wide: owns schema changes.
    SchemaMaster,
    /// Forest-wide: owns adding/removing naming contexts (domains).
    DomainNamingMaster,
    /// Per-domain: allocates RID pools to DCs.
    RidMaster,
    /// Per-domain: password changes, time source, GPO edits.
    PdcEmulator,
    /// Per-domain: maintains cross-domain object references.
    InfrastructureMaster,
}

impl FsmoRole {
    /// All five roles, in a stable order.
    pub fn all() -> [FsmoRole; 5] {
        [
            FsmoRole::SchemaMaster,
            FsmoRole::DomainNamingMaster,
            FsmoRole::RidMaster,
            FsmoRole::PdcEmulator,
            FsmoRole::InfrastructureMaster,
        ]
    }

    /// Whether this role is forest-wide (Schema, Domain Naming) rather than per-domain.
    pub fn is_forest_wide(&self) -> bool {
        matches!(self, FsmoRole::SchemaMaster | FsmoRole::DomainNamingMaster)
    }

    /// A short stable label for logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            FsmoRole::SchemaMaster => "schema-master",
            FsmoRole::DomainNamingMaster => "domain-naming-master",
            FsmoRole::RidMaster => "rid-master",
            FsmoRole::PdcEmulator => "pdc-emulator",
            FsmoRole::InfrastructureMaster => "infrastructure-master",
        }
    }

    /// Parse a short operator key (case-insensitive) into a role: `schema`, `naming`
    /// (or `domain-naming`), `rid`, `pdc`, `infra` (or `infrastructure`). `None` for
    /// an unknown key.
    pub fn from_key(key: &str) -> Option<FsmoRole> {
        match key.trim().to_ascii_lowercase().as_str() {
            "schema" | "schema-master" => Some(FsmoRole::SchemaMaster),
            "naming" | "domain-naming" | "domain-naming-master" => {
                Some(FsmoRole::DomainNamingMaster)
            }
            "rid" | "rid-master" => Some(FsmoRole::RidMaster),
            "pdc" | "pdc-emulator" => Some(FsmoRole::PdcEmulator),
            "infra" | "infrastructure" | "infrastructure-master" => {
                Some(FsmoRole::InfrastructureMaster)
            }
            _ => None,
        }
    }
}

/// Who owns each FSMO role, keyed by DSA id. A standalone magnetite domain elects one
/// holder per role; a freshly promoted single-node domain holds them all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FsmoOwnership {
    owners: BTreeMap<FsmoRole, String>,
}

impl FsmoOwnership {
    /// A single-node domain where `dsa` holds every role (the state right after the
    /// first DC is promoted).
    pub fn all_held_by(dsa: &str) -> Self {
        let owners = FsmoRole::all()
            .into_iter()
            .map(|r| (r, dsa.to_string()))
            .collect();
        Self { owners }
    }

    /// The current owner of `role`, if assigned.
    pub fn owner(&self, role: FsmoRole) -> Option<&str> {
        self.owners.get(&role).map(String::as_str)
    }

    /// Whether `dsa` holds `role`.
    pub fn is_owner(&self, role: FsmoRole, dsa: &str) -> bool {
        self.owner(role) == Some(dsa)
    }

    /// Gracefully transfer `role` to `dsa` (the current holder agreed to hand it over).
    pub fn transfer(&mut self, role: FsmoRole, dsa: &str) {
        self.owners.insert(role, dsa.to_string());
    }

    /// Seize `role` for `dsa` (the previous holder is gone / unreachable). Behaves like
    /// [`transfer`](Self::transfer) but named for the operator intent and audit trail.
    pub fn seize(&mut self, role: FsmoRole, dsa: &str) {
        self.owners.insert(role, dsa.to_string());
    }

    /// The roles currently held by `dsa`.
    pub fn roles_held_by(&self, dsa: &str) -> Vec<FsmoRole> {
        self.owners
            .iter()
            .filter(|(_, owner)| owner.as_str() == dsa)
            .map(|(role, _)| *role)
            .collect()
    }
}

/// The default number of RIDs in a pool handed to a DC -- matches AD's default.
pub const DEFAULT_RID_POOL_SIZE: u32 = 500;

/// A contiguous RID range `[base, base + count)` allocated to one DC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RidPool {
    /// The first RID in the pool.
    pub base: u32,
    /// The number of RIDs in the pool.
    pub count: u32,
}

impl RidPool {
    /// One past the last RID in the pool.
    pub fn end(&self) -> u32 {
        self.base.saturating_add(self.count)
    }

    /// Whether `rid` falls within this pool.
    pub fn contains(&self, rid: u32) -> bool {
        rid >= self.base && rid < self.end()
    }
}

/// The RID Master's allocation state: a global watermark (the low part of AD's
/// `rIDAvailablePool`) plus a record of the pools handed to each DC. Handing out the
/// next free range on request keeps every DC's RIDs disjoint without operators
/// hand-assigning `NODE_INDEX` values.
#[derive(Debug, Clone)]
pub struct RidAllocator {
    next_available: u32,
    pool_size: u32,
    assignments: BTreeMap<String, Vec<RidPool>>,
}

impl RidAllocator {
    /// A fresh allocator whose first pool starts at `first`, using the default pool size.
    pub fn new(first: u32) -> Self {
        Self::with_pool_size(first, DEFAULT_RID_POOL_SIZE)
    }

    /// A fresh allocator with an explicit `pool_size`.
    pub fn with_pool_size(first: u32, pool_size: u32) -> Self {
        Self {
            next_available: first,
            pool_size: pool_size.max(1),
            assignments: BTreeMap::new(),
        }
    }

    /// The next RID the master would hand out (the watermark).
    pub fn next_available(&self) -> u32 {
        self.next_available
    }

    /// Allocate the next free pool to `dsa`, advancing the watermark. Each call yields a
    /// fresh, disjoint range (a DC calls again only once it has consumed its pool).
    pub fn allocate(&mut self, dsa: &str) -> RidPool {
        let pool = RidPool {
            base: self.next_available,
            count: self.pool_size,
        };
        self.next_available = self.next_available.saturating_add(self.pool_size);
        self.assignments
            .entry(dsa.to_string())
            .or_default()
            .push(pool);
        pool
    }

    /// The pools handed to `dsa` so far.
    pub fn pools_for(&self, dsa: &str) -> &[RidPool] {
        self.assignments.get(dsa).map(Vec::as_slice).unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_split_forest_wide_and_domain() {
        assert_eq!(FsmoRole::all().len(), 5);
        assert!(FsmoRole::SchemaMaster.is_forest_wide());
        assert!(FsmoRole::DomainNamingMaster.is_forest_wide());
        assert!(!FsmoRole::RidMaster.is_forest_wide());
        assert!(!FsmoRole::PdcEmulator.is_forest_wide());
        assert!(!FsmoRole::InfrastructureMaster.is_forest_wide());
    }

    #[test]
    fn a_new_domain_holds_every_role_on_one_node() {
        let o = FsmoOwnership::all_held_by("dc1");
        for r in FsmoRole::all() {
            assert!(o.is_owner(r, "dc1"));
        }
        assert_eq!(o.roles_held_by("dc1").len(), 5);
        assert!(o.roles_held_by("dc2").is_empty());
    }

    #[test]
    fn transfer_and_seize_move_a_role() {
        let mut o = FsmoOwnership::all_held_by("dc1");
        o.transfer(FsmoRole::PdcEmulator, "dc2");
        assert!(o.is_owner(FsmoRole::PdcEmulator, "dc2"));
        assert!(!o.is_owner(FsmoRole::PdcEmulator, "dc1"));
        // dc1 keeps the roles it did not transfer.
        assert!(o.is_owner(FsmoRole::RidMaster, "dc1"));
        // Seizure (dc1 gone) reassigns the RID master to dc2.
        o.seize(FsmoRole::RidMaster, "dc2");
        assert_eq!(o.owner(FsmoRole::RidMaster), Some("dc2"));
    }

    #[test]
    fn the_rid_master_hands_out_disjoint_growing_pools() {
        let mut m = RidAllocator::new(1000);
        assert_eq!(m.next_available(), 1000);
        let a1 = m.allocate("dc1");
        let b1 = m.allocate("dc2");
        let a2 = m.allocate("dc1");
        assert_eq!(
            a1,
            RidPool {
                base: 1000,
                count: 500
            }
        );
        assert_eq!(
            b1,
            RidPool {
                base: 1500,
                count: 500
            }
        );
        assert_eq!(
            a2,
            RidPool {
                base: 2000,
                count: 500
            }
        );
        assert_eq!(m.next_available(), 2500);
        // No two pools overlap.
        assert!(!a1.contains(b1.base));
        assert!(a1.contains(1000) && a1.contains(1499) && !a1.contains(1500));
        // Each DC's pools are recorded.
        assert_eq!(m.pools_for("dc1"), &[a1, a2]);
        assert_eq!(m.pools_for("dc2"), &[b1]);
        assert!(m.pools_for("dc3").is_empty());
    }

    #[test]
    fn role_keys_parse_case_insensitively() {
        assert_eq!(FsmoRole::from_key("rid"), Some(FsmoRole::RidMaster));
        assert_eq!(FsmoRole::from_key(" PDC "), Some(FsmoRole::PdcEmulator));
        assert_eq!(
            FsmoRole::from_key("infra"),
            Some(FsmoRole::InfrastructureMaster)
        );
        assert_eq!(
            FsmoRole::from_key("domain-naming"),
            Some(FsmoRole::DomainNamingMaster)
        );
        assert_eq!(
            FsmoRole::from_key("schema-master"),
            Some(FsmoRole::SchemaMaster)
        );
        assert_eq!(FsmoRole::from_key("bogus"), None);
    }

    #[test]
    fn pool_size_is_configurable() {
        let mut m = RidAllocator::with_pool_size(1000, 100);
        assert_eq!(
            m.allocate("dc1"),
            RidPool {
                base: 1000,
                count: 100
            }
        );
        assert_eq!(
            m.allocate("dc1"),
            RidPool {
                base: 1100,
                count: 100
            }
        );
    }
}
