//! Address allocation for the embedded DHCPv4 server (E2 / 08_dhcp_logic §3).
//!
//! [`allocate_ip`] is a **pure** function over a pool, its reservations and the
//! current leases, so the assignment policy is unit-testable without sockets or
//! a DB. Policy order: static reservation for the MAC → the client's existing
//! lease → the client's requested IP (if free) → the first free address in the
//! range.

use magnetite_core::domains::dhcp::model::{Lease, LeaseState, Pool, Reservation};
use magnetite_core::domains::dhcp::validate::normalize_mac;
use std::collections::HashSet;
use std::net::Ipv4Addr;

fn mac_eq(a: &str, b: &str) -> bool {
    match (normalize_mac(a), normalize_mac(b)) {
        (Some(x), Some(y)) => x == y,
        _ => a.eq_ignore_ascii_case(b),
    }
}

/// This DHCP server's disjoint slice of a pool range, so **independent** servers never
/// offer the same address without any inter-server coordination (split-scope, the DHCP
/// analog of the AD per-node RID range). Node `index` of `count` allocates NEW addresses
/// only from the `index`-th contiguous slice of the pool range; the last node absorbs any
/// remainder. Reservations, a client's existing lease, and an explicitly requested IP are
/// still honoured across the WHOLE range (a client keeps its address whichever server it
/// renews against), so only fresh allocation is partitioned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolPartition {
    /// This node's index (0-based).
    pub index: u32,
    /// The number of independent DHCP servers sharing the pool.
    pub count: u32,
}

impl PoolPartition {
    /// The `[node_start, node_end]` sub-range of `[start, end]` this node allocates fresh
    /// addresses from. A degenerate partition (count ≤ 1, index out of range, or a slice
    /// that would be empty) falls back to the whole range.
    fn slice(self, start: u32, end: u32) -> (u32, u32) {
        if self.count <= 1 || self.index >= self.count || start > end {
            return (start, end);
        }
        let total = u64::from(end - start) + 1;
        let size = total / u64::from(self.count);
        if size == 0 {
            return (start, end); // fewer addresses than nodes — don't partition
        }
        let node_start = start + u32::try_from(u64::from(self.index) * size).unwrap_or(0);
        let node_end = if self.index == self.count - 1 {
            end
        } else {
            node_start + u32::try_from(size).unwrap_or(0) - 1
        };
        (node_start, node_end)
    }
}

fn in_range(ip: u32, start: u32, end: u32) -> bool {
    ip >= start && ip <= end
}

/// Whether a lease currently holds an address (active or offered).
fn holds_address(lease: &Lease) -> bool {
    matches!(lease.state, LeaseState::Active | LeaseState::Offered)
}

/// Choose an IPv4 address for `mac` from `pool`, honouring `reservations` and
/// the current `leases`. `requested` is the client's Option-50 preference.
/// Returns `None` if the pool has no usable v4 range or is exhausted.
pub fn allocate_ip(
    pool: &Pool,
    reservations: &[Reservation],
    leases: &[Lease],
    mac: &str,
    requested: Option<Ipv4Addr>,
    partition: Option<PoolPartition>,
) -> Option<Ipv4Addr> {
    // 1. A static reservation for this MAC always wins.
    if let Some(res) = reservations.iter().find(|r| mac_eq(&r.mac_address, mac)) {
        if let Ok(ip) = res.ip_address.parse::<Ipv4Addr>() {
            return Some(ip);
        }
    }

    let start: u32 = pool
        .range_start_v4
        .as_ref()?
        .parse::<Ipv4Addr>()
        .ok()?
        .into();
    let end: u32 = pool.range_end_v4.as_ref()?.parse::<Ipv4Addr>().ok()?.into();
    if start > end {
        return None;
    }

    // Addresses we must not hand out to a different client.
    let reserved: HashSet<u32> = reservations
        .iter()
        .filter_map(|r| r.ip_address.parse::<Ipv4Addr>().ok())
        .map(u32::from)
        .collect();
    let held_by_other: HashSet<u32> = leases
        .iter()
        .filter(|l| holds_address(l))
        .filter(|l| {
            l.mac_address
                .as_deref()
                .map(|m| !mac_eq(m, mac))
                .unwrap_or(true)
        })
        .filter_map(|l| l.ip_address.parse::<Ipv4Addr>().ok())
        .map(u32::from)
        .collect();

    // 2. Reuse this client's current lease if it is still in range and free.
    if let Some(lease) = leases.iter().filter(|l| holds_address(l)).find(|l| {
        l.mac_address
            .as_deref()
            .map(|m| mac_eq(m, mac))
            .unwrap_or(false)
    }) {
        if let Ok(ip) = lease.ip_address.parse::<Ipv4Addr>() {
            let n = u32::from(ip);
            if in_range(n, start, end) && !reserved.contains(&n) {
                return Some(ip);
            }
        }
    }

    // 3. Honour the requested IP when it is in range and free.
    if let Some(req) = requested {
        let n = u32::from(req);
        if in_range(n, start, end) && !reserved.contains(&n) && !held_by_other.contains(&n) {
            return Some(req);
        }
    }

    // 4. First free address in THIS node's slice of the range (split-scope): independent
    //    servers own disjoint slices, so two of them never hand the same address to two
    //    clients. A single-node deployment (partition None / count 1) uses the whole range.
    let (alloc_start, alloc_end) = partition.map_or((start, end), |p| p.slice(start, end));
    (alloc_start..=alloc_end)
        .find(|n| !reserved.contains(n) && !held_by_other.contains(n))
        .map(Ipv4Addr::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use magnetite_core::domains::dhcp::model::ProtoVer;

    fn pool() -> Pool {
        Pool {
            id: "p1".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "t".into(),
            name: "lan".into(),
            subnet_v4: Some("192.0.2.0/24".into()),
            range_start_v4: Some("192.0.2.10".into()),
            range_end_v4: Some("192.0.2.12".into()),
            subnet_v6: None,
            range_start_v6: None,
            range_end_v6: None,
            gateway: Some("192.0.2.1".into()),
            dns_servers: vec!["192.0.2.1".into()],
            domain_name: Some("lan.example".into()),
            lease_duration_secs: Some(3600),
            enabled: true,
        }
    }

    fn reservation(mac: &str, ip: &str) -> Reservation {
        Reservation {
            id: "r".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "t".into(),
            pool_ref: "p1".into(),
            mac_address: mac.into(),
            ip_address: ip.into(),
            hostname: None,
            description: None,
        }
    }

    fn lease(ip: &str, mac: &str, state: LeaseState) -> Lease {
        Lease {
            id: "l".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "dhcp".into(),
            pool_ref: "p1".into(),
            ip_address: ip.into(),
            mac_address: Some(mac.into()),
            client_id: None,
            hostname: None,
            state,
            lease_start: Utc::now(),
            lease_expiry: Utc::now(),
            last_renewal: None,
            protocol_version: ProtoVer::V4,
        }
    }

    #[test]
    fn reservation_wins() {
        let ip = allocate_ip(
            &pool(),
            &[reservation("aa:bb:cc:dd:ee:ff", "192.0.2.50")],
            &[],
            "AA-BB-CC-DD-EE-FF",
            None,
            None,
        );
        assert_eq!(ip, Some("192.0.2.50".parse().unwrap()));
    }

    #[test]
    fn first_free_address() {
        let ip = allocate_ip(&pool(), &[], &[], "aa:bb:cc:dd:ee:01", None, None);
        assert_eq!(ip, Some("192.0.2.10".parse().unwrap()));
    }

    #[test]
    fn skips_addresses_held_by_others() {
        let leases = [
            lease("192.0.2.10", "aa:bb:cc:00:00:01", LeaseState::Active),
            lease("192.0.2.11", "aa:bb:cc:00:00:02", LeaseState::Offered),
        ];
        let ip = allocate_ip(&pool(), &[], &leases, "aa:bb:cc:00:00:09", None, None);
        assert_eq!(ip, Some("192.0.2.12".parse().unwrap()));
    }

    #[test]
    fn reuses_clients_own_lease() {
        let leases = [lease("192.0.2.11", "aa:bb:cc:00:00:09", LeaseState::Active)];
        let ip = allocate_ip(&pool(), &[], &leases, "aa:bb:cc:00:00:09", None, None);
        assert_eq!(ip, Some("192.0.2.11".parse().unwrap()));
    }

    #[test]
    fn honours_requested_when_free() {
        let ip = allocate_ip(
            &pool(),
            &[],
            &[],
            "aa:bb:cc:00:00:09",
            Some("192.0.2.12".parse().unwrap()),
            None,
        );
        assert_eq!(ip, Some("192.0.2.12".parse().unwrap()));
    }

    #[test]
    fn exhausted_pool_returns_none() {
        let leases = [
            lease("192.0.2.10", "aa:bb:cc:00:00:01", LeaseState::Active),
            lease("192.0.2.11", "aa:bb:cc:00:00:02", LeaseState::Active),
            lease("192.0.2.12", "aa:bb:cc:00:00:03", LeaseState::Active),
        ];
        let ip = allocate_ip(&pool(), &[], &leases, "aa:bb:cc:00:00:09", None, None);
        assert_eq!(ip, None);
    }

    #[test]
    fn split_scope_gives_independent_servers_disjoint_addresses() {
        // pool .10-.12 (3 addrs), 2 nodes: node 0 → [.10], node 1 → [.11,.12].
        let a = allocate_ip(
            &pool(),
            &[],
            &[],
            "aa:bb:cc:00:00:01",
            None,
            Some(PoolPartition { index: 0, count: 2 }),
        )
        .unwrap();
        let b = allocate_ip(
            &pool(),
            &[],
            &[],
            "aa:bb:cc:00:00:02",
            None,
            Some(PoolPartition { index: 1, count: 2 }),
        )
        .unwrap();
        assert_eq!(
            a,
            "192.0.2.10".parse::<Ipv4Addr>().unwrap(),
            "node 0's slice"
        );
        assert_eq!(
            b,
            "192.0.2.11".parse::<Ipv4Addr>().unwrap(),
            "node 1's slice"
        );
        assert_ne!(a, b, "independent servers never offer the same address");
    }

    #[test]
    fn split_scope_still_honours_an_existing_lease_in_another_slice() {
        // A client leased .12 (node 1's slice) renews against node 0 → keeps its address
        // (reservation/existing-lease/requested span the whole range; only fresh alloc
        // is partitioned), rather than getting a second address from node 0's slice.
        let leases = [lease("192.0.2.12", "aa:bb:cc:00:00:09", LeaseState::Active)];
        let ip = allocate_ip(
            &pool(),
            &[],
            &leases,
            "aa:bb:cc:00:00:09",
            None,
            Some(PoolPartition { index: 0, count: 2 }),
        )
        .unwrap();
        assert_eq!(ip, "192.0.2.12".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn partition_slices_are_contiguous_disjoint_and_cover_the_range() {
        let (s, e) = (0u32, 99u32);
        let mut prev_end: Option<u32> = None;
        let mut covered = 0u32;
        for i in 0..4 {
            let (ns, ne) = PoolPartition { index: i, count: 4 }.slice(s, e);
            if let Some(pe) = prev_end {
                assert_eq!(ns, pe + 1, "slice {i} is contiguous with the previous");
            }
            covered += ne - ns + 1;
            prev_end = Some(ne);
        }
        assert_eq!(
            prev_end,
            Some(99),
            "the last node reaches the end of the range"
        );
        assert_eq!(
            covered, 100,
            "every address covered exactly once (disjoint)"
        );
    }
}
