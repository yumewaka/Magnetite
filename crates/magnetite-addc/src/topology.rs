//! KCC-equivalent intra-site replication topology.
//!
//! A magnetite mesh replaces the static `REPL_PEERS` list with a *computed* topology:
//! given the set of domain controllers, each node derives its own inbound replication
//! partners. The topology is the classic Active Directory intra-site **ring** — the
//! live DCs are ordered by a stable id and connected in a bidirectional ring, so every
//! DC pulls from its two ring neighbours and the whole mesh stays connected with a
//! bounded number of hops. Excluding a dead DC before the ring is built closes the ring
//! around it, so a failed node is automatically routed around (self-heal) without an
//! operator editing peer lists.
//!
//! Hop-count "optimizing edges" (chords added to large rings so the diameter stays ≤ 3)
//! are a latency optimization on top of the ring and are a follow-up; a plain ring is
//! already fully connected and is what small deployments run.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use magnetite_db::Db;
use magnetite_krb5::keys::PrincipalStore;
use magnetite_rpc::Directory;
use tokio::sync::watch;

use crate::{spawn_replication_thread, ReplHealthRegistry, ReplPeerHealth, ReplicationConfig};

/// The default consecutive-failure count after which a peer is treated as dead and the
/// ring reroutes around it.
pub const DEFAULT_FAILURE_THRESHOLD: u32 = 3;

/// A domain controller known to the local topology builder: a stable ring-ordering
/// identity plus the coordinates needed to replicate *from* it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyDc {
    /// Stable ring-ordering key — the DSA GUID hex, or any stable unique id. Every node
    /// in the mesh must agree on this value for a DC, or the rings won't line up.
    pub id: String,
    /// The DC's DRSUAPI endpoint (`host:port`, `ncacn_ip_tcp`) to pull changes from.
    pub drs: SocketAddr,
    /// The KDC (`host:88`) to obtain a service ticket from.
    pub kdc: SocketAddr,
    /// The DRS service SPN to request a ticket for.
    pub spn: String,
}

/// Replication parameters shared by every partner in the mesh — combined with a
/// [`TopologyDc`] to produce a concrete [`ReplicationConfig`].
#[derive(Debug, Clone)]
pub struct ReplicationCommon {
    /// The Kerberos realm (e.g. `MAGTEST.LOCAL`).
    pub realm: String,
    /// The account to replicate as (must hold replication rights).
    pub user: String,
    /// That account's password (used when `keytab` is `None`).
    pub password: String,
    /// Optional keytab holding `user`'s Kerberos key (production: no cleartext password).
    pub keytab: Option<std::path::PathBuf>,
    /// The naming-context DN to replicate (e.g. `DC=magtest,DC=local`).
    pub nc_dn: String,
    /// How long to wait between replication cycles.
    pub interval: Duration,
}

impl TopologyDc {
    /// Derive this DC's DNS DC-locator identity `(dns_domain, dc_label, ipv4)` from its
    /// service SPN (`service/<host>.<domain>`) and DRS address — used to withdraw or
    /// re-seed its locator records as it dies / recovers. `None` if the SPN carries no
    /// host FQDN or the DRS address is not IPv4.
    pub fn locator_identity(&self) -> Option<(String, String, String)> {
        let fqdn = self.spn.split('/').nth(1)?;
        let (label, domain) = fqdn.split_once('.')?;
        if label.is_empty() || domain.is_empty() {
            return None;
        }
        let ip = match self.drs.ip() {
            std::net::IpAddr::V4(v4) => v4.to_string(),
            std::net::IpAddr::V6(_) => return None,
        };
        Some((domain.to_string(), label.to_string(), ip))
    }

    /// Build a [`ReplicationConfig`] that pulls from this DC using the shared `common`
    /// parameters.
    pub fn to_replication_config(&self, common: &ReplicationCommon) -> ReplicationConfig {
        ReplicationConfig {
            kdc: self.kdc,
            drs: self.drs,
            realm: common.realm.clone(),
            user: common.user.clone(),
            password: common.password.clone(),
            keytab: common.keytab.clone(),
            spn: self.spn.clone(),
            nc_dn: common.nc_dn.clone(),
            // A magnetite mesh peer synthesizes its own Config/Schema, so no partition
            // seeding from peers.
            extra_ncs: Vec::new(),
            interval: common.interval,
        }
    }
}

/// Compute the inbound replication partners for `self_id` from the set of `dcs`,
/// excluding any whose id is in `dead`.
///
/// The live DCs (self included) are ordered by their stable id and connected in a
/// bidirectional ring; this node's partners are its two ring neighbours (or the single
/// other node when only two are live). Dead DCs are removed *before* ordering, so the
/// ring closes around a failed node and the survivors stay fully connected.
///
/// Returns an empty vector when `self_id` is unknown or dead, or when it is the only
/// live DC (nothing to replicate from).
pub fn ring_inbound_partners<'a>(
    dcs: &'a [TopologyDc],
    self_id: &str,
    dead: &HashSet<String>,
) -> Vec<&'a TopologyDc> {
    let mut live: Vec<&TopologyDc> = dcs.iter().filter(|d| !dead.contains(&d.id)).collect();
    live.sort_by(|a, b| a.id.cmp(&b.id));
    live.dedup_by(|a, b| a.id == b.id);

    let n = live.len();
    let Some(pos) = live.iter().position(|d| d.id == self_id) else {
        return Vec::new();
    };
    match n {
        0 | 1 => Vec::new(),
        2 => vec![live[1 - pos]],
        _ => vec![live[(pos + n - 1) % n], live[(pos + 1) % n]],
    }
}

/// Compute this node's inbound [`ReplicationConfig`]s from the topology: the ring
/// partners of `self_id`, each combined with the shared `common` parameters. This is
/// what the daemon spawns replication agents from when running in computed-topology
/// mode instead of a static peer list.
pub fn inbound_configs(
    dcs: &[TopologyDc],
    self_id: &str,
    dead: &HashSet<String>,
    common: &ReplicationCommon,
) -> Vec<ReplicationConfig> {
    ring_inbound_partners(dcs, self_id, dead)
        .into_iter()
        .map(|dc| dc.to_replication_config(common))
        .collect()
}

/// The peers considered **dead**: those whose replication health shows at least
/// `threshold` consecutive failures, keyed back to their topology id. A dead peer is
/// excluded from the live ring so this node reroutes around it.
pub fn dead_peers(
    dcs: &[TopologyDc],
    health: &BTreeMap<SocketAddr, ReplPeerHealth>,
    threshold: u32,
) -> HashSet<String> {
    let threshold = threshold.max(1);
    dcs.iter()
        .filter(|dc| {
            health
                .get(&dc.drs)
                .is_some_and(|h| h.consecutive_failures >= threshold)
        })
        .map(|dc| dc.id.clone())
        .collect()
}

/// The set of partner ids this node should keep replication agents for: the **static**
/// ring neighbours (so a dead neighbour keeps being probed and its recovery is detected)
/// UNION the **live** ring neighbours (so connectivity is restored around a dead node).
/// When every neighbour is healthy the two coincide (the minimal 2-partner ring); during
/// a failure the live reroute adds a replacement, dropped again once the dead neighbour
/// recovers.
pub fn desired_partner_ids(
    dcs: &[TopologyDc],
    self_id: &str,
    dead: &HashSet<String>,
) -> BTreeSet<String> {
    let none = HashSet::new();
    let mut ids: BTreeSet<String> = ring_inbound_partners(dcs, self_id, &none)
        .into_iter()
        .map(|dc| dc.id.clone())
        .collect();
    for dc in ring_inbound_partners(dcs, self_id, dead) {
        ids.insert(dc.id.clone());
    }
    ids
}

/// Run the dynamic KCC topology manager until `shutdown` flips to `true`. Every
/// `reconcile_interval` it reads the replication `health`, marks peers with
/// `failure_threshold` consecutive failures as dead, recomputes this node's desired ring
/// partners (see [`desired_partner_ids`]) and reconciles the running replication agents:
/// it starts an agent for a newly-needed partner and stops one no longer needed. A dead
/// neighbour keeps a probing agent (its own exponential backoff) so its recovery is
/// detected and the ring reverts to the minimal set. This is the self-healing counterpart
/// to the static [`inbound_configs`] wiring; on shutdown every agent is signalled to stop.
#[allow(clippy::too_many_arguments)]
pub async fn run_topology_manager(
    dcs: Vec<TopologyDc>,
    self_id: String,
    common: ReplicationCommon,
    db: Db,
    live_directory: Option<Arc<Directory>>,
    kdc: Option<Arc<PrincipalStore>>,
    health: ReplHealthRegistry,
    failure_threshold: u32,
    reconcile_interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    // Each running partner id → (its own shutdown sender, the agent thread handle).
    let mut running: HashMap<String, (watch::Sender<bool>, std::thread::JoinHandle<()>)> =
        HashMap::new();
    // DCs whose DNS locator records we have withdrawn (dead), to only act on transitions.
    let mut withdrawn: HashSet<String> = HashSet::new();
    loop {
        let dead = {
            let snap = health.lock().expect("replication health");
            dead_peers(&dcs, &snap, failure_threshold)
        };
        let desired = desired_partner_ids(&dcs, &self_id, &dead);

        // Dead-node SRV withdrawal: a DC that has just died has its DC-locator records
        // (SRV + A) withdrawn from DNS so clients stop being referred to it; a recovered
        // DC has them re-seeded. Best-effort — a DNS error must not stall reconciliation.
        for dc in &dcs {
            let is_dead = dead.contains(&dc.id);
            let Some((domain, label, ip)) = dc.locator_identity() else {
                continue;
            };
            if is_dead && !withdrawn.contains(&dc.id) {
                match db.withdraw_dc_locator(&domain, &label, &ip).await {
                    Ok(n) => {
                        tracing::info!(peer = %dc.id, removed = n, "topology: withdrew dead DC locators");
                        withdrawn.insert(dc.id.clone());
                    }
                    Err(e) => {
                        tracing::warn!(peer = %dc.id, error = %e, "topology: locator withdraw failed")
                    }
                }
            } else if !is_dead && withdrawn.contains(&dc.id) {
                match db.seed_dc_locator(&domain, &label, &ip).await {
                    Ok(()) => {
                        tracing::info!(peer = %dc.id, "topology: re-seeded recovered DC locators");
                        withdrawn.remove(&dc.id);
                    }
                    Err(e) => {
                        tracing::warn!(peer = %dc.id, error = %e, "topology: locator reseed failed")
                    }
                }
            }
        }

        // Stop agents no longer desired (a recovered neighbour's reroute replacement).
        let stale: Vec<String> = running
            .keys()
            .filter(|id| !desired.contains(*id))
            .cloned()
            .collect();
        for id in stale {
            if let Some((tx, _handle)) = running.remove(&id) {
                let _ = tx.send(true); // the agent observes it and exits; detach the thread
                tracing::info!(peer = %id, "topology: stopped replication agent");
            }
        }

        // Start agents for newly-desired partners.
        for id in &desired {
            if running.contains_key(id) {
                continue;
            }
            let Some(dc) = dcs.iter().find(|d| &d.id == id) else {
                continue;
            };
            let (tx, rx) = watch::channel(false);
            let handle = spawn_replication_thread(
                dc.to_replication_config(&common),
                db.clone(),
                rx,
                live_directory.clone(),
                kdc.clone(),
                Some(health.clone()),
            );
            running.insert(id.clone(), (tx, handle));
            tracing::info!(peer = %id, "topology: started replication agent");
        }

        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
            _ = tokio::time::sleep(reconcile_interval) => {}
        }
    }
    // Global shutdown: signal every agent to stop.
    for (_, (tx, _)) in running.drain() {
        let _ = tx.send(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dc(id: &str) -> TopologyDc {
        // A distinct drs port per id so health (keyed by addr) maps back to one dc.
        let port = 1025u16 + u16::from(id.bytes().next().unwrap_or(b'a'));
        TopologyDc {
            id: id.to_string(),
            drs: format!("127.0.0.1:{port}").parse().unwrap(),
            kdc: "127.0.0.1:88".parse().unwrap(),
            spn: format!("ldap/{id}"),
        }
    }

    fn ids<'a>(p: &[&'a TopologyDc]) -> Vec<&'a str> {
        p.iter().map(|d| d.id.as_str()).collect()
    }

    #[test]
    fn a_lone_node_has_no_partner() {
        let dcs = [dc("a")];
        assert!(ring_inbound_partners(&dcs, "a", &HashSet::new()).is_empty());
    }

    #[test]
    fn two_nodes_partner_each_other() {
        let dcs = [dc("a"), dc("b")];
        assert_eq!(
            ids(&ring_inbound_partners(&dcs, "a", &HashSet::new())),
            ["b"]
        );
        assert_eq!(
            ids(&ring_inbound_partners(&dcs, "b", &HashSet::new())),
            ["a"]
        );
    }

    #[test]
    fn a_ring_connects_each_node_to_its_two_neighbours() {
        // Sorted ring: a - b - c - (back to a).
        let dcs = [dc("c"), dc("a"), dc("b")];
        let empty = HashSet::new();
        assert_eq!(ids(&ring_inbound_partners(&dcs, "a", &empty)), ["c", "b"]);
        assert_eq!(ids(&ring_inbound_partners(&dcs, "b", &empty)), ["a", "c"]);
        assert_eq!(ids(&ring_inbound_partners(&dcs, "c", &empty)), ["b", "a"]);
    }

    #[test]
    fn a_dead_node_is_routed_around() {
        // Ring a-b-c-d. Kill c: the live ring is a-b-d, so b's neighbours become a and d.
        let dcs = [dc("a"), dc("b"), dc("c"), dc("d")];
        let dead: HashSet<String> = ["c".to_string()].into_iter().collect();
        assert_eq!(ids(&ring_inbound_partners(&dcs, "b", &dead)), ["a", "d"]);
        assert_eq!(ids(&ring_inbound_partners(&dcs, "d", &dead)), ["b", "a"]);
        // The dead node itself has no partners.
        assert!(ring_inbound_partners(&dcs, "c", &dead).is_empty());
    }

    #[test]
    fn an_unknown_self_has_no_partners() {
        let dcs = [dc("a"), dc("b")];
        assert!(ring_inbound_partners(&dcs, "zzz", &HashSet::new()).is_empty());
    }

    fn health(failures: u32) -> ReplPeerHealth {
        let mut h = ReplPeerHealth::default();
        for _ in 0..failures {
            h.record_failure("down");
        }
        h
    }

    #[test]
    fn locator_identity_derives_domain_label_and_ip_from_spn_and_addr() {
        let dc = TopologyDc {
            id: "dc2".into(),
            drs: "10.0.0.2:1025".parse().unwrap(),
            kdc: "10.0.0.2:88".parse().unwrap(),
            spn: "ldap/dc2.magtest.local".into(),
        };
        assert_eq!(
            dc.locator_identity(),
            Some(("magtest.local".into(), "dc2".into(), "10.0.0.2".into()))
        );
        // No host FQDN in the SPN → None.
        let bad = TopologyDc {
            spn: "ldap/dc2".into(),
            ..dc.clone()
        };
        assert_eq!(bad.locator_identity(), None);
    }

    #[test]
    fn dead_peers_flags_only_those_over_the_threshold() {
        let dcs = [dc("a"), dc("b"), dc("c")];
        let mut reg: BTreeMap<SocketAddr, ReplPeerHealth> = BTreeMap::new();
        // All three share the same drs addr in `dc()`, so key by that; give it 3 fails.
        reg.insert(dcs[0].drs, health(3));
        // threshold 3 → dead; threshold 4 → not yet.
        assert!(dead_peers(&dcs, &reg, 3).contains("a"));
        assert!(dead_peers(&dcs, &reg, 4).is_empty());
        // A healthy (0-failure) peer is never dead.
        reg.insert(dcs[0].drs, health(0));
        assert!(dead_peers(&dcs, &reg, 3).is_empty());
    }

    #[test]
    fn desired_partners_reroute_on_death_then_revert_on_recovery() {
        // Ring a-b-c-d. From b: healthy neighbours are a and c.
        let dcs = [dc("a"), dc("b"), dc("c"), dc("d")];
        let healthy = desired_partner_ids(&dcs, "b", &HashSet::new());
        assert_eq!(healthy, BTreeSet::from(["a".to_string(), "c".to_string()]));

        // c dies: the live ring gives b the neighbours a and d, but the static ring
        // still lists c (kept for recovery probing) → desired = {a, c, d}.
        let dead: HashSet<String> = ["c".to_string()].into_iter().collect();
        let during = desired_partner_ids(&dcs, "b", &dead);
        assert_eq!(
            during,
            BTreeSet::from(["a".to_string(), "c".to_string(), "d".to_string()]),
            "dead neighbour kept for probing + live reroute added"
        );

        // c recovers → back to the minimal ring {a, c}; the reroute agent for d is dropped.
        let recovered = desired_partner_ids(&dcs, "b", &HashSet::new());
        assert_eq!(recovered, healthy);
        assert!(!recovered.contains("d"));
    }

    #[test]
    fn inbound_configs_carry_the_partner_coordinates_and_common_params() {
        let dcs = [dc("a"), dc("b"), dc("c")];
        let common = ReplicationCommon {
            realm: "MAGTEST.LOCAL".to_string(),
            user: "magnetite$".to_string(),
            password: "pw".to_string(),
            keytab: None,
            nc_dn: "DC=magtest,DC=local".to_string(),
            interval: Duration::from_secs(300),
        };
        let cfgs = inbound_configs(&dcs, "a", &HashSet::new(), &common);
        assert_eq!(cfgs.len(), 2); // c and b
        assert!(cfgs
            .iter()
            .all(|c| c.realm == "MAGTEST.LOCAL" && c.nc_dn == "DC=magtest,DC=local"));
        let spns: Vec<&str> = cfgs.iter().map(|c| c.spn.as_str()).collect();
        assert!(spns.contains(&"ldap/b") && spns.contains(&"ldap/c"));
    }
}
