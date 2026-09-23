//! The embedded DHCPv4 server (E2). Binds UDP :67, runs DORA (DISCOVER→OFFER,
//! REQUEST→ACK/NAK, RELEASE) allocating from the shared DB's pools/reservations/
//! leases. Registered as an [`EmbeddedService`] so `magnetite-server` runs it
//! in-process (09b §-1).
//!
//! Also runs a periodic lease-expiry sweep and (optionally) logs each
//! OFFER/ACK/NAK/RELEASE to the shared `log` table (S-Logs).
//!
//! Scope (E2): DHCPv4 DORA on a single v4 pool. Deferred: multi-pool / relay
//! subnet selection, DHCPv6, DECLINE/INFORM, Option 82, DDNS.

use crate::alloc::{allocate_ip, PoolPartition};
use crate::wire;
use chrono::{Duration as ChronoDuration, Utc};
use dhcproto::v4::MessageType;
use magnetite_core::domain::DomainKey;
use magnetite_core::domains::dhcp::model::{Lease, LeaseState, ProtoVer};
use magnetite_core::models::common::{LogKind, LogLevel};
use magnetite_db::{Db, EmbeddedService, NewLogEntry, ServiceHealth};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::watch;

const H_STARTING: u8 = 0;
const H_HEALTHY: u8 = 1;
const H_ERROR: u8 = 2;

/// How often the lease-expiry sweep runs.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Embedded DHCPv4 server bound to `addr` (usually `0.0.0.0:67`).
pub struct DhcpService {
    addr: SocketAddr,
    log_events: bool,
    health: Arc<AtomicU8>,
    /// This server's split-scope partition of each pool (multi-server redundancy). `None`
    /// = single server, allocate from the whole range.
    partition: Option<PoolPartition>,
}

impl DhcpService {
    /// `log_events` ⇒ write an operation LogEntry per OFFER/ACK/NAK/RELEASE.
    pub fn new(addr: SocketAddr, log_events: bool) -> Self {
        Self {
            addr,
            log_events,
            health: Arc::new(AtomicU8::new(H_STARTING)),
            partition: None,
        }
    }

    /// Run as node `index` of `count` **independent** DHCP servers sharing the pools:
    /// this server allocates fresh addresses only from its disjoint slice (split-scope),
    /// so two servers never hand the same address to two clients without any inter-server
    /// coordination. Reservations and existing leases are still honoured across the whole
    /// range. `count ≤ 1` is a no-op (single server).
    #[must_use]
    pub fn with_partition(mut self, index: u32, count: u32) -> Self {
        self.partition = (count > 1).then_some(PoolPartition { index, count });
        self
    }
}

impl EmbeddedService for DhcpService {
    fn domain(&self) -> DomainKey {
        DomainKey::Dhcp
    }

    fn health(&self) -> ServiceHealth {
        match self.health.load(Ordering::Relaxed) {
            H_HEALTHY => ServiceHealth::Healthy,
            H_ERROR => ServiceHealth::Error,
            _ => ServiceHealth::Unknown,
        }
    }

    fn start(&self, db: Db, shutdown: watch::Receiver<bool>) {
        let addr = self.addr;
        let health = self.health.clone();
        let log_events = self.log_events;
        let partition = self.partition;

        // Lease-expiry sweep (09 §1): periodically expire stale leases.
        let sweep_db = db.clone();
        let mut sweep_shutdown = shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(SWEEP_INTERVAL) => {
                        match sweep_db.expire_stale_leases().await {
                            Ok(n) if n > 0 => tracing::debug!("Expired {n} stale DHCP lease(s)"),
                            Ok(_) => {}
                            Err(e) => tracing::warn!("DHCP lease sweep failed: {e}"),
                        }
                    }
                    _ = sweep_shutdown.changed() => break,
                }
            }
        });

        // UDP DORA loop.
        magnetite_db::spawn_health_guarded("dhcp", health.clone(), H_ERROR, async move {
            if let Err(e) = run(addr, db, shutdown, health.clone(), log_events, partition).await {
                tracing::error!("DHCP server on {addr} failed: {e}");
                health.store(H_ERROR, Ordering::Relaxed);
            }
        });
    }
}

/// The server's own IPv4 (for `siaddr` / Server Identifier) when the bind
/// address is unspecified.
fn bind_ip(addr: SocketAddr) -> Ipv4Addr {
    match addr {
        SocketAddr::V4(v4) => *v4.ip(),
        _ => Ipv4Addr::UNSPECIFIED,
    }
}

/// Handle one DHCP message: returns the reply bytes and destination, or `None`
/// when no reply is warranted (RELEASE, or an unserviceable request).
async fn handle_message(
    db: &Db,
    bytes: &[u8],
    bind: Ipv4Addr,
    log_events: bool,
    partition: Option<PoolPartition>,
) -> Option<(Vec<u8>, SocketAddr)> {
    let msg = wire::decode(bytes)?;
    let mtype = wire::msg_type(&msg)?;
    let mac = wire::client_mac(&msg);

    // Multi-pool selection: among the enabled v4 pools, pick the one whose subnet
    // contains the request's selector — the relay `giaddr` when the request came
    // through a DHCP relay, else this server's bound address. Falls back to the first
    // enabled pool (the single-pool / directly-attached case).
    let pools: Vec<_> = db
        .list_pools()
        .await
        .ok()?
        .into_iter()
        .filter(|p| p.enabled && p.range_start_v4.is_some() && p.range_end_v4.is_some())
        .collect();
    let giaddr = msg.giaddr();
    let selector = if giaddr != Ipv4Addr::UNSPECIFIED {
        giaddr
    } else {
        bind
    };
    let pool = pools
        .iter()
        .find(|p| {
            p.subnet_v4
                .as_deref()
                .map(|c| cidr_contains_v4(c, selector))
                .unwrap_or(false)
        })
        .or_else(|| pools.first())
        .cloned()?;
    let reservations = db.list_reservations(&pool.id).await.ok()?;
    let leases = db.list_leases(Some(&pool.id)).await.ok()?;
    let config = db.get_dhcp_config().await.ok()?;
    let lease_secs = pool
        .lease_duration_secs
        .unwrap_or(config.default_lease_secs)
        .max(1);
    let server_ip = pool
        .gateway
        .as_ref()
        .and_then(|g| g.parse().ok())
        .unwrap_or(bind);

    match mtype {
        MessageType::Discover => {
            let Some(ip) = allocate_ip(
                &pool,
                &reservations,
                &leases,
                &mac,
                wire::requested_ip(&msg),
                partition,
            ) else {
                pool_exhausted(db, log_events, &pool.name, &mac).await;
                return None;
            };
            persist_lease(
                db,
                &pool.id,
                ip,
                &mac,
                wire::hostname(&msg),
                LeaseState::Offered,
                lease_secs,
            )
            .await?;
            let reply = wire::build_reply(
                &msg,
                MessageType::Offer,
                ip,
                &pool,
                &config,
                server_ip,
                lease_secs,
            )?;
            log_event(db, log_events, format!("DHCPOFFER {ip} -> {mac}")).await;
            Some((reply, wire::reply_destination(&msg)))
        }
        MessageType::Request => {
            let requested = wire::requested_ip(&msg).or_else(|| {
                let c = msg.ciaddr();
                (c != Ipv4Addr::UNSPECIFIED).then_some(c)
            });
            let Some(ip) = allocate_ip(&pool, &reservations, &leases, &mac, requested, partition)
            else {
                pool_exhausted(db, log_events, &pool.name, &mac).await;
                return None;
            };
            // If the client insists on an address we won't assign, NAK it.
            if let Some(req) = requested {
                if req != ip {
                    let nak = wire::build_nak(&msg, server_ip)?;
                    log_event(db, log_events, format!("DHCPNAK {req} -> {mac}")).await;
                    return Some((nak, SocketAddr::from(([255, 255, 255, 255], 68))));
                }
            }
            persist_lease(
                db,
                &pool.id,
                ip,
                &mac,
                wire::hostname(&msg),
                LeaseState::Active,
                lease_secs,
            )
            .await?;
            let reply = wire::build_reply(
                &msg,
                MessageType::Ack,
                ip,
                &pool,
                &config,
                server_ip,
                lease_secs,
            )?;
            log_event(
                db,
                log_events,
                format!("DHCPACK {ip} -> {mac} ({lease_secs}s)"),
            )
            .await;
            Some((reply, wire::reply_destination(&msg)))
        }
        MessageType::Release => {
            let ciaddr = msg.ciaddr();
            if let Some(lease) = leases.iter().find(|l| {
                l.state.is_releasable() && l.ip_address.parse::<Ipv4Addr>().ok() == Some(ciaddr)
            }) {
                let _ = db.release_lease(&lease.id).await;
                log_event(db, log_events, format!("DHCPRELEASE {ciaddr} -> {mac}")).await;
            }
            None
        }
        _ => None,
    }
}

/// Append an info-level DHCP operation LogEntry (S-Logs ingestion, F-08).
async fn log_event(db: &Db, enabled: bool, message: String) {
    log_event_at(db, enabled, LogLevel::Info, message).await;
}

/// Append a DHCP operation LogEntry at `level`.
async fn log_event_at(db: &Db, enabled: bool, level: LogLevel, message: String) {
    if !enabled {
        return;
    }
    let _ = db
        .append_log(NewLogEntry {
            domain: DomainKey::Dhcp,
            log_kind: LogKind::Operation,
            level,
            message,
            at: Utc::now(),
            meta: None,
        })
        .await;
}

/// Record (log + trace) that `pool` could offer no address to `mac`.
async fn pool_exhausted(db: &Db, log_events: bool, pool: &str, mac: &str) {
    tracing::warn!("DHCP pool '{pool}' exhausted; no address for {mac}");
    log_event_at(
        db,
        log_events,
        LogLevel::Warn,
        format!("DHCP pool '{pool}' exhausted; no address for {mac}"),
    )
    .await;
}

/// Whether the IPv4 `ip` falls within the `a.b.c.d/n` CIDR. A malformed CIDR, a
/// bare address (no `/`), or a v6 value never matches.
fn cidr_contains_v4(cidr: &str, ip: Ipv4Addr) -> bool {
    let Some((net, prefix)) = cidr.split_once('/') else {
        return false;
    };
    let (Ok(net), Ok(prefix)) = (net.trim().parse::<Ipv4Addr>(), prefix.trim().parse::<u32>())
    else {
        return false;
    };
    if prefix > 32 {
        return false;
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(net) & mask) == (u32::from(ip) & mask)
}

/// Create/replace the lease for `ip` and return it.
async fn persist_lease(
    db: &Db,
    pool_ref: &str,
    ip: Ipv4Addr,
    mac: &str,
    hostname: Option<String>,
    state: LeaseState,
    lease_secs: u32,
) -> Option<()> {
    let now = Utc::now();
    let lease = Lease {
        id: String::new(),
        created_at: now,
        updated_at: now,
        created_by: "dhcp".into(),
        pool_ref: pool_ref.to_string(),
        ip_address: ip.to_string(),
        mac_address: Some(mac.to_string()),
        client_id: None,
        hostname,
        state,
        lease_start: now,
        lease_expiry: now + ChronoDuration::seconds(lease_secs as i64),
        last_renewal: None,
        protocol_version: ProtoVer::V4,
    };
    db.upsert_lease(&lease).await.ok().map(|_| ())
}

async fn run(
    addr: SocketAddr,
    db: Db,
    mut shutdown: watch::Receiver<bool>,
    health: Arc<AtomicU8>,
    log_events: bool,
    partition: Option<PoolPartition>,
) -> std::io::Result<()> {
    let socket = Arc::new(UdpSocket::bind(addr).await?);
    let _ = socket.set_broadcast(true);
    let bind = bind_ip(addr);
    health.store(H_HEALTHY, Ordering::Relaxed);
    tracing::info!("DHCP server listening on {addr} (UDP)");

    let mut buf = vec![0u8; 1500];
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
            recv = socket.recv_from(&mut buf) => {
                let (n, src) = match recv { Ok(v) => v, Err(_) => continue };
                tracing::trace!(target: "conn", %src, "DHCP datagram ({n} B)");
                let packet = buf[..n].to_vec();
                let db = db.clone();
                let sock = socket.clone();
                tokio::spawn(async move {
                    if let Some((reply, dest)) = handle_message(&db, &packet, bind, log_events, partition).await {
                        let _ = sock.send_to(&reply, dest).await;
                    }
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dhcproto::v4::{DhcpOption, Message, Opcode};
    use dhcproto::{Decodable, Encodable};
    use magnetite_core::domains::dhcp::model::Pool;

    async fn seed_pool(db: &Db) -> Pool {
        let pool = Pool {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "admin".into(),
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
        };
        db.create_pool(&pool).await.unwrap()
    }

    async fn test_db() -> (Db, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        (db, dir)
    }

    fn client_msg(mtype: MessageType, mac: &[u8; 6], requested: Option<Ipv4Addr>) -> Vec<u8> {
        let mut m = Message::default();
        m.set_opcode(Opcode::BootRequest);
        m.set_xid(0x1234);
        m.set_chaddr(mac);
        m.opts_mut().insert(DhcpOption::MessageType(mtype));
        if let Some(ip) = requested {
            m.opts_mut().insert(DhcpOption::RequestedIpAddress(ip));
        }
        m.to_vec().unwrap()
    }

    fn reply_type(bytes: &[u8]) -> Option<MessageType> {
        Message::from_bytes(bytes).ok()?.opts().msg_type()
    }
    fn reply_yiaddr(bytes: &[u8]) -> Ipv4Addr {
        Message::from_bytes(bytes).unwrap().yiaddr()
    }

    #[tokio::test]
    async fn discover_offers_and_persists_offered_lease() {
        let (db, _dir) = test_db().await;
        let pool = seed_pool(&db).await;
        let mac = [0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x09];

        let (reply, _dest) = handle_message(
            &db,
            &client_msg(MessageType::Discover, &mac, None),
            Ipv4Addr::UNSPECIFIED,
            false,
            None,
        )
        .await
        .expect("no OFFER");
        assert_eq!(reply_type(&reply), Some(MessageType::Offer));
        assert_eq!(
            reply_yiaddr(&reply),
            "192.0.2.10".parse::<Ipv4Addr>().unwrap()
        );

        let leases = db.list_leases(Some(&pool.id)).await.unwrap();
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].state, LeaseState::Offered);
        assert_eq!(leases[0].ip_address, "192.0.2.10");
        assert_eq!(leases[0].mac_address.as_deref(), Some("aa:bb:cc:00:00:09"));
    }

    #[tokio::test]
    async fn request_acks_and_activates_lease() {
        let (db, _dir) = test_db().await;
        let pool = seed_pool(&db).await;
        let mac = [0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x09];
        let want: Ipv4Addr = "192.0.2.10".parse().unwrap();

        let (reply, _dest) = handle_message(
            &db,
            &client_msg(MessageType::Request, &mac, Some(want)),
            Ipv4Addr::UNSPECIFIED,
            true, // log_events
            None,
        )
        .await
        .expect("no ACK");
        assert_eq!(reply_type(&reply), Some(MessageType::Ack));
        assert_eq!(reply_yiaddr(&reply), want);

        let leases = db.list_leases(Some(&pool.id)).await.unwrap();
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].state, LeaseState::Active);

        // The ACK is logged to the shared log table (S-Logs).
        let logs = db
            .query_logs(Some("dhcp"), Some("operation"), None, 10)
            .await
            .unwrap();
        assert!(logs
            .iter()
            .any(|l| l.message.contains("DHCPACK 192.0.2.10")));
    }

    #[tokio::test]
    async fn request_for_out_of_range_ip_is_nakked() {
        let (db, _dir) = test_db().await;
        seed_pool(&db).await;
        let mac = [0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x09];
        let bogus: Ipv4Addr = "10.9.9.9".parse().unwrap();

        let (reply, _dest) = handle_message(
            &db,
            &client_msg(MessageType::Request, &mac, Some(bogus)),
            Ipv4Addr::UNSPECIFIED,
            false,
            None,
        )
        .await
        .expect("no NAK");
        assert_eq!(reply_type(&reply), Some(MessageType::Nak));
    }

    #[tokio::test]
    async fn expired_leases_are_swept() {
        use magnetite_core::domains::dhcp::model::{Lease, ProtoVer};

        let (db, _dir) = test_db().await;
        let pool = seed_pool(&db).await;
        // An active lease that expired an hour ago.
        let past = Utc::now() - ChronoDuration::hours(1);
        db.upsert_lease(&Lease {
            id: String::new(),
            created_at: past,
            updated_at: past,
            created_by: "dhcp".into(),
            pool_ref: pool.id.clone(),
            ip_address: "192.0.2.10".into(),
            mac_address: Some("aa:bb:cc:00:00:09".into()),
            client_id: None,
            hostname: None,
            state: LeaseState::Active,
            lease_start: past,
            lease_expiry: past,
            last_renewal: None,
            protocol_version: ProtoVer::V4,
        })
        .await
        .unwrap();

        let swept = db.expire_stale_leases().await.unwrap();
        assert_eq!(swept, 1);
        let leases = db.list_leases(Some(&pool.id)).await.unwrap();
        assert_eq!(leases[0].state, LeaseState::Expired);
    }
}
