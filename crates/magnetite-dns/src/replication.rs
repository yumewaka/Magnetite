//! DNS zone replication (07_data_dns replication extension).
//!
//! Primary side: authorize AXFR by IP allow-list and send DNS NOTIFY (RFC 1996)
//! to configured secondaries when a zone's SOA serial changes. Secondary side:
//! a background task refreshes each secondary zone from its primary (SOA poll +
//! AXFR pull), and inbound NOTIFY triggers an immediate refresh.
//!
//! Transfers are authorized by an IP allow-list and, when a zone has a TSIG key
//! (RFC 8945), by **verifying the request's** HMAC signature (hmac-sha256/384/
//! 512) — this authenticates who may transfer the zone. **Mutual TSIG**: the
//! primary then signs every response message (chaining MACs from the request MAC
//! across the multi-message stream), and the secondary verifies those signatures,
//! so each side authenticates the other. Response signing derives its to-be-signed
//! bytes from the exact placeholder-signed wire bytes (via the verifier's own
//! reconstruction), avoiding `message_tbs`'s compression-offset shift. AXFR
//! responses split across multiple messages (RFC 5936) so large zones transfer.
//! IXFR requests are accepted and served as a full-zone AXFR fallback (RFC 1995).

use crate::geo::cidr_contains;
use crate::wire::from_rr;
use base64::Engine;
use hickory_proto::dnssec::rdata::tsig::{
    make_tsig_record, signed_bitmessage_to_buf, TsigAlgorithm as HTsigAlgorithm, TSIG,
};
use hickory_proto::dnssec::tsig::TSigner;
use hickory_proto::op::{Message, MessageType, MessageVerifier, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType as HRecordType};
use magnetite_core::domains::dns::model::{
    Record, Soa, TsigAlgorithm, Zone, ZoneRole, ZoneTransferState,
};
use magnetite_db::Db;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};

/// TSIG time fudge (max client/server clock skew), seconds (RFC 8945).
const TSIG_FUDGE: u16 = 300;

/// Current UNIX time in seconds (for TSIG inception).
fn now_secs() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

/// Build a hickory TSIG signer from a stored key by name, if it exists and uses
/// a supported algorithm.
pub async fn signer_for_key(db: &Db, key_name: &str) -> Option<TSigner> {
    let (alg, secret_b64) = db.get_tsig_secret(key_name).await.ok().flatten()?;
    let key = base64::engine::general_purpose::STANDARD
        .decode(secret_b64.trim())
        .ok()?;
    let h_alg = match alg {
        TsigAlgorithm::HmacSha256 => HTsigAlgorithm::HmacSha256,
        TsigAlgorithm::HmacSha384 => HTsigAlgorithm::HmacSha384,
        TsigAlgorithm::HmacSha512 => HTsigAlgorithm::HmacSha512,
    };
    let name = Name::from_str(key_name).ok()?;
    TSigner::new(key, h_alg, name, TSIG_FUDGE).ok()
}

/// The TSIG signer configured for a zone, if any.
pub async fn zone_signer(db: &Db, zone: &Zone) -> Option<TSigner> {
    let key_name = zone.tsig_key_name.as_deref()?;
    signer_for_key(db, key_name).await
}

/// Serialize `msg`, signing it with TSIG when `signer` is set. Returns the wire
/// bytes plus an optional verifier for the response.
fn serialize_signed(
    mut msg: Message,
    signer: Option<&TSigner>,
) -> Option<(Vec<u8>, Option<MessageVerifier>)> {
    let verifier = match signer {
        Some(s) => msg.finalize(s, now_secs()).ok().flatten(),
        None => None,
    };
    Some((msg.to_vec().ok()?, verifier))
}

/// Verify an inbound (request) message's TSIG against `signer` (server side).
/// Returns the request's MAC when the signature is valid and its timestamp is
/// within the fudge window (the MAC seeds the response signature), else `None`.
pub fn verify_tsig(signer: &TSigner, message_bytes: &[u8]) -> Option<Vec<u8>> {
    match signer.verify_message_byte(None, message_bytes, true) {
        Ok((mac, range, _time)) if range.contains(&(now_secs() as u64)) => Some(mac),
        _ => None,
    }
}

/// Sign one response message with TSIG (RFC 8945), using `prev_mac` as the digest
/// prefix — the request's MAC for the first message, the previous message's MAC
/// for subsequent ones in a multi-message transfer. Returns the signed wire bytes
/// and this message's MAC (to chain the next message).
///
/// The to-be-signed bytes are derived from the *exact* placeholder-signed wire
/// bytes via [`signed_bitmessage_to_buf`] (the verifier's own reconstruction)
/// rather than `message_tbs`, which re-emits the message behind the `prev_mac`
/// prefix and shifts name-compression pointers — the mismatch that previously
/// blocked server-side response signing.
fn sign_response(
    signer: &TSigner,
    mut response: Message,
    prev_mac: &[u8],
    time: u32,
    first: bool,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let pre = TSIG::new(
        signer.algorithm().clone(),
        time as u64,
        signer.fudge(),
        Vec::new(),
        response.id(),
        0,
        Vec::new(),
    );
    // Placeholder TSIG → serialize → derive the TBS from those verbatim bytes.
    response.add_tsig(make_tsig_record(signer.signer_name().clone(), pre.clone()));
    let dummy = response.to_vec().ok()?;
    let (tbv, _) = signed_bitmessage_to_buf(Some(prev_mac), &dummy, first).ok()?;
    let mac = signer.sign(&tbv).ok()?;
    // Swap the placeholder for the real MAC; the record body before the TSIG is
    // byte-identical, so the transmitted bytes reproduce the same TBS on verify.
    let _ = response.take_signature();
    response.add_tsig(make_tsig_record(
        signer.signer_name().clone(),
        pre.set_mac(mac.clone()),
    ));
    Some((response.to_vec().ok()?, mac))
}

/// Sign a multi-message AXFR/IXFR response, chaining MACs per RFC 8945: the first
/// message uses `request_mac` as the digest prefix and each subsequent message
/// the previous message's MAC. Returns empty (transfer aborted) if any message
/// fails to sign — the secondary must never receive a partially-signed stream.
pub fn sign_axfr_messages(
    signer: &TSigner,
    msgs: Vec<Message>,
    request_mac: &[u8],
) -> Vec<Vec<u8>> {
    let time = now_secs();
    let mut prev = request_mac.to_vec();
    let mut out = Vec::with_capacity(msgs.len());
    for (i, msg) in msgs.into_iter().enumerate() {
        match sign_response(signer, msg, &prev, time, i == 0) {
            Some((bytes, mac)) => {
                prev = mac;
                out.push(bytes);
            }
            None => {
                tracing::error!("AXFR TSIG response signing failed; aborting transfer");
                return Vec::new();
            }
        }
    }
    out
}

const DEFAULT_DNS_PORT: u16 = 53;
const SOA_TIMEOUT: Duration = Duration::from_secs(5);
const AXFR_TIMEOUT: Duration = Duration::from_secs(30);
/// How often the background task scans zones for notify/refresh work.
const SCAN_INTERVAL: Duration = Duration::from_secs(15);

/// Sender used by the query path to force a secondary refresh on inbound NOTIFY.
pub type NotifySender = mpsc::UnboundedSender<String>;

/// Whether `client` is authorized to transfer `zone` (primary side). An empty
/// allow-list denies all transfers (secure by default); `any` allows all.
pub fn transfer_allowed(zone: &Zone, client: IpAddr) -> bool {
    zone.allow_transfer.iter().any(|entry| {
        let e = entry.trim();
        e.eq_ignore_ascii_case("any") || cidr_contains(e, client)
    })
}

/// Resolve a `host` / `host:port` / IP target to a socket address (port 53 by
/// default), performing a DNS lookup for hostnames.
async fn resolve_target(s: &str) -> Option<SocketAddr> {
    let s = s.trim();
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Some(addr);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, DEFAULT_DNS_PORT));
    }
    let hostport = if s.contains(':') {
        s.to_string()
    } else {
        format!("{s}:{DEFAULT_DNS_PORT}")
    };
    tokio::net::lookup_host(hostport).await.ok()?.next()
}

fn build_query_msg(zone: &str, qtype: HRecordType) -> Option<Message> {
    let mut msg = Message::new();
    msg.set_id(0x4242);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(false);
    msg.add_query(Query::query(Name::from_str(zone).ok()?, qtype));
    Some(msg)
}

fn build_notify_msg(zone: &str) -> Option<Message> {
    let mut msg = Message::new();
    msg.set_id(0x4243);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Notify);
    msg.set_authoritative(true);
    msg.add_query(Query::query(Name::from_str(zone).ok()?, HRecordType::SOA));
    Some(msg)
}

fn soa_from_hickory(s: &hickory_proto::rr::rdata::SOA) -> Soa {
    Soa {
        mname: s.mname().to_string(),
        rname: s.rname().to_string(),
        serial: s.serial(),
        refresh: s.refresh().max(0) as u32,
        retry: s.retry().max(0) as u32,
        expire: s.expire().max(0) as u32,
        minimum: s.minimum(),
    }
}

/// Query a server for a zone's current SOA serial (UDP), TSIG-signed when a
/// signer is provided (and verifying the response's TSIG).
async fn query_soa_serial(server: SocketAddr, zone: &str, signer: Option<&TSigner>) -> Option<u32> {
    // Sign the request when a key is set (so a TSIG-protected primary accepts
    // it); response TSIG is not verified (see the module note on response
    // signing).
    let (query, _verifier) = serialize_signed(build_query_msg(zone, HRecordType::SOA)?, signer)?;
    let bind: SocketAddr = if server.is_ipv6() {
        "[::]:0".parse().ok()?
    } else {
        "0.0.0.0:0".parse().ok()?
    };
    let sock = UdpSocket::bind(bind).await.ok()?;
    sock.send_to(&query, server).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(SOA_TIMEOUT, sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    let msg = Message::from_vec(&buf[..n]).ok()?;
    msg.answers().iter().find_map(|ans| match ans.data() {
        RData::SOA(s) => Some(s.serial()),
        _ => None,
    })
}

/// Pull a full zone via AXFR over TCP, returning its SOA and records. TSIG-signs
/// the request and verifies the (first) response message when a signer is set.
async fn axfr_pull(
    server: SocketAddr,
    zone: &str,
    signer: Option<&TSigner>,
) -> Option<(Soa, Vec<Record>)> {
    // Sign the request when a key is set (so a TSIG-protected primary accepts it),
    // and verify the primary's response TSIG in turn (mutual TSIG). The verifier
    // threads MACs across the multi-message stream.
    let (query, mut verifier) =
        serialize_signed(build_query_msg(zone, HRecordType::AXFR)?, signer)?;
    let mut stream = tokio::time::timeout(AXFR_TIMEOUT, TcpStream::connect(server))
        .await
        .ok()?
        .ok()?;
    let len = (query.len() as u16).to_be_bytes();
    stream.write_all(&len).await.ok()?;
    stream.write_all(&query).await.ok()?;

    let mut soa: Option<Soa> = None;
    let mut records: Vec<Record> = Vec::new();
    let mut soa_seen = 0u8;
    loop {
        let mut lenb = [0u8; 2];
        match tokio::time::timeout(AXFR_TIMEOUT, stream.read_exact(&mut lenb)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }
        let mlen = u16::from_be_bytes(lenb) as usize;
        let mut mbuf = vec![0u8; mlen];
        if stream.read_exact(&mut mbuf).await.is_err() {
            break;
        }
        // Reject the transfer if the primary's response fails TSIG verification.
        if let Some(v) = verifier.as_mut() {
            if v(&mbuf).is_err() {
                tracing::warn!("AXFR from {server} for {zone}: response TSIG verify failed");
                return None;
            }
        }
        let Ok(msg) = Message::from_vec(&mbuf) else {
            break;
        };
        for ans in msg.answers() {
            if let RData::SOA(s) = ans.data() {
                soa_seen += 1;
                if soa.is_none() {
                    soa = Some(soa_from_hickory(s));
                }
                if soa_seen >= 2 {
                    // Closing SOA — a well-formed AXFR is complete.
                    return soa.map(|s| (s, records));
                }
            } else if let Some(rec) = from_rr(ans) {
                records.push(rec);
            }
        }
    }
    // Stream ended without an explicit closing SOA; accept what we have if the
    // opening SOA was present.
    soa.map(|s| (s, records))
}

/// Outcome of an IXFR pull.
enum IxfrResponse {
    /// The secondary is already current (server sent just the SOA).
    UpToDate,
    /// Incremental difference sequences (each: records removed, then added).
    Incremental {
        new_soa: Soa,
        sequences: Vec<(Vec<Record>, Vec<Record>)>,
    },
    /// The server fell back to a full zone (AXFR-style response).
    Full { soa: Soa, records: Vec<Record> },
}

fn rr_soa_serial(rr: &hickory_proto::rr::Record) -> Option<u32> {
    match rr.data() {
        RData::SOA(s) => Some(s.serial()),
        _ => None,
    }
}

/// Request an IXFR from `server` for `zone` starting at `current_serial`, parsing
/// the response into incremental sequences, a full zone, or up-to-date. Signs the
/// request when a key is set.
async fn ixfr_pull(
    server: SocketAddr,
    zone: &str,
    current_serial: u32,
    signer: Option<&TSigner>,
) -> Option<IxfrResponse> {
    use hickory_proto::rr::rdata::SOA as HSOA;
    use hickory_proto::rr::Record as HRecord;

    // Build the IXFR query with the client's current SOA in the authority section.
    let mut msg = build_query_msg(zone, HRecordType::IXFR)?;
    let name = Name::from_str(zone).ok()?;
    let soa = HSOA::new(
        name.clone(),
        name.clone(),
        current_serial,
        3600,
        900,
        604_800,
        300,
    );
    msg.add_name_server(HRecord::from_rdata(name, 0, RData::SOA(soa)));
    let (query, mut verifier) = serialize_signed(msg, signer)?;

    let mut stream = tokio::time::timeout(AXFR_TIMEOUT, TcpStream::connect(server))
        .await
        .ok()?
        .ok()?;
    stream
        .write_all(&(query.len() as u16).to_be_bytes())
        .await
        .ok()?;
    stream.write_all(&query).await.ok()?;

    // Collect every answer RR across the response messages.
    let mut rrs: Vec<HRecord> = Vec::new();
    let mut soa_seen = 0u8;
    'outer: loop {
        let mut lenb = [0u8; 2];
        match tokio::time::timeout(AXFR_TIMEOUT, stream.read_exact(&mut lenb)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }
        let mlen = u16::from_be_bytes(lenb) as usize;
        let mut mbuf = vec![0u8; mlen];
        if stream.read_exact(&mut mbuf).await.is_err() {
            break;
        }
        // Mutual TSIG: verify the primary's response signature when we signed the
        // request (the verifier threads MACs across messages).
        if let Some(v) = verifier.as_mut() {
            if v(&mbuf).is_err() {
                tracing::warn!("IXFR from {server} for {zone}: response TSIG verify failed");
                return None;
            }
        }
        let Ok(m) = Message::from_vec(&mbuf) else {
            break;
        };
        for ans in m.answers() {
            rrs.push(ans.clone());
            // The transfer ends after the closing SOA (2nd for full, last for
            // incremental); a simple SOA count bounds the read.
            if rr_soa_serial(ans).is_some() {
                soa_seen += 1;
            }
        }
        // Heuristic stop: once we have seen the trailing SOA matching the first.
        if rrs.len() >= 2 {
            if let (Some(first), Some(last)) = (
                rrs.first().and_then(rr_soa_serial),
                rrs.last().and_then(rr_soa_serial),
            ) {
                if last == first && (soa_seen >= 2) {
                    break 'outer;
                }
            }
        }
    }

    if rrs.is_empty() {
        return None;
    }
    let new_serial = rr_soa_serial(&rrs[0])?;
    let new_soa = match rrs[0].data() {
        RData::SOA(s) => soa_from_hickory(s),
        _ => return None,
    };
    if rrs.len() == 1 {
        return Some(IxfrResponse::UpToDate);
    }
    // Incremental when the second RR is an SOA of a *different* (older) serial.
    let incremental = rr_soa_serial(&rrs[1]).is_some_and(|s| s != new_serial);
    if !incremental {
        let records = rrs.iter().filter_map(from_rr).collect();
        return Some(IxfrResponse::Full {
            soa: new_soa,
            records,
        });
    }
    // Parse difference sequences: [SOA(old), deleted.., SOA(new_i), added..]*.
    let mut sequences = Vec::new();
    let mut i = 1usize;
    while i < rrs.len() {
        if rr_soa_serial(&rrs[i]) == Some(new_serial) {
            break; // trailing SOA
        }
        i += 1; // skip SOA(old)
        let mut removed = Vec::new();
        while i < rrs.len() && rr_soa_serial(&rrs[i]).is_none() {
            if let Some(r) = from_rr(&rrs[i]) {
                removed.push(r);
            }
            i += 1;
        }
        if i >= rrs.len() {
            break;
        }
        i += 1; // skip SOA(new_i)
        let mut added = Vec::new();
        while i < rrs.len() && rr_soa_serial(&rrs[i]).is_none() {
            if let Some(r) = from_rr(&rrs[i]) {
                added.push(r);
            }
            i += 1;
        }
        sequences.push((removed, added));
    }
    Some(IxfrResponse::Incremental { new_soa, sequences })
}

/// Send NOTIFY for a zone to every configured `also_notify` target, TSIG-signed
/// when the zone has a key.
async fn notify_secondaries(db: &Db, zone: &Zone) {
    let signer = zone_signer(db, zone).await;
    let Some(msg) = build_notify_msg(&zone.name) else {
        return;
    };
    let Some((payload, _)) = serialize_signed(msg, signer.as_ref()) else {
        return;
    };
    for target in &zone.also_notify {
        let Some(addr) = resolve_target(target).await else {
            tracing::warn!("NOTIFY target '{target}' did not resolve");
            continue;
        };
        let bind = if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        if let Ok(sock) = UdpSocket::bind(bind).await {
            let _ = sock.send_to(&payload, addr).await;
            tracing::info!("sent NOTIFY for {} to {addr}", zone.name);
        }
    }
}

/// Refresh one secondary zone from its primaries. Once the zone has been fully
/// synced, subsequent refreshes use IXFR (incremental) and apply only the deltas;
/// the first sync (and any unbridgeable IXFR) uses a full AXFR.
async fn refresh_secondary(db: &Db, zone: &Zone) {
    let current = zone.transfer_state.as_ref().map(|s| s.last_serial);
    let prev_success = zone.transfer_state.as_ref().and_then(|s| s.last_success);
    let ever_synced = prev_success.is_some();
    let signer = zone_signer(db, zone).await;

    // Apply a freshly transferred full zone.
    async fn store_full(db: &Db, zone: &Zone, soa: Soa, mut records: Vec<Record>) -> u32 {
        let serial = soa.serial;
        for r in &mut records {
            r.zone = zone.id.clone();
        }
        let _ = db.replace_zone_records(&zone.id, &soa, &records).await;
        tracing::info!(
            "secondary zone {} full-transferred (serial {serial}, {} records)",
            zone.name,
            records.len()
        );
        serial
    }

    for primary in &zone.primaries {
        let Some(addr) = resolve_target(primary).await else {
            continue;
        };

        if ever_synced {
            // Incremental path: IXFR from the serial we currently hold.
            match ixfr_pull(addr, &zone.name, zone.soa.serial, signer.as_ref()).await {
                Some(IxfrResponse::UpToDate) => {
                    record_state(db, &zone.id, zone.soa.serial, true, None, prev_success).await;
                    return;
                }
                Some(IxfrResponse::Incremental { new_soa, sequences }) => {
                    for (removed, added) in &sequences {
                        let _ = db.apply_zone_delta(&zone.id, removed, added).await;
                    }
                    let _ = db.set_zone_soa(&zone.id, &new_soa).await;
                    tracing::info!(
                        "secondary zone {} IXFR from {addr} → serial {} ({} sequence(s))",
                        zone.name,
                        new_soa.serial,
                        sequences.len()
                    );
                    record_state(db, &zone.id, new_soa.serial, true, None, prev_success).await;
                    return;
                }
                Some(IxfrResponse::Full { soa, records }) => {
                    let serial = store_full(db, zone, soa, records).await;
                    record_state(db, &zone.id, serial, true, None, prev_success).await;
                    return;
                }
                None => continue,
            }
        }

        // First sync: skip if not newer, else full AXFR.
        if let (Some(cur), Some(remote)) = (
            current,
            query_soa_serial(addr, &zone.name, signer.as_ref()).await,
        ) {
            if !serial_newer(remote, cur) {
                record_state(db, &zone.id, cur, true, None, prev_success).await;
                return;
            }
        }
        if let Some((soa, records)) = axfr_pull(addr, &zone.name, signer.as_ref()).await {
            let serial = store_full(db, zone, soa, records).await;
            record_state(db, &zone.id, serial, true, None, prev_success).await;
            return;
        }
    }
    // No primary succeeded.
    record_state(
        db,
        &zone.id,
        current.unwrap_or(0),
        false,
        Some("no primary reachable".into()),
        prev_success,
    )
    .await;
}

/// RFC 1982 serial arithmetic: is `a` newer than `b`?
fn serial_newer(a: u32, b: u32) -> bool {
    a != b && a.wrapping_sub(b) < (1 << 31)
}

/// Whether a secondary zone has expired (RFC 1035 §3.2.3): it has not been
/// successfully transferred within `soa.expire`, so it must stop being served
/// authoritatively. Primary zones never expire.
pub fn secondary_expired(zone: &Zone) -> bool {
    if zone.role != ZoneRole::Secondary {
        return false;
    }
    match zone.transfer_state.as_ref().and_then(|s| s.last_success) {
        // Never transferred: not yet authoritative.
        None => true,
        Some(ts) => {
            chrono::Utc::now().signed_duration_since(ts).num_seconds() > zone.soa.expire as i64
        }
    }
}

async fn record_state(
    db: &Db,
    zone_id: &str,
    serial: u32,
    ok: bool,
    error: Option<String>,
    prev_success: Option<chrono::DateTime<chrono::Utc>>,
) {
    let now = chrono::Utc::now();
    let state = ZoneTransferState {
        last_serial: serial,
        last_attempt: now,
        last_ok: ok,
        last_error: error,
        last_success: if ok { Some(now) } else { prev_success },
    };
    let _ = db.set_zone_transfer_state(zone_id, &state).await;
}

/// Whether a secondary zone is due for a refresh based on its SOA timers.
fn refresh_due(zone: &Zone) -> bool {
    match &zone.transfer_state {
        None => true,
        Some(state) => {
            let interval = if state.last_ok {
                zone.soa.refresh
            } else {
                zone.soa.retry.max(60)
            };
            let elapsed = chrono::Utc::now()
                .signed_duration_since(state.last_attempt)
                .num_seconds();
            elapsed >= interval as i64
        }
    }
}

/// Background replication task: periodically send NOTIFY for changed primary
/// zones and refresh due secondary zones; also refreshes on inbound NOTIFY.
pub async fn replication_task(
    db: Db,
    mut shutdown: watch::Receiver<bool>,
    mut notify_rx: mpsc::UnboundedReceiver<String>,
) {
    // Primary zone name -> serial last observed (to detect changes for NOTIFY).
    let mut seen_serials: HashMap<String, u32> = HashMap::new();
    let mut ticker = tokio::time::interval(SCAN_INTERVAL);
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
            forced = notify_rx.recv() => {
                let Some(zone_name) = forced else { continue };
                if let Ok(zones) = db.list_zones().await {
                    if let Some(zone) = zones.into_iter().find(|z| {
                        z.role == ZoneRole::Secondary && z.name == zone_name
                    }) {
                        tracing::info!("NOTIFY received for {zone_name}; refreshing");
                        refresh_secondary(&db, &zone).await;
                    }
                }
            }
            _ = ticker.tick() => {
                let zones = db.list_zones().await.unwrap_or_default();
                for zone in zones {
                    if !zone.enabled { continue; }
                    match zone.role {
                        ZoneRole::Primary => {
                            if !zone.notify_enabled || zone.also_notify.is_empty() { continue; }
                            let serial = zone.soa.serial;
                            match seen_serials.get(&zone.name) {
                                // First observation: record without notifying.
                                None => { seen_serials.insert(zone.name.clone(), serial); }
                                Some(&prev) if serial_newer(serial, prev) => {
                                    seen_serials.insert(zone.name.clone(), serial);
                                    notify_secondaries(&db, &zone).await;
                                }
                                _ => {}
                            }
                        }
                        ZoneRole::Secondary => {
                            if refresh_due(&zone) {
                                refresh_secondary(&db, &zone).await;
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn signer(secret: &[u8]) -> TSigner {
        TSigner::new(
            secret.to_vec(),
            HTsigAlgorithm::HmacSha256,
            Name::from_str("key.example.").unwrap(),
            TSIG_FUDGE,
        )
        .unwrap()
    }

    #[test]
    fn tsig_sign_then_verify_roundtrips() {
        let s = signer(b"0123456789abcdef0123456789abcdef");
        let msg = build_query_msg("example.com.", HRecordType::AXFR).unwrap();
        let (bytes, _verifier) = serialize_signed(msg, Some(&s)).unwrap();
        // The same key verifies the signed query (returning its MAC).
        assert!(verify_tsig(&s, &bytes).is_some());
        // A different key does not.
        let other = signer(b"ffffffffffffffffffffffffffffffff");
        assert!(verify_tsig(&other, &bytes).is_none());
    }

    #[test]
    fn unsigned_query_fails_tsig_verification() {
        let s = signer(b"0123456789abcdef0123456789abcdef");
        let msg = build_query_msg("example.com.", HRecordType::AXFR).unwrap();
        let (bytes, _) = serialize_signed(msg, None).unwrap();
        assert!(verify_tsig(&s, &bytes).is_none());
    }

    /// Build a response with several names under example.com (exercises DNS name
    /// compression — the case that previously broke server-side response signing).
    fn sample_response(id: u16) -> Message {
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::{RData, Record as HRecord};
        let mut resp = Message::new();
        resp.set_id(id);
        resp.set_message_type(MessageType::Response);
        resp.set_op_code(OpCode::Query);
        for host in ["www.example.com.", "mail.example.com.", "ns.example.com."] {
            let name = Name::from_str(host).unwrap();
            resp.add_answer(HRecord::from_rdata(
                name,
                300,
                RData::A(A(Ipv4Addr::new(10, 0, 0, 1))),
            ));
        }
        resp
    }

    #[test]
    fn tsig_response_signing_roundtrips_with_compression() {
        let s = signer(b"0123456789abcdef0123456789abcdef");
        // A signed request → its MAC seeds the response signature.
        let req = build_query_msg("example.com.", HRecordType::AXFR).unwrap();
        let (req_bytes, _v) = serialize_signed(req, Some(&s)).unwrap();
        let request_mac = verify_tsig(&s, &req_bytes).unwrap();

        let (signed, mac0) =
            sign_response(&s, sample_response(0x1234), &request_mac, now_secs(), true).unwrap();

        // The secondary's verification (request MAC as prefix, first message) accepts it.
        let (returned_mac, range, _t) = s
            .verify_message_byte(Some(&request_mac), &signed, true)
            .unwrap();
        assert_eq!(returned_mac, mac0);
        assert!(range.contains(&(now_secs() as u64)));

        // A different key rejects it.
        let other = signer(b"ffffffffffffffffffffffffffffffff");
        assert!(other
            .verify_message_byte(Some(&request_mac), &signed, true)
            .is_err());
    }

    #[test]
    fn tsig_multi_message_mac_chaining_verifies() {
        let s = signer(b"0123456789abcdef0123456789abcdef");
        let req = build_query_msg("example.com.", HRecordType::AXFR).unwrap();
        let (req_bytes, _v) = serialize_signed(req, Some(&s)).unwrap();
        let request_mac = verify_tsig(&s, &req_bytes).unwrap();

        let signed = sign_axfr_messages(
            &s,
            vec![sample_response(1), sample_response(2), sample_response(3)],
            &request_mac,
        );
        assert_eq!(signed.len(), 3);

        // Verify the chain exactly as a secondary would: the first message with the
        // request MAC (first=true), each subsequent with the previous message's MAC.
        let (mac0, _r, _t) = s
            .verify_message_byte(Some(&request_mac), &signed[0], true)
            .unwrap();
        let (mac1, _r, _t) = s
            .verify_message_byte(Some(&mac0), &signed[1], false)
            .unwrap();
        let _ = s
            .verify_message_byte(Some(&mac1), &signed[2], false)
            .unwrap();
    }

    #[test]
    fn allow_transfer_matches_cidr_and_any() {
        let mut zone = Zone {
            id: "z".into(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            created_by: "t".into(),
            name: "example.com.".into(),
            soa: Soa::default(),
            enabled: true,
            dnssec_enabled: false,
            nsec3_enabled: false,
            role: ZoneRole::Primary,
            allow_transfer: vec!["192.0.2.0/24".into()],
            also_notify: vec![],
            notify_enabled: false,
            primaries: vec![],
            tsig_key_name: None,
            transfer_state: None,
        };
        let inside = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5));
        let outside = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        assert!(transfer_allowed(&zone, inside));
        assert!(!transfer_allowed(&zone, outside));
        // Empty list denies all.
        zone.allow_transfer.clear();
        assert!(!transfer_allowed(&zone, inside));
        // "any" allows all.
        zone.allow_transfer = vec!["any".into()];
        assert!(transfer_allowed(&zone, outside));
    }

    use magnetite_core::domains::dns::model::{Record, RecordType, TsigAlgorithm};
    use magnetite_db::{Db, EmbeddedService, ServiceHealth};

    async fn test_zone(name: &str, records: usize) -> (Db, tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        let soa = Soa {
            mname: format!("ns1.{name}"),
            rname: format!("admin.{name}"),
            ..Soa::default()
        };
        let zone = db.create_zone(name, &soa, true, "t").await.unwrap();
        for i in 0..records {
            let now = chrono::Utc::now();
            db.create_record(&Record {
                id: String::new(),
                created_at: now,
                updated_at: now,
                created_by: "t".into(),
                zone: zone.id.clone(),
                name: format!("a{i}.{name}"),
                ttl: 300,
                record_type: RecordType::A,
                data: serde_json::json!({ "address": "10.0.0.1" }),
                enabled: true,
            })
            .await
            .unwrap();
        }
        (db, dir, zone.id)
    }

    /// Start a primary DNS server; returns its address and the shutdown sender
    /// (held by the caller so the server stops cleanly when the test ends).
    async fn start_primary(db: Db) -> (std::net::SocketAddr, watch::Sender<bool>) {
        use crate::service::DnsService;
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        let svc = DnsService::new(addr, vec![], false);
        let (tx, rx) = watch::channel(false);
        svc.start(db, rx);
        for _ in 0..50 {
            if svc.health() == ServiceHealth::Healthy {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        (addr, tx)
    }

    /// A large unsigned zone transfers across multiple AXFR messages.
    #[tokio::test]
    async fn unsigned_multimessage_axfr_roundtrips() {
        let count = crate::wire::AXFR_CHUNK_RECORDS * 3 + 7;
        let (db, _dir, zone_id) = test_zone("big.example.com.", count).await;
        db.update_zone_replication(
            &zone_id,
            ZoneRole::Primary,
            &["any".to_string()],
            &[],
            false,
            &[],
            None,
        )
        .await
        .unwrap();
        let (addr, _tx) = start_primary(db).await;

        let (_soa, records) = axfr_pull(addr, "big.example.com.", None)
            .await
            .expect("unsigned AXFR should succeed");
        assert_eq!(records.len(), count);
    }

    /// A TSIG-keyed zone transfers as a single signed message; the right key
    /// verifies and a wrong key is rejected.
    #[tokio::test]
    async fn signed_axfr_roundtrips_and_rejects_wrong_key() {
        let (db, _dir, zone_id) = test_zone("secure.example.com.", 5).await;
        let secret =
            base64::engine::general_purpose::STANDARD.encode(b"0123456789abcdef0123456789abcdef");
        db.create_tsig_key("xfr.key.", TsigAlgorithm::HmacSha256, &secret, "t")
            .await
            .unwrap();
        db.update_zone_replication(
            &zone_id,
            ZoneRole::Primary,
            &["any".to_string()],
            &[],
            false,
            &[],
            Some("xfr.key."),
        )
        .await
        .unwrap();
        let (addr, _tx) = start_primary(db.clone()).await;

        let signer = signer_for_key(&db, "xfr.key.").await.unwrap();
        let (_soa, records) = axfr_pull(addr, "secure.example.com.", Some(&signer))
            .await
            .expect("signed AXFR should succeed with the right key");
        assert_eq!(records.len(), 5);

        let bad = TSigner::new(
            b"ffffffffffffffffffffffffffffffff".to_vec(),
            HTsigAlgorithm::HmacSha256,
            Name::from_str("xfr.key.").unwrap(),
            TSIG_FUDGE,
        )
        .unwrap();
        assert!(axfr_pull(addr, "secure.example.com.", Some(&bad))
            .await
            .is_none());
    }

    /// Send an IXFR query with `client_serial` in the authority section and
    /// collect every answer record across the response messages.
    async fn ixfr_pull(
        server: std::net::SocketAddr,
        zone: &str,
        client_serial: u32,
    ) -> Vec<hickory_proto::rr::Record> {
        use hickory_proto::rr::rdata::SOA as HSOA;
        use hickory_proto::rr::Record as HRecord;
        let mut msg = Message::new();
        msg.set_id(0x5151);
        msg.set_message_type(MessageType::Query);
        msg.set_op_code(OpCode::Query);
        msg.add_query(Query::query(
            Name::from_str(zone).unwrap(),
            HRecordType::IXFR,
        ));
        let soa = HSOA::new(
            Name::from_str("ns1.").unwrap(),
            Name::from_str("admin.").unwrap(),
            client_serial,
            3600,
            900,
            604_800,
            300,
        );
        msg.add_name_server(HRecord::from_rdata(
            Name::from_str(zone).unwrap(),
            300,
            RData::SOA(soa),
        ));
        let bytes = msg.to_vec().unwrap();
        let mut stream = TcpStream::connect(server).await.unwrap();
        stream
            .write_all(&(bytes.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&bytes).await.unwrap();

        let mut answers = Vec::new();
        loop {
            let mut lenb = [0u8; 2];
            let done = tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut lenb))
                .await
                .map(|r| r.is_err())
                .unwrap_or(true);
            if done {
                break;
            }
            let mlen = u16::from_be_bytes(lenb) as usize;
            let mut mbuf = vec![0u8; mlen];
            if stream.read_exact(&mut mbuf).await.is_err() {
                break;
            }
            if let Ok(m) = Message::from_vec(&mbuf) {
                answers.extend(m.answers().to_vec());
            }
        }
        answers
    }

    /// IXFR from a known serial returns only the changed records (incremental);
    /// from an unbridgeable serial it falls back to a full AXFR.
    #[tokio::test]
    async fn ixfr_serves_incremental_then_falls_back() {
        use magnetite_core::domains::dns::model::{Record, RecordType};

        let (db, _dir, zone_id) = test_zone("inc.example.com.", 0).await;
        db.update_zone_replication(
            &zone_id,
            ZoneRole::Primary,
            &["any".to_string()],
            &[],
            false,
            &[],
            None,
        )
        .await
        .unwrap();
        // Three journaled edits → serials 2, 3, 4 (each adds one record).
        for i in 0..3 {
            let now = chrono::Utc::now();
            let rec = Record {
                id: String::new(),
                created_at: now,
                updated_at: now,
                created_by: "t".into(),
                zone: zone_id.clone(),
                name: format!("a{i}.inc.example.com."),
                ttl: 300,
                record_type: RecordType::A,
                data: serde_json::json!({ "address": format!("10.0.0.{}", i + 1) }),
                enabled: true,
            };
            let created = db.create_record(&rec).await.unwrap();
            let serial = db.bump_zone_serial(&zone_id).await.unwrap().unwrap();
            db.append_zone_journal(&zone_id, serial, std::slice::from_ref(&created), &[])
                .await
                .unwrap();
        }

        let (addr, _tx) = start_primary(db.clone()).await;

        // From serial 2: only the two newer records (serials 3 and 4).
        let incremental = ixfr_pull(addr, "inc.example.com.", 2).await;
        let inc_a = incremental
            .iter()
            .filter(|r| r.record_type() == HRecordType::A)
            .count();
        assert_eq!(
            inc_a, 2,
            "IXFR from serial 2 carries only the 2 newer records"
        );

        // From serial 0 (unbridgeable): full AXFR fallback = all three records.
        let full = ixfr_pull(addr, "inc.example.com.", 0).await;
        let full_a = full
            .iter()
            .filter(|r| r.record_type() == HRecordType::A)
            .count();
        assert_eq!(
            full_a, 3,
            "IXFR from an unbridgeable serial falls back to a full AXFR"
        );
    }

    /// Add one journaled A record to a primary zone, returning the new serial.
    async fn journaled_add(db: &Db, zone_id: &str, name: &str, addr: &str) -> u32 {
        use magnetite_core::domains::dns::model::{Record, RecordType};
        let now = chrono::Utc::now();
        let created = db
            .create_record(&Record {
                id: String::new(),
                created_at: now,
                updated_at: now,
                created_by: "t".into(),
                zone: zone_id.into(),
                name: name.into(),
                ttl: 300,
                record_type: RecordType::A,
                data: serde_json::json!({ "address": addr }),
                enabled: true,
            })
            .await
            .unwrap();
        let serial = db.bump_zone_serial(zone_id).await.unwrap().unwrap();
        db.append_zone_journal(zone_id, serial, std::slice::from_ref(&created), &[])
            .await
            .unwrap();
        serial
    }

    /// A secondary first AXFRs a zone, then applies an incremental IXFR after the
    /// primary changes.
    #[tokio::test]
    async fn secondary_applies_incremental_ixfr() {
        // Primary with three records (serial 4).
        let (pdb, _pdir, pzone) = test_zone("mirror.example.com.", 0).await;
        pdb.update_zone_replication(
            &pzone,
            ZoneRole::Primary,
            &["any".to_string()],
            &[],
            false,
            &[],
            None,
        )
        .await
        .unwrap();
        for i in 0..3 {
            journaled_add(
                &pdb,
                &pzone,
                &format!("a{i}.mirror.example.com."),
                "10.0.0.1",
            )
            .await;
        }
        let (addr, _tx) = start_primary(pdb.clone()).await;

        // Secondary pointing at the primary.
        let sdir = tempfile::tempdir().unwrap();
        let sdb = Db::connect(sdir.path().join("db")).await.unwrap();
        let szone = sdb
            .create_zone("mirror.example.com.", &Soa::default(), true, "t")
            .await
            .unwrap();
        sdb.update_zone_replication(
            &szone.id,
            ZoneRole::Secondary,
            &[],
            &[],
            false,
            &[addr.to_string()],
            None,
        )
        .await
        .unwrap();

        // First refresh: full AXFR → 3 records at serial 4.
        let z = sdb.get_zone(&szone.id).await.unwrap().unwrap();
        refresh_secondary(&sdb, &z).await;
        assert_eq!(sdb.list_records(&szone.id).await.unwrap().len(), 3);
        let z = sdb.get_zone(&szone.id).await.unwrap().unwrap();
        assert_eq!(z.soa.serial, 4);
        assert!(z.transfer_state.as_ref().unwrap().last_ok);

        // Primary adds a record (serial 5).
        journaled_add(&pdb, &pzone, "a3.mirror.example.com.", "10.0.0.9").await;

        // Second refresh: incremental IXFR applies just the new record.
        let z = sdb.get_zone(&szone.id).await.unwrap().unwrap();
        refresh_secondary(&sdb, &z).await;
        assert_eq!(
            sdb.list_records(&szone.id).await.unwrap().len(),
            4,
            "IXFR should have added the new record"
        );
        let z = sdb.get_zone(&szone.id).await.unwrap().unwrap();
        assert_eq!(z.soa.serial, 5);
    }
}
