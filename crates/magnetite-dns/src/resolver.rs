//! Authoritative resolution over the shared DB.
//!
//! [`resolve_in`] is a **pure** function over an in-memory [`Snapshot`], so the
//! answer logic is unit-testable without sockets or a DB. [`load_snapshot`]
//! reads the current zones/records and RPZ rules from magnetite-db.
//!
//! Implemented: RPZ policy (nxdomain/nodata/drop/redirect), authoritative
//! answers for A/AAAA/CNAME/MX/NS/PTR/TXT, apex SOA, RFC 4592 wildcards,
//! bounded in-zone CNAME chasing, and SOA in the authority section of negative
//! (NXDOMAIN/NODATA) responses (RFC 2308). REFUSED for out-of-zone names.
//!
//! Deferred to later increments: DNSSEC, recursion/forwarding, caching, GeoDNS,
//! DNS64, AXFR, SRV/CAA rdata.

use magnetite_core::domains::dns::model::{Record, RecordType, RpzAction, RpzRule, Soa, Zone};
use magnetite_core::domains::dns::validate::normalize_name;
use magnetite_db::{Db, DbResult};

/// A zone plus its records, as loaded for resolution.
#[derive(Clone)]
pub struct ZoneData {
    pub zone: Zone,
    pub records: Vec<Record>,
}

/// Everything resolution needs: the authoritative zones and the RPZ policy.
#[derive(Clone, Default)]
pub struct Snapshot {
    pub zones: Vec<ZoneData>,
    pub rpz: Vec<RpzRule>,
}

/// What the client asked for, mapped from the wire query type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryType {
    Record(RecordType),
    Soa,
    /// `ANY`/`*` — return every record at the name.
    Any,
    /// A type we don't serve authoritative rdata for (e.g. DNSKEY).
    Other,
}

/// Response code decided by resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rcode {
    NoError,
    NxDomain,
    Refused,
}

/// The outcome of resolving one question, as plain data (converted to wire
/// records by the `wire` module).
#[derive(Debug, Clone)]
pub struct Resolution {
    pub rcode: Rcode,
    pub authoritative: bool,
    /// RPZ `drop`: the server should send no reply at all.
    pub drop: bool,
    /// Whether this outcome came from an RPZ rule (for query-log source).
    pub from_rpz: bool,
    /// Answer-section records (CNAME chain already expanded).
    pub answers: Vec<Record>,
    /// A positive SOA answer (SOA query at apex): (apex fqdn, soa).
    pub soa_answer: Option<(String, Soa)>,
    /// SOA for the AUTHORITY section of a negative response (RFC 2308).
    pub authority_soa: Option<(String, Soa)>,
}

impl Resolution {
    fn base() -> Self {
        Self {
            rcode: Rcode::NoError,
            authoritative: false,
            drop: false,
            from_rpz: false,
            answers: Vec::new(),
            soa_answer: None,
            authority_soa: None,
        }
    }
    fn refused() -> Self {
        Self {
            rcode: Rcode::Refused,
            ..Self::base()
        }
    }
    fn dropped() -> Self {
        Self {
            drop: true,
            ..Self::base()
        }
    }
    fn answers(answers: Vec<Record>) -> Self {
        Self {
            authoritative: true,
            answers,
            ..Self::base()
        }
    }
    /// A negative authoritative response carrying the zone SOA in AUTHORITY.
    fn negative(rcode: Rcode, apex: &str, soa: &Soa) -> Self {
        Self {
            rcode,
            authoritative: true,
            authority_soa: Some((apex.to_string(), soa.clone())),
            ..Self::base()
        }
    }
}

/// Load every zone (with records) and the RPZ rules into a snapshot.
pub async fn load_snapshot(db: &Db) -> DbResult<Snapshot> {
    let zones = db.list_zones().await?;
    let mut zone_data = Vec::with_capacity(zones.len());
    for zone in zones {
        // A secondary zone that has expired (not refreshed within soa.expire) is
        // no longer authoritative and must not be served (RFC 1035 §3.2.3).
        if crate::replication::secondary_expired(&zone) {
            continue;
        }
        let records = db.list_records(&zone.id).await?;
        zone_data.push(ZoneData { zone, records });
    }
    let rpz = db.list_rpz().await?;
    Ok(Snapshot {
        zones: zone_data,
        rpz,
    })
}

/// How long a loaded snapshot is reused before a rebuild. Short, so a Web-UI or
/// dynamic-update change is reflected quickly, while a flood of queries shares one
/// build instead of each re-reading every zone from the store.
const SNAPSHOT_TTL: std::time::Duration = std::time::Duration::from_secs(2);

/// A cached [`Snapshot`], shared across query handlers. Every DNS query used to
/// rebuild the snapshot from the store (`list_zones` + per-zone `list_records` +
/// `list_rpz`), so a cheap query flood amplified into unbounded DB reads. This caches
/// the snapshot for [`SNAPSHOT_TTL`] and collapses a concurrent rebuild "thundering
/// herd" to a single load; writers can [`invalidate`](Self::invalidate) for immediacy.
#[derive(Clone, Default)]
pub struct SnapshotCache {
    inner: std::sync::Arc<tokio::sync::RwLock<Option<Cached>>>,
}

struct Cached {
    at: std::time::Instant,
    snap: std::sync::Arc<Snapshot>,
}

impl SnapshotCache {
    /// The current snapshot, rebuilt from the store only when the cache is empty or
    /// older than [`SNAPSHOT_TTL`].
    ///
    /// # Errors
    /// Returns [`DbError`](magnetite_db::DbError) if a rebuild's store read fails.
    pub async fn get(&self, db: &Db) -> DbResult<std::sync::Arc<Snapshot>> {
        if let Some(c) = self.inner.read().await.as_ref() {
            if c.at.elapsed() < SNAPSHOT_TTL {
                return Ok(c.snap.clone());
            }
        }
        // Rebuild under the write lock; re-check so a herd of waiters collapses to one.
        let mut w = self.inner.write().await;
        if let Some(c) = w.as_ref() {
            if c.at.elapsed() < SNAPSHOT_TTL {
                return Ok(c.snap.clone());
            }
        }
        let snap = std::sync::Arc::new(load_snapshot(db).await?);
        *w = Some(Cached {
            at: std::time::Instant::now(),
            snap: snap.clone(),
        });
        Ok(snap)
    }

    /// Drop the cached snapshot so the next `get` rebuilds — call after a write that
    /// must be visible immediately (e.g. a dynamic update).
    pub async fn invalidate(&self) {
        *self.inner.write().await = None;
    }
}

/// Resolve one question against the snapshot (pure).
pub fn resolve_in(snapshot: &Snapshot, qname_raw: &str, qtype: QueryType) -> Resolution {
    let qname = normalize_name(qname_raw);

    // RPZ policy is applied first, regardless of whether we are authoritative.
    if let Some((action, redirect_to)) = rpz_action(&snapshot.rpz, &qname) {
        return apply_rpz(snapshot, &qname, qtype, action, redirect_to);
    }

    let Some(zd) = find_zone(&snapshot.zones, &qname) else {
        return Resolution::refused();
    };
    let apex = normalize_name(&zd.zone.name);
    let soa = &zd.zone.soa;

    // Positive SOA answer only at the apex.
    if qtype == QueryType::Soa && qname == apex {
        return Resolution {
            authoritative: true,
            soa_answer: Some((apex, soa.clone())),
            ..Resolution::base()
        };
    }

    let at = records_at(zd, &qname);
    let name_exists = qname == apex || !at.is_empty();

    if !name_exists {
        // RFC 4592 wildcard synthesis.
        if let Some(wildcard_records) = wildcard_at(zd, &qname) {
            return match qtype {
                QueryType::Record(rt) => answer_at(snapshot, &wildcard_records, rt, &apex, soa),
                QueryType::Any => Resolution::answers(wildcard_records),
                _ => Resolution::negative(Rcode::NoError, &apex, soa),
            };
        }
        return Resolution::negative(Rcode::NxDomain, &apex, soa);
    }

    match qtype {
        // SOA at a non-apex name, or an unsupported type at an existing name.
        QueryType::Soa | QueryType::Other => Resolution::negative(Rcode::NoError, &apex, soa),
        QueryType::Any => {
            // Every record at the name; the apex additionally reports its SOA.
            let all: Vec<Record> = at.iter().map(|r| (*r).clone()).collect();
            let mut res = Resolution::answers(all);
            if qname == apex {
                res.soa_answer = Some((apex.clone(), soa.clone()));
            }
            res
        }
        QueryType::Record(rt) => {
            let owned: Vec<Record> = at.iter().map(|r| (*r).clone()).collect();
            answer_at(snapshot, &owned, rt, &apex, soa)
        }
    }
}

/// Produce an answer from the records logically present at a name: exact type
/// match, else a CNAME (chased), else NODATA (with authority SOA).
fn answer_at(
    snapshot: &Snapshot,
    records: &[Record],
    rt: RecordType,
    apex: &str,
    soa: &Soa,
) -> Resolution {
    let exact: Vec<Record> = records
        .iter()
        .filter(|r| r.record_type == rt)
        .cloned()
        .collect();
    if !exact.is_empty() {
        return Resolution::answers(exact);
    }
    if rt != RecordType::Cname {
        if let Some(cname) = records.iter().find(|r| r.record_type == RecordType::Cname) {
            let mut answers = vec![cname.clone()];
            chase_cname(&snapshot.zones, cname, rt, &mut answers, 0);
            return Resolution::answers(answers);
        }
    }
    Resolution::negative(Rcode::NoError, apex, soa)
}

/// The most specific enabled zone authoritative for `qname`, if any.
pub(crate) fn find_zone<'a>(zones: &'a [ZoneData], qname: &str) -> Option<&'a ZoneData> {
    zones
        .iter()
        .filter(|z| z.zone.enabled)
        .filter(|z| {
            let apex = normalize_name(&z.zone.name);
            qname == apex || qname.ends_with(&format!(".{apex}"))
        })
        .max_by_key(|z| normalize_name(&z.zone.name).len())
}

/// Enabled records owned by exactly `name` within `zd`.
fn records_at<'a>(zd: &'a ZoneData, name: &str) -> Vec<&'a Record> {
    zd.records
        .iter()
        .filter(|r| r.enabled && normalize_name(&r.name) == name)
        .collect()
}

/// Wildcard match (RFC 4592): the closest `*.base` whose `base` is a proper
/// suffix of `qname`. Returns the wildcard's records rewritten to own `qname`.
fn wildcard_at(zd: &ZoneData, qname: &str) -> Option<Vec<Record>> {
    let mut best: Option<(usize, String)> = None;
    for r in &zd.records {
        if !r.enabled {
            continue;
        }
        let owner = normalize_name(&r.name);
        if let Some(base) = owner.strip_prefix("*.") {
            if qname.ends_with(&format!(".{base}")) {
                let len = base.len();
                if best.as_ref().is_none_or(|(l, _)| len > *l) {
                    best = Some((len, owner.clone()));
                }
            }
        }
    }
    let (_, wildcard_owner) = best?;
    let records: Vec<Record> = zd
        .records
        .iter()
        .filter(|r| r.enabled && normalize_name(&r.name) == wildcard_owner)
        .map(|r| {
            let mut clone = r.clone();
            clone.name = qname.to_string();
            clone
        })
        .collect();
    (!records.is_empty()).then_some(records)
}

/// Follow a CNAME target within our authoritative zones, appending the target's
/// records of type `rt` (or the next CNAME in the chain). Bounded to avoid loops.
fn chase_cname(
    zones: &[ZoneData],
    cname: &Record,
    rt: RecordType,
    answers: &mut Vec<Record>,
    depth: usize,
) {
    if depth >= 8 {
        return;
    }
    let Some(target) = cname.data.get("target").and_then(|v| v.as_str()) else {
        return;
    };
    let tname = normalize_name(target);
    let Some(zd) = find_zone(zones, &tname) else {
        return;
    };
    let at = records_at(zd, &tname);
    if let Some(next) = at.iter().find(|r| r.record_type == RecordType::Cname) {
        let next = (*next).clone();
        answers.push(next.clone());
        chase_cname(zones, &next, rt, answers, depth + 1);
        return;
    }
    for rec in at.iter().filter(|r| r.record_type == rt) {
        answers.push((*rec).clone());
    }
}

// ---- RPZ ------------------------------------------------------------------

/// The most specific matching enabled RPZ rule for `qname`.
fn rpz_action(rules: &[RpzRule], qname: &str) -> Option<(RpzAction, Option<String>)> {
    rules
        .iter()
        .filter(|r| r.enabled && rpz_matches(qname, &r.domain))
        .max_by_key(|r| normalize_name(&r.domain).trim_start_matches("*.").len())
        .map(|r| (r.action, r.redirect_to.clone()))
}

/// RPZ domain match: exact, or `*.suffix` covering the suffix and its
/// descendants (mirrors the source semantics).
fn rpz_matches(qname: &str, pattern: &str) -> bool {
    let pattern = normalize_name(pattern);
    if let Some(suffix) = pattern.strip_prefix("*.") {
        qname == suffix || qname.ends_with(&format!(".{suffix}"))
    } else {
        qname == pattern
    }
}

fn apply_rpz(
    snapshot: &Snapshot,
    qname: &str,
    qtype: QueryType,
    action: RpzAction,
    redirect_to: Option<String>,
) -> Resolution {
    let mut res = apply_rpz_inner(snapshot, qname, qtype, action, redirect_to);
    res.from_rpz = true;
    res
}

fn apply_rpz_inner(
    snapshot: &Snapshot,
    qname: &str,
    qtype: QueryType,
    action: RpzAction,
    redirect_to: Option<String>,
) -> Resolution {
    match action {
        RpzAction::Nxdomain => Resolution {
            rcode: Rcode::NxDomain,
            ..Resolution::base()
        },
        RpzAction::Nodata => Resolution::base(),
        RpzAction::Drop => Resolution::dropped(),
        RpzAction::Redirect => {
            let Some(target) = redirect_to.filter(|t| !t.trim().is_empty()) else {
                return Resolution {
                    rcode: Rcode::NxDomain,
                    ..Resolution::base()
                };
            };
            // Redirect via a synthesized CNAME, chased within our zones.
            let cname = synth_cname(qname, &target);
            let mut answers = vec![cname.clone()];
            if let QueryType::Record(rt) = qtype {
                if rt != RecordType::Cname {
                    chase_cname(&snapshot.zones, &cname, rt, &mut answers, 0);
                }
            }
            Resolution {
                answers,
                ..Resolution::base()
            }
        }
    }
}

fn synth_cname(qname: &str, target: &str) -> Record {
    Record {
        id: String::new(),
        created_at: chrono_now(),
        updated_at: chrono_now(),
        created_by: "rpz".into(),
        zone: String::new(),
        name: qname.to_string(),
        ttl: 60,
        record_type: RecordType::Cname,
        data: serde_json::json!({ "target": normalize_name(target) }),
        enabled: true,
    }
}

fn chrono_now() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn zone(name: &str) -> Zone {
        Zone {
            id: format!("z:{name}"),
            created_at: chrono_now(),
            updated_at: chrono_now(),
            created_by: "t".into(),
            name: name.into(),
            soa: Soa {
                mname: format!("ns1.{name}"),
                rname: format!("admin.{name}"),
                ..Soa::default()
            },
            enabled: true,
            dnssec_enabled: false,
            nsec3_enabled: false,
            role: Default::default(),
            allow_transfer: Vec::new(),
            also_notify: Vec::new(),
            notify_enabled: false,
            primaries: Vec::new(),
            tsig_key_name: None,
            transfer_state: None,
        }
    }

    fn rec(name: &str, rt: RecordType, data: serde_json::Value) -> Record {
        Record {
            id: format!("r:{name}:{}", rt.as_str()),
            created_at: chrono_now(),
            updated_at: chrono_now(),
            created_by: "t".into(),
            zone: "z:example.com".into(),
            name: name.into(),
            ttl: 300,
            record_type: rt,
            data,
            enabled: true,
        }
    }

    fn snapshot() -> Snapshot {
        Snapshot {
            zones: vec![ZoneData {
                zone: zone("example.com"),
                records: vec![
                    rec(
                        "www.example.com",
                        RecordType::A,
                        json!({"address": "192.0.2.1"}),
                    ),
                    rec(
                        "alias.example.com",
                        RecordType::Cname,
                        json!({"target": "www.example.com"}),
                    ),
                    rec(
                        "example.com",
                        RecordType::Mx,
                        json!({"preference": 10, "exchange": "mail.example.com"}),
                    ),
                    rec(
                        "*.wild.example.com",
                        RecordType::A,
                        json!({"address": "192.0.2.9"}),
                    ),
                    rec(
                        "_sip._tcp.example.com",
                        RecordType::Srv,
                        json!({"priority": 10, "weight": 20, "port": 5060, "target": "sip.example.com"}),
                    ),
                ],
            }],
            rpz: Vec::new(),
        }
    }

    fn rpz_rule(domain: &str, action: RpzAction, redirect_to: Option<&str>) -> RpzRule {
        RpzRule {
            id: format!("rpz:{domain}"),
            created_at: chrono_now(),
            updated_at: chrono_now(),
            created_by: "t".into(),
            domain: domain.into(),
            action,
            redirect_to: redirect_to.map(String::from),
            enabled: true,
        }
    }

    #[test]
    fn a_record_positive() {
        let r = resolve_in(
            &snapshot(),
            "www.example.com.",
            QueryType::Record(RecordType::A),
        );
        assert_eq!(r.rcode, Rcode::NoError);
        assert_eq!(r.answers.len(), 1);
    }

    #[test]
    fn cname_is_chased_to_a() {
        let r = resolve_in(
            &snapshot(),
            "alias.example.com",
            QueryType::Record(RecordType::A),
        );
        assert_eq!(r.answers.len(), 2);
        assert_eq!(r.answers[0].record_type, RecordType::Cname);
        assert_eq!(r.answers[1].record_type, RecordType::A);
    }

    #[test]
    fn soa_at_apex() {
        let r = resolve_in(&snapshot(), "example.com", QueryType::Soa);
        assert!(r.soa_answer.is_some());
    }

    #[test]
    fn nodata_carries_authority_soa() {
        let r = resolve_in(
            &snapshot(),
            "www.example.com",
            QueryType::Record(RecordType::Aaaa),
        );
        assert_eq!(r.rcode, Rcode::NoError);
        assert!(r.answers.is_empty());
        assert!(r.authority_soa.is_some());
    }

    #[test]
    fn nxdomain_carries_authority_soa() {
        let r = resolve_in(
            &snapshot(),
            "nope.example.com",
            QueryType::Record(RecordType::A),
        );
        assert_eq!(r.rcode, Rcode::NxDomain);
        assert!(r.authority_soa.is_some());
    }

    #[test]
    fn wildcard_synthesizes_answer() {
        let r = resolve_in(
            &snapshot(),
            "host.wild.example.com",
            QueryType::Record(RecordType::A),
        );
        assert_eq!(r.rcode, Rcode::NoError);
        assert_eq!(r.answers.len(), 1);
        assert_eq!(r.answers[0].record_type, RecordType::A);
        // Owner is rewritten to the queried name.
        assert_eq!(normalize_name(&r.answers[0].name), "host.wild.example.com");
    }

    #[test]
    fn wildcard_does_not_match_base_itself() {
        // "wild.example.com" has no exact record and the wildcard must not cover it.
        let r = resolve_in(
            &snapshot(),
            "wild.example.com",
            QueryType::Record(RecordType::A),
        );
        assert_eq!(r.rcode, Rcode::NxDomain);
    }

    #[test]
    fn refused_out_of_zone() {
        let r = resolve_in(
            &snapshot(),
            "www.other.org",
            QueryType::Record(RecordType::A),
        );
        assert_eq!(r.rcode, Rcode::Refused);
    }

    #[test]
    fn srv_resolves() {
        let r = resolve_in(
            &snapshot(),
            "_sip._tcp.example.com",
            QueryType::Record(RecordType::Srv),
        );
        assert_eq!(r.rcode, Rcode::NoError);
        assert_eq!(r.answers.len(), 1);
        assert_eq!(r.answers[0].record_type, RecordType::Srv);
    }

    #[test]
    fn any_returns_all_records_at_apex() {
        let r = resolve_in(&snapshot(), "example.com", QueryType::Any);
        assert_eq!(r.rcode, Rcode::NoError);
        assert!(r.answers.iter().any(|a| a.record_type == RecordType::Mx));
        assert!(r.soa_answer.is_some());
    }

    #[test]
    fn rpz_nxdomain_blocks() {
        let mut s = snapshot();
        s.rpz
            .push(rpz_rule("bad.example.com", RpzAction::Nxdomain, None));
        let r = resolve_in(&s, "bad.example.com", QueryType::Record(RecordType::A));
        assert_eq!(r.rcode, Rcode::NxDomain);
        assert!(!r.authoritative);
    }

    #[test]
    fn rpz_wildcard_and_drop() {
        let mut s = snapshot();
        s.rpz
            .push(rpz_rule("*.evil.example.com", RpzAction::Drop, None));
        let r = resolve_in(&s, "x.evil.example.com", QueryType::Record(RecordType::A));
        assert!(r.drop);
    }

    #[test]
    fn rpz_redirect_to_in_zone_host() {
        let mut s = snapshot();
        s.rpz.push(rpz_rule(
            "phish.example.com",
            RpzAction::Redirect,
            Some("www.example.com"),
        ));
        let r = resolve_in(&s, "phish.example.com", QueryType::Record(RecordType::A));
        assert_eq!(r.rcode, Rcode::NoError);
        // CNAME to the redirect target, then the target's A (chased in-zone).
        assert_eq!(r.answers[0].record_type, RecordType::Cname);
        assert!(r.answers.iter().any(|a| a.record_type == RecordType::A));
    }
}
