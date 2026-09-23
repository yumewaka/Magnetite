//! RFC 2136 Dynamic DNS Update — the update engine: parse an UPDATE message, check
//! its prerequisites, and apply its additions/deletions to the zone.
//!
//! Authorization (who may update) is a separate concern layered on top: Active
//! Directory secures dynamic updates with GSS-TSIG (RFC 3645), verified before this
//! engine runs. This module is the mechanism only, so it can be unit-tested in
//! isolation and reused regardless of how the request was authenticated.
//!
//! Message sections (RFC 2136 §2): the *zone* is the single SOA query, the
//! *prerequisites* ride in the answer section, and the *updates* in the authority
//! (name-server) section — matching hickory's [`Message`] accessors.

use hickory_proto::op::{Header, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, Record as HRecord, RecordType as HRecordType};
use magnetite_core::domains::dns::model::{Record, RecordType};
use magnetite_db::Db;

/// Normalize a DNS name for comparison: drop the root dot and lower-case it.
fn norm(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Map a hickory record type to the stored [`RecordType`], or `None` for types the
/// directory does not persist.
fn core_type(t: HRecordType) -> Option<RecordType> {
    Some(match t {
        HRecordType::A => RecordType::A,
        HRecordType::AAAA => RecordType::Aaaa,
        HRecordType::CNAME => RecordType::Cname,
        HRecordType::NS => RecordType::Ns,
        HRecordType::PTR => RecordType::Ptr,
        HRecordType::MX => RecordType::Mx,
        HRecordType::TXT => RecordType::Txt,
        HRecordType::SRV => RecordType::Srv,
        HRecordType::CAA => RecordType::Caa,
        _ => return None,
    })
}

/// Process an RFC 2136 UPDATE, returning the response message (with the RCODE set).
/// Callers MUST authorize the request (GSS-TSIG) before invoking this.
pub async fn handle_update(db: &Db, request: &Message) -> Message {
    let rcode = apply(db, request).await.unwrap_or_else(|code| code);
    let mut header = Header::response_from_request(request.header());
    header.set_op_code(OpCode::Update);
    header.set_message_type(MessageType::Response);
    header.set_response_code(rcode);
    let mut resp = Message::new();
    resp.set_header(header);
    resp.add_queries(request.queries().to_vec());
    resp
}

/// The engine: resolve the zone, check prerequisites, then apply the updates.
/// Returns the success RCODE, or an error RCODE via `Err`.
async fn apply(db: &Db, request: &Message) -> Result<ResponseCode, ResponseCode> {
    // Zone section: exactly one SOA query naming the zone to update (RFC 2136 §3.1).
    let zone_q = request.queries().first().ok_or(ResponseCode::FormErr)?;
    if zone_q.query_type() != HRecordType::SOA {
        return Err(ResponseCode::FormErr);
    }
    let zone_name = norm(&zone_q.name().to_string());
    let zone = db
        .list_zones()
        .await
        .map_err(|_| ResponseCode::ServFail)?
        .into_iter()
        .find(|z| norm(&z.name) == zone_name)
        .ok_or(ResponseCode::NotAuth)?;

    let existing = db
        .list_records(&zone.id)
        .await
        .map_err(|_| ResponseCode::ServFail)?;

    // Prerequisite section (RFC 2136 §3.2): all must hold before any update.
    for pre in request.answers() {
        check_prerequisite(pre, &existing)?;
    }

    // Update prescan (RFC 2136 §3.4.1): every update name must be in the zone.
    for up in request.name_servers() {
        if !in_zone(&norm(&up.name().to_string()), &zone_name) {
            return Err(ResponseCode::NotZone);
        }
    }

    // Apply the updates (RFC 2136 §3.4.2).
    for up in request.name_servers() {
        apply_one(db, &zone.id, up, &existing).await?;
    }
    Ok(ResponseCode::NoError)
}

/// Whether `name` is at or below `zone` (both already normalized).
fn in_zone(name: &str, zone: &str) -> bool {
    name == zone || name.ends_with(&format!(".{zone}"))
}

/// Check one prerequisite RR (RFC 2136 §3.2). The value-independent forms (class
/// ANY / NONE) are supported; the value-dependent form (zone class) requires the
/// exact RR to be present.
fn check_prerequisite(pre: &HRecord, existing: &[Record]) -> Result<(), ResponseCode> {
    let name = norm(&pre.name().to_string());
    let name_in_use = existing.iter().any(|r| norm(&r.name) == name);
    let ty = core_type(pre.record_type());
    let rrset_exists = ty.is_some_and(|t| {
        existing
            .iter()
            .any(|r| norm(&r.name) == name && r.record_type == t)
    });

    match pre.dns_class() {
        // "Name is in use" / "RRset exists (value independent)".
        DNSClass::ANY => {
            if pre.record_type() == HRecordType::ANY {
                if !name_in_use {
                    return Err(ResponseCode::NXDomain);
                }
            } else if !rrset_exists {
                return Err(ResponseCode::NXRRSet);
            }
        }
        // "Name is not in use" / "RRset does not exist".
        DNSClass::NONE => {
            if pre.record_type() == HRecordType::ANY {
                if name_in_use {
                    return Err(ResponseCode::YXDomain);
                }
            } else if rrset_exists {
                return Err(ResponseCode::YXRRSet);
            }
        }
        // "RRset exists (value dependent)": the exact RR must be present.
        _ => {
            let Some(rec) = crate::wire::from_rr(pre) else {
                return Err(ResponseCode::FormErr);
            };
            if !existing.iter().any(|r| same_rr(r, &rec)) {
                return Err(ResponseCode::NXRRSet);
            }
        }
    }
    Ok(())
}

/// Apply one update RR (RFC 2136 §3.4.2): add, delete an RRset, delete all RRsets
/// at a name, or delete a single RR.
async fn apply_one(
    db: &Db,
    zone_id: &str,
    up: &HRecord,
    existing: &[Record],
) -> Result<(), ResponseCode> {
    let name = norm(&up.name().to_string());
    match up.dns_class() {
        // Add an RR (class = zone class). Skip if an identical RR already exists.
        DNSClass::IN => {
            let Some(mut rec) = crate::wire::from_rr(up) else {
                return Err(ResponseCode::FormErr);
            };
            rec.zone = zone_id.to_string();
            rec.created_by = "dynamic-update".into();
            if !existing.iter().any(|r| same_rr(r, &rec)) {
                db.create_record(&rec)
                    .await
                    .map_err(|_| ResponseCode::ServFail)?;
            }
        }
        // Delete an RRset (type-specific) or all RRsets at the name.
        DNSClass::ANY => {
            let ty = core_type(up.record_type());
            for r in existing.iter().filter(|r| norm(&r.name) == name) {
                let matches = match up.record_type() {
                    HRecordType::ANY => true,
                    _ => ty == Some(r.record_type),
                };
                if matches {
                    db.delete_record(&r.id)
                        .await
                        .map_err(|_| ResponseCode::ServFail)?;
                }
            }
        }
        // Delete a single RR (class NONE): remove the exact matching record.
        DNSClass::NONE => {
            if let Some(rec) = crate::wire::from_rr(up) {
                for r in existing.iter().filter(|r| same_rr(r, &rec)) {
                    db.delete_record(&r.id)
                        .await
                        .map_err(|_| ResponseCode::ServFail)?;
                }
            }
        }
        _ => return Err(ResponseCode::FormErr),
    }
    Ok(())
}

/// Whether two records are the same RR: same name, type and rdata (ignoring TTL).
fn same_rr(a: &Record, b: &Record) -> bool {
    norm(&a.name) == norm(&b.name) && a.record_type == b.record_type && a.data == b.data
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, OpCode, Query};
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{DNSClass, Name, RData, Record as HRecord, RecordType as HRecordType};
    use magnetite_core::domains::dns::model::Soa;
    use std::str::FromStr;

    async fn seeded_zone() -> (Db, tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        let zone = db
            .create_zone("example.com", &Soa::default(), true, "test")
            .await
            .unwrap();
        (db, dir, zone.id)
    }

    fn update_msg(records: Vec<HRecord>, prereqs: Vec<HRecord>) -> Message {
        let mut m = Message::new();
        m.set_op_code(OpCode::Update);
        m.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            HRecordType::SOA,
        ));
        m.add_answers(prereqs);
        m.add_name_servers(records);
        m
    }

    fn a_record(name: &str, ip: [u8; 4], class: DNSClass, ttl: u32) -> HRecord {
        let mut r = HRecord::from_rdata(Name::from_str(name).unwrap(), ttl, RData::A(A(ip.into())));
        r.set_dns_class(class);
        r
    }

    #[tokio::test]
    async fn add_creates_an_a_record() {
        let (db, _d, zid) = seeded_zone().await;
        let msg = update_msg(
            vec![a_record(
                "win10.example.com.",
                [10, 0, 0, 5],
                DNSClass::IN,
                300,
            )],
            vec![],
        );
        let resp = handle_update(&db, &msg).await;
        assert_eq!(resp.response_code(), ResponseCode::NoError);

        let recs = db.list_records(&zid).await.unwrap();
        let a = recs
            .iter()
            .find(|r| norm(&r.name) == "win10.example.com")
            .expect("A record added");
        assert_eq!(a.record_type, RecordType::A);
        assert_eq!(a.data["address"], "10.0.0.5");

        // Re-adding the identical RR is idempotent (no duplicate).
        let resp2 = handle_update(&db, &msg).await;
        assert_eq!(resp2.response_code(), ResponseCode::NoError);
        let count = db
            .list_records(&zid)
            .await
            .unwrap()
            .iter()
            .filter(|r| norm(&r.name) == "win10.example.com")
            .count();
        assert_eq!(count, 1, "no duplicate on re-add");
    }

    #[tokio::test]
    async fn delete_rrset_removes_matching_records() {
        let (db, _d, zid) = seeded_zone().await;
        handle_update(
            &db,
            &update_msg(
                vec![a_record(
                    "win10.example.com.",
                    [10, 0, 0, 5],
                    DNSClass::IN,
                    300,
                )],
                vec![],
            ),
        )
        .await;
        // Delete the A RRset (class ANY, TTL 0, no rdata → here just the type).
        let mut del = HRecord::update0(
            Name::from_str("win10.example.com.").unwrap(),
            0,
            HRecordType::A,
        );
        del.set_dns_class(DNSClass::ANY);
        let resp = handle_update(&db, &update_msg(vec![del], vec![])).await;
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert!(
            db.list_records(&zid)
                .await
                .unwrap()
                .iter()
                .all(|r| norm(&r.name) != "win10.example.com"),
            "A RRset removed"
        );
    }

    #[tokio::test]
    async fn prerequisite_name_not_in_use_blocks_when_present() {
        let (db, _d, _zid) = seeded_zone().await;
        handle_update(
            &db,
            &update_msg(
                vec![a_record(
                    "win10.example.com.",
                    [10, 0, 0, 5],
                    DNSClass::IN,
                    300,
                )],
                vec![],
            ),
        )
        .await;
        // Prerequisite "name is not in use" (class NONE, type ANY) must now fail.
        let mut pre = HRecord::update0(
            Name::from_str("win10.example.com.").unwrap(),
            0,
            HRecordType::ANY,
        );
        pre.set_dns_class(DNSClass::NONE);
        let resp = handle_update(
            &db,
            &update_msg(
                vec![a_record(
                    "win10.example.com.",
                    [10, 0, 0, 9],
                    DNSClass::IN,
                    300,
                )],
                vec![pre],
            ),
        )
        .await;
        assert_eq!(resp.response_code(), ResponseCode::YXDomain);
    }

    #[tokio::test]
    async fn update_outside_the_zone_is_refused() {
        let (db, _d, _zid) = seeded_zone().await;
        let resp = handle_update(
            &db,
            &update_msg(
                vec![a_record(
                    "host.other.test.",
                    [1, 2, 3, 4],
                    DNSClass::IN,
                    300,
                )],
                vec![],
            ),
        )
        .await;
        assert_eq!(resp.response_code(), ResponseCode::NotZone);
    }

    #[tokio::test]
    async fn update_to_unknown_zone_is_not_authoritative() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        let mut m = Message::new();
        m.set_op_code(OpCode::Update);
        m.add_query(Query::query(
            Name::from_str("nope.test.").unwrap(),
            HRecordType::SOA,
        ));
        assert_eq!(
            handle_update(&db, &m).await.response_code(),
            ResponseCode::NotAuth
        );
    }
}
