//! Wire encoding: map our core records / [`Resolution`] onto hickory-proto
//! messages. hickory owns the DNS message parsing/serialization; Magnetite only
//! decides the answers (we do not re-implement the protocol codec).

use crate::resolver::{QueryType, Rcode, Resolution};
use hickory_proto::op::{Header, Message, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CAA, CNAME, MX, NS, PTR, SOA, SRV, TXT};
use hickory_proto::rr::{Name, RData, Record as HRecord, RecordType as HRecordType};
use magnetite_core::domains::dns::model::{Record, RecordType, Soa};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Map a wire query type onto our resolution query type.
pub fn query_type_of(rt: HRecordType) -> QueryType {
    match rt {
        HRecordType::A => QueryType::Record(RecordType::A),
        HRecordType::AAAA => QueryType::Record(RecordType::Aaaa),
        HRecordType::CNAME => QueryType::Record(RecordType::Cname),
        HRecordType::MX => QueryType::Record(RecordType::Mx),
        HRecordType::TXT => QueryType::Record(RecordType::Txt),
        HRecordType::NS => QueryType::Record(RecordType::Ns),
        HRecordType::PTR => QueryType::Record(RecordType::Ptr),
        HRecordType::SRV => QueryType::Record(RecordType::Srv),
        HRecordType::CAA => QueryType::Record(RecordType::Caa),
        HRecordType::SOA => QueryType::Soa,
        HRecordType::ANY => QueryType::Any,
        _ => QueryType::Other,
    }
}

fn field<'a>(data: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    data.get(key).and_then(|v| v.as_str())
}

/// Convert a core record into a hickory resource record. Returns `None` for
/// malformed data or unrepresentable values (e.g. a CAA `iodef` tag).
pub fn to_rr(rec: &Record) -> Option<HRecord> {
    let name = Name::from_str(&rec.name).ok()?;
    let rdata = match rec.record_type {
        RecordType::A => RData::A(A(field(&rec.data, "address")?.parse::<Ipv4Addr>().ok()?)),
        RecordType::Aaaa => {
            RData::AAAA(AAAA(field(&rec.data, "address")?.parse::<Ipv6Addr>().ok()?))
        }
        RecordType::Cname => RData::CNAME(CNAME(Name::from_str(field(&rec.data, "target")?).ok()?)),
        RecordType::Ns => RData::NS(NS(Name::from_str(field(&rec.data, "nsdname")?).ok()?)),
        RecordType::Ptr => RData::PTR(PTR(Name::from_str(field(&rec.data, "ptrdname")?).ok()?)),
        RecordType::Mx => {
            // Read tolerantly: a `preference` stored as a string (e.g. before it was
            // normalized on save) must still serve, not silently drop the MX record.
            let preference = rec
                .data
                .get("preference")
                .and_then(magnetite_core::domains::dns::validate::as_u64_lenient)?
                as u16;
            let exchange = Name::from_str(field(&rec.data, "exchange")?).ok()?;
            RData::MX(MX::new(preference, exchange))
        }
        RecordType::Txt => RData::TXT(TXT::new(vec![field(&rec.data, "text")?.to_string()])),
        RecordType::Srv => {
            let (priority, weight, port, target) = parse_srv(&rec.data)?;
            RData::SRV(SRV::new(
                priority,
                weight,
                port,
                Name::from_str(&target).ok()?,
            ))
        }
        RecordType::Caa => RData::CAA(parse_caa_rdata(&rec.data)?),
    };
    Some(HRecord::from_rdata(name, rec.ttl, rdata))
}

/// Parse SRV rdata from the canonical `{priority,weight,port,target}` shape or
/// the raw `{"value":"<priority> <weight> <port> <target>"}` form.
fn parse_srv(data: &serde_json::Value) -> Option<(u16, u16, u16, String)> {
    let u16f = |k: &str| data.get(k).and_then(|v| v.as_u64()).map(|n| n as u16);
    if let (Some(p), Some(w), Some(port), Some(t)) = (
        u16f("priority"),
        u16f("weight"),
        u16f("port"),
        field(data, "target"),
    ) {
        return Some((p, w, port, t.to_string()));
    }
    let parts: Vec<&str> = field(data, "value")?.split_whitespace().collect();
    if parts.len() == 4 {
        Some((
            parts[0].parse().ok()?,
            parts[1].parse().ok()?,
            parts[2].parse().ok()?,
            parts[3].to_string(),
        ))
    } else {
        None
    }
}

/// Parse CAA rdata from the canonical `{flags,tag,value}` shape or the raw
/// `{"value":"<flags> <tag> <value>"}` form. Only `issue`/`issuewild` tags are
/// served (the common case); `iodef` and unknown tags yield `None`.
fn parse_caa_rdata(data: &serde_json::Value) -> Option<CAA> {
    let (flags, tag, value) = if let Some(tag) = field(data, "tag") {
        let flags = data.get("flags").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
        (
            flags,
            tag.to_string(),
            field(data, "value").unwrap_or("").to_string(),
        )
    } else {
        let raw = field(data, "value")?;
        let mut it = raw.splitn(3, char::is_whitespace);
        let flags = it.next()?.parse::<u8>().ok()?;
        (flags, it.next()?.to_string(), it.next()?.trim().to_string())
    };
    let critical = flags & 0x80 != 0;
    let issuer = {
        let domain = value.split(';').next().unwrap_or("").trim();
        if domain.is_empty() {
            return None;
        }
        Name::from_str(domain).ok()?
    };
    match tag.to_ascii_lowercase().as_str() {
        "issue" => Some(CAA::new_issue(critical, Some(issuer), vec![])),
        "issuewild" => Some(CAA::new_issuewild(critical, Some(issuer), vec![])),
        _ => None,
    }
}

/// Reverse of [`to_rr`]: convert a transferred hickory record into a core
/// [`Record`] for storage on a secondary. Returns `None` for the zone's SOA
/// (handled separately) and for types we do not persist (e.g. CAA/DNSSEC),
/// which are skipped on the secondary. `zone`/timestamps are filled by the
/// caller.
pub fn from_rr(rr: &HRecord) -> Option<Record> {
    use chrono::Utc;
    let (record_type, data) = match rr.data() {
        RData::A(a) => (
            RecordType::A,
            serde_json::json!({ "address": a.0.to_string() }),
        ),
        RData::AAAA(a) => (
            RecordType::Aaaa,
            serde_json::json!({ "address": a.0.to_string() }),
        ),
        RData::CNAME(c) => (
            RecordType::Cname,
            serde_json::json!({ "target": c.0.to_string() }),
        ),
        RData::NS(n) => (
            RecordType::Ns,
            serde_json::json!({ "nsdname": n.0.to_string() }),
        ),
        RData::PTR(p) => (
            RecordType::Ptr,
            serde_json::json!({ "ptrdname": p.0.to_string() }),
        ),
        RData::MX(m) => (
            RecordType::Mx,
            serde_json::json!({ "preference": m.preference(), "exchange": m.exchange().to_string() }),
        ),
        RData::TXT(t) => {
            let text: String = t
                .txt_data()
                .iter()
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .collect();
            (RecordType::Txt, serde_json::json!({ "text": text }))
        }
        RData::SRV(s) => (
            RecordType::Srv,
            serde_json::json!({
                "priority": s.priority(), "weight": s.weight(),
                "port": s.port(), "target": s.target().to_string(),
            }),
        ),
        RData::CAA(caa) => {
            // Only issue/issuewild are represented (matches `to_rr`); iodef and
            // unknown tags are skipped.
            let issuer = caa.value_as_issue().ok()?.0?;
            (
                RecordType::Caa,
                serde_json::json!({
                    "flags": caa.flags(),
                    "tag": caa.tag().as_str(),
                    "value": issuer.to_string().trim_end_matches('.'),
                }),
            )
        }
        // SOA is the transfer boundary; DNSSEC/unknown types are not persisted.
        _ => return None,
    };
    let now = Utc::now();
    Some(Record {
        id: String::new(),
        created_at: now,
        updated_at: now,
        created_by: "axfr".into(),
        zone: String::new(),
        name: rr.name().to_string(),
        ttl: rr.ttl(),
        record_type,
        data,
        enabled: true,
    })
}

/// Max resource records per AXFR message. Kept well under the 64 KiB TCP message
/// limit for typical record sizes so large zones split across messages (RFC 5936).
pub const AXFR_CHUNK_RECORDS: usize = 150;

/// Build an AXFR (full zone transfer) as one or more response messages: the RRset
/// is `SOA, every record, SOA` split into chunks of [`AXFR_CHUNK_RECORDS`]. The
/// first message opens with the SOA and the last closes with it. Signing is left
/// to the caller (chained TSIG). Returns an empty vec if the SOA is malformed.
pub fn build_axfr_messages(
    request: &Message,
    apex: &str,
    soa: &Soa,
    records: &[Record],
) -> Vec<Message> {
    let Some(boundary) = soa_rr(apex, soa) else {
        return Vec::new();
    };
    let mut all: Vec<HRecord> = Vec::with_capacity(records.len() + 2);
    all.push(boundary.clone());
    all.extend(records.iter().filter_map(to_rr));
    all.push(boundary);
    messages_from_records(request, all)
}

/// Chunk a flat record list into transfer response messages (shared by AXFR and
/// IXFR): each message repeats the request's header/question and carries up to
/// [`AXFR_CHUNK_RECORDS`] answers.
fn messages_from_records(request: &Message, records: Vec<HRecord>) -> Vec<Message> {
    records
        .chunks(AXFR_CHUNK_RECORDS)
        .map(|chunk| {
            let mut response = Message::new();
            let mut header = Header::response_from_request(request.header());
            header.set_authoritative(true);
            response.set_header(header);
            response.add_queries(request.queries().to_vec());
            for rr in chunk {
                response.add_answer(rr.clone());
            }
            response
        })
        .collect()
}

fn soa_with_serial(base: &Soa, serial: u32) -> Soa {
    let mut s = base.clone();
    s.serial = serial;
    s
}

/// Build an incremental IXFR response (RFC 1995 §4) as one or more messages:
/// header SOA(current), then per journal step `[SOA(old), deleted RRs, SOA(new),
/// added RRs]`, and a trailing SOA(current). `journal` is ordered ascending and
/// contiguous from `client_serial`.
pub fn build_ixfr_messages(
    request: &Message,
    apex: &str,
    current_soa: &Soa,
    client_serial: u32,
    journal: &[(u32, Vec<Record>, Vec<Record>)],
) -> Vec<Message> {
    let Some(header_soa) = soa_rr(apex, current_soa) else {
        return Vec::new();
    };
    let mut all: Vec<HRecord> = Vec::new();
    all.push(header_soa.clone());
    let mut prev = client_serial;
    for (serial, added, removed) in journal {
        if let Some(s) = soa_rr(apex, &soa_with_serial(current_soa, prev)) {
            all.push(s);
        }
        all.extend(removed.iter().filter_map(to_rr));
        if let Some(s) = soa_rr(apex, &soa_with_serial(current_soa, *serial)) {
            all.push(s);
        }
        all.extend(added.iter().filter_map(to_rr));
        prev = *serial;
    }
    all.push(header_soa);
    messages_from_records(request, all)
}

/// Build an "already up to date" IXFR response: a single message with just the
/// current SOA (RFC 1995 §2).
pub fn build_ixfr_uptodate(request: &Message, apex: &str, current_soa: &Soa) -> Vec<Message> {
    match soa_rr(apex, current_soa) {
        Some(soa) => messages_from_records(request, vec![soa]),
        None => Vec::new(),
    }
}

/// Build an AXFR (full zone transfer) response: SOA, every record, SOA again.
pub fn build_axfr(request: &Message, apex: &str, soa: &Soa, records: &[Record]) -> Option<Message> {
    let mut response = Message::new();
    let mut header = Header::response_from_request(request.header());
    header.set_authoritative(true);
    response.set_header(header);
    response.add_queries(request.queries().to_vec());

    let boundary = soa_rr(apex, soa)?;
    response.add_answer(boundary.clone());
    for rec in records {
        if let Some(rr) = to_rr(rec) {
            response.add_answer(rr);
        }
    }
    response.add_answer(boundary);
    Some(response)
}

/// A minimal REFUSED response (e.g. AXFR over UDP or for a non-hosted zone).
pub fn build_refused(request: &Message) -> Message {
    let mut response = Message::new();
    let mut header = Header::response_from_request(request.header());
    header.set_response_code(ResponseCode::Refused);
    response.set_header(header);
    response.add_queries(request.queries().to_vec());
    response
}

fn soa_rr(apex: &str, soa: &Soa) -> Option<HRecord> {
    let rdata = RData::SOA(SOA::new(
        Name::from_str(&soa.mname).ok()?,
        Name::from_str(&soa.rname).ok()?,
        soa.serial,
        soa.refresh as i32,
        soa.retry as i32,
        soa.expire as i32,
        soa.minimum,
    ));
    Some(HRecord::from_rdata(
        Name::from_str(apex).ok()?,
        soa.minimum,
        rdata,
    ))
}

/// Build the response message for `request` from a resolution.
pub fn build_response(request: &Message, res: &Resolution) -> Message {
    let mut response = Message::new();
    let mut header = Header::response_from_request(request.header());
    header.set_authoritative(res.authoritative);
    header.set_recursion_available(false);
    header.set_response_code(match res.rcode {
        Rcode::NoError => ResponseCode::NoError,
        Rcode::NxDomain => ResponseCode::NXDomain,
        Rcode::Refused => ResponseCode::Refused,
    });
    response.set_header(header);
    response.add_queries(request.queries().to_vec());

    if let Some((apex, soa)) = &res.soa_answer {
        if let Some(rr) = soa_rr(apex, soa) {
            response.add_answer(rr);
        }
    }
    for rec in &res.answers {
        if let Some(rr) = to_rr(rec) {
            response.add_answer(rr);
        }
    }
    // SOA in the authority section for negative responses (RFC 2308).
    if let Some((apex, soa)) = &res.authority_soa {
        if let Some(rr) = soa_rr(apex, soa) {
            response.add_name_server(rr);
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;

    fn rec(rt: RecordType, data: serde_json::Value) -> Record {
        Record {
            id: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "t".into(),
            zone: "z".into(),
            name: "x.example.com".into(),
            ttl: 300,
            record_type: rt,
            data,
            enabled: true,
        }
    }

    #[test]
    fn srv_structured_and_raw() {
        let structured = rec(
            RecordType::Srv,
            json!({"priority": 1, "weight": 2, "port": 5060, "target": "sip.example.com"}),
        );
        assert!(matches!(to_rr(&structured).unwrap().data(), RData::SRV(_)));

        let raw = rec(
            RecordType::Srv,
            json!({"value": "1 2 5060 sip.example.com"}),
        );
        assert!(matches!(to_rr(&raw).unwrap().data(), RData::SRV(_)));

        let bad = rec(RecordType::Srv, json!({"value": "not-an-srv"}));
        assert!(to_rr(&bad).is_none());
    }

    #[test]
    fn caa_issue_and_iodef() {
        let issue = rec(
            RecordType::Caa,
            json!({"flags": 0, "tag": "issue", "value": "letsencrypt.org"}),
        );
        assert!(matches!(to_rr(&issue).unwrap().data(), RData::CAA(_)));

        let raw = rec(
            RecordType::Caa,
            json!({"value": "0 issuewild letsencrypt.org"}),
        );
        assert!(matches!(to_rr(&raw).unwrap().data(), RData::CAA(_)));

        // iodef is not served (rare; would need URL parsing).
        let iodef = rec(
            RecordType::Caa,
            json!({"flags": 0, "tag": "iodef", "value": "mailto:a@b"}),
        );
        assert!(to_rr(&iodef).is_none());
    }
}
