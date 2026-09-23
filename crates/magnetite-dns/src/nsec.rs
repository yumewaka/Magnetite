//! NSEC authenticated denial of existence (RFC 4034 §4 / RFC 4035 §3.1.3).
//!
//! Builds the NSEC record(s) that prove a negative answer: the NSEC *at* the
//! queried name for NODATA, or the covering NSEC(s) for NXDOMAIN (including the
//! wildcard-non-existence proof). Only the record data is built here — the RRSIGs
//! over these NSEC/SOA RRsets are added by [`crate::dnssec::sign_authority`], and
//! the type-bitmap + canonical serialization are handled by hickory's NSEC rdata.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use hickory_proto::dnssec::rdata::{DNSSECRData, NSEC};
use hickory_proto::rr::{Name, RData, Record as HRecord, RecordType as HRt};
use magnetite_core::domains::dns::model::{Record, RecordType};
use magnetite_core::domains::dns::validate::normalize_name;

/// The kind of negative answer we are proving.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Denial {
    NxDomain,
    NoData,
}

/// One owner name in the zone with the set of RR types present at it.
struct Owner {
    name: String,
    /// Canonical-ordering key (RFC 4034 §6.1): lowercased labels, reversed.
    key: Vec<Vec<u8>>,
    /// RR type codes present at the name (always includes RRSIG + NSEC).
    types: BTreeSet<u16>,
}

/// Map a magnetite record type onto the hickory type used in the NSEC bitmap.
fn hickory_type(rt: RecordType) -> HRt {
    match rt {
        RecordType::A => HRt::A,
        RecordType::Aaaa => HRt::AAAA,
        RecordType::Cname => HRt::CNAME,
        RecordType::Mx => HRt::MX,
        RecordType::Txt => HRt::TXT,
        RecordType::Ns => HRt::NS,
        RecordType::Ptr => HRt::PTR,
        RecordType::Srv => HRt::SRV,
        RecordType::Caa => HRt::CAA,
    }
}

/// Canonical DNS name ordering key (RFC 4034 §6.1): labels lowercased and
/// reversed (least-significant first). `Vec<Vec<u8>>`'s derived `Ord` then yields
/// the correct label-by-label, shorter-prefix-first comparison.
fn canonical_key(name: &str) -> Vec<Vec<u8>> {
    let mut labels: Vec<Vec<u8>> = normalize_name(name)
        .split('.')
        .filter(|l| !l.is_empty())
        .map(|l| l.as_bytes().to_vec())
        .collect();
    labels.reverse();
    labels
}

/// The zone's owner names (apex + every enabled record name), each with its type
/// bitmap, sorted into canonical order — the NSEC chain.
fn build_chain(zone_records: &[Record], apex: &str) -> Vec<Owner> {
    let apex = normalize_name(apex);
    let mut by_name: BTreeMap<String, BTreeSet<u16>> = BTreeMap::new();

    // The apex always has SOA + DNSKEY (from the signer) plus its own records.
    let apex_types = by_name.entry(apex.clone()).or_default();
    apex_types.insert(u16::from(HRt::SOA));
    apex_types.insert(u16::from(HRt::DNSKEY));

    for r in zone_records {
        if !r.enabled {
            continue;
        }
        by_name
            .entry(normalize_name(&r.name))
            .or_default()
            .insert(u16::from(hickory_type(r.record_type)));
    }

    let mut owners: Vec<Owner> = by_name
        .into_iter()
        .map(|(name, mut types)| {
            // Every signed name authenticates its own RRSIG and NSEC.
            types.insert(u16::from(HRt::RRSIG));
            types.insert(u16::from(HRt::NSEC));
            Owner {
                key: canonical_key(&name),
                name,
                types,
            }
        })
        .collect();
    owners.sort_by(|a, b| a.key.cmp(&b.key));
    owners
}

/// Index of the owner whose NSEC *covers* `target`: the greatest owner name that
/// is canonically less than `target`. Its `next` (the following owner) is greater
/// than `target`, so the pair brackets the non-existent name.
fn covering_index(owners: &[Owner], target: &[Vec<u8>]) -> Option<usize> {
    let mut found = None;
    for (i, owner) in owners.iter().enumerate() {
        if owner.key.as_slice() < target {
            found = Some(i);
        } else {
            break;
        }
    }
    found
}

/// The closest encloser of `qname`: its longest ancestor that exists in the zone
/// (falling back to the apex). Used to name the wildcard `*.<ce>` in NXDOMAIN.
fn closest_encloser(owners: &[Owner], qname: &str, apex: &str) -> String {
    let apex = normalize_name(apex);
    let existing: BTreeSet<&str> = owners.iter().map(|o| o.name.as_str()).collect();
    let mut name = normalize_name(qname);
    loop {
        match name.split_once('.') {
            Some((_, rest)) => {
                name = rest.to_string();
                if name == apex || existing.contains(name.as_str()) {
                    return name;
                }
            }
            None => return apex,
        }
    }
}

/// Build the NSEC record for `owner`, pointing at `next` in the chain.
fn nsec_record(owner: &Owner, next: &str, ttl: u32) -> Option<HRecord> {
    let owner_name = Name::from_str(&owner.name).ok()?;
    let next_name = Name::from_str(next).ok()?;
    let types = owner.types.iter().map(|c| HRt::from(*c));
    let nsec = NSEC::new(next_name, types);
    Some(HRecord::from_rdata(
        owner_name,
        ttl,
        RData::DNSSEC(DNSSECRData::NSEC(nsec)),
    ))
}

/// The NSEC record(s) that prove a negative answer for `qname` (RFC 4035 §3.1.3):
/// the NSEC at the name for NODATA, or the covering NSEC + wildcard-covering NSEC
/// for NXDOMAIN. `ttl` is the zone's SOA minimum.
pub(crate) fn denial_records(
    zone_records: &[Record],
    apex: &str,
    ttl: u32,
    qname: &str,
    kind: Denial,
) -> Vec<HRecord> {
    let owners = build_chain(zone_records, apex);
    if owners.is_empty() {
        return Vec::new();
    }
    let qkey = canonical_key(qname);

    let mut indices: Vec<usize> = Vec::new();
    match kind {
        Denial::NoData => {
            // The name exists: its own NSEC's bitmap proves the type is absent.
            if let Some(i) = owners.iter().position(|o| o.key == qkey) {
                indices.push(i);
            } else if let Some(i) = covering_index(&owners, &qkey) {
                indices.push(i);
            }
        }
        Denial::NxDomain => {
            // Prove no exact match, then that no wildcard could have synthesised one.
            if let Some(i) = covering_index(&owners, &qkey) {
                indices.push(i);
            }
            let encloser = closest_encloser(&owners, qname, apex);
            let wildcard = canonical_key(&format!("*.{encloser}"));
            if let Some(i) = covering_index(&owners, &wildcard) {
                indices.push(i);
            }
        }
    }
    indices.sort_unstable();
    indices.dedup();
    indices
        .into_iter()
        .filter_map(|i| nsec_record(&owners[i], &owners[(i + 1) % owners.len()].name, ttl))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rec(name: &str, rt: RecordType) -> Record {
        Record {
            id: String::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            created_by: "t".into(),
            zone: "z".into(),
            name: name.into(),
            ttl: 300,
            record_type: rt,
            data: json!({}),
            enabled: true,
        }
    }

    fn nsec_of(rr: &HRecord) -> &NSEC {
        match rr.data() {
            RData::DNSSEC(DNSSECRData::NSEC(n)) => n,
            other => panic!("expected NSEC, got {other:?}"),
        }
    }

    #[test]
    fn chain_is_in_canonical_order_with_apex_first() {
        let recs = vec![
            rec("z.example.com", RecordType::A),
            rec("a.example.com", RecordType::A),
            rec("foo.bar.example.com", RecordType::A),
        ];
        let owners = build_chain(&recs, "example.com");
        let names: Vec<&str> = owners.iter().map(|o| o.name.as_str()).collect();
        // Apex first, then canonical (label-reversed) order.
        assert_eq!(
            names,
            [
                "example.com",
                "a.example.com",
                "foo.bar.example.com",
                "z.example.com"
            ]
        );
    }

    #[test]
    fn nodata_returns_the_nsec_at_the_name() {
        let recs = vec![rec("www.example.com", RecordType::A)];
        // AAAA at www (which has only A) → NODATA.
        let nsecs = denial_records(
            &recs,
            "example.com",
            3600,
            "www.example.com",
            Denial::NoData,
        );
        assert_eq!(nsecs.len(), 1);
        assert_eq!(
            nsecs[0].name().to_string().trim_end_matches('.'),
            "www.example.com"
        );
        let bitmap = nsec_of(&nsecs[0]).type_bit_maps().collect::<Vec<_>>();
        assert!(bitmap.contains(&HRt::A));
        assert!(!bitmap.contains(&HRt::AAAA)); // proves AAAA is absent
        assert!(bitmap.contains(&HRt::RRSIG) && bitmap.contains(&HRt::NSEC));
    }

    #[test]
    fn nxdomain_returns_covering_and_wildcard_nsecs() {
        let recs = vec![
            rec("a.example.com", RecordType::A),
            rec("z.example.com", RecordType::A),
        ];
        // "m.example.com" doesn't exist → NXDOMAIN.
        let nsecs = denial_records(
            &recs,
            "example.com",
            3600,
            "m.example.com",
            Denial::NxDomain,
        );
        // The a→z NSEC covers "m"; the apex NSEC (example.com → a) covers "*.example.com".
        let owners: Vec<String> = nsecs
            .iter()
            .map(|r| r.name().to_string().trim_end_matches('.').to_string())
            .collect();
        assert!(
            owners.contains(&"a.example.com".to_string()),
            "covering NSEC: {owners:?}"
        );
        assert!(
            owners.contains(&"example.com".to_string()),
            "wildcard NSEC: {owners:?}"
        );
    }
}
