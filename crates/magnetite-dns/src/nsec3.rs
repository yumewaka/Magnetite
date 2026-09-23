//! NSEC3 hashed authenticated denial of existence (RFC 5155).
//!
//! Like [`crate::nsec`] but the owner names are SHA-1 hashed (with salt +
//! iterations) so the zone contents can't be walked. Proving NXDOMAIN needs the
//! **closest-encloser proof** (RFC 5155 §7.2.1): an NSEC3 that MATCHES the
//! closest encloser, one that COVERS the next-closer name, and one that COVERS
//! the wildcard. NODATA is the NSEC3 that MATCHES the name. The SHA-1 iterated
//! hash and rdata serialization come from hickory. Params follow RFC 9276
//! (0 iterations, empty salt).

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use hickory_proto::dnssec::rdata::{DNSSECRData, NSEC3};
use hickory_proto::dnssec::Nsec3HashAlgorithm;
use hickory_proto::rr::{Name, RData, Record as HRecord, RecordType as HRt};
use magnetite_core::domains::dns::model::{Record, RecordType};
use magnetite_core::domains::dns::validate::normalize_name;

use crate::nsec::Denial;

/// NSEC3 iterations (RFC 9276: use 0 — extra iterations add cost, not security).
const ITERATIONS: u16 = 0;
/// NSEC3 salt (RFC 9276: empty).
const SALT: &[u8] = &[];

/// One owner name in the zone with its NSEC3 hash and the RR types present.
struct Node {
    name: String,
    hash: Vec<u8>,
    types: BTreeSet<u16>,
}

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

/// The NSEC3 hash of a name (SHA-1, salt + iterations), via hickory.
fn nsec3_hash(name: &str) -> Option<Vec<u8>> {
    let name = Name::from_str(name).ok()?;
    Some(
        Nsec3HashAlgorithm::SHA1
            .hash(SALT, &name, ITERATIONS)
            .ok()?
            .as_ref()
            .to_vec(),
    )
}

/// The zone's owner names (apex + record names + empty non-terminals), each with
/// its NSEC3 hash and type bitmap, sorted by hash — the NSEC3 chain.
fn build_chain(zone_records: &[Record], apex: &str) -> Vec<Node> {
    let apex = normalize_name(apex);

    // Real names → type set (apex carries SOA/DNSKEY/NSEC3PARAM).
    let mut real: BTreeMap<String, BTreeSet<u16>> = BTreeMap::new();
    let apex_types = real.entry(apex.clone()).or_default();
    apex_types.insert(u16::from(HRt::SOA));
    apex_types.insert(u16::from(HRt::DNSKEY));
    apex_types.insert(u16::from(HRt::NSEC3PARAM));
    for r in zone_records {
        if r.enabled {
            real.entry(normalize_name(&r.name))
                .or_default()
                .insert(u16::from(hickory_type(r.record_type)));
        }
    }
    for types in real.values_mut() {
        types.insert(u16::from(HRt::RRSIG)); // every real name's RRsets are signed
    }

    // Empty non-terminals: ancestors of real names that aren't themselves real
    // still need an NSEC3 (with an empty bitmap) for the closest-encloser proof.
    let mut names: BTreeSet<String> = real.keys().cloned().collect();
    for name in real.keys().cloned().collect::<Vec<_>>() {
        if name == apex {
            continue; // the apex has no in-zone ancestors (don't walk above it)
        }
        let mut n = name.as_str();
        while let Some((_, rest)) = n.split_once('.') {
            if rest == apex {
                break; // reached the apex; stop before leaving the zone
            }
            names.insert(rest.to_string());
            n = rest;
        }
    }

    let mut nodes: Vec<Node> = names
        .into_iter()
        .filter_map(|name| {
            let hash = nsec3_hash(&name)?;
            let types = real.get(&name).cloned().unwrap_or_default();
            Some(Node { name, hash, types })
        })
        .collect();
    nodes.sort_by(|a, b| a.hash.cmp(&b.hash));
    nodes
}

/// Index of the NSEC3 whose owner hash equals `hash(name)` (a MATCH).
fn match_index(chain: &[Node], name: &str) -> Option<usize> {
    let target = nsec3_hash(name)?;
    chain.iter().position(|n| n.hash == target)
}

/// Index of the NSEC3 that COVERS `name`: its owner hash `< hash(name) <` next
/// hash in the (wrapping) chain.
fn cover_index(chain: &[Node], name: &str) -> Option<usize> {
    let target = nsec3_hash(name)?;
    let len = chain.len();
    for i in 0..len {
        let owner = chain[i].hash.as_slice();
        let next = chain[(i + 1) % len].hash.as_slice();
        let covers = if owner < next {
            owner < target.as_slice() && target.as_slice() < next
        } else {
            // The last node wraps to the first: it covers the ends of the range.
            target.as_slice() > owner || target.as_slice() < next
        };
        if covers {
            return Some(i);
        }
    }
    None
}

/// The closest encloser of `qname`: its longest ancestor that exists in the zone.
fn closest_encloser(chain: &[Node], qname: &str, apex: &str) -> String {
    let apex = normalize_name(apex);
    let names: BTreeSet<&str> = chain.iter().map(|n| n.name.as_str()).collect();
    let mut name = normalize_name(qname);
    loop {
        match name.split_once('.') {
            Some((_, rest)) => {
                name = rest.to_string();
                if name == apex || names.contains(name.as_str()) {
                    return name;
                }
            }
            None => return apex,
        }
    }
}

/// The next-closer name: one label longer than `ce` towards `qname`.
fn next_closer(qname: &str, ce: &str) -> Option<String> {
    let qname = normalize_name(qname);
    let ce = normalize_name(ce);
    let prefix = qname.strip_suffix(&format!(".{ce}"))?;
    let label = prefix.rsplit('.').next()?;
    Some(format!("{label}.{ce}"))
}

/// Build the NSEC3 record for chain node `i`.
fn nsec3_record(chain: &[Node], i: usize, apex: &str, ttl: u32) -> Option<HRecord> {
    let node = &chain[i];
    let label = data_encoding::BASE32_DNSSEC.encode(&node.hash);
    let owner = Name::from_str(&format!("{label}.{apex}")).ok()?;
    let next_hash = chain[(i + 1) % chain.len()].hash.clone();
    let types = node.types.iter().map(|c| HRt::from(*c));
    let nsec3 = NSEC3::new(
        Nsec3HashAlgorithm::SHA1,
        false, // opt-out off
        ITERATIONS,
        SALT.to_vec(),
        next_hash,
        types,
    );
    Some(HRecord::from_rdata(
        owner,
        ttl,
        RData::DNSSEC(DNSSECRData::NSEC3(nsec3)),
    ))
}

/// The NSEC3 record(s) proving a negative answer for `qname` (RFC 5155 §7.2):
/// the MATCH for NODATA, or the closest-encloser proof (MATCH closest encloser +
/// COVER next-closer + COVER wildcard) for NXDOMAIN. `ttl` is the SOA minimum.
pub(crate) fn denial_records(
    zone_records: &[Record],
    apex: &str,
    ttl: u32,
    qname: &str,
    kind: Denial,
) -> Vec<HRecord> {
    let chain = build_chain(zone_records, apex);
    if chain.is_empty() {
        return Vec::new();
    }

    let mut indices: Vec<usize> = Vec::new();
    match kind {
        Denial::NoData => {
            if let Some(i) = match_index(&chain, qname).or_else(|| cover_index(&chain, qname)) {
                indices.push(i);
            }
        }
        Denial::NxDomain => {
            let encloser = closest_encloser(&chain, qname, apex);
            if let Some(i) = match_index(&chain, &encloser) {
                indices.push(i); // closest encloser exists
            }
            if let Some(next) = next_closer(qname, &encloser) {
                if let Some(i) = cover_index(&chain, &next) {
                    indices.push(i); // next-closer name does not
                }
            }
            if let Some(i) = cover_index(&chain, &format!("*.{encloser}")) {
                indices.push(i); // no wildcard either
            }
        }
    }
    indices.sort_unstable();
    indices.dedup();
    indices
        .into_iter()
        .filter_map(|i| nsec3_record(&chain, i, apex, ttl))
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

    fn is_nsec3(rr: &HRecord) -> bool {
        matches!(rr.data(), RData::DNSSEC(DNSSECRData::NSEC3(_)))
    }

    #[test]
    fn chain_is_hash_sorted_with_20_byte_sha1_hashes() {
        let recs = vec![
            rec("www.example.com", RecordType::A),
            rec("mail.example.com", RecordType::A),
        ];
        let chain = build_chain(&recs, "example.com");
        assert_eq!(chain.len(), 3); // apex + www + mail
        assert!(chain.iter().all(|n| n.hash.len() == 20)); // SHA-1
        assert!(chain.windows(2).all(|w| w[0].hash <= w[1].hash)); // sorted by hash
    }

    #[test]
    fn nodata_returns_the_matching_nsec3() {
        let recs = vec![rec("www.example.com", RecordType::A)];
        let nsecs = denial_records(
            &recs,
            "example.com",
            3600,
            "www.example.com",
            Denial::NoData,
        );
        assert_eq!(nsecs.len(), 1);
        assert!(is_nsec3(&nsecs[0]));
        // The owner name is base32(hash(www.example.com)).example.com.
        let expected = format!(
            "{}.example.com",
            data_encoding::BASE32_DNSSEC.encode(&nsec3_hash("www.example.com").unwrap())
        );
        assert_eq!(
            nsecs[0].name().to_string().trim_end_matches('.'),
            expected.to_ascii_lowercase().trim_end_matches('.')
        );
    }

    #[test]
    fn nxdomain_returns_closest_encloser_proof() {
        let recs = vec![
            rec("a.example.com", RecordType::A),
            rec("z.example.com", RecordType::A),
        ];
        let nsecs = denial_records(
            &recs,
            "example.com",
            3600,
            "nope.example.com",
            Denial::NxDomain,
        );
        // All returned records are NSEC3, and there is at least the closest-encloser
        // match (apex) plus the covering NSEC3(s).
        assert!(!nsecs.is_empty());
        assert!(nsecs.iter().all(is_nsec3));
        // The apex (closest encloser) NSEC3 must be present.
        let apex_owner = format!(
            "{}.example.com",
            data_encoding::BASE32_DNSSEC.encode(&nsec3_hash("example.com").unwrap())
        )
        .to_ascii_lowercase();
        let owners: Vec<String> = nsecs
            .iter()
            .map(|r| {
                r.name()
                    .to_string()
                    .trim_end_matches('.')
                    .to_ascii_lowercase()
            })
            .collect();
        assert!(
            owners.contains(&apex_owner),
            "owners {owners:?} want {apex_owner}"
        );
    }
}
