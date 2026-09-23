//! GeoDNS: subnet/region-based answer routing. A [`GeoRule`] owns one
//! `(name, record_type)` and serves per-region data when the client IP falls in
//! a region's CIDRs, else the rule's default data. This is split-horizon /
//! client-subnet routing (no external GeoIP database); country-level GeoIP would
//! be a further extension. Client identity is the query source IP — EDNS Client
//! Subnet (ECS) is not yet consulted, and geo answers are not DNSSEC-signed.

use crate::resolver::{Rcode, Resolution};
use chrono::Utc;
use hickory_proto::rr::RecordType as HRecordType;
use magnetite_core::domains::dns::model::{GeoRule, Record, RecordType};
use serde_json::Value;
use std::net::IpAddr;

/// The geo answer for a client IP: the data of the first region whose CIDRs
/// contain the client, else the rule's default data. Uses the first rule.
pub(crate) fn resolve_geo(rules: &[GeoRule], client_ip: IpAddr) -> Option<(u32, Value)> {
    let rule = rules.first()?;
    for region in &rule.regions {
        if region.cidrs.iter().any(|c| cidr_contains(c, client_ip)) {
            return Some((rule.ttl, region.data.clone()));
        }
    }
    Some((rule.ttl, rule.default_data.clone()))
}

/// Build an authoritative single-answer resolution from geo data.
pub(crate) fn geo_resolution(qname: &str, rt: RecordType, ttl: u32, data: Value) -> Resolution {
    let now = Utc::now();
    let record = Record {
        id: String::new(),
        created_at: now,
        updated_at: now,
        created_by: "geodns".into(),
        zone: String::new(),
        name: qname.to_string(),
        ttl,
        record_type: rt,
        data,
        enabled: true,
    };
    Resolution {
        rcode: Rcode::NoError,
        authoritative: true,
        drop: false,
        from_rpz: false,
        answers: vec![record],
        soa_answer: None,
        authority_soa: None,
    }
}

/// Map a hickory query type to a core record type (the geo-routable types).
pub(crate) fn core_record_type(t: HRecordType) -> Option<RecordType> {
    Some(match t {
        HRecordType::A => RecordType::A,
        HRecordType::AAAA => RecordType::Aaaa,
        HRecordType::CNAME => RecordType::Cname,
        HRecordType::MX => RecordType::Mx,
        HRecordType::TXT => RecordType::Txt,
        HRecordType::NS => RecordType::Ns,
        HRecordType::PTR => RecordType::Ptr,
        HRecordType::SRV => RecordType::Srv,
        HRecordType::CAA => RecordType::Caa,
        _ => return None,
    })
}

/// Whether `cidr` (`10.0.0.0/8`, `2001:db8::/32`, or a bare IP) contains `addr`.
pub(crate) fn cidr_contains(cidr: &str, addr: IpAddr) -> bool {
    let Some((net, prefix)) = cidr.split_once('/') else {
        return cidr.parse::<IpAddr>().map(|ip| ip == addr).unwrap_or(false);
    };
    let Ok(prefix_len) = prefix.parse::<u32>() else {
        return false;
    };
    match (net.parse::<IpAddr>(), addr) {
        (Ok(IpAddr::V4(n)), IpAddr::V4(c)) => {
            if prefix_len > 32 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0
            } else {
                !0u32 << (32 - prefix_len)
            };
            (u32::from(n) & mask) == (u32::from(c) & mask)
        }
        (Ok(IpAddr::V6(n)), IpAddr::V6(c)) => {
            if prefix_len > 128 {
                return false;
            }
            let mask = if prefix_len == 0 {
                0
            } else {
                !0u128 << (128 - prefix_len)
            };
            (u128::from(n) & mask) == (u128::from(c) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use magnetite_core::domains::dns::model::GeoRegion;
    use serde_json::json;
    use std::str::FromStr;

    fn rule() -> GeoRule {
        GeoRule {
            id: "g1".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "t".into(),
            zone: "z".into(),
            name: "www.example.com".into(),
            record_type: RecordType::A,
            ttl: 60,
            default_data: json!({"address": "203.0.113.1"}),
            regions: vec![
                GeoRegion {
                    region: "internal".into(),
                    cidrs: vec!["10.0.0.0/8".into()],
                    data: json!({"address": "10.0.0.5"}),
                },
                GeoRegion {
                    region: "eu".into(),
                    cidrs: vec!["192.168.0.0/16".into()],
                    data: json!({"address": "192.168.1.9"}),
                },
            ],
            enabled: true,
        }
    }

    #[test]
    fn cidr_matching() {
        assert!(cidr_contains("10.0.0.0/8", "10.1.2.3".parse().unwrap()));
        assert!(!cidr_contains("10.0.0.0/8", "11.0.0.1".parse().unwrap()));
        assert!(cidr_contains(
            "2001:db8::/32",
            "2001:db8::1".parse().unwrap()
        ));
        assert!(cidr_contains("127.0.0.1", "127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn region_match_then_default() {
        let rs = [rule()];
        // Internal client → internal region.
        let (_, d) = resolve_geo(&rs, IpAddr::from_str("10.9.9.9").unwrap()).unwrap();
        assert_eq!(d["address"], "10.0.0.5");
        // EU client → eu region.
        let (_, d) = resolve_geo(&rs, IpAddr::from_str("192.168.5.5").unwrap()).unwrap();
        assert_eq!(d["address"], "192.168.1.9");
        // No region → default.
        let (ttl, d) = resolve_geo(&rs, IpAddr::from_str("8.8.8.8").unwrap()).unwrap();
        assert_eq!(d["address"], "203.0.113.1");
        assert_eq!(ttl, 60);
    }

    #[test]
    fn maps_record_types() {
        assert_eq!(core_record_type(HRecordType::A), Some(RecordType::A));
        assert_eq!(core_record_type(HRecordType::AAAA), Some(RecordType::Aaaa));
        assert_eq!(core_record_type(HRecordType::DNSKEY), None);
    }
}
