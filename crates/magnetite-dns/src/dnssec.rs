//! DNSSEC online signing (ECDSA P-256 SHA-256, algorithm 13).
//!
//! Each DNSSEC-enabled zone has a single combined signing key (CSK — both the
//! zone-signing and key-signing key), generated on first use and stored
//! server-side. When a query carries the DNSSEC-OK (DO) bit we sign the positive
//! answer RRsets with RRSIGs and serve the zone's DNSKEY at the apex.
//!
//! Not yet included: NSEC/NSEC3 authenticated denial of existence for negative
//! answers, key rollover, and DS export to the parent (a read-only helper).

use hickory_proto::dnssec::crypto::EcdsaSigningKey;
use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY, RRSIG};
use hickory_proto::dnssec::{Algorithm, SigSigner, SigningKey, TBS};
use hickory_proto::op::{Header, Message, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordSet, RecordType};
use magnetite_db::Db;
use rustls_pki_types::PrivatePkcs8KeyDer;
use std::str::FromStr;
use std::time::Duration as StdDuration;
use time::{Duration as TimeDuration, OffsetDateTime};

const ALGORITHM: Algorithm = Algorithm::ECDSAP256SHA256;
const SIG_VALIDITY_DAYS: i64 = 14;
const DNSKEY_TTL: u32 = 3600;

/// A zone's signing material: the `SigSigner`, its DNSKEY, and the apex name.
pub(crate) struct ZoneSigner {
    signer: SigSigner,
    dnskey: DNSKEY,
    apex: Name,
    key_tag: u16,
}

impl ZoneSigner {
    /// Build a signer from a PKCS#8 DER private key for `apex` (an FQDN).
    fn from_der(apex: &str, der: Vec<u8>) -> Option<Self> {
        // Force an absolute (FQDN) apex so signatures use the canonical name.
        let apex = Name::from_str(&format!("{}.", apex.trim_end_matches('.'))).ok()?;
        let pkcs8 = PrivatePkcs8KeyDer::from(der);
        let ecdsa = EcdsaSigningKey::from_pkcs8(&pkcs8, ALGORITHM).ok()?;
        let public = ecdsa.to_public_key().ok()?;
        // Combined signing key: zone key + secure entry point.
        let dnskey = DNSKEY::new(true, true, false, public);
        let boxed: Box<dyn SigningKey> = Box::new(ecdsa);
        let signer = SigSigner::dnssec(
            dnskey.clone(),
            boxed,
            apex.clone(),
            StdDuration::from_secs(SIG_VALIDITY_DAYS as u64 * 86_400),
        );
        let key_tag = signer.calculate_key_tag().ok()?;
        Some(Self {
            signer,
            dnskey,
            apex,
            key_tag,
        })
    }

    /// The DNSKEY resource record served at the zone apex.
    fn dnskey_record(&self) -> Record {
        Record::from_rdata(
            self.apex.clone(),
            DNSKEY_TTL,
            RData::DNSSEC(DNSSECRData::DNSKEY(self.dnskey.clone())),
        )
    }
}

/// Load a zone's signer, generating and persisting a key on first use.
pub(crate) async fn load_signer(db: &Db, apex: &str) -> Option<ZoneSigner> {
    if let Ok(Some(der)) = db.get_zone_dnssec_key(apex).await {
        if let Some(signer) = ZoneSigner::from_der(apex, der) {
            return Some(signer);
        }
    }
    // Generate a fresh key, store it, then re-read (stabilises a concurrent
    // first-use race so all responders converge on one stored key).
    let pkcs8 = EcdsaSigningKey::generate_pkcs8(ALGORITHM).ok()?;
    let der = pkcs8.secret_pkcs8_der().to_vec();
    let _ = db.put_zone_dnssec_key(apex, &der).await;
    let der = db
        .get_zone_dnssec_key(apex)
        .await
        .ok()
        .flatten()
        .unwrap_or(der);
    ZoneSigner::from_der(apex, der)
}

/// Public DNSSEC key material for the management UI: the zone's DNSKEY (which
/// the operator uses to publish a DS record at the parent) plus its key tag.
pub struct ZoneKeyInfo {
    /// DNSKEY key tag, referenced by the parent DS record.
    pub key_tag: u16,
    /// Zone-file presentation of the apex DNSKEY resource record.
    pub dnskey_record: String,
}

/// Ensure a DNSSEC signing key exists for `apex` (generating and persisting one
/// on first call) and return its public DNSKEY material. Returns `None` if key
/// initialization fails. The private key never leaves the server.
pub async fn ensure_zone_key(db: &Db, apex: &str) -> Option<ZoneKeyInfo> {
    let signer = load_signer(db, apex).await?;
    Some(ZoneKeyInfo {
        key_tag: signer.key_tag,
        dnskey_record: signer.dnskey_record().to_string(),
    })
}

/// Produce the RRSIG record covering one RRset, or `None` if signing fails.
fn sign_rrset(rrset: &RecordSet, signer: &ZoneSigner) -> Option<Record> {
    let now = OffsetDateTime::now_utc();
    let inception = now - TimeDuration::hours(1);
    let expiration = now + TimeDuration::days(SIG_VALIDITY_DAYS);
    let tbs = TBS::from_rrset(rrset, DNSClass::IN, inception, expiration, &signer.signer).ok()?;
    let signature = signer.signer.sign(&tbs).ok()?;
    let rrsig = RRSIG::new(
        rrset.record_type(),
        ALGORITHM,
        rrset.name().num_labels(),
        rrset.ttl(),
        expiration.unix_timestamp() as u32,
        inception.unix_timestamp() as u32,
        signer.key_tag,
        signer.apex.clone(),
        signature,
    );
    Some(Record::from_rdata(
        rrset.name().clone(),
        rrset.ttl(),
        RData::DNSSEC(DNSSECRData::RRSIG(rrsig)),
    ))
}

/// Sign every answer RRset in `response`, appending an RRSIG after each.
pub(crate) fn sign_answers(response: &mut Message, signer: &ZoneSigner) {
    let answers = response.take_answers();

    // Group consecutive records by (name, type), preserving order.
    let mut groups: Vec<(Name, RecordType, u32, Vec<Record>)> = Vec::new();
    for rec in answers {
        match groups
            .iter_mut()
            .find(|(n, t, _, _)| n == rec.name() && *t == rec.record_type())
        {
            Some(g) => g.3.push(rec),
            None => groups.push((rec.name().clone(), rec.record_type(), rec.ttl(), vec![rec])),
        }
    }

    for (name, rtype, ttl, recs) in groups {
        let mut rrset = RecordSet::new(name, rtype, 0);
        let _ = ttl;
        for r in &recs {
            rrset.insert(r.clone(), 0);
        }
        let rrsig = sign_rrset(&rrset, signer);
        for r in recs {
            response.add_answer(r);
        }
        if let Some(sig) = rrsig {
            response.add_answer(sig);
        }
    }
    // NB: echoing an EDNS OPT (DO) on the response drops the answer-section
    // RRSIGs on hickory 0.25's wire round-trip, so it is intentionally omitted.
}

/// Sign every RRset in the AUTHORITY section (the SOA and any NSEC records of a
/// negative response), appending an RRSIG after each — authenticated denial of
/// existence (RFC 4035 §3.1.3). Mirrors [`sign_answers`] over the name-server
/// section.
pub(crate) fn sign_authority(response: &mut Message, signer: &ZoneSigner) {
    let authority = response.take_name_servers();

    let mut groups: Vec<(Name, RecordType, Vec<Record>)> = Vec::new();
    for rec in authority {
        match groups
            .iter_mut()
            .find(|(n, t, _)| n == rec.name() && *t == rec.record_type())
        {
            Some(g) => g.2.push(rec),
            None => groups.push((rec.name().clone(), rec.record_type(), vec![rec])),
        }
    }

    for (name, rtype, recs) in groups {
        let mut rrset = RecordSet::new(name, rtype, 0);
        for r in &recs {
            rrset.insert(r.clone(), 0);
        }
        let rrsig = sign_rrset(&rrset, signer);
        for r in recs {
            response.add_name_server(r);
        }
        if let Some(sig) = rrsig {
            response.add_name_server(sig);
        }
    }
}

/// Build the response to a `DNSKEY` query at the zone apex (with its RRSIG when
/// the DO bit was set).
pub(crate) fn dnskey_answer(request: &Message, signer: &ZoneSigner, want_sig: bool) -> Message {
    let mut response = Message::new();
    let mut header = Header::response_from_request(request.header());
    header.set_authoritative(true);
    header.set_response_code(ResponseCode::NoError);
    response.set_header(header);
    response.add_queries(request.queries().to_vec());

    response.add_answer(signer.dnskey_record());
    if want_sig {
        // Reuse the positive-answer signing path (also sets EDNS DO).
        sign_answers(&mut response, signer);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_signer() -> ZoneSigner {
        let pkcs8 = EcdsaSigningKey::generate_pkcs8(ALGORITHM).unwrap();
        ZoneSigner::from_der("example.com.", pkcs8.secret_pkcs8_der().to_vec()).unwrap()
    }

    #[tokio::test]
    async fn stored_key_signs_like_fresh_key() {
        let dir = tempfile::tempdir().unwrap();
        let db = magnetite_db::Db::connect(dir.path().join("db"))
            .await
            .unwrap();
        // First load generates + stores; second load reads it back from storage.
        let fresh = load_signer(&db, "example.com").await.expect("generate");
        let stored = load_signer(&db, "example.com").await.expect("load stored");

        let name = Name::from_str("www.example.com.").unwrap();
        let mut rrset = RecordSet::new(name.clone(), RecordType::A, 0);
        rrset.insert(
            Record::from_rdata(name, 300, RData::A(Ipv4Addr::new(192, 0, 2, 1).into())),
            0,
        );
        assert!(sign_rrset(&rrset, &fresh).is_some(), "fresh key must sign");
        assert!(
            sign_rrset(&rrset, &stored).is_some(),
            "stored key must sign"
        );
        // Both keys must be the SAME (stored, not regenerated each load).
        assert_eq!(
            fresh.key_tag, stored.key_tag,
            "key must be stable across loads"
        );
    }

    #[test]
    fn signs_an_a_rrset() {
        let signer = test_signer();
        let name = Name::from_str("www.example.com.").unwrap();
        let mut rrset = RecordSet::new(name.clone(), RecordType::A, 0);
        rrset.insert(
            Record::from_rdata(name, 300, RData::A(Ipv4Addr::new(192, 0, 2, 1).into())),
            0,
        );

        let rrsig = sign_rrset(&rrset, &signer).expect("rrsig produced");
        assert_eq!(rrsig.record_type(), RecordType::RRSIG);
        assert!(matches!(rrsig.data(), RData::DNSSEC(DNSSECRData::RRSIG(_))));
    }

    #[test]
    fn dnskey_answer_carries_key_and_sig() {
        let signer = test_signer();
        let mut request = Message::new();
        request.add_query({
            let mut q = hickory_proto::op::Query::new();
            q.set_name(Name::from_str("example.com.").unwrap());
            q.set_query_type(RecordType::DNSKEY);
            q
        });
        let resp = dnskey_answer(&request, &signer, true);
        let types: Vec<RecordType> = resp.answers().iter().map(|r| r.record_type()).collect();
        assert!(types.contains(&RecordType::DNSKEY));
        assert!(types.contains(&RecordType::RRSIG));
    }
}
