//! AD DC-locator DNS records. Windows locates a domain controller by querying a
//! well-known set of SRV records (and the DC's A record) before it ever talks to
//! the DC. This module generates that record set for our tracer-bullet DC and
//! seeds it into the DNS zone the embedded `magnetite-dns` server answers from.
//!
//! Scope: the core `_ldap`/`_kerberos`/`_kpasswd`/`_gc` locators under the domain
//! (and the `dc._msdcs` / `pdc._msdcs` / `gc._msdcs` trees for LDAP/Kerberos), plus
//! the DC and apex A records. Site-specific (`_sites`) locators are intentionally
//! omitted.

use crate::error::DbResult;
use crate::store::Db;
use chrono::Utc;
use magnetite_core::domains::dns::model::{Record, RecordType, Soa};
use serde_json::json;

/// A DC-locator record to publish: its owner name, type and JSON rdata (matching
/// the shapes `magnetite-dns` parses — SRV `{priority,weight,port,target}`, A
/// `{address}`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DcLocatorRecord {
    pub name: String,
    pub record_type: RecordType,
    pub data: serde_json::Value,
}

fn srv(name: String, port: u16, target: &str) -> DcLocatorRecord {
    DcLocatorRecord {
        name,
        record_type: RecordType::Srv,
        data: json!({ "priority": 0, "weight": 100, "port": port, "target": target }),
    }
}

fn a_record(name: String, ipv4: &str) -> DcLocatorRecord {
    DcLocatorRecord {
        name,
        record_type: RecordType::A,
        data: json!({ "address": ipv4 }),
    }
}

/// The DC-locator records for `dns_domain` (e.g. `example.com`) whose DC is
/// `<dc_label>.<dns_domain>` (e.g. `magnetite`/`dc2`) answering at `dc_ipv4`. Each
/// DC generates its own record set with its own host label so several DCs' records
/// coexist in the zone (the SRV locators share owner names but carry distinct
/// targets; the apex/GC A records round-robin across the DCs' IPs).
pub fn dc_locator_records(dns_domain: &str, dc_label: &str, dc_ipv4: &str) -> Vec<DcLocatorRecord> {
    let d = dns_domain;
    let host = format!("{dc_label}.{d}");
    vec![
        // Kerberos (KDC :88) — TCP + UDP, under the domain and dc._msdcs.
        srv(format!("_kerberos._tcp.{d}"), 88, &host),
        srv(format!("_kerberos._udp.{d}"), 88, &host),
        srv(format!("_kerberos._tcp.dc._msdcs.{d}"), 88, &host),
        // kpasswd (Change/Set Password, :464) — TCP + UDP under the domain.
        srv(format!("_kpasswd._tcp.{d}"), 464, &host),
        srv(format!("_kpasswd._udp.{d}"), 464, &host),
        // LDAP (:389) — domain, dc._msdcs, pdc._msdcs.
        srv(format!("_ldap._tcp.{d}"), 389, &host),
        srv(format!("_ldap._tcp.dc._msdcs.{d}"), 389, &host),
        srv(format!("_ldap._tcp.pdc._msdcs.{d}"), 389, &host),
        // Global catalog (:3268).
        srv(format!("_gc._tcp.{d}"), 3268, &host),
        srv(format!("_ldap._tcp.gc._msdcs.{d}"), 3268, &host),
        // Address records: the DC host, the domain apex, and the GC alias.
        a_record(host.clone(), dc_ipv4),
        a_record(d.to_string(), dc_ipv4),
        a_record(format!("gc._msdcs.{d}"), dc_ipv4),
    ]
}

fn name_eq(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
}

/// The comparable target of a locator record: an SRV's `target` host or an A's
/// `address`. Two records with the same owner name + type but different targets are
/// distinct (e.g. two DCs' `_ldap._tcp` SRVs), so seeding must key on this too.
fn rec_target(data: &serde_json::Value) -> String {
    data.get("target")
        .or_else(|| data.get("address"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

impl Db {
    /// Seed this DC's DC-locator records into the `dns_domain` zone (creating the
    /// zone on first run), with `<dc_label>.<dns_domain>` as the DC host.
    /// **Append-style**: a record is left as-is only when an existing one matches on
    /// owner name + type **and** target (SRV host / A address), so re-seeding is
    /// idempotent yet a *second* DC (different `dc_label`/IP) adds its own SRV
    /// targets and host A alongside the first — several DCs share one zone.
    ///
    /// # Errors
    /// Propagates zone/record creation failures.
    pub async fn seed_dc_locator(
        &self,
        dns_domain: &str,
        dc_label: &str,
        dc_ipv4: &str,
    ) -> DbResult<()> {
        let host = format!("{dc_label}.{dns_domain}");
        let zone = match self
            .list_zones()
            .await?
            .into_iter()
            .find(|z| name_eq(&z.name, dns_domain))
        {
            Some(z) => z,
            None => {
                let soa = Soa {
                    mname: host,
                    rname: format!("hostmaster.{dns_domain}"),
                    ..Soa::default()
                };
                self.create_zone(dns_domain, &soa, true, "magnetite-addc")
                    .await?
            }
        };

        let existing = self.list_records(&zone.id).await?;
        for rec in dc_locator_records(dns_domain, dc_label, dc_ipv4) {
            let already = existing.iter().any(|e| {
                e.record_type == rec.record_type
                    && name_eq(&e.name, &rec.name)
                    && rec_target(&e.data) == rec_target(&rec.data)
            });
            if already {
                continue;
            }
            let now = Utc::now();
            let record = Record {
                id: String::new(),
                created_at: now,
                updated_at: now,
                created_by: "magnetite-addc".to_string(),
                zone: zone.id.clone(),
                name: rec.name,
                ttl: 600,
                record_type: rec.record_type,
                data: rec.data,
                enabled: true,
            };
            self.create_record(&record).await?;
        }
        Ok(())
    }

    /// **Withdraw** a DC's DC-locator records from the `dns_domain` zone — the inverse of
    /// [`seed_dc_locator`](Self::seed_dc_locator). Removes exactly the records that DC
    /// (`<dc_label>.<dns_domain>` at `dc_ipv4`) contributed: its SRV locators (matched by
    /// owner name + target host), its host A record, and its apex / GC A records (matched
    /// by address). Other DCs' records in the shared zone are left intact, so a client
    /// doing DC discovery is no longer referred to a dead/demoted DC. Returns the number
    /// of records removed.
    ///
    /// # Errors
    /// Propagates zone/record lookup and delete failures.
    pub async fn withdraw_dc_locator(
        &self,
        dns_domain: &str,
        dc_label: &str,
        dc_ipv4: &str,
    ) -> DbResult<usize> {
        let Some(zone) = self
            .list_zones()
            .await?
            .into_iter()
            .find(|z| name_eq(&z.name, dns_domain))
        else {
            return Ok(0);
        };
        let existing = self.list_records(&zone.id).await?;
        let mut removed = 0;
        for rec in dc_locator_records(dns_domain, dc_label, dc_ipv4) {
            for e in &existing {
                if e.record_type == rec.record_type
                    && name_eq(&e.name, &rec.name)
                    && rec_target(&e.data) == rec_target(&rec.data)
                {
                    self.delete_record(&e.id).await?;
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_db() -> (Db, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path()).await.unwrap();
        (db, dir)
    }

    #[test]
    fn generator_covers_kerberos_ldap_gc_and_a_records() {
        let recs = dc_locator_records("example.com", "magnetite", "10.0.0.5");
        let find = |name: &str, rt: RecordType| {
            recs.iter().find(|r| r.name == name && r.record_type == rt)
        };
        // Kerberos TCP under the domain → port 88, target the DC host.
        let krb = find("_kerberos._tcp.example.com", RecordType::Srv).expect("kerberos SRV");
        assert_eq!(krb.data["port"], 88);
        assert_eq!(krb.data["target"], "magnetite.example.com");
        // The dc._msdcs LDAP locator → port 389.
        let ldap = find("_ldap._tcp.dc._msdcs.example.com", RecordType::Srv).expect("ldap SRV");
        assert_eq!(ldap.data["port"], 389);
        // Global catalog → 3268.
        assert_eq!(
            find("_gc._tcp.example.com", RecordType::Srv).unwrap().data["port"],
            3268
        );
        // The DC host A record resolves to the configured IP.
        let a = find("magnetite.example.com", RecordType::A).expect("host A");
        assert_eq!(a.data["address"], "10.0.0.5");
        // Kerberos also offered over UDP.
        assert!(find("_kerberos._udp.example.com", RecordType::Srv).is_some());
        // kpasswd (Change/Set Password) → port 464, TCP + UDP.
        let kpw = find("_kpasswd._tcp.example.com", RecordType::Srv).expect("kpasswd SRV");
        assert_eq!(kpw.data["port"], 464);
        assert!(find("_kpasswd._udp.example.com", RecordType::Srv).is_some());
    }

    #[tokio::test]
    async fn seed_creates_zone_and_is_idempotent() {
        let (db, _dir) = test_db().await;
        db.seed_dc_locator("example.com", "magnetite", "127.0.0.1")
            .await
            .unwrap();

        let zone = db
            .list_zones()
            .await
            .unwrap()
            .into_iter()
            .find(|z| name_eq(&z.name, "example.com"))
            .expect("zone created");
        let count_after_first = db.list_records(&zone.id).await.unwrap().len();
        assert_eq!(
            count_after_first,
            dc_locator_records("example.com", "magnetite", "127.0.0.1").len()
        );

        // A Kerberos SRV is present and points at the DC on :88.
        let records = db.list_records(&zone.id).await.unwrap();
        let krb = records
            .iter()
            .find(|r| {
                name_eq(&r.name, "_kerberos._tcp.example.com") && r.record_type == RecordType::Srv
            })
            .expect("kerberos SRV seeded");
        assert_eq!(krb.data["port"], 88);

        // Re-seeding the SAME DC does not duplicate.
        db.seed_dc_locator("example.com", "magnetite", "127.0.0.1")
            .await
            .unwrap();
        assert_eq!(
            db.list_records(&zone.id).await.unwrap().len(),
            count_after_first
        );
    }

    #[tokio::test]
    async fn second_dc_appends_its_own_targets() {
        let (db, _dir) = test_db().await;
        db.seed_dc_locator("example.com", "magnetite", "10.0.0.1")
            .await
            .unwrap();
        // A second DC with a distinct label + IP self-registers into the same zone.
        db.seed_dc_locator("example.com", "dc2", "10.0.0.2")
            .await
            .unwrap();

        let zone = db
            .list_zones()
            .await
            .unwrap()
            .into_iter()
            .find(|z| name_eq(&z.name, "example.com"))
            .expect("zone");
        let records = db.list_records(&zone.id).await.unwrap();

        // The `_ldap._tcp` locator now has BOTH DCs' hosts as SRV targets.
        let ldap_targets: Vec<String> = records
            .iter()
            .filter(|r| {
                name_eq(&r.name, "_ldap._tcp.example.com") && r.record_type == RecordType::Srv
            })
            .map(|r| rec_target(&r.data))
            .collect();
        assert!(
            ldap_targets.contains(&"magnetite.example.com".to_string()),
            "{ldap_targets:?}"
        );
        assert!(
            ldap_targets.contains(&"dc2.example.com".to_string()),
            "{ldap_targets:?}"
        );

        // Each DC has its own host A record.
        assert!(records
            .iter()
            .any(|r| name_eq(&r.name, "dc2.example.com") && r.record_type == RecordType::A));
        assert!(records
            .iter()
            .any(|r| name_eq(&r.name, "magnetite.example.com") && r.record_type == RecordType::A));

        // The apex A round-robins across both DCs' IPs.
        let apex: Vec<String> = records
            .iter()
            .filter(|r| name_eq(&r.name, "example.com") && r.record_type == RecordType::A)
            .map(|r| rec_target(&r.data))
            .collect();
        assert!(
            apex.contains(&"10.0.0.1".to_string()) && apex.contains(&"10.0.0.2".to_string()),
            "{apex:?}"
        );
    }

    #[tokio::test]
    async fn withdraw_removes_only_the_dead_dcs_records() {
        let (db, _dir) = test_db().await;
        db.seed_dc_locator("example.com", "magnetite", "10.0.0.1")
            .await
            .unwrap();
        db.seed_dc_locator("example.com", "dc2", "10.0.0.2")
            .await
            .unwrap();

        let zone = db
            .list_zones()
            .await
            .unwrap()
            .into_iter()
            .find(|z| name_eq(&z.name, "example.com"))
            .expect("zone");

        // dc2 dies: withdraw its locators. It removes dc2's contributions only.
        let removed = db
            .withdraw_dc_locator("example.com", "dc2", "10.0.0.2")
            .await
            .unwrap();
        assert_eq!(
            removed,
            dc_locator_records("example.com", "dc2", "10.0.0.2").len(),
            "every record dc2 registered is withdrawn"
        );
        let records = db.list_records(&zone.id).await.unwrap();

        // No SRV/A now targets dc2, and its host A + IP are gone.
        assert!(
            !records
                .iter()
                .any(|r| rec_target(&r.data) == "dc2.example.com"),
            "no locator still targets dc2"
        );
        assert!(
            !records.iter().any(|r| rec_target(&r.data) == "10.0.0.2"),
            "dc2's IP is no longer in any A record"
        );
        // The surviving DC's records remain: `_ldap._tcp` still points at magnetite.
        let ldap_targets: Vec<String> = records
            .iter()
            .filter(|r| {
                name_eq(&r.name, "_ldap._tcp.example.com") && r.record_type == RecordType::Srv
            })
            .map(|r| rec_target(&r.data))
            .collect();
        assert_eq!(ldap_targets, vec!["magnetite.example.com".to_string()]);
        assert!(records
            .iter()
            .any(|r| name_eq(&r.name, "magnetite.example.com") && r.record_type == RecordType::A));

        // Withdrawing again is a harmless no-op (nothing left to remove).
        assert_eq!(
            db.withdraw_dc_locator("example.com", "dc2", "10.0.0.2")
                .await
                .unwrap(),
            0
        );
    }
}
