//! DNS domain server functions (F-11 / S-DNS). CRUD for zones, records and RPZ
//! rules — each write authorized (08_authz), validated (08_dns_logic §5) and
//! audited (F-04).

use crate::types::DnsMetrics;
use leptos::prelude::*;
use magnetite_core::domains::dns::model::{
    DdnsConfig, DdnsStatus, GeoRule, Record, RpzRule, Soa, TsigAlgorithm, TsigKey, Zone, ZoneRole,
};

/// Record a DNS audit entry (SSR helper).
#[cfg(feature = "ssr")]
async fn audit_dns(
    user: &magnetite_core::models::CurrentUser,
    action: magnetite_core::models::common::ActionKind,
    target_kind: &str,
    target_id: &str,
    result: magnetite_core::models::common::OpResult,
) {
    use crate::server_fns::auth::client_ip;
    use crate::state::AppState;
    let state = expect_context::<AppState>();
    let _ = state
        .db
        .append_audit(magnetite_core::models::NewAuditEntry {
            actor: user.subject.clone(),
            actor_role: user.role,
            domain: magnetite_core::domain::DomainKey::Dns,
            action,
            target_kind: target_kind.to_string(),
            target_id: target_id.to_string(),
            result,
            ip: client_ip().await,
            detail: None,
        })
        .await;
}

/// DNS dashboard metrics (S-DNS-01).
#[server(GetDnsMetrics, "/api")]
pub async fn get_dns_metrics() -> Result<DnsMetrics, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    let (zones, records) = state
        .db
        .dns_metrics()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(DnsMetrics {
        zone_count: zones as u64,
        record_count: records as u64,
    })
}

// ---- Zones ----------------------------------------------------------------

/// List all DNS zones (S-DNS-02).
#[server(ListZones, "/api")]
pub async fn list_zones() -> Result<Vec<Zone>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_zones()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Fetch one zone by id (for the record page header).
#[server(GetZone, "/api")]
pub async fn get_zone(id: String) -> Result<Option<Zone>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .get_zone(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create (id empty) or update a zone (S-DNS-02). Validates zone name + SOA.
#[server(SaveZone, "/api")]
pub async fn save_zone(
    id: String,
    name: String,
    soa: Soa,
    enabled: bool,
) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::dns::validate::{check_soa, check_zone_name};
    use magnetite_core::models::common::{ActionKind, OpResult};

    let user = require(ActionClass::Write).await?;
    check_zone_name(&name).map_err(ServerFnError::new)?;
    check_soa(&soa).map_err(ServerFnError::new)?;

    let state = expect_context::<AppState>();
    let is_create = id.is_empty();
    let result = if is_create {
        state
            .db
            .create_zone(&name, &soa, enabled, &user.subject)
            .await
            .map(|z| z.id)
    } else {
        state
            .db
            .update_zone(&id, &soa, enabled)
            .await
            .map(|_| id.clone())
    };
    match result {
        Ok(zone_id) => {
            audit_dns(
                &user,
                if is_create {
                    ActionKind::Create
                } else {
                    ActionKind::Update
                },
                "zone",
                &zone_id,
                OpResult::Success,
            )
            .await;
            Ok(())
        }
        Err(e) => Err(ServerFnError::new(e.to_string())),
    }
}

/// Count records under a zone (drives the AC-13 cascade confirm).
#[server(CountZoneRecords, "/api")]
pub async fn count_zone_records(id: String) -> Result<u64, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .count_records_in_zone(&id)
        .await
        .map(|n| n as u64)
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Delete a zone and cascade its records (AC-13).
#[server(DeleteZone, "/api")]
pub async fn delete_zone(id: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::{ActionKind, OpResult};

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_zone_cascade(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_dns(&user, ActionKind::Delete, "zone", &id, OpResult::Success).await;
    Ok(())
}

// ---- Records --------------------------------------------------------------

/// List records within a zone (S-DNS-03).
#[server(ListRecords, "/api")]
pub async fn list_records(zone_id: String) -> Result<Vec<Record>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_records(&zone_id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create (id empty) or update a record (S-DNS-03). Validates name/type/data.
#[server(SaveRecord, "/api")]
pub async fn save_record(record: Record) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::dns::validate::{check_record, normalize_record_data};
    use magnetite_core::models::common::{ActionKind, OpResult};

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    // The form-urlencoded server-fn codec stringifies the record's `data` scalars, so an
    // MX `preference` arrives as a string; coerce numeric fields back to JSON numbers
    // before validating and storing, or validation and the DNS wire encoder (both read it
    // via `as_u64`) would reject/drop the record.
    let mut record = record;
    normalize_record_data(record.record_type, &mut record.data);
    let zone = state
        .db
        .get_zone(&record.zone)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .ok_or_else(|| ServerFnError::new("対象が見つかりません。"))?;
    // Secondary zones mirror an external primary and are read-only here.
    if zone.role == ZoneRole::Secondary {
        return Err(ServerFnError::new(
            "セカンダリゾーンのレコードは編集できません（プライマリから複製されます）。",
        ));
    }
    check_record(&zone.name, &record).map_err(ServerFnError::new)?;

    let is_create = record.id.is_empty();
    // Capture the pre-image for the IXFR journal (update replaces an old record).
    let old = if is_create {
        None
    } else {
        state.db.get_record(&record.id).await.ok().flatten()
    };
    let outcome = if is_create {
        state.db.create_record(&record).await.map(|r| r.id)
    } else {
        state
            .db
            .update_record(&record)
            .await
            .map(|_| record.id.clone())
    };
    match outcome {
        Ok(rid) => {
            // Bump the zone's SOA serial so secondaries detect the change, and
            // journal the delta for incremental (IXFR) transfers.
            if let Ok(Some(serial)) = state.db.bump_zone_serial(&record.zone).await {
                let mut added = record.clone();
                added.id = rid.clone();
                let removed: Vec<_> = old.into_iter().collect();
                let _ = state
                    .db
                    .append_zone_journal(&record.zone, serial, &[added], &removed)
                    .await;
            }
            audit_dns(
                &user,
                if is_create {
                    ActionKind::Create
                } else {
                    ActionKind::Update
                },
                "record",
                &rid,
                OpResult::Success,
            )
            .await;
            Ok(())
        }
        Err(e) => Err(ServerFnError::new(e.to_string())),
    }
}

/// Delete a record by id (S-DNS-03).
#[server(DeleteRecord, "/api")]
pub async fn delete_record(id: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::{ActionKind, OpResult};

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    // Capture the record (its zone + pre-image for the IXFR journal) before delete.
    let old = state.db.get_record(&id).await.ok().flatten();
    let zone_id =
        old.as_ref()
            .map(|r| r.zone.clone())
            .or(state.db.get_record_zone(&id).await.ok().flatten());
    state
        .db
        .delete_record(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    if let Some(zid) = zone_id {
        if let Ok(Some(serial)) = state.db.bump_zone_serial(&zid).await {
            let removed: Vec<_> = old.into_iter().collect();
            let _ = state
                .db
                .append_zone_journal(&zid, serial, &[], &removed)
                .await;
        }
    }
    audit_dns(&user, ActionKind::Delete, "record", &id, OpResult::Success).await;
    Ok(())
}

// ---- RPZ ------------------------------------------------------------------

/// List RPZ rules (S-DNS-06).
#[server(ListRpz, "/api")]
pub async fn list_rpz() -> Result<Vec<RpzRule>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_rpz()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create (id empty) or update an RPZ rule (S-DNS-06). Validates domain +
/// redirect condition.
#[server(SaveRpz, "/api")]
pub async fn save_rpz(rule: RpzRule) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::dns::validate::check_rpz;
    use magnetite_core::models::common::{ActionKind, OpResult};

    let user = require(ActionClass::Write).await?;
    check_rpz(&rule).map_err(ServerFnError::new)?;
    let state = expect_context::<AppState>();
    let is_create = rule.id.is_empty();
    let outcome = if is_create {
        state.db.create_rpz(&rule).await.map(|r| r.id)
    } else {
        state.db.update_rpz(&rule).await.map(|_| rule.id.clone())
    };
    match outcome {
        Ok(rid) => {
            audit_dns(
                &user,
                if is_create {
                    ActionKind::Create
                } else {
                    ActionKind::Update
                },
                "rpz",
                &rid,
                OpResult::Success,
            )
            .await;
            Ok(())
        }
        Err(e) => Err(ServerFnError::new(e.to_string())),
    }
}

/// Delete an RPZ rule by id (S-DNS-06).
#[server(DeleteRpz, "/api")]
pub async fn delete_rpz(id: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::{ActionKind, OpResult};

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_rpz(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_dns(&user, ActionKind::Delete, "rpz", &id, OpResult::Success).await;
    Ok(())
}

// ---- Query test (AC-13 / S-DNS query-test) --------------------------------

/// One answer row from a DNS query test.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DnsAnswerRow {
    pub name: String,
    pub ttl: u32,
    pub record_type: String,
    pub value: String,
}

/// The result of resolving a name against the embedded authoritative server.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DnsQueryResult {
    pub rcode: String,
    pub authoritative: bool,
    pub answers: Vec<DnsAnswerRow>,
}

/// Resolve `name`/`qtype` against Magnetite's own authoritative data (AC-13).
/// This exercises the real resolver (`magnetite-dns`) over the shared DB —
/// forwarding is intentionally not applied, so the result reflects our zones.
#[server(DnsQueryTest, "/api")]
pub async fn dns_query_test(name: String, qtype: String) -> Result<DnsQueryResult, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::dns::model::RecordType;
    use magnetite_dns::resolver::{load_snapshot, resolve_in, QueryType, Rcode};

    require(ActionClass::Read).await?;
    let name = name.trim();
    if name.is_empty() {
        return Err(ServerFnError::new("名前を入力してください。"));
    }
    let qt = match qtype.to_ascii_uppercase().as_str() {
        "ANY" => QueryType::Any,
        "SOA" => QueryType::Soa,
        other => match RecordType::from_str(other) {
            Some(rt) => QueryType::Record(rt),
            None => QueryType::Other,
        },
    };

    let state = expect_context::<AppState>();
    let snapshot = load_snapshot(&state.db)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    let res = resolve_in(&snapshot, name, qt);

    let rcode = match res.rcode {
        Rcode::NoError => "NOERROR",
        Rcode::NxDomain => "NXDOMAIN",
        Rcode::Refused => "REFUSED",
    };
    let mut answers = Vec::new();
    if let Some((apex, soa)) = res.soa_answer {
        answers.push(DnsAnswerRow {
            name: apex,
            ttl: soa.minimum,
            record_type: "SOA".to_string(),
            value: format!("{} {} {}", soa.mname, soa.rname, soa.serial),
        });
    }
    for rec in res.answers {
        answers.push(DnsAnswerRow {
            name: rec.name.clone(),
            ttl: rec.ttl,
            record_type: rec.record_type.as_str().to_string(),
            value: format_answer_value(&rec),
        });
    }
    Ok(DnsQueryResult {
        rcode: rcode.to_string(),
        authoritative: res.authoritative,
        answers,
    })
}

// ---- DNSSEC (S-DNS DNSSEC / online signing) -------------------------------

/// Public DNSSEC key material for the zone list (the operator publishes a DS
/// record at the parent from this). The private key stays server-side.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DnssecKeyInfo {
    pub key_tag: u16,
    pub dnskey_record: String,
}

/// Toggle DNSSEC online signing for a zone. Enabling generates and persists the
/// zone's signing key on first use and returns its public DNSKEY material.
#[server(SetZoneDnssec, "/api")]
pub async fn set_zone_dnssec(
    id: String,
    name: String,
    enabled: bool,
) -> Result<Option<DnssecKeyInfo>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::{ActionKind, OpResult};

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .set_zone_dnssec_enabled(&id, enabled)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;

    let info = if enabled {
        magnetite_dns::dnssec::ensure_zone_key(&state.db, &name)
            .await
            .map(|k| DnssecKeyInfo {
                key_tag: k.key_tag,
                dnskey_record: k.dnskey_record,
            })
    } else {
        None
    };
    audit_dns(
        &user,
        ActionKind::Update,
        "zone_dnssec",
        &id,
        OpResult::Success,
    )
    .await;
    Ok(info)
}

/// Public DNSKEY material for an already-signed zone (for the UI's "publish DS"
/// panel). Returns `None` when the zone has no stored key, without generating
/// one.
#[server(GetDnssecKeyInfo, "/api")]
pub async fn get_dnssec_key_info(name: String) -> Result<Option<DnssecKeyInfo>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    let has_key = state
        .db
        .get_zone_dnssec_key(&name)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .is_some();
    if !has_key {
        return Ok(None);
    }
    Ok(magnetite_dns::dnssec::ensure_zone_key(&state.db, &name)
        .await
        .map(|k| DnssecKeyInfo {
            key_tag: k.key_tag,
            dnskey_record: k.dnskey_record,
        }))
}

// ---- GeoDNS (subnet/region answer routing) --------------------------------

/// List all GeoDNS rules (S-DNS GeoDNS).
#[server(ListGeoRules, "/api")]
pub async fn list_geo_rules() -> Result<Vec<GeoRule>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_geo_rules()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create a GeoDNS rule. Editing is not supported — delete and recreate.
#[server(CreateGeoRule, "/api")]
pub async fn create_geo_rule(rule: GeoRule) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::{ActionKind, OpResult};

    let user = require(ActionClass::Write).await?;
    if rule.name.trim().is_empty() {
        return Err(ServerFnError::new("名前を入力してください。"));
    }
    if rule.zone.trim().is_empty() {
        return Err(ServerFnError::new("ゾーンを選択してください。"));
    }
    let state = expect_context::<AppState>();
    let created = state
        .db
        .create_geo_rule(&rule)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_dns(
        &user,
        ActionKind::Create,
        "geo_rule",
        &created.id,
        OpResult::Success,
    )
    .await;
    Ok(())
}

/// Toggle a GeoDNS rule's enabled flag.
#[server(ToggleGeoRule, "/api")]
pub async fn toggle_geo_rule(id: String, enabled: bool) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::{ActionKind, OpResult};

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .set_geo_rule_enabled(&id, enabled)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_dns(
        &user,
        ActionKind::Update,
        "geo_rule",
        &id,
        OpResult::Success,
    )
    .await;
    Ok(())
}

/// Delete a GeoDNS rule by id.
#[server(DeleteGeoRule, "/api")]
pub async fn delete_geo_rule(id: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::{ActionKind, OpResult};

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_geo_rule(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_dns(
        &user,
        ActionKind::Delete,
        "geo_rule",
        &id,
        OpResult::Success,
    )
    .await;
    Ok(())
}

// ---- Replication (07_data_dns replication extension) ----------------------

/// Update a zone's replication settings (primary/secondary role + transfer
/// config). Roles: `"primary"` or `"secondary"`.
#[server(SetZoneReplication, "/api")]
#[allow(clippy::too_many_arguments)]
pub async fn set_zone_replication(
    id: String,
    role: String,
    allow_transfer: Vec<String>,
    also_notify: Vec<String>,
    notify_enabled: bool,
    primaries: Vec<String>,
    tsig_key_name: Option<String>,
) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::{ActionKind, OpResult};

    let user = require(ActionClass::Write).await?;
    let role = if role == "secondary" {
        ZoneRole::Secondary
    } else {
        ZoneRole::Primary
    };
    let clean = |v: Vec<String>| -> Vec<String> {
        v.into_iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };
    if role == ZoneRole::Secondary && clean(primaries.clone()).is_empty() {
        return Err(ServerFnError::new(
            "セカンダリには少なくとも1つのプライマリを指定してください。",
        ));
    }
    let tsig = tsig_key_name.and_then(|s| {
        let s = s.trim().to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    });
    let state = expect_context::<AppState>();
    state
        .db
        .update_zone_replication(
            &id,
            role,
            &clean(allow_transfer),
            &clean(also_notify),
            notify_enabled,
            &clean(primaries),
            tsig.as_deref(),
        )
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_dns(
        &user,
        ActionKind::Update,
        "zone_replication",
        &id,
        OpResult::Success,
    )
    .await;
    Ok(())
}

/// List TSIG keys (secrets are never projected).
#[server(ListTsigKeys, "/api")]
pub async fn list_tsig_keys() -> Result<Vec<TsigKey>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .list_tsig_keys()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))
}

/// Create a TSIG key. `algorithm` is one of hmac-sha256/512/1; `secret_b64` is
/// the shared base64 HMAC secret (must match the peer). Stored server-side.
#[server(CreateTsigKey, "/api")]
pub async fn create_tsig_key(
    name: String,
    algorithm: String,
    secret_b64: String,
) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::{ActionKind, OpResult};

    let user = require(ActionClass::Write).await?;
    let name = name.trim().to_string();
    let secret_b64 = secret_b64.trim().to_string();
    if name.is_empty() {
        return Err(ServerFnError::new("鍵名を入力してください。"));
    }
    if secret_b64.is_empty() {
        return Err(ServerFnError::new("秘密鍵（base64）を入力してください。"));
    }
    let algorithm = match algorithm.as_str() {
        "hmac-sha512" => TsigAlgorithm::HmacSha512,
        "hmac-sha384" => TsigAlgorithm::HmacSha384,
        _ => TsigAlgorithm::HmacSha256,
    };
    let state = expect_context::<AppState>();
    let created = state
        .db
        .create_tsig_key(&name, algorithm, &secret_b64, &user.subject)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_dns(
        &user,
        ActionKind::Create,
        "tsig_key",
        &created.id,
        OpResult::Success,
    )
    .await;
    Ok(())
}

/// Delete a TSIG key by id.
#[server(DeleteTsigKey, "/api")]
pub async fn delete_tsig_key(id: String) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::{ActionKind, OpResult};

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<AppState>();
    state
        .db
        .delete_tsig_key(&id)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_dns(
        &user,
        ActionKind::Delete,
        "tsig_key",
        &id,
        OpResult::Success,
    )
    .await;
    Ok(())
}

/// Format a record's `data` for display (mirrors the records list).
#[cfg(feature = "ssr")]
fn format_answer_value(record: &Record) -> String {
    use magnetite_core::domains::dns::model::RecordType;
    let d = &record.data;
    let s = |k: &str| d.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    match record.record_type {
        RecordType::A | RecordType::Aaaa => s("address"),
        RecordType::Cname => s("target"),
        RecordType::Ns => s("nsdname"),
        RecordType::Ptr => s("ptrdname"),
        RecordType::Mx => {
            let pref = d
                .get("preference")
                .and_then(magnetite_core::domains::dns::validate::as_u64_lenient)
                .unwrap_or(0);
            format!("{pref} {}", s("exchange"))
        }
        RecordType::Txt => s("text"),
        RecordType::Srv | RecordType::Caa => s("value"),
    }
}

/// The configured DNS forwarders (upstream resolvers as `host:port`) — the live,
/// DB-backed list the server uses for out-of-zone names (S-DNS forwarder settings).
#[server(GetDnsForwarders, "/api")]
pub async fn get_dns_forwarders() -> Result<Vec<String>, ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    let list = state
        .db
        .get_dns_forwarders()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok(list.unwrap_or_default())
}

/// Replace the DNS forwarders. Each entry is validated as `host:port`; blanks are
/// dropped. Applied without a restart (the server re-reads the list periodically).
#[server(SaveDnsForwarders, "/api")]
pub async fn save_dns_forwarders(forwarders: Vec<String>) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::{ActionKind, OpResult};

    let user = require(ActionClass::Write).await?;
    let mut cleaned = Vec::new();
    for entry in &forwarders {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.parse::<std::net::SocketAddr>().is_err() {
            return Err(ServerFnError::new(format!(
                "フォワーダ '{trimmed}' は host:port 形式ではありません（例 8.8.8.8:53）。"
            )));
        }
        cleaned.push(trimmed.to_string());
    }
    let state = expect_context::<AppState>();
    state
        .db
        .save_dns_forwarders(&cleaned)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_dns(
        &user,
        ActionKind::Update,
        "dns_forwarders",
        "singleton",
        OpResult::Success,
    )
    .await;
    Ok(())
}

// ---- Dynamic-DNS client (DB-backed, hot-reloaded) -------------------------

/// The current DDNS client settings + last-run status for the Web UI, in ONE call so the
/// page uses a single SSR resource (two resources sharing one source signal tripped an
/// SSR context panic). The provider password is scrubbed (blank; preserved on save).
#[server(GetDdnsPage, "/api")]
pub async fn get_ddns_page() -> Result<(DdnsConfig, DdnsStatus), ServerFnError> {
    use crate::server_fns::auth::require;
    use crate::state::AppState;
    use magnetite_core::authz::ActionClass;

    require(ActionClass::Read).await?;
    let state = expect_context::<AppState>();
    let mut cfg = state
        .db
        .get_ddns_config()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .unwrap_or_default();
    cfg.password = String::new();
    let status = state
        .db
        .get_ddns_status()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    Ok((cfg, status))
}

/// Save the DDNS client settings. An empty submitted password preserves the stored one (so
/// editing other fields never wipes the secret). Applied without a restart — the scheduler
/// re-reads the settings on its next poll.
#[server(SaveDdnsConfig, "/api")]
pub async fn save_ddns_config(config: DdnsConfig) -> Result<(), ServerFnError> {
    use crate::server_fns::auth::require;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::domains::dns::model::DdnsMode;
    use magnetite_core::models::common::{ActionKind, OpResult};

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<crate::state::AppState>();
    let mut config = config;
    config.server = config.server.trim().to_string();
    config.hostname = config.hostname.trim().to_string();
    config.username = config.username.trim().to_string();
    config.url_template = config.url_template.trim().to_string();
    config.public_ip_source = config
        .public_ip_source
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if config.enabled {
        match config.mode {
            DdnsMode::Dyndns if config.server.is_empty() || config.hostname.is_empty() => {
                return Err(ServerFnError::new(
                    "サーバとホスト名は必須です。".to_string(),
                ));
            }
            DdnsMode::Template if config.url_template.is_empty() => {
                return Err(ServerFnError::new(
                    "URLテンプレートは必須です。".to_string(),
                ));
            }
            _ => {}
        }
    }
    // Preserve the existing secret when the client submits an empty password.
    if config.password.is_empty() {
        let existing = state
            .db
            .get_ddns_config()
            .await
            .map_err(|e| ServerFnError::new(e.to_string()))?;
        config.password = existing.map(|c| c.password).unwrap_or_default();
    }
    state
        .db
        .save_ddns_config(&config)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_dns(
        &user,
        ActionKind::Control,
        "ddns",
        "singleton",
        OpResult::Success,
    )
    .await;
    Ok(())
}

/// Trigger a DDNS update right now (the "手動通知" button). Uses the stored settings
/// (full, with the real password), records the result, and returns it.
#[server(TriggerDdnsUpdate, "/api")]
pub async fn trigger_ddns_update() -> Result<DdnsStatus, ServerFnError> {
    use crate::server_fns::auth::require;
    use magnetite_core::authz::ActionClass;
    use magnetite_core::models::common::{ActionKind, OpResult};

    let user = require(ActionClass::Write).await?;
    let state = expect_context::<crate::state::AppState>();
    let config = state
        .db
        .get_ddns_config()
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?
        .unwrap_or_default();
    let status = magnetite_dns::ddns::perform_update(&config).await;
    state
        .db
        .record_ddns_status(&status)
        .await
        .map_err(|e| ServerFnError::new(e.to_string()))?;
    audit_dns(
        &user,
        ActionKind::Control,
        "ddns_update",
        "manual",
        if status.last_ok {
            OpResult::Success
        } else {
            OpResult::Failure
        },
    )
    .await;
    Ok(status)
}
