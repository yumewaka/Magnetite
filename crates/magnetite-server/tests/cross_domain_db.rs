//! Cross-cutting integration tests (05 §6.6): a single embedded DB is the sole
//! source of truth for every domain (09_runtime_spec §13). These exercise the
//! shared store across DNS, LDAP and Mail at once — including the online-signing
//! (DNSSEC), GeoDNS, LDAP-ACL and DKIM features — without going through sockets,
//! so they are fully deterministic.

use magnetite_core::authz::Role;
use magnetite_core::domain::DomainKey;
use magnetite_core::domains::dns::model::{GeoRegion, GeoRule, Record, RecordType, Soa};
use magnetite_core::domains::ldap::model::{
    LdapAclEffect, LdapAclOperation, LdapAclRule, LdapAclSubject,
};
use magnetite_core::models::common::{ActionKind, OpResult};
use magnetite_core::models::NewAuditEntry;
use magnetite_db::Db;

async fn temp_db() -> (Db, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = Db::connect(dir.path().join("db"))
        .await
        .expect("connect db");
    (db, dir)
}

fn sample_soa() -> Soa {
    Soa {
        mname: "ns1.example.test.".into(),
        rname: "hostmaster.example.test.".into(),
        serial: 1,
        refresh: 3600,
        retry: 900,
        expire: 604_800,
        minimum: 300,
    }
}

fn a_record(zone_id: &str, name: &str, addr: &str) -> Record {
    let now = chrono::Utc::now();
    Record {
        id: String::new(),
        created_at: now,
        updated_at: now,
        created_by: "admin".into(),
        zone: zone_id.into(),
        name: name.into(),
        ttl: 300,
        record_type: RecordType::A,
        data: serde_json::json!({ "address": addr }),
        enabled: true,
    }
}

/// One DB, seeded across DNS + LDAP + Mail with this migration's newer features,
/// then read back per domain with no cross-domain leakage.
#[tokio::test]
async fn shared_db_serves_every_domain_independently() {
    let (db, _dir) = temp_db().await;

    // --- DNS: zone + record + DNSSEC online signing --------------------------
    let zone = db
        .create_zone("example.test", &sample_soa(), true, "admin")
        .await
        .expect("create zone");
    db.create_record(&a_record(&zone.id, "www.example.test", "192.0.2.10"))
        .await
        .expect("create record");
    db.set_zone_dnssec_enabled(&zone.id, true)
        .await
        .expect("enable dnssec");
    // Server-side key generation is idempotent and persists.
    let key = magnetite_dns::dnssec::ensure_zone_key(&db, "example.test").await;
    assert!(key.is_some(), "a DNSSEC signing key should be generated");
    assert!(
        db.get_zone_dnssec_key("example.test")
            .await
            .expect("read key")
            .is_some(),
        "the generated key should be stored"
    );

    // --- DNS: GeoDNS rule ----------------------------------------------------
    let now = chrono::Utc::now();
    let geo = GeoRule {
        id: String::new(),
        created_at: now,
        updated_at: now,
        created_by: "admin".into(),
        zone: zone.id.clone(),
        name: "geo.example.test".into(),
        record_type: RecordType::A,
        ttl: 60,
        default_data: serde_json::json!({ "address": "192.0.2.1" }),
        regions: vec![GeoRegion {
            region: "EU".into(),
            cidrs: vec!["10.0.0.0/8".into()],
            data: serde_json::json!({ "address": "192.0.2.99" }),
        }],
        enabled: true,
    };
    db.create_geo_rule(&geo).await.expect("create geo rule");
    let found = db
        .find_geo_rules("geo.example.test", RecordType::A)
        .await
        .expect("find geo rules");
    assert_eq!(found.len(), 1, "the enabled geo rule should be found");

    // --- LDAP: base + user + ACL denying anonymous search --------------------
    let base = db
        .ensure_ldap_base("dc=example,dc=com", "admin")
        .await
        .expect("ldap base");
    let user = db
        .create_user(
            &base,
            "alice",
            "Alice Example",
            "Example",
            Some("alice@example.test"),
            "admin",
        )
        .await
        .expect("create user");
    // First-match by priority: deny anonymous, then allow authenticated. Once
    // any rule exists an unmatched request is denied, so the allow rule is what
    // lets the bound user through.
    let deny_anon = LdapAclRule {
        id: String::new(),
        created_at: now,
        updated_at: now,
        created_by: "admin".into(),
        priority: 10,
        target_dn: "*".into(),
        operations: vec![LdapAclOperation::Search],
        subject: LdapAclSubject::Anonymous,
        effect: LdapAclEffect::Deny,
        enabled: true,
    };
    let allow_auth = LdapAclRule {
        id: String::new(),
        created_at: now,
        updated_at: now,
        created_by: "admin".into(),
        priority: 20,
        target_dn: "*".into(),
        operations: vec![LdapAclOperation::Search],
        subject: LdapAclSubject::Authenticated,
        effect: LdapAclEffect::Allow,
        enabled: true,
    };
    db.create_ldap_acl(&deny_anon)
        .await
        .expect("create deny acl");
    db.create_ldap_acl(&allow_auth)
        .await
        .expect("create allow acl");
    assert!(
        !db.evaluate_ldap_acl(None, LdapAclOperation::Search, &base)
            .await
            .expect("eval anon"),
        "anonymous search should be denied by the first-match rule"
    );
    assert!(
        db.evaluate_ldap_acl(Some(&user.dn), LdapAclOperation::Search, &base)
            .await
            .expect("eval bound"),
        "a bound user should be allowed by the authenticated-allow rule"
    );

    // --- Mail: DKIM signing config (private key held server-side) ------------
    db.save_mail_dkim("example.test", "sel1", "PEM-PLACEHOLDER", true)
        .await
        .expect("save dkim");
    assert!(
        db.get_mail_dkim("example.test")
            .await
            .expect("read dkim")
            .is_some(),
        "enabled DKIM config should be retrievable"
    );

    // --- Independence: each domain sees only its own rows --------------------
    assert_eq!(db.list_zones().await.expect("zones").len(), 1);
    assert_eq!(db.list_users().await.expect("users").len(), 1);
    assert_eq!(db.list_geo_rules().await.expect("geo").len(), 1);
    assert_eq!(db.list_ldap_acls().await.expect("acls").len(), 2);
}

/// The audit trail is a cross-cutting store shared by every domain (09 §13).
#[tokio::test]
async fn audit_trail_spans_domains() {
    let (db, _dir) = temp_db().await;
    for (domain, kind) in [
        (DomainKey::Dns, "zone"),
        (DomainKey::Ldap, "user"),
        (DomainKey::Mail, "mail_dkim"),
    ] {
        db.append_audit(NewAuditEntry {
            actor: "admin".into(),
            actor_role: Role::Admin,
            domain,
            action: ActionKind::Create,
            target_kind: kind.into(),
            target_id: "x".into(),
            result: OpResult::Success,
            ip: "127.0.0.1".into(),
            detail: None,
        })
        .await
        .expect("append audit");
    }

    let entries = db.list_audit(50, 0).await.expect("list audit");
    assert_eq!(entries.len(), 3, "all three audit entries are stored");
    for domain in [DomainKey::Dns, DomainKey::Ldap, DomainKey::Mail] {
        assert!(
            entries.iter().any(|e| e.domain == domain),
            "audit trail should include a {domain:?} entry"
        );
    }
}
