//! Socket-level integration for the embedded DNS server (09b §-1, §76: "listen
//! 系はポートを使うため統合テストで"). Boots the real `DnsService` against a
//! shared temp DB on an ephemeral port and resolves a seeded zone over UDP.

use std::str::FromStr;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType as HRecordType};
use magnetite_core::domains::dns::model::{Record, RecordType, Soa};
use magnetite_db::{Db, EmbeddedService, ServiceHealth};
use magnetite_dns::DnsService;

async fn temp_db() -> (Db, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = Db::connect(dir.path().join("db"))
        .await
        .expect("connect db");
    (db, dir)
}

fn query_bytes(name: &str) -> Vec<u8> {
    let mut msg = Message::new();
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);
    msg.add_query(Query::query(Name::from_str(name).unwrap(), HRecordType::A));
    msg.to_vec().unwrap()
}

#[tokio::test]
async fn dns_server_resolves_seeded_zone_over_udp() {
    let (db, _dir) = temp_db().await;

    // Seed one authoritative zone with a single A record.
    let soa = Soa {
        mname: "ns1.example.test.".into(),
        rname: "hostmaster.example.test.".into(),
        serial: 1,
        refresh: 3600,
        retry: 900,
        expire: 604_800,
        minimum: 300,
    };
    let zone = db
        .create_zone("example.test", &soa, true, "admin")
        .await
        .expect("create zone");
    let now = chrono::Utc::now();
    db.create_record(&Record {
        id: String::new(),
        created_at: now,
        updated_at: now,
        created_by: "admin".into(),
        zone: zone.id.clone(),
        name: "www.example.test".into(),
        ttl: 300,
        record_type: RecordType::A,
        data: serde_json::json!({ "address": "192.0.2.10" }),
        enabled: true,
    })
    .await
    .expect("create record");

    // Pick a free port (TCP probe; the DNS server also binds UDP on it).
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("probe bind");
    let addr = probe.local_addr().unwrap();
    drop(probe);

    // Boot the embedded server (authoritative-only: no forwarders).
    let svc = DnsService::new(addr, vec![], false);
    let (_tx, rx) = tokio::sync::watch::channel(false);
    svc.start(db.clone(), rx);
    for _ in 0..50 {
        if svc.health() == ServiceHealth::Healthy {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(svc.health(), ServiceHealth::Healthy, "server should be up");

    // Resolve www.example.test over UDP (retry a couple of times to absorb any
    // startup/datagram race on slower CI).
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("client socket");
    let request = query_bytes("www.example.test.");
    let mut response = None;
    for _ in 0..3 {
        sock.send_to(&request, addr).await.expect("send query");
        let mut buf = vec![0u8; 1232];
        match tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => {
                response = Message::from_vec(&buf[..n]).ok();
                if response.is_some() {
                    break;
                }
            }
            _ => continue,
        }
    }

    let response = response.expect("a DNS response");
    assert_eq!(response.response_code(), ResponseCode::NoError);
    let a_answer = response
        .answers()
        .iter()
        .find(|r| r.record_type() == HRecordType::A);
    let a_answer = a_answer.expect("an A answer for the seeded record");
    assert!(
        a_answer.name().to_string().starts_with("www.example.test"),
        "answer name should be the queried record"
    );
}
