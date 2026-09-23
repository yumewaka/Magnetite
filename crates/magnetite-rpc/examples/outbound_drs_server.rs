//! OUTBOUND replication rig: run magnetite's DRSUAPI server so a REAL peer DC (Samba)
//! can replicate FROM magnetite. Serves the Endpoint Mapper (:135) — how Samba resolves
//! the DRS dynamic port — and the Kerberos-authenticated DRSUAPI endpoint, verifying
//! Samba's AP-REQ with magnetite's machine key.
//!
//! To avoid re-deriving the machine key (salt-sensitive), pass the EXACT AES256 key
//! Samba stored for magnetite's account (recover it by DCSyncing MAGNETITE$ first).
//!
//! `KEY=<64 hex chars> DC_IPV4=192.168.127.254 DRS_PORT=1027 EPM_PORT=135 \
//!  cargo run -p magnetite-rpc --example outbound_drs_server`

use std::sync::Arc;

use magnetite_rpc::interface::RpcInterface;
use magnetite_rpc::server::{serve, serve_with_kerberos};
use magnetite_rpc::{Directory, DrsuapiInterface, EpmInterface, Registration};

/// DRSUAPI interface UUID as endpoint-mapper tower bytes.
const DRSUAPI_UUID_BYTES: [u8; 16] = [
    0x35, 0x42, 0x51, 0xe3, 0x06, 0x4b, 0xd1, 0x11, 0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2,
];

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = hex_to_bytes(&std::env::var("KEY").expect("KEY=<hex machine AES256 key>"))
        .expect("KEY must be hex");
    let drs_port: u16 = std::env::var("DRS_PORT")
        .unwrap_or_else(|_| "1027".into())
        .parse()?;
    let epm_port: u16 = std::env::var("EPM_PORT")
        .unwrap_or_else(|_| "135".into())
        .parse()?;
    let dc_ipv4: [u8; 4] = {
        let s = std::env::var("DC_IPV4").unwrap_or_else(|_| "192.168.127.254".into());
        let o: Vec<u8> = s.split('.').filter_map(|p| p.parse().ok()).collect();
        o.try_into().expect("DC_IPV4 = a.b.c.d")
    };

    // A small directory for Samba to pull: a couple of users originated here. The
    // domain SID must be the TARGET domain's real SID (S-1-5-21-…) so a consumer
    // accepts the replicated objects; DOMAIN_SID overrides it (space/dash-separated
    // sub-authorities after S-1-5), defaulting to the magtest.local test domain.
    let sid: Vec<u32> = std::env::var("DOMAIN_SID")
        .unwrap_or_else(|_| "21 2171852460 1012688135 3873131180".into())
        .split([' ', '-'])
        .filter_map(|p| p.parse().ok())
        .collect();
    let mut dir = Directory::new("MAGTEST", "magtest.local", "MAGTEST.LOCAL", sid);
    dir.add_user("mag-outbound-1", 3301, "OutboundPass!1").ok();
    dir.add_user("mag-outbound-2", 3302, "OutboundPass!2").ok();
    // A group originated here, with both users as members — so a real Samba consumer
    // pulling from magnetite CREATES the group object AND applies the `member` linked
    // values (the Tier C group + membership outbound path, extended to a real peer).
    dir.add_group_with_members("mag-outbound-grp", 3400, vec![3301, 3302]);
    let dir = Arc::new(dir);

    // EPM on :135 — resolves DRSUAPI to its real port for Samba's DRS client.
    let epm: Arc<dyn RpcInterface> = Arc::new(EpmInterface::new(
        vec![Registration {
            uuid: DRSUAPI_UUID_BYTES,
            major_version: 4,
            port: drs_port,
        }],
        dc_ipv4,
    ));
    let epm_addr = format!("0.0.0.0:{epm_port}").parse()?;
    let drs_addr = format!("0.0.0.0:{drs_port}").parse()?;

    eprintln!("[outbound] EPM on :{epm_port} -> DRSUAPI :{drs_port} @ {dc_ipv4:?}");
    eprintln!(
        "[outbound] DRSUAPI (Kerberos) on :{drs_port}, machine key {} bytes",
        key.len()
    );

    let epm_task = tokio::spawn(async move { serve(epm_addr, epm).await });
    let drs = Arc::new(DrsuapiInterface::new(dir));
    let drs_task = tokio::spawn(async move { serve_with_kerberos(drs_addr, drs, key).await });

    let _ = tokio::try_join!(async { epm_task.await? }, async { drs_task.await? })?;
    Ok(())
}
