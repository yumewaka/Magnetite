//! Probe DRS `IDL_DRSAddEntry` (opnum 17) against a live Samba DC: bind the sealed
//! Kerberos DRS channel and attempt to create an `nTDSDSA` object (which LDAP refuses
//! as system-only). Reports Samba's reply/fault to learn whether the opnum is
//! reachable + permitted and what the DC-add requires.
//!
//! The server parent must already exist (create it first via the LDAP
//! `dc_join_promote` example, which adds the server object before it stops).
//!
//! `KDC=127.0.0.1:8088 DRS=127.0.0.1:49152 SPN=ldap/dc1.magtest.local \
//!  USERK=Administrator cargo run -p magnetite-rpc --example dc_join_dsaddentry`

use magnetite_krb5::keys::{default_salt, derive_aes256_key};
use magnetite_krb5::obtain_service_ticket;
use magnetite_rpc::DrsClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let realm = "MAGTEST.LOCAL";
    let kdc = std::env::var("KDC")
        .unwrap_or_else(|_| "127.0.0.1:8088".into())
        .parse()?;
    let drs = std::env::var("DRS")
        .unwrap_or_else(|_| "127.0.0.1:49152".into())
        .parse()?;
    let user = std::env::var("USERK").unwrap_or_else(|_| "Administrator".into());
    let pass = std::env::var("PASS").unwrap_or_else(|_| "Passw0rd!23".into());
    let spn_str = std::env::var("SPN").unwrap_or_else(|_| "ldap/dc1.magtest.local".into());
    let spn: Vec<&str> = spn_str.split('/').collect();

    let key = derive_aes256_key(&pass, &default_salt(realm, std::slice::from_ref(&user)))
        .map_err(|e| format!("derive: {e}"))?;
    let ticket = obtain_service_ticket(kdc, realm, &[user.as_str()], &key, &spn)
        .await
        .map_err(|e| format!("ticket: {e}"))?;
    let mut client = DrsClient::connect_kerberos_ticket(
        drs,
        &ticket.ticket_der,
        &ticket.session_key,
        realm,
        &[user.as_str()],
    )
    .await
    .map_err(|e| format!("bind: {e}"))?;
    eprintln!("[dsaddentry] sealed DRS bind OK");

    // nTDSDSA under the (LDAP-created) server object. objectClass value = the nTDSDSA
    // governsID as an ATTRTYP (OID 1.2.840.113556.1.3.30 → prefix 3, tail 0x1e).
    let dn = "CN=NTDS Settings,CN=MAGNETITE,CN=Servers,CN=Default-First-Site-Name,\
              CN=Sites,CN=Configuration,DC=magtest,DC=local";
    let object_class_ntdsdsa: u32 = 0x0003_001e;
    let attrs: Vec<(u32, Vec<Vec<u8>>)> = vec![
        (
            0x0000_0000,
            vec![object_class_ntdsdsa.to_le_bytes().to_vec()],
        ), // objectClass = nTDSDSA
    ];

    eprintln!("[dsaddentry] DsAddEntry nTDSDSA {dn} ...");
    match client.ds_add_entry(dn, [0u8; 16], &attrs).await {
        Ok(reply) => {
            eprintln!(
                "[dsaddentry] reply {} bytes (no fault) — opnum reachable + permitted",
                reply.len()
            );
            for (i, chunk) in reply.chunks(16).enumerate().take(6) {
                let hex: String = chunk.iter().map(|b| format!("{b:02x}")).collect();
                eprintln!("    {:3}: {hex}", i * 16);
            }
        }
        Err(e) => eprintln!("[dsaddentry] {e}"),
    }
    Ok(())
}
