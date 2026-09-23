//! DC promotion, slice 4: create magnetite's nTDSDSA via DRS DsAddEntry by copying a
//! real nTDSDSA's attributes. Replicate DC1's nTDSDSA (its values are already in DRS
//! wire form), drop the server-assigned `whenCreated`, give a fresh `invocationId`,
//! and DsAddEntry them under magnetite's server object (create it first with the LDAP
//! `dc_join_promote` example). Reports Samba's reply.
//!
//! `KDC=127.0.0.1:8088 DRS=127.0.0.1:49152 SPN=ldap/dc1.magtest.local \
//!  USERK=Administrator cargo run -p magnetite-rpc --example promote_ntdsdsa`

use magnetite_krb5::keys::{default_salt, derive_aes256_key};
use magnetite_krb5::obtain_service_ticket;
use magnetite_rpc::DrsClient;

const ATTID_WHEN_CREATED: u32 = 0x0002_0002;
const ATTID_INVOCATION_ID: u32 = 0x0002_0073;

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

    // Replicate DC1's nTDSDSA (its objectGUID = the source-DSA GUID).
    let dc1_ntds: [u8; 16] = [
        0xe2, 0xd9, 0x3e, 0x6f, 0xd5, 0xc4, 0xc4, 0x49, 0xa9, 0x97, 0xc6, 0x1c, 0xa6, 0xda, 0xa5,
        0x54,
    ];
    let src = client
        .replicate_single_object(dc1_ntds)
        .await?
        .ok_or("nTDSDSA not returned")?;
    eprintln!(
        "[promote] copied {} attrs from DC1's nTDSDSA",
        src.attrs.len()
    );

    // Build magnetite's nTDSDSA attributes: copy DC1's, drop whenCreated, new invocationId.
    let magnetite_invocation_id: Vec<u8> = vec![
        0x4d, 0x41, 0x47, 0x4e, 0x33, 0x31, 0x30, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8,
        0x09,
    ];
    let mut attrs: Vec<(u32, Vec<Vec<u8>>)> = Vec::new();
    for a in &src.attrs {
        match a.attid {
            ATTID_WHEN_CREATED => {} // server-assigned
            ATTID_INVOCATION_ID => attrs.push((a.attid, vec![magnetite_invocation_id.clone()])),
            _ => attrs.push((a.attid, a.values.clone())),
        }
    }

    let dn = "CN=NTDS Settings,CN=MAGNETITE,CN=Servers,CN=Default-First-Site-Name,\
              CN=Sites,CN=Configuration,DC=magtest,DC=local";
    eprintln!("[promote] DsAddEntry {} attrs -> {dn}", attrs.len());
    match client.ds_add_entry(dn, [0u8; 16], &attrs).await {
        Ok(reply) => {
            eprintln!("[promote] reply {} bytes:", reply.len());
            for (i, chunk) in reply.chunks(16).enumerate().take(8) {
                let hex: String = chunk.iter().map(|b| format!("{b:02x}")).collect();
                eprintln!("    {:3}: {hex}", i * 16);
            }
        }
        Err(e) => eprintln!("[promote] {e}"),
    }
    Ok(())
}
