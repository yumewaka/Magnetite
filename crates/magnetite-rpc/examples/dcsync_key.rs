//! DCSync a single account by objectGUID and print its recovered AES256 Kerberos key
//! as hex — the exact key Samba stored, to feed the outbound DRS server so Samba's
//! AP-REQ (encrypted with this key) verifies.
//!
//! `GUID=7d65c5b2-136b-4f8a-99c7-5fee617ab222 KDC=127.0.0.1:8088 DRS=127.0.0.1:49152 \
//!  SPN=ldap/dc1.magtest.local USERK=Administrator cargo run -p magnetite-rpc --example dcsync_key`

use magnetite_krb5::keys::{default_salt, derive_aes256_key};
use magnetite_krb5::obtain_service_ticket;
use magnetite_rpc::{DrsClient, KERB_ETYPE_AES256};

fn guid_wire(s: &str) -> Option<[u8; 16]> {
    let hex: Vec<u8> = s.bytes().filter(|b| *b != b'-').collect();
    if hex.len() != 32 {
        return None;
    }
    let b: Vec<u8> = (0..16)
        .map(|i| u8::from_str_radix(std::str::from_utf8(&hex[i * 2..i * 2 + 2]).ok()?, 16).ok())
        .collect::<Option<_>>()?;
    Some([
        b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13],
        b[14], b[15],
    ])
}

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
    let guid = guid_wire(&std::env::var("GUID")?).ok_or("bad GUID")?;

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

    let obj = client
        .replicate_single_object(guid)
        .await?
        .ok_or("account not returned")?;
    let session_key = client.session_key().ok_or("no session key")?.to_vec();
    let keys = obj.kerberos_keys(&session_key);
    eprintln!(
        "[dcsync] {} attrs, {} kerberos keys",
        obj.attrs.len(),
        keys.len()
    );
    for k in &keys {
        let hex: String = k.key.iter().map(|b| format!("{b:02x}")).collect();
        let label = if k.key_type == KERB_ETYPE_AES256 {
            " <- AES256 (use as KEY)"
        } else {
            ""
        };
        eprintln!(
            "[dcsync] etype {} ({} bytes): {hex}{label}",
            k.key_type,
            k.key.len()
        );
    }
    Ok(())
}
