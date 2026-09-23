//! Replicate DC1's own nTDSDSA object by GUID and dump its attributes (attid + value
//! preview) — ground truth for building an nTDSDSA to DsAddEntry.

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

    // DC1's nTDSDSA objectGUID = 6f3ed9e2-c4d5-49c4-a997-c61ca6daa554 (AD wire order).
    let guid: [u8; 16] = [
        0xe2, 0xd9, 0x3e, 0x6f, 0xd5, 0xc4, 0xc4, 0x49, 0xa9, 0x97, 0xc6, 0x1c, 0xa6, 0xda, 0xa5,
        0x54,
    ];
    let obj = client
        .replicate_single_object(guid)
        .await?
        .ok_or("nTDSDSA not returned")?;
    eprintln!("nTDSDSA {} — {} attrs:", obj.name, obj.attrs.len());
    for a in &obj.attrs {
        let v0 = a.values.first();
        let preview: String = v0
            .map(|v| v.iter().take(24).map(|b| format!("{b:02x}")).collect())
            .unwrap_or_default();
        eprintln!(
            "  attid {:#010x}  vals={}  len0={}  {preview}",
            a.attid,
            a.values.len(),
            v0.map_or(0, |v| v.len())
        );
    }
    Ok(())
}
