//! DC promotion, FSMO transfer: request the transfer of an operation-master role
//! from the source DC (current owner) to magnetite's nTDSDSA over a Kerberos-sealed
//! DRS bind. Run *after* magnetite's nTDSDSA exists in the target (dc_join_link +
//! promote_ntdsdsa); pass its objectGUID as DEST_NTDS_GUID.
//!
//! `KDC=127.0.0.1:8088 DRS=127.0.0.1:49152 SPN=ldap/dc1.magtest.local USERK=Administrator \
//!  DEST_NTDS_GUID=13c62d91-1872-4461-893f-ebf95889f810 ROLE=infrastructure \
//!  cargo run -p magnetite-rpc --example fsmo_transfer`

use magnetite_krb5::keys::{default_salt, derive_aes256_key};
use magnetite_krb5::obtain_service_ticket;
use magnetite_rpc::{DrsClient, FsmoRole};

/// Parse a `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` GUID into its 16-byte wire form
/// (Data1/2/3 little-endian, Data4 as-is).
fn guid_wire(s: &str) -> Option<[u8; 16]> {
    let hex: Vec<u8> = s.bytes().filter(|b| *b != b'-').collect();
    if hex.len() != 32 {
        return None;
    }
    let b: Vec<u8> = (0..16)
        .map(|i| u8::from_str_radix(std::str::from_utf8(&hex[i * 2..i * 2 + 2]).ok()?, 16).ok())
        .collect::<Option<_>>()?;
    Some([
        b[3], b[2], b[1], b[0], // Data1 LE
        b[5], b[4], // Data2 LE
        b[7], b[6], // Data3 LE
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], // Data4
    ])
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let realm = "MAGTEST.LOCAL";
    let domain_nc = "DC=magtest,DC=local";
    let config_nc = "CN=Configuration,DC=magtest,DC=local";
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
    let dest_guid = guid_wire(&std::env::var("DEST_NTDS_GUID")?).ok_or("bad DEST_NTDS_GUID")?;
    let role = match std::env::var("ROLE")
        .unwrap_or_else(|_| "infrastructure".into())
        .as_str()
    {
        "schema" => FsmoRole::Schema,
        "naming" | "domainnaming" => FsmoRole::DomainNaming,
        "pdc" => FsmoRole::PdcEmulator,
        "rid" => FsmoRole::RidMaster,
        _ => FsmoRole::Infrastructure,
    };
    let role_dn = role.object_dn(domain_nc, config_nc);

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

    // ROLE=pool requests a RID allocation pool from the RID master instead of a role
    // transfer; every other ROLE requests a role transfer.
    if std::env::var("ROLE").as_deref() == Ok("pool") {
        let rid_manager = FsmoRole::RidMaster.object_dn(domain_nc, config_nc);
        eprintln!("[fsmo] requesting RID allocation pool from {rid_manager}");
        let (result, pool) = client
            .request_rid_pool(&rid_manager, [0u8; 16], dest_guid)
            .await?;
        eprintln!("[fsmo] extended-op result: {result:?}");
        // The granted pool is decoded from the reply object's rIDAllocationPool.
        match pool {
            Some((first, count)) => eprintln!(
                "[fsmo] granted RID pool: {first}..{} ({count} RIDs)",
                first + count - 1
            ),
            None => eprintln!("[fsmo] no RID pool in the reply"),
        }
        return Ok(());
    }

    eprintln!("[fsmo] requesting {role:?} transfer");
    eprintln!("[fsmo]   role object : {role_dn}");
    eprintln!(
        "[fsmo]   -> dest DSA : {}",
        std::env::var("DEST_NTDS_GUID")?
    );
    let (result, object) = client
        .transfer_fsmo_role(role, &role_dn, [0u8; 16], dest_guid)
        .await?;
    eprintln!("[fsmo] extended-op result: {result:?}");
    match object {
        Some(o) => eprintln!(
            "[fsmo] source replicated the role object back ({} attrs)",
            o.attrs.len()
        ),
        None => eprintln!("[fsmo] no object returned"),
    }
    Ok(())
}
