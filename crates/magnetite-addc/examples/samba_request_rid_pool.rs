//! Real-client interop (Tier C C1, item 6a): magnetite requests a **RID allocation
//! pool** from a live Samba AD DC's RID master over Kerberos-sealed DRSUAPI
//! (`IDL_DRSGetNCChanges` with `ulExtendedOp = EXOP_FSMO_RID_ALLOC`), and reports what
//! Samba grants (or the extended-op error it returns). This is the inverse of magnetite
//! serving pools: here magnetite is the CLIENT obtaining RIDs from Samba, the path a
//! freshly promoted magnetite DC uses during migration while Samba still holds the RID
//! master role.
//!
//! Run (with the samba-dc container up):
//! `KDC=127.0.0.1:8088 DRS=127.0.0.1:49152 SPN=ldap/dc1.magtest.local USERK=Administrator \
//!  RID_MANAGER_DN='CN=RID Manager$,CN=System,DC=magtest,DC=local' \
//!  DEST_NTDS_GUID=<hex32> cargo run -p magnetite-addc --example samba_request_rid_pool`

use magnetite_krb5::keys::{default_salt, derive_aes256_key};
use magnetite_krb5::obtain_service_ticket;
use magnetite_rpc::DrsClient;

fn parse_guid(s: &str) -> [u8; 16] {
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let mut g = [0u8; 16];
    for (i, byte) in g.iter_mut().enumerate() {
        if let Some(pair) = hex.get(i * 2..i * 2 + 2) {
            *byte = u8::from_str_radix(pair, 16).unwrap_or(0);
        }
    }
    g
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
    let rid_manager_dn = std::env::var("RID_MANAGER_DN")
        .unwrap_or_else(|_| "CN=RID Manager$,CN=System,DC=magtest,DC=local".into());
    let dest_ntds_guid = std::env::var("DEST_NTDS_GUID")
        .map(|s| parse_guid(&s))
        .unwrap_or([0u8; 16]);

    let key = derive_aes256_key(&pass, &default_salt(realm, std::slice::from_ref(&user)))
        .map_err(|e| format!("derive key: {e}"))?;

    eprintln!("[1] AS->TGS + Kerberos-sealed DRS bind at {drs} ...");
    let ticket = obtain_service_ticket(kdc, realm, &[user.as_str()], &key, &spn)
        .await
        .map_err(|e| format!("obtain_service_ticket: {e}"))?;
    let mut client = DrsClient::connect_kerberos_ticket(
        drs,
        &ticket.ticket_der,
        &ticket.session_key,
        realm,
        &[user.as_str()],
    )
    .await
    .map_err(|e| format!("connect_kerberos_ticket: {e}"))?;

    eprintln!("[2] EXOP_FSMO_RID_ALLOC on {rid_manager_dn}");
    eprintln!(
        "    dest nTDSDSA GUID = {}",
        dest_ntds_guid
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    match client
        .request_rid_pool_object(&rid_manager_dn, [0u8; 16], dest_ntds_guid)
        .await
    {
        Ok((result, obj)) => {
            eprintln!("[3] Samba extended-op result: {result:?}");
            match &obj {
                Some(o) => {
                    eprintln!(
                        "    reply object: name={:?}, {} attrs",
                        o.name,
                        o.attrs.len()
                    );
                    for a in &o.attrs {
                        let v = a.values.first().map(|v| v.as_slice()).unwrap_or(&[]);
                        let decoded = if v.len() == 8 {
                            let h = u64::from_le_bytes(v.try_into().unwrap());
                            format!("  hyper={h:#x}  (pool {}..{})", h & 0xffff_ffff, h >> 32)
                        } else {
                            String::new()
                        };
                        eprintln!("      attid {:#010x}: {} bytes{decoded}", a.attid, v.len());
                    }
                    if let Some((first, count)) = o.rid_allocation_pool() {
                        eprintln!(
                            "    DECODED rIDAllocationPool: {first}..{} ({count})",
                            first + count - 1
                        );
                    }
                    if let Some((next, max)) = o.rid_available_pool() {
                        eprintln!(
                            "    DECODED rIDAvailablePool: next={next}, max={max}  [RID-ALLOC-INTEROP-OK]"
                        );
                        eprintln!("    (Samba granted the op; the caller's own pool is on its");
                        eprintln!(
                            "     rIDSet.rIDAllocationPool — needs magnetite's rIDSet, i.e. dcpromo)"
                        );
                    }
                }
                None => eprintln!("    (no object in the reply)"),
            }
        }
        Err(e) => eprintln!("[3] request_rid_pool failed: {e}"),
    }
    Ok(())
}
