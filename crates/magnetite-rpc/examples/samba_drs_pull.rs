//! Scratch: attempt a Kerberos-authenticated DRS pull against the local Samba DC
//! (Tier C C1 4b-3). Obtains a ticket from Samba's KDC and binds its DRSUAPI.
//! Run: `SPN=ldap/dc1.magtest.local cargo run -p magnetite-rpc --example samba_drs_pull`

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
        .unwrap_or_else(|_| "127.0.0.1:1027".into())
        .parse()?;
    let user = std::env::var("USERK").unwrap_or_else(|_| "administrator".into());
    let pass = std::env::var("PASS").unwrap_or_else(|_| "Passw0rd!23".into());
    let spn_str = std::env::var("SPN").unwrap_or_else(|_| "ldap/dc1.magtest.local".into());
    let spn: Vec<&str> = spn_str.split('/').collect();

    let key = derive_aes256_key(&pass, &default_salt(realm, std::slice::from_ref(&user)))
        .map_err(|e| format!("derive key: {e}"))?;

    eprintln!("[1] AS->TGS for SPN {spn:?} at KDC {kdc} ...");
    let ticket = obtain_service_ticket(kdc, realm, &[user.as_str()], &key, &spn)
        .await
        .map_err(|e| format!("obtain_service_ticket: {e}"))?;
    eprintln!(
        "    OK: service ticket, session key {} bytes",
        ticket.session_key.len()
    );

    eprintln!("[2] Kerberos DRS bind at {drs} ...");
    let mut client = DrsClient::connect_kerberos_ticket(
        drs,
        &ticket.ticket_der,
        &ticket.session_key,
        realm,
        &[user.as_str()],
    )
    .await
    .map_err(|e| format!("connect_kerberos_ticket: {e}"))?;
    eprintln!("    OK: bound");

    // DRS_INIT_SYNC | DRS_WRIT_REP | DRS_NEVER_SYNCED = a from-scratch full pull.
    // DRS_WRIT_REP asks for a writeable replica, so secrets (unicodePwd) are included.
    let flags = 0x0000_0020 | 0x0000_0010 | 0x0020_0000;
    // NC defaults to the domain NC; set NC= to pull the Configuration or Schema NC
    // (bidirectional multi-master needs a replica to hold every NC, not just domain).
    let nc = std::env::var("NC").unwrap_or_else(|_| "DC=magtest,DC=local".into());
    eprintln!("[3] Replicating {nc} (paged full sync) ...");
    let objects = client
        .replicate_nc(&nc, flags, 200, 16)
        .await
        .map_err(|e| format!("replicate_nc: {e}"))?;
    eprintln!(
        "    OK: {} objects replicated across all pages",
        objects.len()
    );

    // The GSS session key unwraps replicated secrets (MS-DRSR §5.16.4).
    let session_key = client.session_key().ok_or("no GSS session key")?.to_vec();

    eprintln!("[4] DCSync: recovering NT hashes + Kerberos keys from replicated secrets ...");
    let mut recovered = 0usize;
    for o in &objects {
        let Some(sam) = o.sam_account_name() else {
            continue;
        };
        let Some(hash) = o.nt_hash(&session_key) else {
            continue;
        };
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        eprintln!("      {sam:<24} NT:{hex}");
        recovered += 1;
        for k in o.kerberos_keys(&session_key) {
            let khex: String = k.key.iter().map(|b| format!("{b:02x}")).collect();
            let name = match k.key_type {
                magnetite_rpc::KERB_ETYPE_AES256 => "aes256-cts",
                magnetite_rpc::KERB_ETYPE_AES128 => "aes128-cts",
                23 => "rc4-hmac",
                3 | 1 => "des-cbc",
                other => {
                    eprintln!("        etype {other:<19} {khex}");
                    continue;
                }
            };
            eprintln!("        {name:<24} {khex}");
        }
    }
    eprintln!("    OK: recovered {recovered} accounts' secrets from real Samba");

    // Targeted DCSync of a single account via EXOP_REPL_OBJ (like secretsdump
    // -just-dc-user): replicate just Administrator by its objectGUID and confirm the
    // one returned object carries the same NT hash as the full-sync page did.
    if let Some(admin) = objects
        .iter()
        .find(|o| o.sam_account_name().as_deref() == Some("Administrator"))
    {
        eprintln!("[6] EXOP_REPL_OBJ: targeted DCSync of Administrator by GUID ...");
        match client.replicate_single_object(admin.guid).await {
            Ok(Some(one)) => {
                let same = one.nt_hash(&session_key) == admin.nt_hash(&session_key);
                eprintln!(
                    "    OK: {} [{} attrs] NT-hash-matches-full-sync={same}",
                    one.name,
                    one.attrs.len()
                );
            }
            Ok(None) => eprintln!("    EXOP returned an empty reply"),
            Err(e) => eprintln!("    EXOP failed: {e}"),
        }
    }

    // Verify: derive Administrator's AES256 key from the known password and salt and
    // confirm it matches the key we recovered from supplementalCredentials.
    if let Some(admin) = objects
        .iter()
        .find(|o| o.sam_account_name().as_deref() == Some("Administrator"))
    {
        let admin_name = "Administrator".to_string();
        let derived = derive_aes256_key(
            &pass,
            &default_salt(realm, std::slice::from_ref(&admin_name)),
        )
        .map_err(|e| format!("derive: {e}"))?;
        let recovered_aes = admin
            .kerberos_keys(&session_key)
            .into_iter()
            .find(|k| k.key_type == magnetite_rpc::KERB_ETYPE_AES256)
            .map(|k| k.key);
        match recovered_aes {
            Some(k) if k == derived => eprintln!("[5] AES256 verification: MATCH (Administrator)"),
            Some(_) => eprintln!("[5] AES256 verification: MISMATCH"),
            None => eprintln!("[5] AES256 verification: no AES256 key recovered"),
        }
    }
    Ok(())
}
