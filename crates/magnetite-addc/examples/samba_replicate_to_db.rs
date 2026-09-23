//! End-to-end (Tier C C1): replicate `DC=magtest,DC=local` from a **live Samba** AD
//! DC over Kerberos-sealed DRSUAPI and apply the principals — NT hash, AES256
//! Kerberos key and origin stamp — into a fresh `magnetite-db` store, then verify the
//! store and the idempotency of a re-apply (conflict resolution).
//!
//! Run (with the samba-dc container up):
//! `KDC=127.0.0.1:8088 DRS=127.0.0.1:49152 SPN=ldap/dc1.magtest.local
//!  USERK=Administrator cargo run -p magnetite-addc --example samba_replicate_to_db`

use magnetite_addc::{apply_replicated_changes, replicate_cycle};
use magnetite_db::Db;
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
    let session_key = client.session_key().ok_or("no GSS session key")?.to_vec();

    // DRS_INIT_SYNC | DRS_WRIT_REP | DRS_NEVER_SYNCED — a full sync that includes
    // secrets. cMaxObjects=400 pulls the whole small domain in one reply.
    let flags = 0x0000_0020 | 0x0000_0010 | 0x0020_0000;
    eprintln!("[2] Replicating full NC (with secrets) ...");
    let changes = client
        .get_nc_changes_v8("DC=magtest,DC=local", [0u8; 16], [0u8; 16], 0, flags, 400)
        .await
        .map_err(|e| format!("get_nc_changes_v8: {e}"))?;
    eprintln!("    {} objects in the reply", changes.objects.len());

    eprintln!("[3] Applying into a fresh magnetite-db store (full sync) ...");
    let dir = tempfile::tempdir()?;
    let db = Db::connect(dir.path().join("db")).await?;
    let applied = apply_replicated_changes(&db, &changes, &session_key, realm).await?;
    let source_dsa = changes.source_invocation_id;
    eprintln!("    applied {applied} principals");

    eprintln!("[4] Verify the store holds the replicated secrets ...");
    let principals = db.list_ad_principals().await?;
    eprintln!("    {} AD principals now in magnetite-db", principals.len());
    for p in principals.iter().filter(|p| {
        ["Administrator", "krbtgt", "Guest", "DC1$"].contains(&p.sam_account_name.as_str())
    }) {
        let nt: String = p.nt_hash.iter().map(|b| format!("{b:02x}")).collect();
        eprintln!(
            "      {:<16} rid={:<5} NT={nt} aes256={} bytes",
            p.sam_account_name,
            p.rid,
            p.kerberos_key.len()
        );
    }

    // Groups + memberships replicated in the same pass (from the linked values).
    let groups = db.list_ad_groups().await?;
    let with_members: Vec<_> = groups
        .iter()
        .filter(|g| !g.member_sids.is_empty())
        .collect();
    eprintln!(
        "    {} groups replicated, {} with members",
        groups.len(),
        with_members.len()
    );
    for g in with_members.iter().take(8) {
        eprintln!(
            "      {} (rid {}) — {} member(s)",
            g.sam_account_name,
            g.rid,
            g.member_sids.len()
        );
    }
    // Confirm Administrator (RID 500) is a member of some replicated group.
    let rid_of = |s: &str| -> u32 {
        let b: Vec<u8> = (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap_or(0))
            .collect();
        if b.len() >= 4 {
            u32::from_le_bytes(b[b.len() - 4..].try_into().unwrap())
        } else {
            0
        }
    };
    match groups
        .iter()
        .find(|g| g.member_sids.iter().any(|s| rid_of(s) == 500))
    {
        Some(g) => eprintln!(
            "    membership: Administrator is a member of {}",
            g.sam_account_name
        ),
        None => eprintln!("    membership: Administrator not found in a replicated group"),
    }

    // An incremental cycle: we send our up-to-dateness vector, so the source ships
    // only objects newer than our cursor. With nothing changed on the source this is a
    // true wire-level delta — near-zero objects pulled, zero applied.
    eprintln!("[5] Incremental cycle (delta via pUpToDateVecDest) ...");
    let out = replicate_cycle(
        &db,
        &mut client,
        "DC=magtest,DC=local",
        &session_key,
        realm,
        Some(source_dsa),
    )
    .await?;
    eprintln!(
        "    delta cycle pulled {} objects, applied {} principals (expect ~0 pulled — source-side cursor filter)",
        out.pulled, out.applied
    );
    Ok(())
}
