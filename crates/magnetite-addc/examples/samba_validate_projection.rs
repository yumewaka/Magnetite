//! Validation (B1 + generic projection): replicate `DC=magtest,DC=local` from a live
//! Samba AD DC and confirm the applied objects are ALSO projected into the LDAP `entry`
//! tree — replicated users/groups become `user`/`group` entries (B1) and any classifiable
//! non-principal object (e.g. an `OU=…`) is projected generically (Config/Schema part 1).
//!
//! Run (samba-dc up): `KDC=172.17.0.2:88 DRS=172.17.0.2:49152 SPN=ldap/dc1.magtest.local
//!  USERK=Administrator PASS=Passw0rd!23 cargo run -p magnetite-addc --example samba_validate_projection`

use magnetite_addc::{apply_replicated_changes, build_directory_from_db};
use magnetite_db::Db;
use magnetite_krb5::keys::{default_salt, derive_aes256_key};
use magnetite_krb5::obtain_service_ticket;
use magnetite_rpc::DrsClient;
use std::collections::BTreeMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let realm = "MAGTEST.LOCAL";
    let kdc = std::env::var("KDC")
        .unwrap_or_else(|_| "172.17.0.2:88".into())
        .parse()?;
    let drs = std::env::var("DRS")
        .unwrap_or_else(|_| "172.17.0.2:49152".into())
        .parse()?;
    let user = std::env::var("USERK").unwrap_or_else(|_| "Administrator".into());
    let pass = std::env::var("PASS").unwrap_or_else(|_| "Passw0rd!23".into());
    let spn_str = std::env::var("SPN").unwrap_or_else(|_| "ldap/dc1.magtest.local".into());
    let spn: Vec<&str> = spn_str.split('/').collect();

    let key = derive_aes256_key(&pass, &default_salt(realm, std::slice::from_ref(&user)))
        .map_err(|e| format!("derive key: {e}"))?;
    eprintln!("[1] Kerberos-sealed DRS bind + pull DC=magtest,DC=local ...");
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
    .map_err(|e| format!("connect: {e}"))?;
    let session_key = client.session_key().ok_or("no GSS session key")?.to_vec();
    let flags = 0x0000_0020 | 0x0000_0010 | 0x0020_0000;

    // Persistent store when MAGNETITE_DB_PATH is set (so a delete can be validated across
    // two runs: replicate → delete the user in Samba → replicate again); else a tempdir.
    let _tmp = tempfile::tempdir()?;
    let db_path = std::env::var("MAGNETITE_DB_PATH")
        .unwrap_or_else(|_| _tmp.path().join("db").to_string_lossy().into_owned());
    let db = Db::connect(&db_path).await?;
    // Seed the LDAP base so projected entries have a naming context to hang under.
    db.ensure_ldap_base("dc=magtest,dc=local", "system").await?;

    // Pull the DOMAIN NC always; add the Config + Schema NCs when PULL_CONFIG_SCHEMA=1
    // (part 2 — their objects project generically). Each is a full sync (from=0);
    // projection is idempotent. Schema is large (~1600 objects, may page), so it can be
    // slow.
    let mut ncs = vec!["DC=magtest,DC=local".to_string()];
    if std::env::var("PULL_CONFIG_SCHEMA").is_ok() {
        ncs.push("CN=Configuration,DC=magtest,DC=local".into());
        ncs.push("CN=Schema,CN=Configuration,DC=magtest,DC=local".into());
    }
    let mut applied = 0usize;
    for nc in &ncs {
        let changes = client
            .get_nc_changes_v8(nc, [0u8; 16], [0u8; 16], 0, flags, 2000)
            .await
            .map_err(|e| format!("get_nc_changes_v8({nc}): {e}"))?;
        eprintln!("    {nc}: {} objects", changes.objects.len());
        applied += apply_replicated_changes(&db, &changes, &session_key, realm).await?;
    }
    eprintln!("[2] applied {applied} principals; inspecting the LDAP `entry` tree ...");

    // B4b tombstone check: report whether a specific user (TOMB_USER) is still present —
    // both as a stored principal and as a projected entry. After the user is deleted in
    // Samba and replication runs again, both must be gone.
    if let Ok(u) = std::env::var("TOMB_USER") {
        let in_store = db
            .list_ad_principals()
            .await?
            .iter()
            .any(|p| p.sam_account_name.eq_ignore_ascii_case(&u));
        let dn = format!("cn={},cn=users,dc=magtest,dc=local", u.to_lowercase());
        let in_tree = db.get_entry(&dn).await?.is_some();
        eprintln!("[B4b] user {u:?}: in ad_principal={in_store}, in entry tree={in_tree}");
    }

    // Build the served directory too (so we can cross-check counts).
    let _ = build_directory_from_db(&db, realm).await?;

    let entries = db.list_all_entries().await?;
    let mut by_class: BTreeMap<String, usize> = BTreeMap::new();
    for e in &entries {
        *by_class.entry(e.structural_class.clone()).or_default() += 1;
    }
    eprintln!(
        "[3] {} entries projected, by structural objectClass:",
        entries.len()
    );
    for (class, n) in &by_class {
        eprintln!("      {class:<24} {n}");
    }

    // B1: a replicated user + group are LDAP-servable entries with their attributes.
    let show = |kind: &str, class: &str| {
        for e in entries
            .iter()
            .filter(|e| e.structural_class == class)
            .take(3)
        {
            let sam = e
                .attributes
                .get("sAMAccountName")
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_default();
            let sid = e.attributes.get("objectSid").map(|v| v.len()).unwrap_or(0);
            let members = e.attributes.get("member").map(|v| v.len()).unwrap_or(0);
            eprintln!(
                "      {kind}: {} (sAMAccountName={sam}, objectSid={} members={members})",
                e.dn,
                if sid > 0 { "yes" } else { "no" }
            );
        }
    };
    eprintln!("[4] B1 — replicated users/groups as LDAP entries:");
    show("user", "user");
    show("group", "group");

    // Generic projection (part 1): any OU / classifiable non-principal object.
    let generic: Vec<_> = entries
        .iter()
        .filter(|e| {
            matches!(
                e.structural_class.as_str(),
                "organizationalUnit" | "attributeSchema" | "classSchema" | "crossRef"
            )
        })
        .collect();
    eprintln!(
        "[5] generic projection — {} classifiable non-principal object(s):",
        generic.len()
    );
    let mut by_gen: BTreeMap<String, usize> = BTreeMap::new();
    for e in &generic {
        *by_gen.entry(e.structural_class.clone()).or_default() += 1;
    }
    for (class, n) in &by_gen {
        eprintln!("      {class:<20} {n}");
    }
    // Show a sample attributeSchema with its rendered schema attributes (part 2 / 2a).
    if let Some(a) = generic
        .iter()
        .find(|e| e.structural_class == "attributeSchema")
    {
        let get = |k: &str| {
            a.attributes
                .get(k)
                .and_then(|v| v.first())
                .cloned()
                .unwrap_or_else(|| "-".into())
        };
        eprintln!(
            "      sample attributeSchema {}: lDAPDisplayName={} oMSyntax={} isSingleValued={} instanceType={}",
            a.dn, get("lDAPDisplayName"), get("oMSyntax"), get("isSingleValued"), get("instanceType"),
        );
    }
    if generic.is_empty() {
        eprintln!("      (none — set PULL_CONFIG_SCHEMA=1 to also pull the Config/Schema NCs)");
    }
    Ok(())
}
