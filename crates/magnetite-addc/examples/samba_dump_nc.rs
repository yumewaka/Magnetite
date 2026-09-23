//! Exploration: pull ONE naming context (env `NC`) from the live Samba DC and dump, for
//! a sample of objects, what the part-1 generic projection renders (DN, inferred classes,
//! rendered attributes) alongside the RAW attids present — so I can see which OID-valued
//! schema attributes (attributeID/governsID/…) are still missing.
//!
//! Run: `KDC=172.17.0.2:88 DRS=172.17.0.2:49152 SPN=ldap/dc1.magtest.local
//!  USERK=Administrator PASS=Passw0rd!23 NC='CN=Schema,CN=Configuration,DC=magtest,DC=local'
//!  cargo run -p magnetite-addc --example samba_dump_nc`

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
    let nc = std::env::var("NC").unwrap_or_else(|_| "CN=Configuration,DC=magtest,DC=local".into());
    let filter = std::env::var("RDN_FILTER")
        .unwrap_or_default()
        .to_lowercase();

    let key = derive_aes256_key(&pass, &default_salt(realm, std::slice::from_ref(&user)))?;
    let ticket = obtain_service_ticket(kdc, realm, &[user.as_str()], &key, &spn).await?;
    let mut client = DrsClient::connect_kerberos_ticket(
        drs,
        &ticket.ticket_der,
        &ticket.session_key,
        realm,
        &[user.as_str()],
    )
    .await?;
    let flags = 0x0000_0020 | 0x0000_0010 | 0x0020_0000;
    eprintln!("Pulling NC {nc} ...");
    let changes = client
        .get_nc_changes_v8(&nc, [0u8; 16], [0u8; 16], 0, flags, 2000)
        .await?;
    eprintln!("  {} objects in the reply\n", changes.objects.len());

    // Histogram of inferred projection class.
    let mut classes: BTreeMap<String, usize> = BTreeMap::new();
    for o in &changes.objects {
        let c = o
            .projected_object_classes()
            .map(|v| v.last().cloned().unwrap_or_default())
            .unwrap_or_else(|| "<unclassified>".into());
        *classes.entry(c).or_default() += 1;
    }
    eprintln!("Inferred projection classes:");
    for (c, n) in &classes {
        eprintln!("  {c:<20} {n}");
    }
    eprintln!();

    // Sample a few classifiable objects (optionally RDN-filtered), dumping rendered attrs
    // + the raw attids present (so missing OID-valued attrs are visible).
    let mut shown = 0;
    for o in &changes.objects {
        if o.is_deleted() || o.projected_object_classes().is_none() {
            continue;
        }
        if !filter.is_empty() && !o.dn().to_lowercase().contains(&filter) {
            continue;
        }
        let attrs = o.ldap_attributes();
        eprintln!("--- {}", o.dn());
        eprintln!("    classes: {:?}", o.projected_object_classes().unwrap());
        eprintln!(
            "    rendered ({}): {:?}",
            attrs.len(),
            attrs.keys().collect::<Vec<_>>()
        );
        let mut attids: Vec<String> = o
            .attrs
            .iter()
            .map(|a| format!("0x{:08x}", a.attid))
            .collect();
        attids.sort();
        eprintln!("    raw attids ({}): {}", o.attrs.len(), attids.join(" "));
        shown += 1;
        if shown >= 6 {
            break;
        }
    }
    Ok(())
}
