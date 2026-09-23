//! dcpromo completion (Tier C, item A): give magnetite a **rIDSet** in the Samba domain
//! and acquire a real RID pool from the RID master.
//!
//! magnetite's DC identity (MAGNETITE$, nTDSDSA, server) already exists, but without a
//! `rIDSet` (a system-only object) and a `rIDSetReferences` link the RID master has
//! nowhere to write a granted pool. This tool, against a live Samba DC:
//!   1. copies DC1's rIDSet as a template (DRS single-object replicate), strips the
//!      pool/DC-specific attributes, and creates magnetite's rIDSet via `DsAddEntry`;
//!   2. links `MAGNETITE$.rIDSetReferences` -> that rIDSet (LDAP);
//!   3. requests a RID pool (`EXOP_FSMO_RID_ALLOC`) for magnetite's nTDSDSA.
//!
//! Samba then writes the granted pool to magnetite's rIDSet.rIDAllocationPool (verify
//! with ldbsearch).
//!
//! `KDC=127.0.0.1:8088 DRS=127.0.0.1:49152 SPN=ldap/dc1.magtest.local \
//!  LDAP=dc1.magtest.local:389 cargo run -p magnetite-addc --example rid_set_acquire`

use magnetite_krb5::keys::{default_salt, derive_aes256_key};
use magnetite_krb5::obtain_service_ticket;
use magnetite_ldap::dc_join::{read_object_guid, set_attribute_relax, JoinTarget};
use magnetite_rpc::DrsClient;

const BASE: &str = "DC=magtest,DC=local";
// The four rID pool attributes are MANDATORY on a rIDSet, so they must be present on
// create — but ZEROED (an empty pool) rather than copied from DC1, so magnetite's rIDSet
// starts empty and the RID master fills rIDAllocationPool on the pool request.
// OIDs 1.2.840.113556.1.4.{348,350,371,373}.
const ZERO_ATTIDS: &[u32] = &[0x0009_015C, 0x0009_015E, 0x0009_0173, 0x0009_0175];
// Attributes to DROP entirely: whenCreated (server-assigned) and the DC1
// nTSecurityDescriptor (the target re-derives one on add).
const DROP_ATTIDS: &[u32] = &[0x0002_0002, 0x0002_0119];

/// magnetite's nTDSDSA objectGUID (c0ad5139-2944-4dad-966c-145654b8b490) in wire form.
fn magnetite_ntds_guid() -> [u8; 16] {
    [
        0x39, 0x51, 0xad, 0xc0, 0x44, 0x29, 0xad, 0x4d, 0x96, 0x6c, 0x14, 0x56, 0x54, 0xb8, 0xb4,
        0x90,
    ]
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
    let spn = std::env::var("SPN").unwrap_or_else(|_| "ldap/dc1.magtest.local".into());
    let ldap = std::env::var("LDAP").unwrap_or_else(|_| "dc1.magtest.local:389".into());
    let user = std::env::var("USERK").unwrap_or_else(|_| "Administrator".into());
    let pass = std::env::var("PASS").unwrap_or_else(|_| "Passw0rd!23".into());

    let target = JoinTarget {
        host_port: ldap,
        bind_dn: format!("{user}@{realm}"),
        bind_password: pass.clone(),
        // Samba requires an encrypted channel for the bind (StrongerAuthRequired on a
        // plaintext simple bind); StartTLS upgrades it. tls_ca_pem=None accepts any cert
        // (encryption without peer auth — fine for this PoC over the mapped port).
        use_starttls: true,
        use_ldaps: false,
        tls_ca_pem: None,
    };

    // Kerberos-sealed DRS bind to Samba.
    let key = derive_aes256_key(&pass, &default_salt(realm, std::slice::from_ref(&user)))
        .map_err(|e| format!("derive key: {e}"))?;
    let spn_parts: Vec<&str> = spn.split('/').collect();
    let ticket = obtain_service_ticket(kdc, realm, &[user.as_str()], &key, &spn_parts)
        .await
        .map_err(|e| format!("ticket: {e}"))?;
    let mut drs = DrsClient::connect_kerberos_ticket(
        drs,
        &ticket.ticket_der,
        &ticket.session_key,
        realm,
        &[user.as_str()],
    )
    .await
    .map_err(|e| format!("DRS bind: {e}"))?;
    eprintln!("[1] Kerberos-sealed DRS bind OK");

    // 1. Copy DC1's rIDSet as a template, strip pool/DC-specific attrs.
    let dc1_rid_set = format!("CN=RID Set,CN=DC1,OU=Domain Controllers,{BASE}");
    let dc1_guid = read_object_guid(&target, &dc1_rid_set).await?;
    let template = drs
        .replicate_single_object(dc1_guid)
        .await?
        .ok_or("DC1 rIDSet not returned")?;
    let attrs: Vec<(u32, Vec<Vec<u8>>)> = template
        .attrs
        .iter()
        .filter(|a| !DROP_ATTIDS.contains(&a.attid))
        .map(|a| {
            if ZERO_ATTIDS.contains(&a.attid) {
                (a.attid, vec![vec![0u8; 8]]) // a mandatory rID attr, emptied
            } else {
                (a.attid, a.values.clone())
            }
        })
        .collect();
    eprintln!(
        "[2] rIDSet template: {} attrs kept (from {})",
        attrs.len(),
        template.attrs.len()
    );

    eprintln!(
        "    kept attids: {}",
        attrs
            .iter()
            .map(|(a, _)| format!("{a:#010x}"))
            .collect::<Vec<_>>()
            .join(" ")
    );

    // 2. Create magnetite's rIDSet via DsAddEntry (system-only class).
    let mag_rid_set = format!("CN=RID Set,CN=MAGNETITE,OU=Domain Controllers,{BASE}");
    let reply = drs.ds_add_entry(&mag_rid_set, [0u8; 16], &attrs).await?;
    // The DRS_MSG_ADDENTRYREPLY ends with a status; dump the tail to surface a WERR.
    let tail = &reply[reply.len().saturating_sub(16)..];
    eprintln!(
        "    DsAddEntry reply {} bytes, tail: {}",
        reply.len(),
        tail.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let mag_rid_set_guid = read_object_guid(&target, &mag_rid_set).await?;
    eprintln!(
        "[3] DsAddEntry rIDSet OK: {mag_rid_set} (guid {})",
        mag_rid_set_guid
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );

    // 3. Link MAGNETITE$.rIDSetReferences -> the rIDSet. This attribute is systemOnly:
    // a plain LDAP modify is refused (ConstraintViolation "can only be modified as
    // system"), and setting it needs the LDAP *relax* control sent CRITICAL — which
    // ldap3_proto 0.5.2 cannot emit (LdapControl::Unknown is always non-critical). In a
    // real dcpromo the system sets this link; here it is provisioned once out-of-band:
    //   ldbmodify -H .../sam.ldb --controls=relax:0  (add: rIDSetReferences)
    let computer_dn = format!("CN=MAGNETITE,OU=Domain Controllers,{BASE}");
    match set_attribute_relax(
        &target,
        &computer_dn,
        "rIDSetReferences",
        vec![mag_rid_set.as_bytes().to_vec()],
    )
    .await
    {
        Ok(()) => eprintln!("[4] rIDSetReferences linked on MAGNETITE$ (relax control)"),
        Err(e) => {
            eprintln!("[4] rIDSetReferences link failed: {e}");
            eprintln!("    (magnetite now sends the relax control CRITICAL, but Samba does not");
            eprintln!("     register it for network LDAP — a server-side policy; the link is a");
            eprintln!(
                "     system/DRS operation. Provision out-of-band: ldbmodify --controls=relax:0)"
            );
        }
    }

    // 4. Request a RID pool for magnetite's nTDSDSA from the RID master.
    let rid_manager = format!("CN=RID Manager$,CN=System,{BASE}");
    let (res, pool) = drs
        .request_rid_pool(&rid_manager, [0u8; 16], magnetite_ntds_guid())
        .await?;
    eprintln!("[5] EXOP_FSMO_RID_ALLOC result: {res:?}");
    if let Some((first, count)) = pool {
        eprintln!("    reply pool hint: {first}..{}", first + count - 1);
    }
    eprintln!("    -> verify magnetite's granted pool with:");
    eprintln!("       ldbsearch -b '{mag_rid_set}' rIDAllocationPool");
    Ok(())
}
