//! DC-promotion **orchestrator** — the single operator-facing entry point that turns
//! a bare magnetite host into a replica DC of an existing AD domain by running the
//! whole sequence the individual slices proved out, in order:
//!
//! 1. discover the domain layout (LDAP)
//! 2. create the DC **computer** account (LDAP)
//! 3. create the **server** object + link `serverReference` (LDAP)
//! 4. create the **nTDSDSA** by copying a live DC's, via DRS `DsAddEntry` (system-only)
//! 5. create the **nTDSConnection** topology object (LDAP)
//! 6. register **DNS** — host A, the `<nTDSDSA-GUID>._msdcs` CNAME, `_ldap`/`_kerberos` SRV
//! 7. optionally **transfer FSMO roles** and request a **RID pool** (DRS)
//!
//! Every step reuses the crate functions validated against real Samba; this module is
//! the glue that runs them as one transaction and reports what it created.

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{Context, Result};
use magnetite_krb5::keys::{default_salt, derive_aes256_key};
use magnetite_krb5::obtain_service_ticket;
use magnetite_ldap::dc_join::{
    add_dc_computer, add_dc_server, add_ntds_connection, discover, read_object_guid,
    register_dns_a, register_dns_cname, register_dns_srv, set_server_reference, JoinTarget,
};
use magnetite_rpc::{DrsClient, ExOpErr, FsmoRole};

/// `whenCreated` / `invocationId` ATTRTYPs on the nTDSDSA we copy — `whenCreated` is
/// server-assigned (dropped) and `invocationId` must be fresh for the new DC.
const ATTID_WHEN_CREATED: u32 = 0x0002_0002;
const ATTID_INVOCATION_ID: u32 = 0x0002_0073;

/// Everything the orchestrator needs to promote this host to a replica DC.
#[derive(Debug, Clone)]
pub struct PromoteParams {
    /// LDAP bind to the source DC (admin credentials).
    pub target: JoinTarget,
    /// The new DC's short name (the server / computer CN, e.g. `MAGNETITE`).
    pub dc_name: String,
    /// The Kerberos realm (e.g. `MAGTEST.LOCAL`).
    pub realm: String,
    /// The source DC's KDC (`host:88`).
    pub kdc: SocketAddr,
    /// The source DC's DRSUAPI endpoint (`host:port`).
    pub drs: SocketAddr,
    /// The admin principal used for the Kerberos-sealed DRS bind.
    pub admin_user: String,
    /// The admin principal's password (to derive the AS key).
    pub admin_pass: String,
    /// The source DC's service principal, `service/host` (e.g. `ldap/dc1.magtest.local`).
    pub source_spn: String,
    /// The new DC's IPv4 address (its host A record).
    pub ip: Ipv4Addr,
    /// FSMO roles to transfer to the new DC (empty = leave all where they are).
    pub roles: Vec<FsmoRole>,
    /// Whether to also request a RID allocation pool for the new DC.
    pub request_rid_pool: bool,
    /// Skip step 6 (registering this DC's locator DNS: host A, `_msdcs` CNAME,
    /// `_ldap`/`_kerberos` SRV). When `true` no DNS records are written to the
    /// domain — the operator manages this DC's DNS out of band. Preferred for a
    /// validation join, since it never opens the DC-discovery window.
    pub skip_dns: bool,
    /// The new DC's `invocationId` (16 bytes), written into its `nTDSDSA` object.
    /// `None` derives it deterministically from the DC name + realm (stable across
    /// re-promotes of the same name). Supply a value to **align it with the running
    /// daemon's persistent id** (`dsa_invocation_id`) and to force a **fresh** id on
    /// a rollback+rejoin (reusing a tombstoned DC's id causes replication conflicts).
    pub invocation_id: Option<Vec<u8>>,
}

/// What the orchestrator created / moved, for reporting and (in tests) cleanup.
#[derive(Debug, Clone)]
pub struct PromoteOutcome {
    pub computer_dn: String,
    pub server_dn: String,
    pub ntds_dn: String,
    pub ntds_guid: [u8; 16],
    pub connection_dn: String,
    pub dns_nodes: Vec<String>,
    pub roles: Vec<(FsmoRole, ExOpErr)>,
    pub rid_pool: Option<ExOpErr>,
}

/// Derive a per-DC `invocationId` (16 bytes) deterministically from the DC name and
/// realm, so re-promoting the same DC is stable while two different DCs never collide.
fn derive_invocation_id(dc_name: &str, realm: &str) -> Vec<u8> {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(format!("{dc_name}.{realm}.invocationId").as_bytes());
    h.finalize().to_vec()
}

/// Split each `.`-label of `domain` into `DC=<label>` and join with the suffix — the
/// DNS-partition zone base under `CN=MicrosoftDNS,DC=<Domain|Forest>DnsZones,<dn>`.
pub(crate) fn zone_dn(domain: &str, partition: &str) -> String {
    let dn = domain
        .split('.')
        .map(|l| format!("DC={l}"))
        .collect::<Vec<_>>()
        .join(",");
    format!("CN=MicrosoftDNS,DC={partition},{dn}")
}

/// Open a Kerberos-sealed DRS client to the source DC as `admin_user`.
async fn connect_drs(p: &PromoteParams) -> Result<DrsClient> {
    let spn: Vec<&str> = p.source_spn.split('/').collect();
    let user = [p.admin_user.as_str()];
    let salt = default_salt(&p.realm, std::slice::from_ref(&p.admin_user));
    let key = derive_aes256_key(&p.admin_pass, &salt)
        .map_err(|e| anyhow::anyhow!("derive AS key: {e}"))?;
    let ticket = obtain_service_ticket(p.kdc, &p.realm, &user, &key, &spn)
        .await
        .map_err(|e| anyhow::anyhow!("obtain service ticket: {e}"))?;
    DrsClient::connect_kerberos_ticket(
        p.drs,
        &ticket.ticket_der,
        &ticket.session_key,
        &p.realm,
        &user,
    )
    .await
    .map_err(|e| anyhow::anyhow!("DRS Kerberos bind: {e}"))
}

/// Run the full promotion. Returns the created objects and the result of any FSMO
/// transfer / RID request. Steps run in dependency order; a failure aborts and is
/// reported with context (the partial objects are not rolled back — the caller decides).
///
/// # Errors
/// Any discovery / LDAP write / Kerberos / DRS step failing.
pub async fn promote(p: &PromoteParams) -> Result<PromoteOutcome> {
    let ctx = discover(&p.target).await.context("discover domain")?;
    let source = ctx
        .existing_dcs
        .first()
        .context("no existing DC in the topology")?;
    let source_ntds_dn = source.ntds_dn.clone().context("source DC has no nTDSDSA")?;
    // The site the source DC lives in (…,CN=Servers,<site>) is where our server goes.
    let site_dn = source
        .server_dn
        .split_once("CN=Servers,")
        .map(|(_, s)| s.to_string())
        .unwrap_or_else(|| format!("CN=Default-First-Site-Name,{}", ctx.sites_dn));
    let domain = ctx
        .domain_nc
        .to_lowercase()
        .replace(",dc=", ".")
        .replace("dc=", "");
    let dns_host = format!("{}.{}", p.dc_name.to_lowercase(), domain);

    // 2-3. Computer, server, serverReference (LDAP).
    let computer_dn = add_dc_computer(&p.target, &ctx, &p.dc_name, &dns_host)
        .await
        .context("create computer account")?;
    let server_dn = add_dc_server(&p.target, &p.dc_name, &dns_host, &site_dn)
        .await
        .context("create server")?;
    set_server_reference(&p.target, &server_dn, &computer_dn)
        .await
        .context("link serverReference")?;

    // 4. nTDSDSA via DsAddEntry, copying the source DC's (dropping whenCreated, fresh
    //    invocationId). The source's own nTDSDSA is the attribute template.
    let mut drs = connect_drs(p).await?;
    let source_ntds_guid = read_object_guid(&p.target, &source_ntds_dn)
        .await
        .context("read source nTDSDSA GUID")?;
    let template = drs
        .replicate_single_object(source_ntds_guid)
        .await
        .context("replicate source nTDSDSA")?
        .context("source nTDSDSA not returned")?;
    let invocation_id = p
        .invocation_id
        .clone()
        .unwrap_or_else(|| derive_invocation_id(&p.dc_name, &p.realm));
    let mut attrs: Vec<(u32, Vec<Vec<u8>>)> = Vec::new();
    for a in &template.attrs {
        match a.attid {
            ATTID_WHEN_CREATED => {} // server-assigned; omit
            ATTID_INVOCATION_ID => attrs.push((a.attid, vec![invocation_id.clone()])),
            _ => attrs.push((a.attid, a.values.clone())),
        }
    }
    let ntds_dn = format!("CN=NTDS Settings,{server_dn}");
    drs.ds_add_entry(&ntds_dn, [0u8; 16], &attrs)
        .await
        .context("DsAddEntry nTDSDSA")?;
    let ntds_guid = read_object_guid(&p.target, &ntds_dn)
        .await
        .context("read new nTDSDSA GUID")?;

    // 5. nTDSConnection: pull from the source DC (LDAP).
    let source_dc_name = source
        .server_dn
        .strip_prefix("CN=")
        .and_then(|s| s.split_once(','))
        .map(|(n, _)| n.to_string())
        .unwrap_or_else(|| "SOURCE".to_string());
    let connection_dn = add_ntds_connection(&p.target, &ntds_dn, &source_ntds_dn, &source_dc_name)
        .await
        .context("create nTDSConnection")?;

    // 6. DNS: host A, <nTDSDSA-GUID>._msdcs CNAME, _ldap/_kerberos SRV (LDAP).
    // Skipped entirely when `skip_dns` is set — the operator manages this DC's DNS
    // out of band, so no locator record is ever written to the domain.
    let mut dns_nodes = Vec::new();
    if p.skip_dns {
        tracing::info!("promote: skip_dns set — no DC-locator DNS records written");
    } else {
        let domain_zone = zone_dn(&domain, "DomainDnsZones");
        let forest_zone = zone_dn(&domain, "ForestDnsZones");
        let msdcs = format!("_msdcs.{domain}");
        let ntds_guid_str = guid_string(&ntds_guid);
        dns_nodes.push(
            register_dns_a(
                &p.target,
                &format!("DC={domain},{domain_zone}"),
                &p.dc_name.to_lowercase(),
                p.ip,
            )
            .await
            .context("register A")?,
        );
        dns_nodes.push(
            register_dns_cname(
                &p.target,
                &format!("DC={msdcs},{forest_zone}"),
                &ntds_guid_str,
                &dns_host,
            )
            .await
            .context("register CNAME")?,
        );
        for (node, port) in [("_ldap._tcp.dc", 389u16), ("_kerberos._tcp.dc", 88u16)] {
            dns_nodes.push(
                register_dns_srv(
                    &p.target,
                    &format!("DC={msdcs},{forest_zone}"),
                    node,
                    0,
                    100,
                    port,
                    &dns_host,
                )
                .await
                .with_context(|| format!("register SRV {node}"))?,
            );
        }
    }

    // 7. RID pool first — request it from the *current* RID master before any role
    //    transfer moves that role away (a new DC needs a pool to mint principals).
    let rid_pool = if p.request_rid_pool {
        let rid_manager = FsmoRole::RidMaster.object_dn(&ctx.domain_nc, &ctx.config_nc);
        let (res, _) = drs
            .request_rid_pool(&rid_manager, [0u8; 16], ntds_guid)
            .await
            .context("request RID pool")?;
        Some(res)
    } else {
        None
    };
    // 8. FSMO role transfers (DRS), if requested.
    let mut roles = Vec::new();
    for role in &p.roles {
        let dn = role.object_dn(&ctx.domain_nc, &ctx.config_nc);
        let (res, _) = drs
            .transfer_fsmo_role(*role, &dn, [0u8; 16], ntds_guid)
            .await
            .with_context(|| format!("transfer {role:?}"))?;
        roles.push((*role, res));
    }

    Ok(PromoteOutcome {
        computer_dn,
        server_dn,
        ntds_dn,
        ntds_guid,
        connection_dn,
        dns_nodes,
        roles,
        rid_pool,
    })
}

/// Format a 16-byte `objectGUID` (DRS wire form) as its canonical
/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` string (Data1/2/3 little-endian).
pub(crate) fn guid_string(g: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{}",
        g[3],
        g[2],
        g[1],
        g[0],
        g[5],
        g[4],
        g[7],
        g[6],
        g[8],
        g[9],
        g[10..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

#[cfg(test)]
mod tests {
    use super::{derive_invocation_id, guid_string, zone_dn};

    #[test]
    fn invocation_id_is_stable_and_per_dc() {
        let a = derive_invocation_id("MAGNETITE", "MAGTEST.LOCAL");
        assert_eq!(a.len(), 16);
        assert_eq!(
            a,
            derive_invocation_id("MAGNETITE", "MAGTEST.LOCAL"),
            "stable"
        );
        assert_ne!(
            a,
            derive_invocation_id("MAGNETITE2", "MAGTEST.LOCAL"),
            "per-DC"
        );
    }

    #[test]
    fn guid_string_round_trips_wire_order() {
        // 13c62d91-1872-4461-893f-ebf95889f810 wire (Data1/2/3 LE).
        let wire = [
            0x91, 0x2d, 0xc6, 0x13, 0x72, 0x18, 0x61, 0x44, 0x89, 0x3f, 0xeb, 0xf9, 0x58, 0x89,
            0xf8, 0x10,
        ];
        assert_eq!(guid_string(&wire), "13c62d91-1872-4461-893f-ebf95889f810");
    }

    #[test]
    fn zone_dn_builds_partition_base() {
        assert_eq!(
            zone_dn("magtest.local", "DomainDnsZones"),
            "CN=MicrosoftDNS,DC=DomainDnsZones,DC=magtest,DC=local"
        );
    }
}
