//! DC-demotion **orchestrator** — the reverse of [`crate::promote`]. It removes a
//! leaving DC's metadata objects from the domain (the "metadata cleanup" a leave
//! performs), talking LDAP to a *surviving* DC as an admin:
//!
//! 1. discover the domain layout and locate the leaving DC's `server` object
//! 2. delete its `nTDSConnection` children (under its NTDS Settings)
//! 3. delete its `nTDSDSA` (NTDS Settings) object
//! 4. delete its `server` object
//! 5. delete its `computer` account (under `OU=Domain Controllers`)
//! 6. optionally remove its DC-specific DNS records (host A + `_msdcs` CNAME)
//!
//! Every step is **best-effort**: a failure is recorded and the remaining steps still
//! run, so a partial cleanup removes what it can and reports the rest. Shared DNS SRV
//! nodes (`_ldap._tcp.dc`, which hold every DC's record) are intentionally left alone —
//! removing a single value there is out of scope; the KCC / scavenging handles the
//! dangling record.

use anyhow::{bail, Context, Result};
use magnetite_ldap::dc_join::{
    delete_entry, discover, list_child_dns, read_object_guid, JoinTarget,
};

use crate::promote::{guid_string, zone_dn};

/// Everything the demotion orchestrator needs to remove a DC from the domain.
#[derive(Debug, Clone)]
pub struct DemoteParams {
    /// LDAP bind to a **surviving** DC (admin credentials).
    pub target: JoinTarget,
    /// The leaving DC's short name (its `server` / `computer` CN, e.g. `MAGNETITE`).
    pub dc_name: String,
    /// Skip step 6 (removing this DC's locator DNS: host A + `_msdcs` CNAME). When
    /// `true` the operator manages DNS out of band (mirrors `promote`'s `skip_dns`).
    pub skip_dns: bool,
}

/// What the orchestrator removed, for reporting. `removed` lists the DNs successfully
/// deleted (in order); `errors` pairs a DN with the reason it could not be deleted.
#[derive(Debug, Clone, Default)]
pub struct DemoteOutcome {
    pub removed: Vec<String>,
    pub errors: Vec<(String, String)>,
}

impl DemoteOutcome {
    /// Attempt to delete `dn`, recording success in `removed` or the reason in `errors`.
    async fn try_delete(&mut self, target: &JoinTarget, dn: &str) {
        match delete_entry(target, dn).await {
            Ok(()) => self.removed.push(dn.to_string()),
            Err(e) => self.errors.push((dn.to_string(), e.to_string())),
        }
    }
}

/// Run the full demotion. Locates the leaving DC in the topology and removes its
/// objects in child-first dependency order, best-effort. Returns what was removed and
/// any per-object failures.
///
/// # Errors
/// A discovery failure, or the named DC not being present in the topology (nothing to
/// clean). Per-object delete failures are reported in the outcome, not returned here.
pub async fn demote(p: &DemoteParams) -> Result<DemoteOutcome> {
    let ctx = discover(&p.target).await.context("discover domain")?;

    // Locate the leaving DC by its server CN (`CN=<dc_name>,CN=Servers,…`).
    let want = format!("CN={},", p.dc_name);
    let dc = ctx
        .existing_dcs
        .iter()
        .find(|d| d.server_dn.to_lowercase().starts_with(&want.to_lowercase()))
        .with_context(|| format!("DC {:?} not found in the topology", p.dc_name))?;
    let server_dn = dc.server_dn.clone();
    let ntds_dn = dc
        .ntds_dn
        .clone()
        .unwrap_or_else(|| format!("CN=NTDS Settings,{server_dn}"));

    // The DC-specific DNS record DNs need the nTDSDSA GUID (for the _msdcs CNAME);
    // read it before we delete the object.
    let ntds_guid = read_object_guid(&p.target, &ntds_dn).await.ok();

    let mut out = DemoteOutcome::default();

    // 2. nTDSConnection children of NTDS Settings (must go before the parent).
    match list_child_dns(&p.target, &ntds_dn).await {
        Ok(children) => {
            for child in children {
                out.try_delete(&p.target, &child).await;
            }
        }
        Err(e) => out.errors.push((ntds_dn.clone(), e.to_string())),
    }

    // 3-5. NTDS Settings, server, computer account.
    out.try_delete(&p.target, &ntds_dn).await;
    out.try_delete(&p.target, &server_dn).await;
    let computer_dn = format!("CN={},OU=Domain Controllers,{}", p.dc_name, ctx.domain_nc);
    out.try_delete(&p.target, &computer_dn).await;

    // 6. DC-specific DNS records (host A + _msdcs CNAME), unless skipped.
    if !p.skip_dns {
        let domain = ctx
            .domain_nc
            .to_lowercase()
            .replace(",dc=", ".")
            .replace("dc=", "");
        let a_dn = format!(
            "DC={},DC={domain},{}",
            p.dc_name.to_lowercase(),
            zone_dn(&domain, "DomainDnsZones")
        );
        out.try_delete(&p.target, &a_dn).await;
        if let Some(guid) = ntds_guid {
            let cname_dn = format!(
                "DC={},DC=_msdcs.{domain},{}",
                guid_string(&guid),
                zone_dn(&domain, "ForestDnsZones")
            );
            out.try_delete(&p.target, &cname_dn).await;
        }
    }

    if out.removed.is_empty() && !out.errors.is_empty() {
        bail!(
            "demote removed nothing; first error: {} ({})",
            out.errors[0].1,
            out.errors[0].0
        );
    }
    Ok(out)
}
