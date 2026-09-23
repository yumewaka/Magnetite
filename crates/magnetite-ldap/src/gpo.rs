//! Persist a provisioned GPO's two halves into the directory + SYSVOL store.
//!
//! A domain member discovers a GPO by reading the `groupPolicyContainer` object
//! from LDAP (`CN=Policies,CN=System,<base>`), taking its `gPCFileSysPath`, then
//! fetching the policy files from that SYSVOL path over SMB. [`seed_group_policy`]
//! wires the **GPC** half (from [`magnetite_gpo`]) into the directory so discovery
//! works, and persists the **GPT** files into the replicated SYSVOL store so they
//! are served over SMB and replicated to peer DCs — keeping the two halves in
//! lock-step (a GPC whose GPT is missing from SYSVOL is a broken policy).

use magnetite_db::Db;
use magnetite_gpo::ProvisionedGpo;
use std::collections::BTreeMap;

/// Persist a provisioned GPO: seed the `CN=System` / `CN=Policies` containers and
/// the GPO's `groupPolicyContainer` (plus its `CN=Machine` / `CN=User`
/// sub-containers) into the directory, and persist the GPT (SYSVOL) files into the
/// replicated store. Re-running is idempotent (the GPT upsert only bumps a file's
/// version when its bytes actually change).
pub async fn seed_group_policy(db: &Db, base_dn: &str, gpo: &ProvisionedGpo) -> anyhow::Result<()> {
    let system = format!("CN=System,{base_dn}");
    let policies = format!("CN=Policies,{system}");
    let gpc = format!("CN={},{policies}", gpo.guid);

    seed_container(db, &system, "System").await?;
    seed_container(db, &policies, "Policies").await?;

    // The GPC itself, from the provisioned attributes.
    let mut object_classes = Vec::new();
    let mut attributes: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (key, value) in &gpo.gpc_attributes {
        if key.eq_ignore_ascii_case("objectClass") {
            object_classes.push(value.clone());
        } else {
            attributes
                .entry(key.clone())
                .or_default()
                .push(value.clone());
        }
    }
    db.apply_ldap_sync_entry(&gpc, &gpo.guid, object_classes, &attributes, true)
        .await?;

    seed_container(db, &format!("CN=Machine,{gpc}"), "Machine").await?;
    seed_container(db, &format!("CN=User,{gpc}"), "User").await?;

    // The GPT half: persist the policy files into the replicated SYSVOL store, so
    // a DC serves this GPO over SMB and it propagates to peers (the same store the
    // SYSVOL feed/pull and live re-serve read from).
    db.seed_sysvol_files(&gpo.sysvol_files).await?;
    Ok(())
}

/// Seed a plain `container` object with a `cn`.
async fn seed_container(db: &Db, dn: &str, cn: &str) -> anyhow::Result<()> {
    let mut attributes = BTreeMap::new();
    attributes.insert("cn".to_string(), vec![cn.to_string()]);
    db.apply_ldap_sync_entry(
        dn,
        dn, // a stable per-entry source id
        vec!["top".to_string(), "container".to_string()],
        &attributes,
        true,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::LdapService;
    use ldap3::{LdapConnAsync, Scope, SearchEntry};
    use magnetite_db::{EmbeddedService, ServiceHealth};
    use std::net::SocketAddr;
    use tokio::net::TcpListener;
    use tokio::sync::watch;

    /// Start the LDAP service on an ephemeral port, returning its address.
    async fn start_ldap(db: Db, base: &str) -> (SocketAddr, watch::Sender<bool>) {
        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);
        let svc = LdapService::new(addr, false, None, base.to_string());
        let (tx, rx) = watch::channel(false);
        svc.start(db, rx);
        for _ in 0..50 {
            if svc.health() == ServiceHealth::Healthy {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(svc.health(), ServiceHealth::Healthy);
        (addr, tx)
    }

    /// The full discovery half: seed a provisioned GPO's GPC, then have an
    /// independent LDAP client find it and read `gPCFileSysPath` / `versionNumber`
    /// — the values a member would use to fetch the policy over SMB.
    #[tokio::test]
    async fn ldap_client_discovers_provisioned_gpo() {
        let dir = tempfile::tempdir().unwrap();
        let db = magnetite_db::Db::connect(dir.path().join("db"))
            .await
            .unwrap();
        let base = db
            .ensure_ldap_base("dc=example,dc=com", "admin")
            .await
            .unwrap();

        let gpo = magnetite_gpo::default_domain_policy();
        seed_group_policy(&db, &base, &gpo).await.unwrap();

        let (addr, _tx) = start_ldap(db, &base).await;
        let (conn, mut ldap) = LdapConnAsync::new(&format!("ldap://{addr}")).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.drive().await;
        });
        ldap.simple_bind("", "").await.unwrap().success().unwrap();

        // Discover the GPO by object class (a member enumerates CN=Policies).
        let (rs, _res) = ldap
            .search(
                &base,
                Scope::Subtree,
                "(objectClass=groupPolicyContainer)",
                vec!["*"],
            )
            .await
            .unwrap()
            .success()
            .unwrap();
        let entries: Vec<SearchEntry> = rs.into_iter().map(SearchEntry::construct).collect();
        assert_eq!(entries.len(), 1, "exactly one GPO discovered");

        let e = &entries[0];
        let guid_lc = gpo.guid.to_lowercase();
        assert!(e.dn.to_lowercase().contains(&guid_lc), "dn: {}", e.dn);

        let path = &e.attrs["gPCFileSysPath"][0];
        assert!(
            path.contains(&gpo.guid),
            "gPCFileSysPath must reference the GUID: {path}"
        );
        assert!(
            path.to_lowercase().contains("sysvol"),
            "gPCFileSysPath points at SYSVOL (fetched over SMB): {path}"
        );
        assert_eq!(
            e.attrs["versionNumber"][0],
            gpo.version.to_string(),
            "GPC versionNumber matches the GPT.INI version"
        );
    }

    /// Provisioning a custom GPO persists BOTH halves: the GPC into the directory
    /// and the GPT files into the replicated SYSVOL store (served + replicated).
    #[tokio::test]
    async fn seed_group_policy_persists_gpt_files_to_store() {
        use magnetite_gpo::{provision, GpoSpec, RegValue, RegistrySetting};

        let dir = tempfile::tempdir().unwrap();
        let db = magnetite_db::Db::connect(dir.path().join("db"))
            .await
            .unwrap();
        let base = db
            .ensure_ldap_base("dc=example,dc=com", "admin")
            .await
            .unwrap();

        let guid = "{11111111-2222-3333-4444-555555555555}";
        let gpo = provision(&GpoSpec {
            display_name: "Test Policy".into(),
            guid: guid.into(),
            domain: "example.com".into(),
            machine_settings: vec![RegistrySetting {
                key: r"Software\Policies\Magnetite".into(),
                value: "Enabled".into(),
                data: RegValue::Dword(1),
            }],
        });

        // The store is empty before provisioning.
        assert!(db.list_sysvol_files().await.unwrap().is_empty());

        seed_group_policy(&db, &base, &gpo).await.unwrap();

        // The GPT files are now in the store, keyed by their SYSVOL paths.
        let files = db.list_sysvol_files().await.unwrap();
        let has = |suffix: &str| {
            files
                .iter()
                .any(|(p, _)| p.contains(guid) && p.ends_with(suffix))
        };
        assert!(has("GPT.INI"), "GPT.INI persisted: {files:?}");
        assert!(
            has(r"Machine\Registry.pol"),
            "machine Registry.pol persisted"
        );
        // The machine Registry.pol carries the MS-GPREG magic.
        let (_, pol) = files
            .iter()
            .find(|(p, _)| p.ends_with(r"Machine\Registry.pol"))
            .unwrap();
        assert_eq!(&pol[0..4], b"PReg", "real MS-GPREG Registry.pol bytes");

        // Idempotent: re-seeding does not duplicate files.
        seed_group_policy(&db, &base, &gpo).await.unwrap();
        assert_eq!(db.list_sysvol_files().await.unwrap().len(), files.len());
    }
}
