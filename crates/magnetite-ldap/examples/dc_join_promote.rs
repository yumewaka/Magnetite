//! Attempt to promote magnetite to a replica DC of the target domain: discover the
//! layout, then create the server / nTDSDSA / computer objects. Reports which step
//! Samba accepts or rejects (DC objects are validated strictly).
//!
//! `TARGET=127.0.0.1:1389 BIND_DN='Administrator@MAGTEST.LOCAL' BIND_PW='Passw0rd!23' \
//!  DC_NAME=MAGNETITE cargo run -p magnetite-ldap --example dc_join_promote`

use magnetite_ldap::dc_join::{discover, promote_dc, JoinTarget, PromotionPlan};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let target = JoinTarget {
        host_port: std::env::var("TARGET").unwrap_or_else(|_| "127.0.0.1:1389".into()),
        bind_dn: std::env::var("BIND_DN").unwrap_or_else(|_| "Administrator@MAGTEST.LOCAL".into()),
        bind_password: std::env::var("BIND_PW").unwrap_or_else(|_| "Passw0rd!23".into()),
        use_starttls: std::env::var("STARTTLS").is_ok(),
        use_ldaps: false,
        tls_ca_pem: std::env::var("TLS_CA")
            .ok()
            .and_then(|p| std::fs::read_to_string(p).ok()),
    };
    let dc_name = std::env::var("DC_NAME").unwrap_or_else(|_| "MAGNETITE".into());

    let ctx = discover(&target).await?;
    // The site to join: the site that holds an existing DC (or the well-known default).
    let site_dn = ctx
        .existing_dcs
        .iter()
        .find_map(|dc| {
            dc.server_dn
                .split_once("CN=Servers,")
                .map(|(_, s)| format!("CN=Servers,{s}"))
        })
        .and_then(|servers| {
            servers
                .split_once("CN=Servers,")
                .map(|(_, s)| s.to_string())
        })
        .unwrap_or_else(|| format!("CN=Default-First-Site-Name,{}", ctx.sites_dn));

    let plan = PromotionPlan {
        dc_name: dc_name.clone(),
        dns_host_name: format!(
            "{}.{}",
            dc_name.to_lowercase(),
            ctx.domain_nc
                .to_lowercase()
                .replace(",dc=", ".")
                .trim_start_matches("dc=")
        ),
        site_dn: site_dn.clone(),
    };
    eprintln!("[promote] site   = {site_dn}");
    eprintln!("[promote] host   = {}", plan.dns_host_name);

    match promote_dc(&target, &ctx, &plan).await {
        Ok(r) => {
            eprintln!("[promote] OK — created:");
            eprintln!("    server   : {}", r.server_dn);
            eprintln!("    nTDSDSA  : {}", r.ntds_dn);
            eprintln!("    computer : {}", r.computer_dn);
        }
        Err(e) => eprintln!("[promote] stopped: {e:#}"),
    }
    Ok(())
}
