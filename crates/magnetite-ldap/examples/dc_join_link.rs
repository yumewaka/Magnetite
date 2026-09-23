//! DC promotion, slice 6 (LDAP part): create the DC's computer + server objects and
//! link them (server.serverReference -> computer). The nTDSDSA between them is added
//! separately via DRS DsAddEntry.
//!
//! `TARGET=127.0.0.1:1389 BIND_DN='Administrator@MAGTEST.LOCAL' BIND_PW='Passw0rd!23' \
//!  DC_NAME=MAGNETITE cargo run -p magnetite-ldap --example dc_join_link`

use magnetite_ldap::dc_join::{
    add_dc_computer, add_dc_server, discover, set_server_reference, JoinTarget,
};

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
    let site_dn = ctx
        .existing_dcs
        .iter()
        .find_map(|dc| {
            dc.server_dn
                .split_once("CN=Servers,")
                .map(|(_, s)| s.to_string())
        })
        .unwrap_or_else(|| format!("CN=Default-First-Site-Name,{}", ctx.sites_dn));
    let dns_domain = ctx
        .domain_nc
        .to_lowercase()
        .replace(",dc=", ".")
        .trim_start_matches("dc=")
        .to_string();
    let dns_host = format!("{}.{}", dc_name.to_lowercase(), dns_domain);

    let computer_dn = add_dc_computer(&target, &ctx, &dc_name, &dns_host).await?;
    eprintln!("[link] computer : {computer_dn}");
    let server_dn = add_dc_server(&target, &dc_name, &dns_host, &site_dn).await?;
    eprintln!("[link] server   : {server_dn}");
    set_server_reference(&target, &server_dn, &computer_dn).await?;
    eprintln!("[link] serverReference set: server -> computer OK");
    Ok(())
}
