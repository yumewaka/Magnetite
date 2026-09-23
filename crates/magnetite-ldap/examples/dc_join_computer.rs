//! Create the DC's computer account (SERVER_TRUST_ACCOUNT) in the target domain.
//!
//! `TARGET=127.0.0.1:1389 BIND_DN='Administrator@MAGTEST.LOCAL' BIND_PW='Passw0rd!23' \
//!  DC_NAME=MAGNETITE cargo run -p magnetite-ldap --example dc_join_computer`

use magnetite_ldap::dc_join::{add_dc_computer, discover, JoinTarget};

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
    let dns_domain = ctx
        .domain_nc
        .to_lowercase()
        .replace(",dc=", ".")
        .trim_start_matches("dc=")
        .to_string();
    let dns_host = format!("{}.{}", dc_name.to_lowercase(), dns_domain);

    eprintln!("[computer] creating DC computer account for {dc_name} ({dns_host}) ...");
    match add_dc_computer(&target, &ctx, &dc_name, &dns_host).await {
        Ok(dn) => eprintln!("[computer] created: {dn}  (SERVER_TRUST_ACCOUNT)"),
        Err(e) => eprintln!("[computer] failed: {e:#}"),
    }
    Ok(())
}
