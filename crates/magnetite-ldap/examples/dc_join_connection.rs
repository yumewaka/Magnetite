//! DC promotion, slice 6 (topology): add the nTDSConnection under magnetite's NTDS
//! Settings that tells the KCC to pull from the source DC. Run *after* the server +
//! nTDSDSA already exist (dc_join_link + promote_ntdsdsa).
//!
//! `TARGET=127.0.0.1:1389 BIND_DN='Administrator@MAGTEST.LOCAL' BIND_PW='Passw0rd!23' \
//!  DC_NAME=MAGNETITE FROM_DC=DC1 cargo run -p magnetite-ldap --example dc_join_connection`

use magnetite_ldap::dc_join::{add_ntds_connection, JoinTarget};

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
    let from_dc = std::env::var("FROM_DC").unwrap_or_else(|_| "DC1".into());
    let base = std::env::var("BASE").unwrap_or_else(|_| {
        "CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=magtest,DC=local".into()
    });

    let dest_ntds = format!("CN=NTDS Settings,CN={dc_name},CN=Servers,{base}");
    let from_ntds = format!("CN=NTDS Settings,CN={from_dc},CN=Servers,{base}");
    eprintln!("[conn] {dest_ntds}\n         <- fromServer {from_ntds}");

    match add_ntds_connection(&target, &dest_ntds, &from_ntds, &from_dc).await {
        Ok(dn) => eprintln!("[conn] created: {dn}"),
        Err(e) => eprintln!("[conn] failed: {e:#}"),
    }
    Ok(())
}
