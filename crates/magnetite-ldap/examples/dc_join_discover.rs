//! DC-join discovery against a live AD DC: bind over LDAP and print the domain
//! layout a promotion needs (naming contexts, sites, existing DCs).
//!
//! Run (with the samba-dc container, LDAP mapped to host 1389):
//! `TARGET=127.0.0.1:1389 BIND_DN='Administrator@MAGTEST.LOCAL' BIND_PW='Passw0rd!23' \
//!  cargo run -p magnetite-ldap --example dc_join_discover`

use magnetite_ldap::dc_join::{discover, JoinTarget};

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

    eprintln!(
        "[join] discovering domain layout via LDAP {} ...",
        target.host_port
    );
    let ctx = discover(&target).await?;
    eprintln!("  Configuration NC : {}", ctx.config_nc);
    eprintln!("  Domain NC        : {}", ctx.domain_nc);
    eprintln!("  Root domain NC   : {}", ctx.root_domain_nc);
    eprintln!("  Bound DSA        : {}", ctx.ds_service_name);
    eprintln!("  Sites container  : {}", ctx.sites_dn);
    eprintln!("  Existing DCs ({}):", ctx.existing_dcs.len());
    for dc in &ctx.existing_dcs {
        eprintln!(
            "    - {}  host={:?}  ntds={:?}",
            dc.server_dn, dc.dns_host_name, dc.ntds_dn
        );
    }
    Ok(())
}
