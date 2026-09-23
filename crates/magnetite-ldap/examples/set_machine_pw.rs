//! Prove machine-account password provisioning: create a DC computer over StartTLS,
//! set its `unicodePwd` to a value we choose, then confirm the password is usable by
//! binding to LDAP as that machine account. Setting a known machine password is what
//! lets magnetite derive its own Kerberos keys and authenticate inbound DRS binds
//! (the auth foundation for serving replication outbound).
//!
//! `STARTTLS=1 TARGET=127.0.0.1:1389 BIND_DN='Administrator@MAGTEST.LOCAL' BIND_PW='Passw0rd!23' \
//!  DC_NAME=OUTBTEST MACHINE_PW='Machine!Pass123' cargo run -p magnetite-ldap --example set_machine_pw`

use magnetite_ldap::dc_join::{add_dc_computer, discover, set_machine_password, JoinTarget};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let admin = JoinTarget {
        host_port: std::env::var("TARGET").unwrap_or_else(|_| "127.0.0.1:1389".into()),
        bind_dn: std::env::var("BIND_DN").unwrap_or_else(|_| "Administrator@MAGTEST.LOCAL".into()),
        bind_password: std::env::var("BIND_PW").unwrap_or_else(|_| "Passw0rd!23".into()),
        use_starttls: std::env::var("STARTTLS").is_ok(),
        use_ldaps: false,
        tls_ca_pem: std::env::var("TLS_CA")
            .ok()
            .and_then(|p| std::fs::read_to_string(p).ok()),
    };
    let dc = std::env::var("DC_NAME").unwrap_or_else(|_| "OUTBTEST".into());
    let machine_pw = std::env::var("MACHINE_PW").unwrap_or_else(|_| "Machine!Pass123".into());

    let ctx = discover(&admin).await?;
    let dns_domain = ctx
        .domain_nc
        .to_lowercase()
        .replace(",dc=", ".")
        .trim_start_matches("dc=")
        .to_string();
    let dns_host = format!("{}.{dns_domain}", dc.to_lowercase());

    let computer_dn = add_dc_computer(&admin, &ctx, &dc, &dns_host).await?;
    eprintln!("[mpw] created computer: {computer_dn}");
    set_machine_password(&admin, &computer_dn, &machine_pw).await?;
    eprintln!("[mpw] unicodePwd set OK");

    // Verify: bind as the machine account with the password we set.
    let realm = ctx
        .domain_nc
        .to_uppercase()
        .replace(",DC=", ".")
        .replace("DC=", "");
    let machine = JoinTarget {
        host_port: admin.host_port.clone(),
        bind_dn: format!("{dc}$@{realm}"),
        bind_password: machine_pw,
        use_starttls: admin.use_starttls,
        use_ldaps: admin.use_ldaps,
        tls_ca_pem: admin.tls_ca_pem.clone(),
    };
    match discover(&machine).await {
        Ok(_) => eprintln!("[mpw] BIND AS {dc}$ SUCCEEDED — machine password is usable"),
        Err(e) => eprintln!("[mpw] bind as machine account failed: {e:#}"),
    }
    Ok(())
}
