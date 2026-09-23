//! Set `unicodePwd` on an existing account DN over StartTLS (password ops require
//! encryption). Used in the outbound rig to give magnetite's already-created computer
//! account a machine password magnetite knows.
//!
//! `STARTTLS=1 TARGET=127.0.0.1:1389 BIND_DN=... BIND_PW=... DN='CN=MAGNETITE,OU=...' \
//!  PW='Machine!Pass123' cargo run -p magnetite-ldap --example set_pw`

use magnetite_ldap::dc_join::{set_machine_password, JoinTarget};

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
    let dn = std::env::var("DN").expect("DN=<account DN>");
    let pw = std::env::var("PW").unwrap_or_else(|_| "Machine!Pass123".into());
    set_machine_password(&target, &dn, &pw).await?;
    eprintln!("[set_pw] unicodePwd set on {dn}");
    Ok(())
}
