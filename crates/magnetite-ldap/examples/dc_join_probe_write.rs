//! Probe whether the target DC accepts authenticated LDAP writes over the discovery
//! transport — a benign OU add. This decides whether the promotion write phase
//! (creating server/nTDSDSA/computer objects) can use this connection or needs a
//! stronger transport (LDAPS / sealed SASL).
//!
//! `TARGET=127.0.0.1:1389 BIND_DN='Administrator@MAGTEST.LOCAL' BIND_PW='Passw0rd!23' \
//!  BASE_DN='DC=magtest,DC=local' cargo run -p magnetite-ldap --example dc_join_probe_write`

use magnetite_ldap::dc_join::{add_entry, JoinTarget};

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
    let base = std::env::var("BASE_DN").unwrap_or_else(|_| "DC=magtest,DC=local".into());
    let dn = format!("OU=magnetite-write-probe,{base}");

    eprintln!("[probe] adding {dn} ...");
    match add_entry(
        &target,
        &dn,
        vec![
            ("objectClass".into(), vec![b"organizationalUnit".to_vec()]),
            ("ou".into(), vec![b"magnetite-write-probe".to_vec()]),
        ],
    )
    .await
    {
        Ok(()) => eprintln!("[probe] WRITE OK — the transport allows authenticated writes"),
        Err(e) => eprintln!("[probe] write rejected: {e}"),
    }
    Ok(())
}
