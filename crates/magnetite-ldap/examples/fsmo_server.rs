//! A standalone magnetite-ldap server for FSMO-discovery interop testing.
//!
//! Seeds a directory (base DN + a bindable user), starts the embedded LDAP service
//! (which seeds the five FSMO role objects), and listens until killed — so a real
//! client (`samba-tool fsmo show`, `netdom query fsmo`, `ldbsearch`) can query which
//! DC holds each FSMO role.
//!
//! ```text
//! LDAP_BASE=dc=magtest,dc=local LDAP_PORT=3899 DB_PATH=/tmp/fsmo-db \
//!   cargo run -p magnetite-ldap --example fsmo_server
//! ```
//!
//! Then, from a Samba host that can reach this machine:
//! ```text
//! samba-tool fsmo show -H ldap://<host>:3899 \
//!   --simple-bind-dn='uid=alice,ou=people,dc=magtest,dc=local' --password='password12'
//! ```

use std::net::SocketAddr;

use magnetite_db::EmbeddedService;
use magnetite_ldap::LdapService;
use tokio::sync::watch;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base_dn = std::env::var("LDAP_BASE").unwrap_or_else(|_| "dc=magtest,dc=local".to_string());
    let port: u16 = std::env::var("LDAP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3899);
    let db_path = std::env::var("DB_PATH").unwrap_or_else(|_| "./fsmo-interop-db".to_string());

    let db = magnetite_db::Db::connect(&db_path).await?;
    let base = db.ensure_ldap_base(&base_dn, "admin").await?;
    // A bindable user for the interop client (simple bind).
    let _ = db.create_ou(&base, "people", None, "admin").await;
    let people = format!("ou=people,{base}");
    let _ = db
        .create_user(
            &people,
            "alice",
            "Alice A",
            "A",
            Some("alice@x.test"),
            "admin",
        )
        .await;
    db.reset_password(&format!("uid=alice,{people}"), "password12")
        .await?;

    let addr: SocketAddr = format!("0.0.0.0:{port}").parse()?;
    let svc = LdapService::new(addr, true, None, base_dn.clone());
    let (_tx, rx) = watch::channel(false);
    svc.start(db, rx);

    println!("magnetite-ldap FSMO interop server: base={base_dn} listening on {addr}");
    println!("bind DN: uid=alice,ou=people,{base_dn}  password: password12");
    // Park until the process is killed.
    tokio::signal::ctrl_c().await?;
    Ok(())
}
