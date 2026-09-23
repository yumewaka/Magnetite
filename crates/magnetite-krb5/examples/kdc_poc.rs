//! Runnable tracer-bullet KDC for interop testing with a real client (`kinit`).
//!
//! ```sh
//! cargo run -p magnetite-krb5 --example kdc_poc
//! # then, with a krb5.conf pointing at this KDC:
//! KRB5_CONFIG=./krb5.conf kinit alice   # password: password12
//! ```
//!
//! Env overrides: `KRB5_REALM` (default `EXAMPLE.COM`), `KDC_ADDR`
//! (default `0.0.0.0:8888`).

use magnetite_krb5::{keys::PrincipalStore, server::KdcServer};
use std::sync::Arc;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let realm = std::env::var("KRB5_REALM").unwrap_or_else(|_| "EXAMPLE.COM".to_string());
    let addr = std::env::var("KDC_ADDR").unwrap_or_else(|_| "0.0.0.0:8888".to_string());

    let mut store = PrincipalStore::new(&realm);
    store
        .add_password_principal(&["alice"], "password12")
        .expect("seed alice");
    store
        .add_password_principal(&["krbtgt", &realm], "krbtgt-secret")
        .expect("seed krbtgt");
    // A service principal so a client can exercise the TGS exchange
    // (`kvno host/app.example.com`).
    store
        .add_password_principal(&["host", "app.example.com"], "service-secret")
        .expect("seed service");
    // The cifs service (for SMB Kerberos auth): a client gets a `cifs/magnetite`
    // ticket and presents it to the SMB server, which holds this same key.
    store
        .add_password_principal(&["cifs", "magnetite"], "cifs-secret")
        .expect("seed cifs service");

    println!("magnetite-krb5 PoC KDC listening realm={realm} addr={addr} (user alice / password12; service host/app.example.com)");
    KdcServer::new(Arc::new(store))
        .run(addr.parse().expect("valid KDC_ADDR"))
        .await
}
