//! Run the SMB2 server with Kerberos authentication enabled. The `cifs/magnetite`
//! service key is derived from the same password the KDC (`kdc_poc`) seeds for
//! that principal, so a client can get a `cifs/magnetite` ticket from the KDC and
//! present it here.
//!
//! ```sh
//! # the KDC (seeds cifs/magnetite / cifs-secret) on :88, and this on :445
//! cargo run -p magnetite-krb5 --example kdc_poc
//! cargo run -p magnetite-smb  --example smb_kerberos_poc
//! ```
//! Env override: `SMB_ADDR` (default `0.0.0.0:445`).

use magnetite_krb5::keys::{default_salt, derive_aes256_key};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let addr = std::env::var("SMB_ADDR").unwrap_or_else(|_| "0.0.0.0:445".to_string());

    // Must match the KDC's cifs/magnetite principal (realm + name + password).
    let realm = "EXAMPLE.COM";
    let service = ["cifs".to_string(), "magnetite".to_string()];
    let key32 = derive_aes256_key("cifs-secret", &default_salt(realm, &service))
        .expect("derive cifs service key");
    let mut service_key = [0u8; 32];
    service_key.copy_from_slice(&key32);

    println!("magnetite-smb Kerberos PoC on {addr} (cifs/magnetite; share SYSVOL)");
    magnetite_smb::serve_with_kerberos(addr.parse().expect("valid SMB_ADDR"), service_key).await
}
