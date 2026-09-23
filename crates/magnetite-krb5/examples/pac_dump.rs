//! Write a signed PAC (the exact bytes our KDC embeds in a service ticket) to a
//! file, for independent validation with e.g. Samba `ndrdump krb5pac PAC_DATA`.
//!
//! ```sh
//! cargo run -p magnetite-krb5 --example pac_dump /tmp/pac.bin
//! ndrdump krb5pac PAC_DATA struct /tmp/pac.bin
//! ```

use magnetite_krb5::keys::derive_aes256_key;
use magnetite_krb5::pac::{build_pac, PacIdentity};
use std::io::Write;

fn main() {
    // The same principals the PoC KDC seeds (see examples/kdc_poc.rs).
    let service_key =
        derive_aes256_key("service-secret", "EXAMPLE.COMhostapp.example.com").expect("service key");
    let krbtgt_key =
        derive_aes256_key("krbtgt-secret", "EXAMPLE.COMkrbtgtEXAMPLE.COM").expect("krbtgt key");

    let pac = build_pac(
        &service_key,
        &krbtgt_key,
        "alice",
        "EXAMPLE.COM",
        1_700_000_000,
        &PacIdentity::minimal(1000, vec![21, 1, 2, 3]),
    )
    .expect("build PAC");

    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "pac.bin".to_string());
    std::fs::File::create(&path)
        .and_then(|mut f| f.write_all(&pac))
        .expect("write PAC");
    eprintln!("wrote {} PAC bytes to {path}", pac.len());
}
