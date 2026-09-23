//! Run the RPC server exposing the minimal LSA interface, for interop testing
//! with impacket's typed LSAD/LSAT client (`hLsarOpenPolicy2`,
//! `hLsarQueryInformationPolicy2`, `hLsarLookupSids`).
//!
//! ```sh
//! cargo run -p magnetite-rpc --example lsa_poc     # listens on 0.0.0.0:8893
//! ```
//! Env override: `RPC_ADDR` (default `0.0.0.0:8893`).

use magnetite_rpc::{serve, LsaInterface};
use std::sync::Arc;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let addr = std::env::var("RPC_ADDR").unwrap_or_else(|_| "0.0.0.0:8893".to_string());
    println!(
        "magnetite-rpc LSA PoC on {addr} (OpenPolicy/QueryInformationPolicy/LookupSids; domain EXAMPLE)"
    );
    serve(
        addr.parse().expect("valid RPC_ADDR"),
        Arc::new(LsaInterface::default()),
    )
    .await
}
