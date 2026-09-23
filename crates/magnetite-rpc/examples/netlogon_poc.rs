//! Run the RPC server exposing the Netlogon secure-channel interface, for interop
//! testing with impacket's `nrpc` client and crypto helpers.
//!
//! ```sh
//! cargo run -p magnetite-rpc --example netlogon_poc     # listens on 0.0.0.0:8892
//! ```
//! The machine-account password is `Machine123` (env `MACHINE_PASSWORD` to change).

use magnetite_rpc::{serve, NetlogonInterface};
use std::sync::Arc;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let addr = std::env::var("RPC_ADDR").unwrap_or_else(|_| "0.0.0.0:8892".to_string());
    let password = std::env::var("MACHINE_PASSWORD").unwrap_or_else(|_| "Machine123".to_string());
    println!("magnetite-rpc Netlogon PoC on {addr} (ReqChallenge + Authenticate3; machine pw '{password}')");
    serve(
        addr.parse().expect("valid RPC_ADDR"),
        Arc::new(NetlogonInterface::new(&password)),
    )
    .await
}
