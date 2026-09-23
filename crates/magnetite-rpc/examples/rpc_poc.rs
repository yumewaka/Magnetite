//! Run the tracer-bullet RPC server with the demo interface, for interop testing
//! with a real client (e.g. impacket's `DCERPC_v5`).
//!
//! ```sh
//! cargo run -p magnetite-rpc --example rpc_poc          # listens on 0.0.0.0:8890
//! ```
//! Env override: `RPC_ADDR` (default `0.0.0.0:8890`).

use magnetite_rpc::{interface::DemoInterface, serve};
use std::sync::Arc;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let addr = std::env::var("RPC_ADDR").unwrap_or_else(|_| "0.0.0.0:8890".to_string());
    println!(
        "magnetite-rpc PoC listening on {addr} (ncacn_ip_tcp; demo interface: opnum 0=Add, 1=Echo)"
    );
    serve(
        addr.parse().expect("valid RPC_ADDR"),
        Arc::new(DemoInterface),
    )
    .await
}
