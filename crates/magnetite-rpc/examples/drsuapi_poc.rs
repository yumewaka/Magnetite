//! Run the RPC server exposing the minimal DRSUAPI interface, for interop testing
//! with a replication client (impacket `drsuapi.DRSBind` / `DRSGetNCChanges`).
//!
//! ```sh
//! cargo run -p magnetite-rpc --example drsuapi_poc     # listens on 0.0.0.0:1027
//! ```
//! Env override: `RPC_ADDR` (default `0.0.0.0:1027`).

use magnetite_rpc::ntlmssp::nt_hash;
use magnetite_rpc::server::serve_with_ntlm;
use magnetite_rpc::DrsuapiInterface;
use std::sync::Arc;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let addr = std::env::var("RPC_ADDR").unwrap_or_else(|_| "0.0.0.0:1027".to_string());
    println!(
        "magnetite-rpc DRSUAPI PoC on {addr} (DRSBind / DRSGetNCChanges — replicates 'alice'; \
         NTLM bind as alice/password12 → real negotiated session key)"
    );
    // Accept NTLM binds as alice/password12; unauthenticated binds still work
    // (falling back to the fixed PoC secret key).
    serve_with_ntlm(
        addr.parse().expect("valid RPC_ADDR"),
        Arc::new(DrsuapiInterface::default()),
        nt_hash("password12"),
    )
    .await
}
