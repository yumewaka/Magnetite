//! Serve RPC over SMB named pipes (`ncacn_np`): a client can `connectTree(IPC$)`,
//! open `\pipe\lsarpc` or `\pipe\samr`, and drive the LSA/SAMR interfaces over
//! SMB — for interop testing with impacket's `SMBTransport`.
//!
//! ```sh
//! cargo run -p magnetite-smb --example np_poc     # listens on 0.0.0.0:4450
//! ```
//! Env override: `SMB_ADDR` (default `0.0.0.0:4450`).

use magnetite_rpc::{LsaInterface, RpcInterface, SamrInterface};
use magnetite_smb::{serve_with_pipes, PipeFactory, PipeRegistry};
use std::sync::Arc;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let addr = std::env::var("SMB_ADDR").unwrap_or_else(|_| "0.0.0.0:4450".to_string());

    let mut pipes = PipeRegistry::new();
    let lsa: PipeFactory = Arc::new(|| Arc::new(LsaInterface::default()) as Arc<dyn RpcInterface>);
    let samr: PipeFactory =
        Arc::new(|| Arc::new(SamrInterface::default()) as Arc<dyn RpcInterface>);
    pipes.insert("lsarpc".to_string(), lsa);
    pipes.insert("samr".to_string(), samr);

    println!("magnetite-smb ncacn_np PoC on {addr} (IPC$; pipes: lsarpc, samr)");
    serve_with_pipes(addr.parse().expect("valid SMB_ADDR"), pipes).await
}
