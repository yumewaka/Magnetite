//! Run the RPC server exposing the minimal SAMR interface, for interop testing
//! with impacket's typed SAMR client (`hSamrConnect`, `hSamrLookupDomainInSamServer`).
//!
//! ```sh
//! cargo run -p magnetite-rpc --example samr_poc     # listens on 0.0.0.0:8891
//! ```
//! Env override: `RPC_ADDR` (default `0.0.0.0:8891`).

use magnetite_rpc::directory::Group;
use magnetite_rpc::{serve, Directory, SamrInterface};
use std::sync::Arc;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let addr = std::env::var("RPC_ADDR").unwrap_or_else(|_| "0.0.0.0:8891".to_string());
    // alice (RID 1000) plus a group "Engineers" (RID 4200 = [1000,1001]) added through
    // the *runtime* set (`upsert_runtime_group`) — the exact path the replication agent
    // uses for inbound groups. Serving it via SAMR proves the live-directory merge
    // (all_groups/group_members) reaches a real client without a restart.
    let dir = Directory::default(); // alice RID 1000
    dir.upsert_runtime_group(Group {
        sam_account_name: "Engineers".into(),
        rid: 4200,
        members: vec![1000, 1001],
        member_links: Vec::new(),
        repl_meta: None,
    });
    println!(
        "magnetite-rpc SAMR PoC on {addr} (runtime group Engineers RID 4200 = [1000,1001]; EnumGroups/OpenGroup/GetMembers)"
    );
    serve(
        addr.parse().expect("valid RPC_ADDR"),
        Arc::new(SamrInterface::new(Arc::new(dir))),
    )
    .await
}
