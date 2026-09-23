//! Run the tracer-bullet SMB2 server, for interop testing with a real SMB client
//! (e.g. impacket's `SMBConnection` or `smbclient`).
//!
//! ```sh
//! cargo run -p magnetite-smb --example smb_poc      # listens on 0.0.0.0:445
//! ```
//! Env override: `SMB_ADDR` (default `0.0.0.0:445`; binding :445 needs privileges,
//! so use e.g. `127.0.0.1:4445` for unprivileged local testing).

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let addr = std::env::var("SMB_ADDR").unwrap_or_else(|_| "0.0.0.0:445".to_string());
    println!("magnetite-smb PoC listening on {addr} (SMB2 dialect 2.1; share SYSVOL)");
    magnetite_smb::serve(addr.parse().expect("valid SMB_ADDR")).await
}
