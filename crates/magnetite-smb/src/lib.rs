//! `magnetite-smb` — tracer-bullet SMB2 file server for SYSVOL.
//!
//! A Windows domain member fetches Group Policy over SMB from the DC's `SYSVOL`
//! share. This crate speaks just enough SMB2 (MS-SMB2) for a client to negotiate,
//! authenticate (NTLM, accepted), connect to `SYSVOL`, open a file and read it —
//! the substrate that phase F (GPO) builds on. It also carries RPC over named
//! pipes (`ncacn_np`): [`serve_with_pipes`] exposes `IPC$` and dispatches pipe
//! reads/writes to [`magnetite_rpc`] interfaces. Signing/encryption and SMB 3.x
//! are out of scope.
//!
//! ```no_run
//! # async fn run() -> std::io::Result<()> {
//! magnetite_smb::serve("0.0.0.0:445".parse().unwrap()).await
//! # }
//! ```

#![forbid(unsafe_code)]

mod comp;
mod enc;
mod server;
mod sign;
mod spnego;
mod vfs;

pub use server::{
    serve, serve_with_kerberos, serve_with_kerberos_and_pipes, serve_with_pipes, set_netlogon,
    set_sysvol, NtHashLookup, PipeFactory, PipeRegistry,
};
pub use vfs::{default_sysvol_files, Vfs};
