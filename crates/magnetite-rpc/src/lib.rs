//! `magnetite-rpc` — tracer-bullet DCE/RPC (MS-RPCE) foundation.
//!
//! Connection-oriented RPC over `ncacn_ip_tcp`: the common PDU header, BIND
//! negotiation, and REQUEST → RESPONSE/FAULT opnum dispatch. This is the
//! transport every AD RPC interface (Netlogon, SAMR, LSA, DRSUAPI) rides on; a
//! real DC plugs those interfaces into [`interface::RpcInterface`]. Authenticated
//! (sign/seal) bindings, fragmentation, the endpoint mapper, and the named-pipe
//! transport are out of scope for this slice.
//!
//! ```no_run
//! # async fn run() -> std::io::Result<()> {
//! use std::sync::Arc;
//! use magnetite_rpc::{interface::DemoInterface, serve};
//!
//! serve("127.0.0.1:8890".parse().unwrap(), Arc::new(DemoInterface)).await
//! # }
//! ```

#![forbid(unsafe_code)]

pub mod auth;
pub mod bind;
pub mod client;
pub mod directory;
pub mod drsuapi;
pub mod epm;
pub mod error;
pub mod interface;
pub mod lsa;
pub mod ndr;
pub mod netlogon;
pub mod ntlmssp;
pub mod pdu;
pub mod request;
pub mod samr;
pub mod server;

pub use client::{DrsClient, GetNcChangesRequest};
pub use directory::{Directory, Group, GroupLink, ReplMeta, User};
pub use drsuapi::{
    decrypt_unicode_pwd, exop, parse_get_nc_changes_reply, AttrMetadata, DrsuapiInterface, ExOpErr,
    FsmoRole, KerberosKey, ReplicatedAttr, ReplicatedChanges, ReplicatedLink, ReplicatedObject,
    KERB_ETYPE_AES128, KERB_ETYPE_AES256, LINK_ATTR_MEMBER,
};
pub use epm::{EpmInterface, Registration};
pub use error::{RpcError, RpcResult};
pub use interface::{DemoInterface, RpcInterface};
pub use lsa::LsaInterface;
pub use netlogon::{sign_integrity_aes, NetlogonInterface};
pub use samr::{AccountStore, RidAllocator, SamrInterface};
pub use server::{serve, NtHashLookup, RpcPipe};
