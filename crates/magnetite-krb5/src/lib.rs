//! `magnetite-krb5` — tracer-bullet Kerberos KDC (Option 3, phase C slice).
//!
//! Scope of this PoC: enough of the Kerberos AS exchange (RFC 4120) that a real
//! client (`kinit`) can obtain a TGT against us — proving the KDC crypto and
//! protocol are alive. TGS, PAC (MS-PAC), referrals and directory integration
//! are deliberately out of scope here and land in later phases.
//!
//! The pieces:
//! * [`keys`] — RFC 3961 string-to-key and an in-memory principal store.
//! * [`as_exchange`] — the AS-REQ → AS-REP / KRB-ERROR state machine.
//! * [`tgs_exchange`] — the TGS-REQ → TGS-REP / KRB-ERROR state machine.
//! * [`dispatch`] — route a request to the AS or TGS handler by its tag.
//! * [`server`] — UDP+TCP listeners on the Kerberos port.
//!
//! ```no_run
//! # async fn run() -> std::io::Result<()> {
//! use std::sync::Arc;
//! use magnetite_krb5::{keys::PrincipalStore, server::KdcServer};
//!
//! let mut store = PrincipalStore::new("EXAMPLE.COM");
//! store.add_password_principal(&["alice"], "password12").unwrap();
//! store.add_password_principal(&["krbtgt", "EXAMPLE.COM"], "krbtgt-secret").unwrap();
//!
//! KdcServer::new(Arc::new(store))
//!     .run("127.0.0.1:8888".parse().unwrap())
//!     .await
//! # }
//! ```

#![forbid(unsafe_code)]

pub mod ap_client;
pub mod ap_req;
pub mod as_exchange;
pub mod dispatch;
pub mod error;
pub mod gss;
pub mod kdc_client;
pub mod keys;
pub mod keytab;
pub mod kpasswd;
pub mod ndr;
pub mod pac;
pub mod server;
pub mod spnego;
pub mod tgs_exchange;

#[cfg(test)]
mod test_support;

pub use ap_client::{build_ap_req, dce_style_auth3, decrypt_ap_rep_subkey};
pub use ap_req::{verify_ap_req, VerifiedApReq};
pub use as_exchange::{handle_as_req, handle_request, AsOutcome};
pub use dispatch::handle_kdc_request;
pub use error::{KdcError, KdcResult};
pub use kdc_client::{
    build_ap_req_from_ticket, build_gss_ap_req_from_ticket, obtain_service_ticket, ObtainedTicket,
};
pub use keys::PrincipalStore;
pub use keytab::{load_key as load_keytab_key, parse_keytab, KeytabEntry};
pub use kpasswd::{handle_kpasswd, serve_kpasswd};
pub use server::KdcServer;
pub use tgs_exchange::{handle_tgs_req, TgsOutcome};
