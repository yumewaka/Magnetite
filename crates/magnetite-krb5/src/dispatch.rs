//! Top-level KDC request routing: distinguish AS-REQ from TGS-REQ by their outer
//! ASN.1 application tag and dispatch to the right handler.
//!
//! `[APPLICATION 10]` (AS-REQ) encodes as `0x6a`; `[APPLICATION 12]` (TGS-REQ) as
//! `0x6c` (application class `0b01`, constructed bit `0x20`, plus the tag number).

use crate::keys::PrincipalStore;
use crate::{as_exchange, tgs_exchange};

/// Outer application tag of a TGS-REQ (`[APPLICATION 12]`). AS-REQ is `0x6a`.
const APP_TAG_TGS_REQ: u8 = 0x6c;

/// Route one KDC request to the AS or TGS handler and return the wire response.
pub fn handle_kdc_request(store: &PrincipalStore, request: &[u8]) -> Vec<u8> {
    match request.first().copied() {
        Some(APP_TAG_TGS_REQ) => tgs_exchange::handle_tgs_request(store, request),
        // AS-REQ (0x6a) or anything malformed: the AS path turns unusable input
        // into a clean generic KRB-ERROR rather than a dropped reply.
        _ => as_exchange::handle_request(store, request),
    }
}
