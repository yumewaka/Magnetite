//! Print a Netlogon SSP PKT_INTEGRITY signature (NL_AUTH_SHA2_SIGNATURE) as hex,
//! for byte-exact comparison against impacket's `nrpc.SIGN(..., aes=True)`.
//!
//! Fixed inputs (mirrored by the validation script):
//! * session key = ASCII "0123456789abcdef"
//! * data        = "magnetite-netlogon-ssp"
//! * sequence    = 0

use magnetite_rpc::sign_integrity_aes;

fn main() {
    let session_key: [u8; 16] = *b"0123456789abcdef";
    let data = b"magnetite-netlogon-ssp";
    let sequence = 0;

    let sig = sign_integrity_aes(&session_key, data, sequence);
    let hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();
    println!("{hex}");
}
