//! KDC error type. Distinct from the Kerberos *protocol* `KRB-ERROR` message
//! (which we build and return on the wire) — this is the internal Rust error for
//! request handling failures.

use thiserror::Error;

/// A failure while processing a Kerberos request.
#[derive(Debug, Error)]
pub enum KdcError {
    /// ASN.1/DER decode or encode failure.
    #[error("ASN.1 error: {0}")]
    Asn1(String),
    /// Kerberos crypto (string-to-key, encrypt/decrypt, integrity) failure.
    #[error("kerberos crypto error: {0}")]
    Crypto(String),
    /// The request was structurally invalid or carried unusable field values.
    #[error("malformed request: {0}")]
    Malformed(String),
}

/// Result alias for KDC request handling.
pub type KdcResult<T> = Result<T, KdcError>;
