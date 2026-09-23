//! Error type for the connection-oriented RPC layer.

use thiserror::Error;

/// A failure parsing or handling an RPC PDU.
#[derive(Debug, Error)]
pub enum RpcError {
    /// The buffer ended before a field could be read.
    #[error("truncated PDU")]
    Truncated,
    /// Unexpected RPC major version (we speak version 5).
    #[error("unsupported RPC version {0}")]
    Version(u8),
    /// A structurally invalid PDU.
    #[error("malformed PDU: {0}")]
    Malformed(&'static str),
    /// A client-side transport or protocol failure (dynamic message).
    #[error("{0}")]
    Client(String),
}

/// Result alias for RPC parsing.
pub type RpcResult<T> = Result<T, RpcError>;
