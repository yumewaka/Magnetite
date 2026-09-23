//! Per-acceptor connection limiting for the mail services.
//!
//! Every accepted socket spawns a per-connection task; without a bound, a flood of
//! connections (each cheap for the attacker) spawns an unbounded number of tasks and
//! sockets on the server. Each acceptor (SMTP/IMAP/POP3, plain or implicit-TLS) holds a
//! [`limiter`] of [`MAX_CONNECTIONS`] slots: a connection over the cap is dropped at
//! accept — the client can retry — instead of being serviced. The acquired permit is
//! moved into the connection task, so a slot frees the moment that connection ends.

use std::sync::Arc;
use tokio::sync::Semaphore;

/// Maximum concurrent client connections per mail acceptor. Generous for real use
/// (hundreds of simultaneous clients) while still bounding a connection flood.
pub(crate) const MAX_CONNECTIONS: usize = 256;

/// A fresh connection limiter holding [`MAX_CONNECTIONS`] permits.
pub(crate) fn limiter() -> Arc<Semaphore> {
    Arc::new(Semaphore::new(MAX_CONNECTIONS))
}
