//! Forwarding resolver (E1c). Names outside our authoritative zones are
//! forwarded verbatim to the configured upstream resolvers over UDP; the first
//! valid response wins. Magnetite does not implement recursion itself.

use hickory_proto::op::Message;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// Forward `query` to each upstream in turn, returning the first valid DNS
/// response. Errors if every upstream fails or times out.
pub async fn forward(query: &[u8], upstreams: &[SocketAddr]) -> std::io::Result<Vec<u8>> {
    let mut last_err: Option<std::io::Error> = None;
    for upstream in upstreams {
        match forward_one(query, *upstream).await {
            Ok(response) => return Ok(response),
            Err(e) => {
                tracing::warn!("DNS forwarder {upstream} failed: {e}");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| std::io::Error::other("no upstream resolvers configured")))
}

async fn forward_one(query: &[u8], upstream: SocketAddr) -> std::io::Result<Vec<u8>> {
    let bind: SocketAddr = if upstream.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.send_to(query, upstream).await?;

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(UPSTREAM_TIMEOUT, socket.recv(&mut buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream timeout"))??;
    buf.truncate(n);

    // Only accept parseable DNS responses.
    if Message::from_vec(&buf).is_err() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed upstream response",
        ));
    }
    Ok(buf)
}

/// The minimum TTL across a response's answer records, if any.
pub fn min_answer_ttl(response: &[u8]) -> Option<u32> {
    let msg = Message::from_vec(response).ok()?;
    msg.answers().iter().map(|r| r.ttl()).min()
}
