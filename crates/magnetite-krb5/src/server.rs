//! KDC network front-end: UDP and TCP listeners on the Kerberos port (88).
//!
//! Kerberos runs over both transports. UDP is one datagram per request/reply;
//! TCP frames each message with a 4-byte big-endian length prefix (RFC 4120
//! §7.2.2). Real clients try UDP first and fall back to TCP when a reply would
//! exceed the datagram size (or the KDC sets `KRB_ERR_RESPONSE_TOO_BIG`); this
//! PoC serves both and never asks for the TCP fallback.

use crate::dispatch::handle_kdc_request;
use crate::keys::PrincipalStore;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// Maximum accepted request size (defensive bound; real AS-REQs are ~1 KiB).
const MAX_REQUEST: usize = 64 * 1024;

/// An embedded Kerberos KDC serving one realm from an in-memory principal store.
pub struct KdcServer {
    store: Arc<PrincipalStore>,
}

impl KdcServer {
    /// Create a KDC over `store`.
    pub fn new(store: Arc<PrincipalStore>) -> Self {
        Self { store }
    }

    /// Bind UDP+TCP on `addr` and serve until an unrecoverable I/O error. Binding
    /// `:88` needs privileges; use e.g. `127.0.0.1:8888` for local testing.
    pub async fn run(&self, addr: SocketAddr) -> io::Result<()> {
        let udp = UdpSocket::bind(addr).await?;
        let tcp = TcpListener::bind(addr).await?;
        tracing::info!("magnetite-krb5 KDC listening on {addr} (UDP+TCP)");

        let store_udp = self.store.clone();
        let store_tcp = self.store.clone();
        tokio::select! {
            r = serve_udp(udp, store_udp) => r,
            r = serve_tcp(tcp, store_tcp) => r,
        }
    }
}

/// Best-effort extraction of a KRB-ERROR's `error-code` ([6] INTEGER): scan for the
/// common single-byte DER encoding `a6 03 02 01 <code>`. Diagnostic only.
fn krb_error_code(msg: &[u8]) -> Option<u8> {
    msg.windows(5)
        .find(|w| w[0] == 0xa6 && w[1] == 0x03 && w[2] == 0x02 && w[3] == 0x01)
        .map(|w| w[4])
}

/// Serve the UDP transport: one datagram in, one datagram out.
async fn serve_udp(socket: UdpSocket, store: Arc<PrincipalStore>) -> io::Result<()> {
    let mut buf = vec![0u8; MAX_REQUEST];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        tracing::debug!("KDC UDP request from {peer} ({len} B)");
        let response = handle_kdc_request(&store, &buf[..len]);
        if let Err(e) = socket.send_to(&response, peer).await {
            tracing::warn!("KDC UDP send to {peer} failed: {e}");
        }
    }
}

/// Serve the TCP transport: accept connections, each length-prefixed.
async fn serve_tcp(listener: TcpListener, store: Arc<PrincipalStore>) -> io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        tracing::debug!(target: "conn", %peer, "KDC TCP connection");
        let store = store.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_conn(stream, store).await {
                tracing::debug!("KDC TCP connection ended: {e}");
            }
        });
    }
}

async fn handle_tcp_conn(mut stream: TcpStream, store: Arc<PrincipalStore>) -> io::Result<()> {
    loop {
        // 4-byte big-endian length prefix, then the message.
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            return Ok(()); // clean EOF between requests
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 || len > MAX_REQUEST {
            return Ok(());
        }
        let mut req = vec![0u8; len];
        stream.read_exact(&mut req).await?;

        let response = handle_kdc_request(&store, &req);
        // The reply's outer ASN.1 application tag identifies the outcome: 0x6b AS-REP,
        // 0x6d TGS-REP (success), 0x7e KRB-ERROR (with an error code at a fixed offset).
        let kind = match response.first() {
            Some(0x6b) => "AS-REP".to_string(),
            Some(0x6d) => "TGS-REP".to_string(),
            Some(0x7e) => format!("KRB-ERROR (code {:?})", krb_error_code(&response)),
            other => format!("? tag={other:02x?}"),
        };
        tracing::debug!("KDC TCP request ({len} B) → {kind} ({} B)", response.len());
        let out_len = (response.len() as u32).to_be_bytes();
        stream.write_all(&out_len).await?;
        stream.write_all(&response).await?;
        stream.flush().await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use picky_krb::messages::KrbError;

    /// A minimal AS-REQ (no pre-auth) built to drive the server over UDP.
    fn minimal_as_req() -> Vec<u8> {
        crate::test_support::as_req_no_preauth("EXAMPLE.COM", &["alice"])
    }

    #[tokio::test]
    async fn udp_as_req_without_preauth_returns_krb_error() {
        let mut store = PrincipalStore::new("EXAMPLE.COM");
        store
            .add_password_principal(&["alice"], "password12")
            .unwrap();
        store
            .add_password_principal(&["krbtgt", "EXAMPLE.COM"], "krbtgt-secret")
            .unwrap();
        let store = Arc::new(store);

        // Bind the server to an ephemeral UDP+TCP port.
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        drop(socket);
        let server = KdcServer::new(store);
        tokio::spawn(async move {
            let _ = server.run(addr).await;
        });
        // `run` binds UDP+TCP asynchronously and exposes no readiness signal, so a
        // `UdpSocket::connect` (which always succeeds — it only sets the default peer)
        // cannot tell whether the KDC has bound yet. Retry the whole request until it
        // answers: a datagram sent before the bind is dropped, and a connected UDP
        // socket then surfaces the ICMP port-unreachable as a recv error on some
        // platforms (WSAECONNRESET on Windows, ECONNREFUSED on Linux), so resend on
        // either a timeout or an error rather than unwrapping the first attempt.
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(addr).await.unwrap();
        let mut buf = vec![0u8; MAX_REQUEST];
        let mut len = None;
        for _ in 0..100 {
            if client.send(&minimal_as_req()).await.is_err() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                continue;
            }
            match tokio::time::timeout(std::time::Duration::from_millis(200), client.recv(&mut buf))
                .await
            {
                Ok(Ok(n)) => {
                    len = Some(n);
                    break;
                }
                _ => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
            }
        }
        let len = len.expect("KDC did not respond");

        // The reply must be a KRB-ERROR demanding pre-authentication (code 25).
        let err: KrbError = picky_asn1_der::from_bytes(&buf[..len]).expect("KRB-ERROR");
        assert_eq!(
            err.0.error_code.0, 25,
            "expected KDC_ERR_PREAUTH_REQUIRED, got {}",
            err.0.error_code.0
        );
    }
}
