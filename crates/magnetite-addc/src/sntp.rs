//! A minimal SNTP server (RFC 4330) on UDP 123 — the DC serves time so a domain
//! member can keep its clock within the Kerberos clock-skew window (5 minutes);
//! Windows syncs from the DC it authenticates against (`w32time`).
//!
//! Only the essentials: answer a client-mode (mode 3) request with a server-mode
//! (mode 4) reply as a stratum-1 primary (reference id `LOCL`), echoing the
//! client's transmit timestamp into the origin field and stamping receive/transmit
//! with the current time. NTP timestamps are 64-bit: 32-bit seconds since the 1900
//! epoch, then a 32-bit fraction.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;

/// Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01).
const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

/// The fixed NTP message length (RFC 5905 §7.3) without extensions/MAC.
const NTP_MSG_LEN: usize = 48;

/// The client (request) NTP mode.
const MODE_CLIENT: u8 = 3;
/// The server (response) NTP mode.
const MODE_SERVER: u8 = 4;

/// Encode a Unix time as a 64-bit NTP timestamp (32-bit seconds ‖ 32-bit fraction).
fn ntp_timestamp(unix_secs: u64, nanos: u32) -> u64 {
    let secs = unix_secs.wrapping_add(NTP_UNIX_OFFSET);
    let frac = ((u64::from(nanos)) << 32) / 1_000_000_000;
    (secs << 32) | frac
}

/// Build the SNTP server response for a client `request`, stamped at the given Unix
/// time. Returns `None` if the packet is too short or is not a client-mode request.
pub fn build_response(request: &[u8], unix_secs: u64, nanos: u32) -> Option<Vec<u8>> {
    if request.len() < NTP_MSG_LEN {
        return None;
    }
    let version = (request[0] >> 3) & 0x7;
    if request[0] & 0x7 != MODE_CLIENT {
        return None;
    }
    let now = ntp_timestamp(unix_secs, nanos).to_be_bytes();

    let mut r = vec![0u8; NTP_MSG_LEN];
    // LI = 0 (no leap warning), VN = the client's version, Mode = 4 (server).
    r[0] = (version << 3) | MODE_SERVER;
    r[1] = 1; // Stratum 1 — a primary reference.
    r[2] = request[2]; // Echo the client's poll interval.
    r[3] = 0xEC; // Precision ≈ 2^-20 s (about a microsecond).
                 // Root delay (4..8) and root dispersion (8..12) stay zero.
    r[12..16].copy_from_slice(b"LOCL"); // Reference id: the local clock.
    r[16..24].copy_from_slice(&now); // Reference timestamp (last sync ≈ now).
    r[24..32].copy_from_slice(&request[40..48]); // Origin = client's transmit ts.
    r[32..40].copy_from_slice(&now); // Receive timestamp.
    r[40..48].copy_from_slice(&now); // Transmit timestamp.
    Some(r)
}

/// The current Unix time as `(seconds, nanoseconds)`.
fn now_unix() -> (u64, u32) {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| (d.as_secs(), d.subsec_nanos()))
        .unwrap_or((0, 0))
}

/// Serve SNTP on `addr` (UDP, conventionally `:123`), answering each client-mode
/// request with the current time. Runs until an unrecoverable I/O error.
///
/// # Errors
/// Returns an error if the UDP socket cannot be bound.
pub async fn serve_sntp(addr: SocketAddr) -> std::io::Result<()> {
    let socket = UdpSocket::bind(addr).await?;
    tracing::info!("magnetite-addc SNTP listening on {addr} (UDP)");
    let mut buf = vec![0u8; 128];
    loop {
        let (n, peer) = socket.recv_from(&mut buf).await?;
        let (secs, nanos) = now_unix();
        if let Some(response) = build_response(&buf[..n], secs, nanos) {
            if let Err(e) = socket.send_to(&response, peer).await {
                tracing::warn!("SNTP send to {peer} failed: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_request(version: u8) -> Vec<u8> {
        let mut req = vec![0u8; NTP_MSG_LEN];
        req[0] = (version << 3) | MODE_CLIENT;
        req[2] = 6; // poll interval
        req[40..48].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]); // client transmit ts
        req
    }

    #[test]
    fn response_is_server_mode_stratum1_and_echoes_origin() {
        let resp = build_response(&client_request(4), 1_700_000_000, 500_000_000).unwrap();
        assert_eq!(resp[0] & 0x7, MODE_SERVER, "server mode");
        assert_eq!((resp[0] >> 3) & 0x7, 4, "version echoed");
        assert_eq!(resp[1], 1, "stratum 1");
        assert_eq!(resp[2], 6, "poll echoed");
        assert_eq!(&resp[12..16], b"LOCL", "local-clock reference id");
        // The origin timestamp is the client's transmit timestamp verbatim.
        assert_eq!(&resp[24..32], &[1, 2, 3, 4, 5, 6, 7, 8]);
        // Transmit timestamp seconds = Unix + the 1900-epoch offset.
        let tx = u64::from_be_bytes(resp[40..48].try_into().unwrap());
        assert_eq!(tx >> 32, 1_700_000_000 + NTP_UNIX_OFFSET);
        // Fraction of 0.5 s ≈ 0x80000000.
        assert!((0x7fff_0000..=0x8001_0000).contains(&(tx & 0xffff_ffff)));
    }

    #[test]
    fn non_client_or_short_requests_are_ignored() {
        // A server-mode packet must not be answered (no reflection loops).
        let mut server_mode = client_request(4);
        server_mode[0] = (4 << 3) | MODE_SERVER;
        assert!(build_response(&server_mode, 0, 0).is_none());
        // A truncated packet is ignored.
        assert!(build_response(&[0u8; 20], 0, 0).is_none());
    }
}
