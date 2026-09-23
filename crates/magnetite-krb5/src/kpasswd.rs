//! Kerberos Change/Set Password protocol (RFC 3244) on port 464 — the operation a
//! client (or a joined machine) uses to change its own Kerberos password.
//!
//! The request framing (RFC 3244 §2) is `len(2) ‖ version(2) ‖ ap-req-len(2) ‖
//! AP-REQ ‖ KRB-PRIV`. The AP-REQ authenticates the client against the
//! `kadmin/changepw` service key; the KRB-PRIV (sealed under the AP-REQ
//! authenticator sub-session key, or the ticket session key if none) carries the
//! new password. The reply mirrors the framing with an AP-REP and a KRB-PRIV whose
//! user-data is a 2-byte result code followed by an ASCII message.
//!
//! Scope: change-password (version `0x0001`, raw new password) and set-password
//! (version `0xff80`, a `ChangePasswdData` with an optional target). The client
//! changes its own principal (or `targname` for set-password); the derived AES256
//! key is written to the [`PrincipalStore`] so the next `kinit` uses it.

use crate::ap_req::{build_ap_rep, verify_ap_req};
use crate::as_exchange::{asn1, encrypted_data, int, read_name};
use crate::error::KdcResult;
use crate::keys::PrincipalStore;
use picky_asn1::wrapper::{
    ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag3, ExplicitContextTag4,
    OctetStringAsn1, Optional,
};
use picky_krb::constants::key_usages::KRB_PRIV_ENC_PART;
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{ChangePasswdData, EncKrbPrivPart, EncKrbPrivPartInner, HostAddress};
use picky_krb::messages::{KrbPriv, KrbPrivInner};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// Defensive bound on a `kpasswd` message (real ones are ~1–2 KiB).
const MAX_KPASSWD: usize = 64 * 1024;

/// The KRB-PRIV message type (RFC 4120 §5.7.1).
const KRB_PRIV_MSG_TYPE: i64 = 21;
/// Change-password (original protocol): the KRB-PRIV user-data is the new password.
const VERSION_CHANGE: u16 = 0x0001;
/// Set-password (RFC 3244): the user-data is a DER `ChangePasswdData`.
const VERSION_SET: u16 = 0xff80;

/// `kpasswd` result codes (RFC 3244 §2).
pub const KPASSWD_SUCCESS: u16 = 0;
const KPASSWD_MALFORMED: u16 = 1;
const KPASSWD_HARDERROR: u16 = 2;
const KPASSWD_AUTHERROR: u16 = 3;

/// Handle one `kpasswd` request, returning the framed reply bytes. Returns `None`
/// when the request cannot be parsed or the AP-REQ does not authenticate (no reply
/// can be built without a session key); otherwise a reply is always produced, its
/// KRB-PRIV carrying the success or error result code.
pub fn handle_kpasswd(
    store: &PrincipalStore,
    changepw_key: &[u8],
    request: &[u8],
) -> Option<Vec<u8>> {
    let (version, ap_req, krb_priv) = parse_request(request)?;
    let verified = verify_ap_req(changepw_key, ap_req).ok()?;
    // The KRB-PRIV is keyed on the authenticator sub-session key when present,
    // else the ticket session key (RFC 3244 / RFC 4120 §3.2.6).
    let priv_key = verified
        .authenticator_subkey
        .clone()
        .unwrap_or_else(|| verified.session_key.clone());

    let (code, message) =
        match apply_change(store, &priv_key, version, krb_priv, &verified.client_name) {
            Ok(()) => (KPASSWD_SUCCESS, "Password changed"),
            Err(code) => (code, "Password change rejected"),
        };

    let (ap_rep, _subkey) =
        build_ap_rep(&verified.session_key, verified.ctime, verified.cusec, 0).ok()?;
    let priv_reply = build_priv_reply(&priv_key, code, message).ok()?;
    Some(frame(version, &ap_rep, &priv_reply))
}

/// Parse the request framing, returning `(version, ap_req, krb_priv)`.
fn parse_request(buf: &[u8]) -> Option<(u16, &[u8], &[u8])> {
    if buf.len() < 6 {
        return None;
    }
    let msg_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    let version = u16::from_be_bytes([buf[2], buf[3]]);
    let ap_req_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ap_req_end = 6usize.checked_add(ap_req_len)?;
    if msg_len < ap_req_end || msg_len > buf.len() {
        return None;
    }
    Some((version, &buf[6..ap_req_end], &buf[ap_req_end..msg_len]))
}

/// Decrypt the request KRB-PRIV, extract the new password (+ target), and apply it.
/// Returns a `kpasswd` result code on failure.
fn apply_change(
    store: &PrincipalStore,
    priv_key: &[u8],
    version: u16,
    krb_priv_bytes: &[u8],
    client_name: &[String],
) -> Result<(), u16> {
    let krb_priv: KrbPriv =
        picky_asn1_der::from_bytes(krb_priv_bytes).map_err(|_| KPASSWD_MALFORMED)?;
    let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();
    let plain = cipher
        .decrypt(
            priv_key,
            KRB_PRIV_ENC_PART,
            &krb_priv.0.enc_part.0.cipher.0 .0,
        )
        .map_err(|_| KPASSWD_AUTHERROR)?;
    let priv_part: EncKrbPrivPart =
        picky_asn1_der::from_bytes(&plain).map_err(|_| KPASSWD_MALFORMED)?;
    let user_data = priv_part.0.user_data.0 .0;

    let (new_password, target) = extract_new_password(version, &user_data, client_name)?;
    let target_refs: Vec<&str> = target.iter().map(String::as_str).collect();
    store
        .set_password(&target_refs, &new_password)
        .map_err(|_| KPASSWD_HARDERROR)?;
    Ok(())
}

/// Extract the new password and the target principal from the KRB-PRIV user-data.
fn extract_new_password(
    version: u16,
    user_data: &[u8],
    client_name: &[String],
) -> Result<(String, Vec<String>), u16> {
    match version {
        // change-password: the user-data is the raw new password; target is self.
        VERSION_CHANGE => {
            let password = String::from_utf8(user_data.to_vec()).map_err(|_| KPASSWD_MALFORMED)?;
            Ok((password, client_name.to_vec()))
        }
        // set-password: a ChangePasswdData with the new password + optional target.
        VERSION_SET => {
            let change: ChangePasswdData =
                picky_asn1_der::from_bytes(user_data).map_err(|_| KPASSWD_MALFORMED)?;
            let password =
                String::from_utf8(change.new_passwd.0 .0).map_err(|_| KPASSWD_MALFORMED)?;
            let target = change
                .target_name
                .0
                .as_ref()
                .map(|n| read_name(&n.0))
                .unwrap_or_else(|| client_name.to_vec());
            Ok((password, target))
        }
        _ => Err(KPASSWD_MALFORMED),
    }
}

/// Build the reply KRB-PRIV: a 2-byte result code + ASCII message, sealed under
/// `priv_key` (key usage 13).
fn build_priv_reply(priv_key: &[u8], code: u16, message: &str) -> KdcResult<Vec<u8>> {
    let mut user_data = code.to_be_bytes().to_vec();
    user_data.extend_from_slice(message.as_bytes());

    let enc_part = EncKrbPrivPart::from(EncKrbPrivPartInner {
        user_data: ExplicitContextTag0::from(OctetStringAsn1::from(user_data)),
        timestamp: Optional::from(None),
        usec: Optional::from(None),
        seq_number: Optional::from(None),
        // s-address is mandatory in EncKrbPrivPart; the DC's loopback address is a
        // benign placeholder (a real DC uses the socket's local address).
        s_address: ExplicitContextTag4::from(HostAddress {
            addr_type: ExplicitContextTag0::from(int(2)), // IPv4
            address: ExplicitContextTag1::from(OctetStringAsn1::from(vec![127, 0, 0, 1])),
        }),
        r_address: Optional::from(None),
    });
    let plain = picky_asn1_der::to_vec(&enc_part).map_err(asn1)?;
    let sealed = CipherSuite::Aes256CtsHmacSha196
        .cipher()
        .encrypt(priv_key, KRB_PRIV_ENC_PART, &plain)
        .map_err(|e| crate::error::KdcError::Crypto(format!("KRB-PRIV encrypt failed: {e}")))?;

    let krb_priv = KrbPriv::from(KrbPrivInner {
        pvno: ExplicitContextTag0::from(int(5)),
        msg_type: ExplicitContextTag1::from(int(KRB_PRIV_MSG_TYPE)),
        enc_part: ExplicitContextTag3::from(encrypted_data(sealed)),
    });
    picky_asn1_der::to_vec(&krb_priv).map_err(asn1)
}

/// Frame a reply: `len(2) ‖ version(2) ‖ ap-rep-len(2) ‖ AP-REP ‖ KRB-PRIV`.
fn frame(version: u16, ap_rep: &[u8], krb_priv: &[u8]) -> Vec<u8> {
    let total = 6 + ap_rep.len() + krb_priv.len();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(total as u16).to_be_bytes());
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&(ap_rep.len() as u16).to_be_bytes());
    out.extend_from_slice(ap_rep);
    out.extend_from_slice(krb_priv);
    out
}

/// Serve the Change/Set Password protocol on `addr` (UDP + TCP, conventionally
/// `:464`) using `changepw_key` (the `kadmin/changepw` service key) to verify each
/// AP-REQ. Runs until an unrecoverable I/O error.
///
/// # Errors
/// Returns an error if either socket cannot be bound.
pub async fn serve_kpasswd(
    addr: SocketAddr,
    store: Arc<PrincipalStore>,
    changepw_key: Vec<u8>,
) -> io::Result<()> {
    let udp = UdpSocket::bind(addr).await?;
    let tcp = TcpListener::bind(addr).await?;
    tracing::info!("magnetite-krb5 kpasswd listening on {addr} (UDP+TCP)");
    let key = Arc::new(changepw_key);
    let (store_udp, key_udp) = (store.clone(), key.clone());
    tokio::select! {
        r = serve_udp(udp, store_udp, key_udp) => r,
        r = serve_tcp(tcp, store, key) => r,
    }
}

/// UDP: one datagram per request/reply.
async fn serve_udp(
    socket: UdpSocket,
    store: Arc<PrincipalStore>,
    key: Arc<Vec<u8>>,
) -> io::Result<()> {
    let mut buf = vec![0u8; MAX_KPASSWD];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await?;
        if let Some(reply) = handle_kpasswd(&store, &key, &buf[..len]) {
            if let Err(e) = socket.send_to(&reply, peer).await {
                tracing::warn!("kpasswd UDP send to {peer} failed: {e}");
            }
        }
    }
}

/// TCP: each message is self-framed by its leading 2-byte length (RFC 3244 §2).
async fn serve_tcp(
    listener: TcpListener,
    store: Arc<PrincipalStore>,
    key: Arc<Vec<u8>>,
) -> io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        tracing::debug!(target: "conn", %peer, "kpasswd TCP connection");
        let (store, key) = (store.clone(), key.clone());
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_conn(stream, store, key).await {
                tracing::debug!("kpasswd TCP connection ended: {e}");
            }
        });
    }
}

async fn handle_tcp_conn(
    mut stream: TcpStream,
    store: Arc<PrincipalStore>,
    key: Arc<Vec<u8>>,
) -> io::Result<()> {
    loop {
        // The message's own 2-byte length field (which includes itself) frames it.
        let mut len_buf = [0u8; 2];
        if stream.read_exact(&mut len_buf).await.is_err() {
            return Ok(()); // clean EOF between requests
        }
        let total = u16::from_be_bytes(len_buf) as usize;
        if !(2..=MAX_KPASSWD).contains(&total) {
            return Ok(());
        }
        let mut msg = vec![0u8; total];
        msg[..2].copy_from_slice(&len_buf);
        stream.read_exact(&mut msg[2..]).await?;
        if let Some(reply) = handle_kpasswd(&store, &key, &msg) {
            stream.write_all(&reply).await?;
            stream.flush().await?;
        }
    }
}

/// Read the result code from a reply's decrypted KRB-PRIV user-data.
#[cfg(test)]
pub(crate) fn reply_result_code(user_data: &[u8]) -> Option<u16> {
    (user_data.len() >= 2).then(|| u16::from_be_bytes([user_data[0], user_data[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{default_salt, derive_aes256_key};

    /// Seal arbitrary `user_data` into a KRB-PRIV under `priv_key` — the client
    /// side of the request (its user-data is the new password for version 1).
    fn seal_priv(priv_key: &[u8], user_data: Vec<u8>) -> Vec<u8> {
        let enc_part = EncKrbPrivPart::from(EncKrbPrivPartInner {
            user_data: ExplicitContextTag0::from(OctetStringAsn1::from(user_data)),
            timestamp: Optional::from(None),
            usec: Optional::from(None),
            seq_number: Optional::from(None),
            s_address: ExplicitContextTag4::from(HostAddress {
                addr_type: ExplicitContextTag0::from(int(2)),
                address: ExplicitContextTag1::from(OctetStringAsn1::from(vec![127, 0, 0, 1])),
            }),
            r_address: Optional::from(None),
        });
        let plain = picky_asn1_der::to_vec(&enc_part).unwrap();
        let sealed = CipherSuite::Aes256CtsHmacSha196
            .cipher()
            .encrypt(priv_key, KRB_PRIV_ENC_PART, &plain)
            .unwrap();
        let krb_priv = KrbPriv::from(KrbPrivInner {
            pvno: ExplicitContextTag0::from(int(5)),
            msg_type: ExplicitContextTag1::from(int(KRB_PRIV_MSG_TYPE)),
            enc_part: ExplicitContextTag3::from(encrypted_data(sealed)),
        });
        picky_asn1_der::to_vec(&krb_priv).unwrap()
    }

    #[test]
    fn framing_round_trips() {
        let framed = frame(VERSION_CHANGE, b"the-ap-message", b"the-krb-priv");
        let (version, ap, priv_) = parse_request(&framed).expect("parse");
        assert_eq!(version, VERSION_CHANGE);
        assert_eq!(ap, b"the-ap-message");
        assert_eq!(priv_, b"the-krb-priv");
        // A truncated frame (length field claims more than is present) is rejected.
        assert!(parse_request(&framed[..framed.len() - 1]).is_none());
    }

    #[test]
    fn change_password_v1_updates_the_principal_key() {
        let realm = "EXAMPLE.COM";
        let mut store = PrincipalStore::new(realm);
        store
            .add_password_principal(&["alice"], "oldpass1")
            .unwrap();
        let priv_key: Vec<u8> = (0u8..32).collect();
        let client = vec!["alice".to_string()];
        let new_pw = "N3wAlicePass!";

        let request_priv = seal_priv(&priv_key, new_pw.as_bytes().to_vec());
        apply_change(&store, &priv_key, VERSION_CHANGE, &request_priv, &client).expect("applied");

        // The dynamic key now shadows the seed: alice's key derives from the new pw.
        let principal = store.get(&client).expect("alice present");
        let expected =
            derive_aes256_key(new_pw, &default_salt(realm, &["alice".to_string()])).unwrap();
        assert_eq!(
            principal.key.key, expected,
            "kpasswd updated the Kerberos key"
        );

        // A wrong priv key fails to decrypt the KRB-PRIV → AUTHERROR.
        let wrong: Vec<u8> = (1u8..33).collect();
        assert_eq!(
            apply_change(&store, &wrong, VERSION_CHANGE, &request_priv, &client),
            Err(KPASSWD_AUTHERROR)
        );
    }

    #[test]
    fn set_password_v2_reads_change_passwd_data_target_and_password() {
        let realm = "EXAMPLE.COM";
        let store = PrincipalStore::new(realm);
        let priv_key: Vec<u8> = (0u8..32).collect();

        // A known-good `ChangePasswdData` (from picky-krb's own round-trip vector):
        // new password "qweQWE123!@#", target name "e3", target realm "EXAMPLE.COM".
        let change_passwd_data: &[u8] = &[
            48, 47, 160, 14, 4, 12, 113, 119, 101, 81, 87, 69, 49, 50, 51, 33, 64, 35, 161, 14, 48,
            12, 160, 2, 2, 0, 161, 6, 48, 4, 27, 2, 101, 51, 162, 13, 27, 11, 69, 88, 65, 77, 80,
            76, 69, 46, 67, 79, 77,
        ];
        let request_priv = seal_priv(&priv_key, change_passwd_data.to_vec());

        apply_change(
            &store,
            &priv_key,
            VERSION_SET,
            &request_priv,
            &["alice".to_string()],
        )
        .expect("applied");

        // The change lands on the target "e3" (not the client), with the new password.
        let expected =
            derive_aes256_key("qweQWE123!@#", &default_salt(realm, &["e3".to_string()])).unwrap();
        assert_eq!(store.get(&["e3".to_string()]).unwrap().key.key, expected);
    }

    #[test]
    fn reply_priv_carries_the_result_code() {
        let priv_key: Vec<u8> = (0u8..32).collect();
        let reply = build_priv_reply(&priv_key, KPASSWD_SUCCESS, "Password changed").unwrap();

        // The client decrypts the reply KRB-PRIV and reads the result code.
        let krb_priv: KrbPriv = picky_asn1_der::from_bytes(&reply).unwrap();
        let plain = CipherSuite::Aes256CtsHmacSha196
            .cipher()
            .decrypt(
                &priv_key,
                KRB_PRIV_ENC_PART,
                &krb_priv.0.enc_part.0.cipher.0 .0,
            )
            .unwrap();
        let part: EncKrbPrivPart = picky_asn1_der::from_bytes(&plain).unwrap();
        assert_eq!(
            reply_result_code(&part.0.user_data.0 .0),
            Some(KPASSWD_SUCCESS)
        );
    }
}
