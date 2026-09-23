//! AP-REQ verification (RFC 4120 §3.2): the server side of Kerberos application
//! authentication. A client presents an AP-REQ (a service ticket + an
//! authenticator); the service decrypts the ticket with its own long-term key to
//! recover the session key and the client's identity, then decrypts the
//! authenticator with that session key to prove the client holds it.
//!
//! This is what a Kerberos-authenticated service (e.g. SMB/`cifs`) does to verify
//! a caller — the counterpart to the AS/TGS the KDC performs.

use crate::as_exchange::{asn1, encrypted_data, int, read_name, within_skew};
use crate::error::{KdcError, KdcResult};
use crate::keys::AES256_CTS_HMAC_SHA1_96;
use picky_asn1::wrapper::{
    ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
    OctetStringAsn1, Optional,
};
use picky_krb::constants::key_usages::{AP_REP_ENC, AP_REQ_AUTHENTICATOR, TICKET_REP};
use picky_krb::constants::types::AP_REP_MSG_TYPE;
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{
    Authenticator, EncApRepPart, EncApRepPartInner, EncTicketPart, EncryptionKey, KerberosTime,
    Microseconds,
};
use picky_krb::messages::{ApRep, ApRepInner, ApReq};
use rand::RngCore;

/// The authenticated result of a verified AP-REQ.
pub struct VerifiedApReq {
    /// The client principal's name components (e.g. `["alice"]`).
    pub client_name: Vec<String>,
    /// The client's realm.
    pub client_realm: String,
    /// The ticket session key (used to encrypt the AP-REP enc-part, usage 12).
    pub session_key: Vec<u8>,
    /// The authenticator's sub-session key, if the client supplied one. Kerberos
    /// per-message protection (e.g. the `kpasswd` KRB-PRIV) is keyed on this when
    /// present, falling back to the ticket session key otherwise.
    pub authenticator_subkey: Option<Vec<u8>>,
    /// The authenticator's client time — echoed in the AP-REP for mutual auth.
    pub ctime: KerberosTime,
    /// The authenticator's client microseconds — echoed likewise.
    pub cusec: Microseconds,
}

/// Verify an AP-REQ against the service's long-term key.
///
/// Decrypts the embedded ticket (key usage 2), then the authenticator (key usage
/// 11) with the recovered session key, and checks the authenticator's client and
/// timestamp against the ticket.
pub fn verify_ap_req(service_key: &[u8], ap_req_bytes: &[u8]) -> KdcResult<VerifiedApReq> {
    let ap_req: ApReq = picky_asn1_der::from_bytes(ap_req_bytes).map_err(asn1)?;
    let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();

    // 1. Decrypt the service ticket with our own key → session key + client id.
    let ticket = &ap_req.0.ticket.0;
    let ticket_plain = cipher
        .decrypt(service_key, TICKET_REP, &ticket.0.enc_part.0.cipher.0 .0)
        .map_err(|e| KdcError::Crypto(format!("ticket decrypt failed: {e}")))?;
    let enc_ticket: EncTicketPart = picky_asn1_der::from_bytes(&ticket_plain).map_err(asn1)?;
    let session_key = enc_ticket.0.key.0.key_value.0 .0.clone();
    let client_name = read_name(&enc_ticket.0.cname.0);
    let client_realm = String::from_utf8_lossy(enc_ticket.0.crealm.0.as_bytes()).into_owned();

    // 2. Decrypt the authenticator with the session key (usage 11).
    let auth_plain = cipher
        .decrypt(
            &session_key,
            AP_REQ_AUTHENTICATOR,
            &ap_req.0.authenticator.0.cipher.0 .0,
        )
        .map_err(|e| KdcError::Crypto(format!("authenticator decrypt failed: {e}")))?;
    let authenticator: Authenticator = picky_asn1_der::from_bytes(&auth_plain).map_err(asn1)?;

    // 3. The authenticator's client must match the ticket's, and be fresh.
    if read_name(&authenticator.0.cname.0) != client_name {
        return Err(KdcError::Malformed(
            "AP-REQ authenticator/ticket client mismatch".into(),
        ));
    }
    if !within_skew(&authenticator.0.ctime.0) {
        return Err(KdcError::Malformed(
            "AP-REQ authenticator timestamp outside clock skew".into(),
        ));
    }

    // The optional authenticator sub-session key (RFC 4120 §5.5.1).
    let authenticator_subkey = authenticator
        .0
        .subkey
        .0
        .as_ref()
        .map(|k| k.0.key_value.0 .0.clone());

    Ok(VerifiedApReq {
        client_name,
        client_realm,
        session_key,
        authenticator_subkey,
        ctime: authenticator.0.ctime.0.clone(),
        cusec: authenticator.0.cusec.0.clone(),
    })
}

/// Build the mutual-authentication AP-REP (RFC 4120 §3.2.4): the server proves it
/// holds the ticket session key and hands the client a fresh **acceptor subkey**,
/// which becomes the GSS-API session key both sides use to protect messages.
///
/// Returns the DER-encoded AP-REP and the raw acceptor subkey. The `EncAPRepPart`
/// echoes `ctime`/`cusec` from the authenticator and is sealed under the ticket
/// session key (key usage 12).
///
/// # Errors
/// Returns [`KdcError::Crypto`] if encryption fails or [`KdcError::Asn1`] on an
/// encoding error.
pub fn build_ap_rep(
    ticket_session_key: &[u8],
    ctime: KerberosTime,
    cusec: Microseconds,
    seq_number: u32,
) -> KdcResult<(Vec<u8>, Vec<u8>)> {
    // A fresh acceptor subkey — the negotiated GSS session key.
    let mut subkey = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut subkey);
    let enc_key = EncryptionKey {
        key_type: ExplicitContextTag0::from(int(i64::from(AES256_CTS_HMAC_SHA1_96))),
        key_value: ExplicitContextTag1::from(OctetStringAsn1::from(subkey.clone())),
    };

    let enc_part = EncApRepPart::from(EncApRepPartInner {
        ctime: ExplicitContextTag0::from(ctime),
        cusec: ExplicitContextTag1::from(cusec),
        subkey: Optional::from(Some(ExplicitContextTag2::from(enc_key))),
        seq_number: Optional::from(Some(ExplicitContextTag3::from(int(i64::from(seq_number))))),
    });
    let plain = picky_asn1_der::to_vec(&enc_part).map_err(asn1)?;

    let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();
    let sealed = cipher
        .encrypt(ticket_session_key, AP_REP_ENC, &plain)
        .map_err(|e| KdcError::Crypto(format!("AP-REP enc-part encrypt failed: {e}")))?;

    let ap_rep = ApRep::from(ApRepInner {
        pvno: ExplicitContextTag0::from(int(5)),
        msg_type: ExplicitContextTag1::from(int(i64::from(AP_REP_MSG_TYPE))),
        enc_part: ExplicitContextTag2::from(encrypted_data(sealed)),
    });
    let ap_rep_bytes = picky_asn1_der::to_vec(&ap_rep).map_err(asn1)?;
    Ok((ap_rep_bytes, subkey))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::as_exchange::to_generalized;
    use chrono::{TimeZone, Utc};

    #[test]
    fn ap_rep_round_trips_and_carries_the_acceptor_subkey() {
        // A random ticket session key (the AP-REQ would have recovered this).
        let mut session_key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut session_key);
        let ctime = to_generalized(Utc.with_ymd_and_hms(2026, 8, 7, 12, 0, 0).unwrap());
        let cusec = int(424242);

        let (ap_rep_bytes, subkey) =
            build_ap_rep(&session_key, ctime.clone(), cusec.clone(), 7).unwrap();

        // A client decrypts the AP-REP enc-part with the ticket session key.
        let ap_rep: ApRep = picky_asn1_der::from_bytes(&ap_rep_bytes).unwrap();
        assert_eq!(
            crate::as_exchange::int_to_i64(&ap_rep.0.msg_type.0),
            i64::from(AP_REP_MSG_TYPE),
            "msg-type is AP-REP (15)",
        );
        let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();
        let plain = cipher
            .decrypt(&session_key, AP_REP_ENC, &ap_rep.0.enc_part.0.cipher.0 .0)
            .expect("AP-REP enc-part decrypts under the ticket session key");
        let enc: EncApRepPart = picky_asn1_der::from_bytes(&plain).unwrap();

        // The subkey the client recovers is the acceptor subkey we returned.
        let recovered = enc
            .0
            .subkey
            .0
            .expect("subkey present")
            .0
            .key_value
            .0
             .0
            .clone();
        assert_eq!(recovered, subkey, "AP-REP carries the acceptor subkey");
        assert_eq!(enc.0.ctime.0, ctime, "ctime echoed for mutual auth");
        assert_eq!(
            crate::as_exchange::int_to_i64(&enc.0.seq_number.0.unwrap().0),
            7,
            "server sequence number conveyed",
        );
    }
}
