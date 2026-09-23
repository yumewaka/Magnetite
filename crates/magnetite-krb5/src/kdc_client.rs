//! Kerberos AS/TGS **client**: obtain a service ticket from a KDC over the wire
//! (Tier C C1 4b-3). [`build_ap_req`](crate::ap_client::build_ap_req) self-mints a
//! ticket under a *known* service key — useless against a foreign KDC (Samba), whose
//! service keys we do not hold. There the client must run the real exchanges:
//! AS-REQ → TGT (a PA-ENC-TIMESTAMP preauth under the client's long-term key), then
//! TGS-REQ → service ticket (the TGT presented as an AP-REQ). The returned service
//! ticket + session key then feed an AP-REQ for the Kerberos-authenticated bind.

use crate::as_exchange::{asn1, encrypted_data, int, principal_name, realm_string, to_generalized};
use crate::error::{KdcError, KdcResult};
use chrono::{Duration, Utc};
use picky_asn1::bit_string::BitString;
use picky_asn1::wrapper::{
    Asn1SequenceOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2,
    ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag7,
    ExplicitContextTag8, IntegerAsn1, OctetStringAsn1, Optional,
};
use picky_krb::constants::key_usages::{
    AS_REP_ENC, AS_REQ_TIMESTAMP, TGS_REP_ENC_SESSION_KEY, TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR,
};
use picky_krb::constants::types::{AP_REQ_MSG_TYPE, NT_PRINCIPAL, NT_SRV_INST};
use picky_krb::crypto::{ChecksumSuite, CipherSuite};
use picky_krb::data_types::{
    Authenticator, AuthenticatorInner, Checksum, PaData, PaEncTsEnc, Ticket,
};
use picky_krb::messages::{
    ApReq, ApReqInner, AsRep, AsReq, EncAsRepPart, EncTgsRepPart, KdcReq, KdcReqBody, KrbError,
    TgsRep, TgsReq,
};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn crypto(e: impl std::fmt::Display) -> KdcError {
    KdcError::Crypto(e.to_string())
}

fn comps(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| (*s).to_string()).collect()
}

/// A KDC-REQ-BODY: `cname` present for an AS-REQ (the client), absent for a TGS-REQ
/// (identity comes from the TGT); `sname` names the target (krbtgt or the service).
fn req_body(
    realm: &str,
    cname: Option<&[String]>,
    sname: &[String],
    sname_type: u8,
    nonce: i64,
) -> KdcResult<KdcReqBody> {
    Ok(KdcReqBody {
        kdc_options: ExplicitContextTag0::from(BitStringAsn1::from(BitString::with_len(32))),
        cname: Optional::from(match cname {
            Some(c) => Some(ExplicitContextTag1::from(principal_name(NT_PRINCIPAL, c)?)),
            None => None,
        }),
        realm: ExplicitContextTag2::from(realm_string(realm)?),
        sname: Optional::from(Some(ExplicitContextTag3::from(principal_name(
            sname_type, sname,
        )?))),
        from: Optional::from(None),
        till: ExplicitContextTag5::from(to_generalized(Utc::now() + Duration::hours(10))),
        rtime: Optional::from(None),
        nonce: ExplicitContextTag7::from(int(nonce)),
        etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![int(18)])), // AES256
        addresses: Optional::from(None),
        enc_authorization_data: Optional::from(None),
        additional_tickets: Optional::from(None),
    })
}

/// An AS-REQ carrying a PA-ENC-TIMESTAMP preauth sealed under `client_key`.
fn build_as_req(realm: &str, client: &[String], client_key: &[u8]) -> KdcResult<Vec<u8>> {
    let ts = PaEncTsEnc {
        patimestamp: ExplicitContextTag0::from(to_generalized(Utc::now())),
        pausec: Optional::from(None),
    };
    let ts_der = picky_asn1_der::to_vec(&ts).map_err(asn1)?;
    let sealed = CipherSuite::Aes256CtsHmacSha196
        .cipher()
        .encrypt(client_key, AS_REQ_TIMESTAMP, &ts_der)
        .map_err(crypto)?;
    let pa = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![2])), // PA-ENC-TIMESTAMP
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(
            picky_asn1_der::to_vec(&encrypted_data(sealed)).map_err(asn1)?,
        )),
    };
    let krbtgt = vec!["krbtgt".to_string(), realm.to_string()];
    let req = KdcReq {
        pvno: ExplicitContextTag1::from(int(5)),
        msg_type: ExplicitContextTag2::from(int(10)), // AS-REQ
        padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(vec![
            pa,
        ])))),
        req_body: ExplicitContextTag4::from(req_body(
            realm,
            Some(client),
            &krbtgt,
            NT_SRV_INST,
            111,
        )?),
    };
    picky_asn1_der::to_vec(&AsReq::from(req)).map_err(asn1)
}

/// Key usage 6: the checksum in a TGS-REQ's PA-TGS-REQ AP-REQ authenticator, over
/// the KDC-REQ-BODY.
const TGS_REQ_AUTH_CKSUM_USAGE: i32 = 6;
/// Checksum type HMAC-SHA1-96-AES256 (RFC 3961 §8).
const CKSUM_HMAC_SHA1_96_AES256: i64 = 16;

/// A TGS-REQ for `service`, authenticated by the `tgt` presented as an AP-REQ. The
/// authenticator carries a **checksum over the KDC-REQ-BODY** (usage 6) binding the
/// AP-REQ to this request — RFC 4120 requires it and Heimdal (Samba) rejects a
/// TGS-REQ without it (our own lenient KDC ignores it).
fn build_tgs_req(
    realm: &str,
    service: &[String],
    client: &[String],
    tgt: Ticket,
    tgt_session_key: &[u8],
) -> KdcResult<Vec<u8>> {
    let body = req_body(realm, None, service, NT_PRINCIPAL, 222)?;
    let body_der = picky_asn1_der::to_vec(&body).map_err(asn1)?;
    let mac = ChecksumSuite::HmacSha196Aes256
        .hasher()
        .checksum(tgt_session_key, TGS_REQ_AUTH_CKSUM_USAGE, &body_der)
        .map_err(crypto)?;
    let cksum = Checksum {
        cksumtype: ExplicitContextTag0::from(int(CKSUM_HMAC_SHA1_96_AES256)),
        checksum: ExplicitContextTag1::from(OctetStringAsn1::from(mac)),
    };
    let authenticator = Authenticator::from(AuthenticatorInner {
        authenticator_vno: ExplicitContextTag0::from(int(5)),
        crealm: ExplicitContextTag1::from(realm_string(realm)?),
        cname: ExplicitContextTag2::from(principal_name(NT_PRINCIPAL, client)?),
        cksum: Optional::from(Some(ExplicitContextTag3::from(cksum))),
        cusec: ExplicitContextTag4::from(int(0)),
        ctime: ExplicitContextTag5::from(to_generalized(Utc::now())),
        subkey: Optional::from(None),
        seq_number: Optional::from(None),
        authorization_data: Optional::from(None),
    });
    let auth_cipher = CipherSuite::Aes256CtsHmacSha196
        .cipher()
        .encrypt(
            tgt_session_key,
            TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR,
            &picky_asn1_der::to_vec(&authenticator).map_err(asn1)?,
        )
        .map_err(crypto)?;
    let ap_req = ApReq::from(ApReqInner {
        pvno: ExplicitContextTag0::from(int(5)),
        msg_type: ExplicitContextTag1::from(int(i64::from(AP_REQ_MSG_TYPE))),
        ap_options: ExplicitContextTag2::from(BitStringAsn1::from(BitString::with_len(32))),
        ticket: ExplicitContextTag3::from(tgt),
        authenticator: ExplicitContextTag4::from(encrypted_data(auth_cipher)),
    });
    let pa = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![1])), // PA-TGS-REQ
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(
            picky_asn1_der::to_vec(&ap_req).map_err(asn1)?,
        )),
    };
    let req = KdcReq {
        pvno: ExplicitContextTag1::from(int(5)),
        msg_type: ExplicitContextTag2::from(int(12)), // TGS-REQ
        padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(vec![
            pa,
        ])))),
        req_body: ExplicitContextTag4::from(body),
    };
    picky_asn1_der::to_vec(&TgsReq::from(req)).map_err(asn1)
}

/// One KDC round-trip over TCP (RFC 4120 §7.2.2: a 4-byte big-endian length prefix).
async fn kdc_exchange(kdc: SocketAddr, req: &[u8]) -> KdcResult<Vec<u8>> {
    let mut s = TcpStream::connect(kdc)
        .await
        .map_err(|e| KdcError::Crypto(format!("KDC connect: {e}")))?;
    let mut framed = (req.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(req);
    s.write_all(&framed)
        .await
        .map_err(|e| KdcError::Crypto(format!("KDC send: {e}")))?;
    let mut len = [0u8; 4];
    s.read_exact(&mut len)
        .await
        .map_err(|e| KdcError::Crypto(format!("KDC len: {e}")))?;
    let mut buf = vec![0u8; u32::from_be_bytes(len) as usize];
    s.read_exact(&mut buf)
        .await
        .map_err(|e| KdcError::Crypto(format!("KDC recv: {e}")))?;
    Ok(buf)
}

/// The service ticket obtained from a KDC, ready to present in an AP-REQ.
pub struct ObtainedTicket {
    /// The DER-encoded service `Ticket`.
    pub ticket_der: Vec<u8>,
    /// The service session key (shared with the service via the ticket).
    pub session_key: Vec<u8>,
}

/// Obtain a service ticket for `service_spn` from the KDC at `kdc_addr`,
/// authenticating as `client` with its long-term `client_key`. Runs AS-REQ (preauth)
/// → TGT, then TGS-REQ → service ticket, over TCP.
///
/// # Errors
/// A KDC transport, decrypt, or ASN.1 error, or a KDC error reply (returned as
/// [`KdcError`]).
pub async fn obtain_service_ticket(
    kdc_addr: SocketAddr,
    realm: &str,
    client: &[&str],
    client_key: &[u8],
    service_spn: &[&str],
) -> KdcResult<ObtainedTicket> {
    let client = comps(client);
    let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();

    // --- AS exchange: obtain the TGT + its session key. ---
    let as_reply = kdc_exchange(kdc_addr, &build_as_req(realm, &client, client_key)?).await?;
    check_not_krb_error(&as_reply, "AS-REP")?;
    let as_rep: AsRep = picky_asn1_der::from_bytes(&as_reply).map_err(asn1)?;
    let tgt = as_rep.0.ticket.0.clone();
    let as_enc = cipher
        .decrypt(client_key, AS_REP_ENC, &as_rep.0.enc_part.0.cipher.0 .0)
        .map_err(crypto)?;
    let as_part: EncAsRepPart = picky_asn1_der::from_bytes(&as_enc).map_err(asn1)?;
    let tgt_session_key = as_part.0.key.0.key_value.0 .0.clone();

    // --- TGS exchange: obtain the service ticket + its session key. ---
    let service = comps(service_spn);
    let tgs_req = build_tgs_req(realm, &service, &client, tgt, &tgt_session_key)?;
    let tgs_reply = kdc_exchange(kdc_addr, &tgs_req).await?;
    check_not_krb_error(&tgs_reply, "TGS-REP")?;
    let tgs_rep: TgsRep = picky_asn1_der::from_bytes(&tgs_reply).map_err(asn1)?;
    let service_ticket = tgs_rep.0.ticket.0.clone();
    let tgs_enc = cipher
        .decrypt(
            &tgt_session_key,
            TGS_REP_ENC_SESSION_KEY,
            &tgs_rep.0.enc_part.0.cipher.0 .0,
        )
        .map_err(crypto)?;
    let tgs_part: EncTgsRepPart = picky_asn1_der::from_bytes(&tgs_enc).map_err(asn1)?;
    let session_key = tgs_part.0.key.0.key_value.0 .0.clone();

    Ok(ObtainedTicket {
        ticket_der: picky_asn1_der::to_vec(&service_ticket).map_err(asn1)?,
        session_key,
    })
}

/// Build an AP-REQ presenting an already-obtained service `ticket_der` (from
/// [`obtain_service_ticket`]) with a fresh authenticator sealed under `session_key`.
/// The counterpart to [`build_ap_req`](crate::ap_client::build_ap_req) for the
/// foreign-KDC path (the ticket is opaque — we cannot mint it ourselves).
///
/// # Errors
/// ASN.1 or crypto failure.
pub fn build_ap_req_from_ticket(
    ticket_der: &[u8],
    session_key: &[u8],
    realm: &str,
    client: &[&str],
    sequence: u32,
) -> KdcResult<Vec<u8>> {
    // DCE style (DRSUAPI / ncacn_ip_tcp): the 3-leg BIND / BIND_ACK / AUTH3 handshake.
    build_ap_req_from_ticket_flags(
        ticket_der,
        session_key,
        realm,
        client,
        sequence,
        GSS_FLAGS_DCE,
    )
}

/// GSS per-message service flags MUTUAL|REPLAY|SEQUENCE|CONF|INTEG (`0x3E`).
const GSS_FLAGS_BASE: u32 = 0x02 | 0x04 | 0x08 | 0x10 | 0x20;
/// The above plus `GSS_C_DCE_STYLE` (`0x1000`) — the DCE 3-leg handshake.
const GSS_FLAGS_DCE: u32 = GSS_FLAGS_BASE | 0x1000;

/// Build an AP-REQ from a real ticket for a **non-DCE** GSS acceptor (e.g. an LDAP
/// GSS-SPNEGO SASL bind): the checksum flags omit `GSS_C_DCE_STYLE`, so the acceptor
/// completes the context in one round (emitting its AP-REP with `accept-completed`)
/// rather than staying `CONTINUE_NEEDED` for a DCE third leg. See
/// [`build_ap_req_from_ticket`] for the DCE-style variant used by DRSUAPI.
///
/// # Errors
/// A malformed ticket, or an authenticator encryption failure.
pub fn build_gss_ap_req_from_ticket(
    ticket_der: &[u8],
    session_key: &[u8],
    realm: &str,
    client: &[&str],
    sequence: u32,
) -> KdcResult<Vec<u8>> {
    build_ap_req_from_ticket_flags(
        ticket_der,
        session_key,
        realm,
        client,
        sequence,
        GSS_FLAGS_BASE,
    )
}

fn build_ap_req_from_ticket_flags(
    ticket_der: &[u8],
    session_key: &[u8],
    realm: &str,
    client: &[&str],
    sequence: u32,
    gss_flags: u32,
) -> KdcResult<Vec<u8>> {
    let ticket: Ticket = picky_asn1_der::from_bytes(ticket_der).map_err(asn1)?;
    let client = comps(client);

    // The GSS-API authenticator checksum (RFC 4121 §4.1.1, cksumtype 0x8003):
    // `Lgth(=16) ‖ Bnd(16 zero bytes) ‖ Flags`. The flags tell the GSS acceptor which
    // per-message services the initiator wants — crucially GSS_C_CONF_FLAG so Samba
    // will enable **sealing** (PKT_PRIVACY); without this checksum Samba cannot grant
    // a sealed context and NAKs the bind. MUTUAL|REPLAY|SEQUENCE|CONF|INTEG = 0x3E.
    //
    // `GSS_C_DCE_STYLE` (0x1000) is the decisive flag for Samba's DRSUAPI acceptor:
    // its `gensec_gssapi` runs in DCE style, so the acceptor stays CONTINUE_NEEDED
    // after emitting its AP-REP and expects a third leg (the client AP-REP / AUTH3).
    // The ap-options only carry MUTUAL, so this checksum flag is the *only* place the
    // acceptor can learn the initiator wants the 3-leg DCE handshake. Confirmed against
    // Samba's bundled Heimdal: a DCE-style initiator sets it and the acceptor reports
    // `ret_flags & GSS_C_DCE_STYLE`, driving BIND / BIND_ACK / AUTH3.
    let mut gss_cksum = 16u32.to_le_bytes().to_vec();
    gss_cksum.extend_from_slice(&[0u8; 16]); // channel bindings (none)
    gss_cksum.extend_from_slice(&gss_flags.to_le_bytes());
    let cksum = Checksum {
        cksumtype: ExplicitContextTag0::from(IntegerAsn1::from(vec![0x00, 0x80, 0x03])), // 0x8003
        checksum: ExplicitContextTag1::from(OctetStringAsn1::from(gss_cksum)),
    };
    let authenticator = Authenticator::from(AuthenticatorInner {
        authenticator_vno: ExplicitContextTag0::from(int(5)),
        crealm: ExplicitContextTag1::from(realm_string(realm)?),
        cname: ExplicitContextTag2::from(principal_name(NT_PRINCIPAL, &client)?),
        cksum: Optional::from(Some(ExplicitContextTag3::from(cksum))),
        cusec: ExplicitContextTag4::from(int(0)),
        ctime: ExplicitContextTag5::from(to_generalized(Utc::now())),
        subkey: Optional::from(None),
        // The initiator's initial per-message sequence number. RFC 4121 §4.2.6.1:
        // the acceptor takes this as the expected SND_SEQ of the first Wrap/MIC
        // token, so the caller MUST seed its GSS sequence counter with the same
        // value; Heimdal (Samba) rejects the first sealed request otherwise.
        seq_number: Optional::from(Some(ExplicitContextTag7::from(int(i64::from(sequence))))),
        authorization_data: Optional::from(None),
    });
    let auth_cipher = CipherSuite::Aes256CtsHmacSha196
        .cipher()
        .encrypt(
            session_key,
            picky_krb::constants::key_usages::AP_REQ_AUTHENTICATOR,
            &picky_asn1_der::to_vec(&authenticator).map_err(asn1)?,
        )
        .map_err(crypto)?;

    // MUTUAL-REQUIRED (ap-options bit 2) so the acceptor returns an AP-REP carrying
    // the acceptor subkey — the GSS session key both sides then use.
    let mut opts = BitString::with_len(32);
    opts.set(2, true);
    let ap_req = ApReq::from(ApReqInner {
        pvno: ExplicitContextTag0::from(int(5)),
        msg_type: ExplicitContextTag1::from(int(i64::from(AP_REQ_MSG_TYPE))),
        ap_options: ExplicitContextTag2::from(BitStringAsn1::from(opts)),
        ticket: ExplicitContextTag3::from(ticket),
        authenticator: ExplicitContextTag4::from(encrypted_data(auth_cipher)),
    });
    picky_asn1_der::to_vec(&ap_req).map_err(asn1)
}

/// Reject a KDC reply that is a KRB-ERROR (`[APPLICATION 30]`, tag `0x7e`) rather than
/// the expected AS-REP/TGS-REP, surfacing the KDC error code + e-text.
fn check_not_krb_error(reply: &[u8], what: &str) -> KdcResult<()> {
    if reply.first() == Some(&0x7e) {
        let (code, text) = match picky_asn1_der::from_bytes::<KrbError>(reply) {
            Ok(e) => {
                let text =
                    e.0.e_text
                        .0
                        .as_ref()
                        .map(|t| String::from_utf8_lossy(t.0.as_bytes()).into_owned())
                        .unwrap_or_default();
                (e.0.error_code.0, text)
            }
            Err(_) => (9999, String::new()),
        };
        return Err(KdcError::Malformed(format!(
            "KDC KRB-ERROR (code {code} {text}) instead of {what}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ap_req::verify_ap_req;
    use crate::keys::{default_salt, derive_aes256_key, PrincipalStore};
    use crate::server::KdcServer;
    use std::sync::Arc;
    use std::time::Duration as StdDuration;

    #[tokio::test]
    async fn obtains_a_service_ticket_from_our_own_kdc() {
        let realm = "EXAMPLE.COM";
        // A KDC seeded with a user (alice) and a service (host/magnetite).
        let mut store = PrincipalStore::new(realm);
        store
            .add_password_principal(&["alice"], "password12")
            .unwrap();
        store
            .add_password_principal(&["krbtgt", realm], "krbtgt-secret")
            .unwrap();
        store
            .add_password_principal(&["host", "magnetite"], "host-secret")
            .unwrap();
        let store = Arc::new(store);

        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        drop(l);
        let s = store.clone();
        tokio::spawn(async move {
            let _ = KdcServer::new(s).run(addr).await;
        });
        tokio::time::sleep(StdDuration::from_millis(150)).await;

        let alice_key =
            derive_aes256_key("password12", &default_salt(realm, &["alice".to_string()])).unwrap();
        let obtained =
            obtain_service_ticket(addr, realm, &["alice"], &alice_key, &["host", "magnetite"])
                .await
                .expect("obtain service ticket");
        assert_eq!(obtained.session_key.len(), 32, "AES256 service session key");

        // The obtained ticket presents in an AP-REQ that verifies with the service
        // key — proving the whole AS→TGS→AP-REQ chain is real.
        let ap_req = build_ap_req_from_ticket(
            &obtained.ticket_der,
            &obtained.session_key,
            realm,
            &["alice"],
            1,
        )
        .unwrap();
        let host_key = derive_aes256_key(
            "host-secret",
            &default_salt(realm, &["host".to_string(), "magnetite".to_string()]),
        )
        .unwrap();
        let verified = verify_ap_req(&host_key, &ap_req).expect("AP-REQ verifies");
        assert_eq!(
            verified.session_key, obtained.session_key,
            "GSS session key agrees"
        );
        assert_eq!(verified.client_name, vec!["alice".to_string()]);
    }
}
