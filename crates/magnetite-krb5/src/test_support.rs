//! Client-side AS-REQ builders used only by the crate's tests. Keeping these here
//! (rather than duplicating in each test module) lets the round-trip test and the
//! server test drive the KDC through the same real DER encoding a client emits.

use crate::as_exchange::{encrypted_data, int, principal_name, realm_string, to_generalized};
use chrono::{Duration, Utc};
use picky_asn1::bit_string::BitString;
use picky_asn1::wrapper::{
    Asn1SequenceOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2,
    ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag7,
    ExplicitContextTag8, IntegerAsn1, OctetStringAsn1, Optional,
};
use picky_krb::constants::key_usages::{AS_REQ_TIMESTAMP, TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR};
use picky_krb::constants::types::{AP_REQ_MSG_TYPE, NT_PRINCIPAL, NT_SRV_INST};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{Authenticator, AuthenticatorInner, PaData, PaEncTsEnc, Ticket};
use picky_krb::messages::{ApReq, ApReqInner, AsReq, KdcReq, KdcReqBody, TgsReq};

/// The AES256 etype number.
const AES256: i64 = 18;

fn components(names: &[&str]) -> Vec<String> {
    names.iter().map(|s| s.to_string()).collect()
}

/// A KDC-REQ-BODY requesting a TGT (`krbtgt/REALM`) for `client`.
fn req_body(realm: &str, client: &[String], nonce: i64) -> KdcReqBody {
    let krbtgt = vec!["krbtgt".to_string(), realm.to_string()];
    KdcReqBody {
        kdc_options: ExplicitContextTag0::from(BitStringAsn1::from(BitString::with_len(32))),
        cname: Optional::from(Some(ExplicitContextTag1::from(
            principal_name(NT_PRINCIPAL, client).unwrap(),
        ))),
        realm: ExplicitContextTag2::from(realm_string(realm).unwrap()),
        sname: Optional::from(Some(ExplicitContextTag3::from(
            principal_name(NT_SRV_INST, &krbtgt).unwrap(),
        ))),
        from: Optional::from(None),
        till: ExplicitContextTag5::from(to_generalized(Utc::now() + Duration::hours(10))),
        rtime: Optional::from(None),
        nonce: ExplicitContextTag7::from(int(nonce)),
        etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![int(AES256)])),
        addresses: Optional::from(None),
        enc_authorization_data: Optional::from(None),
        additional_tickets: Optional::from(None),
    }
}

fn encode(req: KdcReq) -> Vec<u8> {
    picky_asn1_der::to_vec(&AsReq::from(req)).expect("encode AS-REQ")
}

/// An AS-REQ with no pre-authentication (the client's first probe).
pub(crate) fn as_req_no_preauth(realm: &str, client: &[&str]) -> Vec<u8> {
    let client = components(client);
    encode(KdcReq {
        pvno: ExplicitContextTag1::from(int(5)),
        msg_type: ExplicitContextTag2::from(int(10)),
        padata: Optional::from(None),
        req_body: ExplicitContextTag4::from(req_body(realm, &client, 12345)),
    })
}

/// An AS-REQ carrying a PA-ENC-TIMESTAMP encrypted under `client_key` (the
/// client's long-term key) — the retry after `KDC_ERR_PREAUTH_REQUIRED`.
pub(crate) fn as_req_with_preauth(
    realm: &str,
    client: &[&str],
    client_key: &[u8],
    nonce: i64,
) -> Vec<u8> {
    let client = components(client);

    // PA-ENC-TS-ENC { patimestamp = now } encrypted with key usage 1.
    let ts = PaEncTsEnc {
        patimestamp: ExplicitContextTag0::from(to_generalized(Utc::now())),
        pausec: Optional::from(None),
    };
    let ts_der = picky_asn1_der::to_vec(&ts).expect("encode PA-ENC-TS-ENC");
    let sealed = CipherSuite::Aes256CtsHmacSha196
        .cipher()
        .encrypt(client_key, AS_REQ_TIMESTAMP, &ts_der)
        .expect("seal timestamp");
    let enc_data_der =
        picky_asn1_der::to_vec(&encrypted_data(sealed)).expect("encode EncryptedData");

    let pa = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![2])),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(enc_data_der)),
    };

    encode(KdcReq {
        pvno: ExplicitContextTag1::from(int(5)),
        msg_type: ExplicitContextTag2::from(int(10)),
        padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(vec![
            pa,
        ])))),
        req_body: ExplicitContextTag4::from(req_body(realm, &client, nonce)),
    })
}

fn encode_tgs(req: KdcReq) -> Vec<u8> {
    picky_asn1_der::to_vec(&TgsReq::from(req)).expect("encode TGS-REQ")
}

/// A KDC-REQ-BODY requesting a service ticket for `service` (no cname — the
/// client identity comes from the TGT in the AP-REQ).
fn tgs_req_body(realm: &str, service: &[String], nonce: i64) -> KdcReqBody {
    KdcReqBody {
        kdc_options: ExplicitContextTag0::from(BitStringAsn1::from(BitString::with_len(32))),
        cname: Optional::from(None),
        realm: ExplicitContextTag2::from(realm_string(realm).unwrap()),
        sname: Optional::from(Some(ExplicitContextTag3::from(
            principal_name(NT_PRINCIPAL, service).unwrap(),
        ))),
        from: Optional::from(None),
        till: ExplicitContextTag5::from(to_generalized(Utc::now() + Duration::hours(10))),
        rtime: Optional::from(None),
        nonce: ExplicitContextTag7::from(int(nonce)),
        etype: ExplicitContextTag8::from(Asn1SequenceOf::from(vec![int(AES256)])),
        addresses: Optional::from(None),
        enc_authorization_data: Optional::from(None),
        additional_tickets: Optional::from(None),
    }
}

/// The PA-TGS-REQ padata: an AP-REQ = { `tgt`, an Authenticator naming `client`,
/// sealed under `tgt_session_key` }.
fn ap_req_padata(realm: &str, client: &[String], tgt: Ticket, tgt_session_key: &[u8]) -> PaData {
    let authenticator = Authenticator::from(AuthenticatorInner {
        authenticator_vno: ExplicitContextTag0::from(int(5)),
        crealm: ExplicitContextTag1::from(realm_string(realm).unwrap()),
        cname: ExplicitContextTag2::from(principal_name(NT_PRINCIPAL, client).unwrap()),
        cksum: Optional::from(None),
        cusec: ExplicitContextTag4::from(int(0)),
        ctime: ExplicitContextTag5::from(to_generalized(Utc::now())),
        subkey: Optional::from(None),
        seq_number: Optional::from(None),
        authorization_data: Optional::from(None),
    });
    let auth_der = picky_asn1_der::to_vec(&authenticator).expect("encode Authenticator");
    let sealed = CipherSuite::Aes256CtsHmacSha196
        .cipher()
        .encrypt(
            tgt_session_key,
            TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR,
            &auth_der,
        )
        .expect("seal authenticator");
    let ap_req = ApReq::from(ApReqInner {
        pvno: ExplicitContextTag0::from(int(5)),
        msg_type: ExplicitContextTag1::from(int(i64::from(AP_REQ_MSG_TYPE))),
        ap_options: ExplicitContextTag2::from(BitStringAsn1::from(BitString::with_len(32))),
        ticket: ExplicitContextTag3::from(tgt),
        authenticator: ExplicitContextTag4::from(encrypted_data(sealed)),
    });
    let ap_req_der = picky_asn1_der::to_vec(&ap_req).expect("encode AP-REQ");
    PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![1])),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(ap_req_der)),
    }
}

/// A TGS-REQ for `service`, authenticated by `tgt` + an Authenticator sealed
/// under `tgt_session_key` (the session key the AS handed the client).
pub(crate) fn tgs_req(
    realm: &str,
    service: &[&str],
    client: &[&str],
    tgt: Ticket,
    tgt_session_key: &[u8],
    nonce: i64,
) -> Vec<u8> {
    let pa = ap_req_padata(realm, &components(client), tgt, tgt_session_key);
    encode_tgs(KdcReq {
        pvno: ExplicitContextTag1::from(int(5)),
        msg_type: ExplicitContextTag2::from(int(12)),
        padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(vec![
            pa,
        ])))),
        req_body: ExplicitContextTag4::from(tgs_req_body(realm, &components(service), nonce)),
    })
}

/// An S4U2Self TGS-REQ: the service `requester` (authenticated by its own `tgt`)
/// asks for a ticket to itself (`service`) impersonating `user`, via a PA-FOR-USER
/// whose checksum is keyed by the TGT session key.
pub(crate) fn tgs_req_s4u2self(
    realm: &str,
    service: &[&str],
    requester: &[&str],
    user: &[&str],
    tgt: Ticket,
    tgt_session_key: &[u8],
    nonce: i64,
) -> Vec<u8> {
    let pa_tgs = ap_req_padata(realm, &components(requester), tgt, tgt_session_key);

    // PA-FOR-USER { userName, userRealm, cksum, auth-package="Kerberos" }.
    let user_name = principal_name(NT_PRINCIPAL, &components(user)).unwrap();
    let s4u = crate::tgs_exchange::s4u_byte_array(&user_name, realm.as_bytes(), b"Kerberos");
    let cksum_bytes = CipherSuite::Aes256CtsHmacSha196
        .cipher()
        .encryption_checksum(tgt_session_key, 17, &s4u)
        .expect("s4u checksum");
    let pa_for_user = crate::tgs_exchange::PaForUser {
        user_name: ExplicitContextTag0::from(user_name),
        user_realm: ExplicitContextTag1::from(realm_string(realm).unwrap()),
        cksum: ExplicitContextTag2::from(picky_krb::data_types::Checksum {
            cksumtype: ExplicitContextTag0::from(int(16)), // hmac-sha1-96-aes256
            checksum: ExplicitContextTag1::from(OctetStringAsn1::from(cksum_bytes)),
        }),
        auth_package: ExplicitContextTag3::from(realm_string("Kerberos").unwrap()),
    };
    let pfu_der = picky_asn1_der::to_vec(&pa_for_user).expect("encode PA-FOR-USER");
    let pa_pfu = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![129])),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(pfu_der)),
    };

    encode_tgs(KdcReq {
        pvno: ExplicitContextTag1::from(int(5)),
        msg_type: ExplicitContextTag2::from(int(12)),
        padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(vec![
            pa_tgs, pa_pfu,
        ])))),
        req_body: ExplicitContextTag4::from(tgs_req_body(realm, &components(service), nonce)),
    })
}

/// An S4U2Proxy TGS-REQ: the service `requester` (authenticated by its own `tgt`)
/// asks for a ticket to `backend` on behalf of the user named in `addl_ticket`
/// (the user's S4U2Self ticket to the requester), presented as an additional ticket.
pub(crate) fn tgs_req_s4u2proxy(
    realm: &str,
    backend: &[&str],
    requester: &[&str],
    tgt: Ticket,
    tgt_session_key: &[u8],
    addl_ticket: Ticket,
    nonce: i64,
) -> Vec<u8> {
    let pa = ap_req_padata(realm, &components(requester), tgt, tgt_session_key);
    let mut body = tgs_req_body(realm, &components(backend), nonce);
    body.additional_tickets = Optional::from(Some(
        picky_asn1::wrapper::ExplicitContextTag11::from(Asn1SequenceOf::from(vec![addl_ticket])),
    ));
    encode_tgs(KdcReq {
        pvno: ExplicitContextTag1::from(int(5)),
        msg_type: ExplicitContextTag2::from(int(12)),
        padata: Optional::from(Some(ExplicitContextTag3::from(Asn1SequenceOf::from(vec![
            pa,
        ])))),
        req_body: ExplicitContextTag4::from(body),
    })
}
