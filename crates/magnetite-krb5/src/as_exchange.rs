//! The Kerberos AS exchange (RFC 4120 §3.1): AS-REQ → AS-REP or KRB-ERROR.
//!
//! This is the tracer-bullet's heart. A client (`kinit`) sends an AS-REQ for a
//! TGT (`krbtgt/REALM`). Windows/AD-style KDCs require pre-authentication, so:
//!
//!   1. An AS-REQ with no PA-ENC-TIMESTAMP ⇒ we reply `KDC_ERR_PREAUTH_REQUIRED`
//!      carrying ETYPE-INFO2 (the salt) so the client knows how to derive its key.
//!   2. The client retries with a PA-ENC-TIMESTAMP (its current time, encrypted
//!      under its long-term key). We decrypt it — successful decryption proves
//!      the client holds the key (integrity-protected by the etype) — and issue a
//!      TGT: a ticket encrypted under the `krbtgt` key plus an EncASRepPart
//!      encrypted under the client key.
//!
//! PAC (MS-PAC), referrals and renew/postdate handling are out of scope for the
//! PoC. The TGS exchange lives in [`crate::tgs_exchange`].

use crate::error::{KdcError, KdcResult};
use crate::keys::{PrincipalStore, AES256_CTS_HMAC_SHA1_96};
use chrono::{DateTime, Datelike, Duration, TimeZone, Timelike, Utc};
use picky_asn1::bit_string::BitString;
use picky_asn1::date::GeneralizedTime;
use picky_asn1::restricted_string::Ia5String;
use picky_asn1::wrapper::{
    Asn1SequenceOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag10,
    ExplicitContextTag2, ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5,
    ExplicitContextTag6, ExplicitContextTag7, ExplicitContextTag9, GeneralStringAsn1,
    GeneralizedTimeAsn1, IntegerAsn1, OctetStringAsn1, Optional,
};
use picky_krb::constants::error_codes::{
    KDC_ERR_C_PRINCIPAL_UNKNOWN, KDC_ERR_ETYPE_NOSUPP, KDC_ERR_PREAUTH_FAILED,
    KDC_ERR_PREAUTH_REQUIRED, KRB_ERR_GENERIC,
};
use picky_krb::constants::key_usages::{AS_REP_ENC, AS_REQ_TIMESTAMP, TICKET_REP};
use picky_krb::constants::types::{AS_REP_MSG_TYPE, KRB_ERROR_MSG_TYPE, NT_PRINCIPAL, NT_SRV_INST};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{
    EncryptedData, EncryptionKey, EtypeInfo2Entry, KerberosStringAsn1, LastReqInner, PaData,
    PaEncTsEnc, PrincipalName, Ticket, TicketInner, TransitedEncoding,
};
use picky_krb::messages::{
    AsRep, AsReq, EncAsRepPart, EncKdcRepPart, KdcRep, KrbError, KrbErrorInner,
};
use rand::RngCore;

/// PA-DATA type for PA-ENC-TIMESTAMP (RFC 4120 §7.5.2).
const PA_ENC_TIMESTAMP_TYPE: i64 = 2;
/// PA-DATA type for PA-ETYPE-INFO2 (RFC 4120 §7.5.2).
const PA_ETYPE_INFO2: u8 = 19;
/// Maximum tolerated clock skew for the pre-auth timestamp.
const MAX_SKEW_SECS: i64 = 5 * 60;
/// TGT lifetime for the PoC.
const TICKET_LIFETIME_HOURS: i64 = 10;

// Ticket flag bit positions (RFC 4120 §5.3, bit 0 = MSB).
const FLAG_FORWARDABLE: usize = 1;
const FLAG_RENEWABLE: usize = 8;
const FLAG_INITIAL: usize = 9;
const FLAG_PRE_AUTHENT: usize = 10;

/// The wire response to an AS-REQ: either an AS-REP or a KRB-ERROR, already
/// DER-encoded and ready to send.
pub enum AsOutcome {
    /// A successful AS-REP (the client obtained a TGT).
    Rep(Vec<u8>),
    /// A KRB-ERROR (e.g. pre-auth required, unknown principal).
    Error(Vec<u8>),
}

impl AsOutcome {
    /// The DER bytes to write back to the client, regardless of variant.
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            AsOutcome::Rep(b) | AsOutcome::Error(b) => b,
        }
    }
}

/// Process one AS-REQ and always return wire bytes: an internal failure is
/// mapped to a generic KRB-ERROR so the client sees a protocol response rather
/// than a dropped connection.
pub fn handle_request(store: &PrincipalStore, request: &[u8]) -> Vec<u8> {
    match handle_as_req(store, request) {
        Ok(outcome) => outcome.into_bytes(),
        Err(e) => {
            tracing::warn!("AS-REQ handling failed: {e}");
            krb_error(store, KRB_ERR_GENERIC, None).unwrap_or_default()
        }
    }
}

/// Handle one AS-REQ against `store`, returning the encoded response.
pub fn handle_as_req(store: &PrincipalStore, request: &[u8]) -> KdcResult<AsOutcome> {
    let as_req: AsReq = picky_asn1_der::from_bytes(request).map_err(asn1)?;
    let body = &as_req.0.req_body.0;

    // Client (cname). AS-REQ carries it; a TGS-only cname would be absent.
    let cname = body
        .cname
        .0
        .as_ref()
        .ok_or_else(|| KdcError::Malformed("AS-REQ without cname".into()))?;
    let client_name = read_name(&cname.0);
    if client_name.is_empty() {
        return Err(KdcError::Malformed("empty client name".into()));
    }

    // The KDC only offers aes256-cts-hmac-sha1-96 in this PoC.
    let etypes = read_etypes(body);
    if !etypes.contains(&AES256_CTS_HMAC_SHA1_96) {
        return Ok(AsOutcome::Error(krb_error(
            store,
            KDC_ERR_ETYPE_NOSUPP,
            None,
        )?));
    }

    let client = match store.get(&client_name) {
        Some(p) => p,
        None => {
            tracing::warn!(
                target: "auth", proto = "kerberos", principal = %client_name.join("/"),
                "AS-REQ rejected: unknown principal"
            );
            return Ok(AsOutcome::Error(krb_error(
                store,
                KDC_ERR_C_PRINCIPAL_UNKNOWN,
                None,
            )?));
        }
    };
    let krbtgt = store
        .krbtgt()
        .ok_or_else(|| KdcError::Malformed("krbtgt principal missing from store".into()))?;

    // Locate the PA-ENC-TIMESTAMP pre-auth, if any.
    let pa_enc_ts = as_req.0.padata.0.as_ref().and_then(|seq| {
        seq.0
            .iter()
            .find(|pa| int_to_i64(&pa.padata_type.0) == PA_ENC_TIMESTAMP_TYPE)
    });

    let Some(pa) = pa_enc_ts else {
        // No pre-auth yet: demand it, and hand back the salt via ETYPE-INFO2.
        return Ok(AsOutcome::Error(krb_error(
            store,
            KDC_ERR_PREAUTH_REQUIRED,
            Some(etype_info2_method_data(&client.key.salt)?),
        )?));
    };

    // Verify the pre-auth: decrypt PA-ENC-TIMESTAMP (EncryptedData) under the
    // client's long-term key. Successful decryption is the authentication.
    let enc: EncryptedData = picky_asn1_der::from_bytes(&pa.padata_data.0 .0).map_err(asn1)?;
    let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();
    let plain = match cipher.decrypt(&client.key.key, AS_REQ_TIMESTAMP, &enc.cipher.0 .0) {
        Ok(p) => p,
        Err(_) => {
            tracing::warn!(
                target: "auth", proto = "kerberos", principal = %client_name.join("/"),
                "AS-REQ pre-auth failed: PA-ENC-TIMESTAMP decrypt failed (bad credentials)"
            );
            return Ok(AsOutcome::Error(krb_error(
                store,
                KDC_ERR_PREAUTH_FAILED,
                None,
            )?));
        }
    };
    let ts: PaEncTsEnc = picky_asn1_der::from_bytes(&plain).map_err(asn1)?;
    if !within_skew(&ts.patimestamp.0) {
        tracing::warn!(
            target: "auth", proto = "kerberos", principal = %client_name.join("/"),
            "AS-REQ pre-auth failed: timestamp outside allowed skew"
        );
        return Ok(AsOutcome::Error(krb_error(
            store,
            KDC_ERR_PREAUTH_FAILED,
            None,
        )?));
    }

    // Pre-auth is good — mint the TGT.
    let rep = build_as_rep(store, &client, &krbtgt, &cname.0, &body.nonce.0)?;
    tracing::info!(
        target: "auth", proto = "kerberos", principal = %client_name.join("/"),
        "AS-REP issued (TGT granted)"
    );
    Ok(AsOutcome::Rep(rep))
}

/// Build a full AS-REP: a TGT (ticket encrypted under the krbtgt key) plus an
/// EncASRepPart encrypted under the client key.
fn build_as_rep(
    store: &PrincipalStore,
    client: &crate::keys::Principal,
    krbtgt: &crate::keys::Principal,
    client_pname: &PrincipalName,
    nonce: &IntegerAsn1,
) -> KdcResult<Vec<u8>> {
    let realm = store.realm();
    let now = Utc::now();
    let end = now + Duration::hours(TICKET_LIFETIME_HOURS);
    let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();

    // Fresh AES256 session key shared between client and TGS.
    let mut session_key = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut session_key);
    let enc_key = EncryptionKey {
        key_type: ExplicitContextTag0::from(int(i64::from(AES256_CTS_HMAC_SHA1_96))),
        key_value: ExplicitContextTag1::from(OctetStringAsn1::from(session_key.clone())),
    };

    let flags = ticket_flags();
    let krbtgt_pname = principal_name(NT_SRV_INST, &krbtgt.name)?;

    // A PAC carrying the client's authorization data. In a TGT the "server" is
    // the krbtgt itself, so both the server and KDC signatures use the krbtgt key.
    let client_account = read_name(client_pname)
        .into_iter()
        .next()
        .unwrap_or_default();
    let identity = crate::pac::PacIdentity {
        user_rid: client.rid,
        primary_group_rid: client.primary_group_rid,
        group_rids: client.group_rids.clone(),
        domain_sid_subauth: store.domain_sid().to_vec(),
        logon_script: String::new(),
        profile_path: String::new(),
        home_directory: String::new(),
    };
    let pac = crate::pac::build_pac_authorization_data(
        &krbtgt.key.key,
        &krbtgt.key.key,
        &client_account,
        realm,
        now.timestamp(),
        &identity,
    )?;

    // --- Ticket enc-part: EncTicketPart encrypted under the krbtgt key ---
    let enc_ticket_part =
        picky_krb::data_types::EncTicketPart::from(picky_krb::data_types::EncTicketPartInner {
            flags: ExplicitContextTag0::from(flags.clone()),
            key: ExplicitContextTag1::from(enc_key.clone()),
            crealm: ExplicitContextTag2::from(realm_string(realm)?),
            cname: ExplicitContextTag3::from(clone_principal_name(client_pname)?),
            transited: ExplicitContextTag4::from(TransitedEncoding {
                tr_type: ExplicitContextTag0::from(int(0)),
                contents: ExplicitContextTag1::from(OctetStringAsn1::from(Vec::new())),
            }),
            auth_time: ExplicitContextTag5::from(to_generalized(now)),
            starttime: Optional::from(Some(ExplicitContextTag6::from(to_generalized(now)))),
            endtime: ExplicitContextTag7::from(to_generalized(end)),
            renew_till: Optional::from(None),
            caddr: Optional::from(None),
            authorization_data: Optional::from(Some(ExplicitContextTag10::from(pac))),
        });
    let enc_ticket_der = picky_asn1_der::to_vec(&enc_ticket_part).map_err(asn1)?;
    let ticket_cipher = cipher
        .encrypt(&krbtgt.key.key, TICKET_REP, &enc_ticket_der)
        .map_err(crypto)?;

    let ticket = Ticket::from(TicketInner {
        tkt_vno: ExplicitContextTag0::from(int(5)),
        realm: ExplicitContextTag1::from(realm_string(realm)?),
        sname: ExplicitContextTag2::from(krbtgt_pname.clone()),
        enc_part: ExplicitContextTag3::from(encrypted_data(ticket_cipher)),
    });

    // --- EncASRepPart: encrypted under the client's long-term key ---
    let last_req = Asn1SequenceOf::from(vec![LastReqInner {
        lr_type: ExplicitContextTag0::from(int(0)),
        lr_value: ExplicitContextTag1::from(to_generalized(now)),
    }]);
    let enc_as_rep_part = EncAsRepPart::from(EncKdcRepPart {
        key: ExplicitContextTag0::from(enc_key),
        last_req: ExplicitContextTag1::from(last_req),
        nonce: ExplicitContextTag2::from(nonce.clone()),
        key_expiration: Optional::from(None),
        flags: ExplicitContextTag4::from(flags),
        auth_time: ExplicitContextTag5::from(to_generalized(now)),
        start_time: Optional::from(Some(ExplicitContextTag6::from(to_generalized(now)))),
        end_time: ExplicitContextTag7::from(to_generalized(end)),
        renew_till: Optional::from(None),
        srealm: ExplicitContextTag9::from(realm_string(realm)?),
        sname: ExplicitContextTag10::from(krbtgt_pname),
        caddr: Optional::from(None),
        encrypted_pa_data: Optional::from(None),
    });
    let enc_as_rep_der = picky_asn1_der::to_vec(&enc_as_rep_part).map_err(asn1)?;
    let _ = client; // client key used below
    let as_rep_cipher = cipher
        .encrypt(&client.key.key, AS_REP_ENC, &enc_as_rep_der)
        .map_err(crypto)?;

    // --- Assemble the AS-REP ---
    let kdc_rep = KdcRep {
        pvno: ExplicitContextTag0::from(int(5)),
        msg_type: ExplicitContextTag1::from(int(i64::from(AS_REP_MSG_TYPE))),
        padata: Optional::from(None),
        crealm: ExplicitContextTag3::from(realm_string(realm)?),
        cname: ExplicitContextTag4::from(clone_principal_name(client_pname)?),
        ticket: ExplicitContextTag5::from(ticket),
        enc_part: ExplicitContextTag6::from(encrypted_data(as_rep_cipher)),
    };
    picky_asn1_der::to_vec(&AsRep::from(kdc_rep)).map_err(asn1)
}

/// Build a KRB-ERROR for `code` naming `krbtgt/REALM` as the service, optionally
/// carrying `e_data` (METHOD-DATA). Used by the AS path.
fn krb_error(store: &PrincipalStore, code: u32, e_data: Option<Vec<u8>>) -> KdcResult<Vec<u8>> {
    let krbtgt_name = vec!["krbtgt".to_string(), store.realm().to_string()];
    build_krb_error(store.realm(), &krbtgt_name, code, e_data)
}

/// Build a KRB-ERROR for `code`, naming `sname_components` as the service and
/// optionally carrying `e_data` (METHOD-DATA). Shared by the AS and TGS paths.
pub(crate) fn build_krb_error(
    realm: &str,
    sname_components: &[String],
    code: u32,
    e_data: Option<Vec<u8>>,
) -> KdcResult<Vec<u8>> {
    let now = Utc::now();
    let inner = KrbErrorInner {
        pvno: ExplicitContextTag0::from(int(5)),
        msg_type: ExplicitContextTag1::from(int(i64::from(KRB_ERROR_MSG_TYPE))),
        ctime: Optional::from(None),
        cusec: Optional::from(None),
        stime: ExplicitContextTag4::from(to_generalized(now)),
        susec: ExplicitContextTag5::from(int(0)),
        error_code: ExplicitContextTag6::from(code),
        crealm: Optional::from(None),
        cname: Optional::from(None),
        realm: ExplicitContextTag9::from(realm_string(realm)?),
        sname: ExplicitContextTag10::from(principal_name(NT_SRV_INST, sname_components)?),
        e_text: Optional::from(None),
        e_data: Optional::from(
            e_data.map(|d| ExplicitContextTag12::from(OctetStringAsn1::from(d))),
        ),
    };
    picky_asn1_der::to_vec(&KrbError::from(inner)).map_err(asn1)
}

/// METHOD-DATA (SEQUENCE OF PA-DATA) advertising the required pre-auth and the
/// client's salt: a PA-ETYPE-INFO2 entry plus an (empty) PA-ENC-TIMESTAMP marker.
fn etype_info2_method_data(salt: &str) -> KdcResult<Vec<u8>> {
    let entry = EtypeInfo2Entry {
        etype: ExplicitContextTag0::from(int(i64::from(AES256_CTS_HMAC_SHA1_96))),
        salt: Optional::from(Some(ExplicitContextTag1::from(kerberos_string(salt)?))),
        s2kparams: Optional::from(None),
    };
    let etype_info2 = Asn1SequenceOf::from(vec![entry]);
    let etype_info2_der = picky_asn1_der::to_vec(&etype_info2).map_err(asn1)?;

    let pa_etype_info2 = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![PA_ETYPE_INFO2])),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(etype_info2_der)),
    };
    let pa_enc_ts_marker = PaData {
        padata_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![
            PA_ENC_TIMESTAMP_TYPE as u8,
        ])),
        padata_data: ExplicitContextTag2::from(OctetStringAsn1::from(Vec::new())),
    };
    let method_data = Asn1SequenceOf::from(vec![pa_etype_info2, pa_enc_ts_marker]);
    picky_asn1_der::to_vec(&method_data).map_err(asn1)
}

// ------------------------------------------------------------------ helpers

use picky_asn1::wrapper::ExplicitContextTag12;

pub(crate) fn asn1<E: std::fmt::Display>(e: E) -> KdcError {
    KdcError::Asn1(e.to_string())
}
pub(crate) fn crypto<E: std::fmt::Display>(e: E) -> KdcError {
    KdcError::Crypto(e.to_string())
}

/// A small non-negative integer as an ASN.1 INTEGER (big-endian, minimal).
pub(crate) fn int(value: i64) -> IntegerAsn1 {
    if value == 0 {
        return IntegerAsn1::from(vec![0]);
    }
    let mut bytes = Vec::new();
    let mut v = value;
    while v > 0 {
        bytes.push((v & 0xff) as u8);
        v >>= 8;
    }
    bytes.reverse();
    IntegerAsn1::from_bytes_be_unsigned(bytes)
}

/// Decode an ASN.1 INTEGER as an i64 (unsigned interpretation; etypes/types are
/// small and non-negative here).
pub(crate) fn int_to_i64(i: &IntegerAsn1) -> i64 {
    let mut v: i64 = 0;
    for b in i.as_unsigned_bytes_be() {
        v = (v << 8) | i64::from(*b);
    }
    v
}

pub(crate) fn kerberos_string(s: &str) -> KdcResult<KerberosStringAsn1> {
    Ok(KerberosStringAsn1::from(
        Ia5String::from_string(s.to_owned()).map_err(|e| KdcError::Malformed(e.to_string()))?,
    ))
}

/// A Realm is a KerberosString; give it its own helper for clarity.
pub(crate) fn realm_string(s: &str) -> KdcResult<GeneralStringAsn1> {
    kerberos_string(s)
}

pub(crate) fn principal_name(name_type: u8, components: &[String]) -> KdcResult<PrincipalName> {
    let mut vals = Vec::with_capacity(components.len());
    for c in components {
        vals.push(kerberos_string(c)?);
    }
    Ok(PrincipalName {
        name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![name_type])),
        name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vals)),
    })
}

/// Re-encode an incoming PrincipalName so we own the value (echoing cname).
fn clone_principal_name(pn: &PrincipalName) -> KdcResult<PrincipalName> {
    let name_type = int_to_i64(&pn.name_type.0) as u8;
    let components = read_name(pn);
    let _ = name_type; // preserve the client's NT_PRINCIPAL type
    principal_name(
        if name_type == 0 {
            NT_PRINCIPAL
        } else {
            name_type
        },
        &components,
    )
}

/// Read the string components out of a PrincipalName.
pub(crate) fn read_name(pn: &PrincipalName) -> Vec<String> {
    pn.name_string
        .0
         .0
        .iter()
        .map(|s| String::from_utf8_lossy(s.as_bytes()).into_owned())
        .collect()
}

/// The list of requested etypes as integers.
fn read_etypes(body: &picky_krb::messages::KdcReqBody) -> Vec<i32> {
    body.etype
        .0
         .0
        .iter()
        .map(|e| int_to_i64(e) as i32)
        .collect()
}

pub(crate) fn encrypted_data(cipher: Vec<u8>) -> EncryptedData {
    EncryptedData {
        etype: ExplicitContextTag0::from(int(i64::from(AES256_CTS_HMAC_SHA1_96))),
        kvno: Optional::from(Some(ExplicitContextTag1::from(int(1)))),
        cipher: ExplicitContextTag2::from(OctetStringAsn1::from(cipher)),
    }
}

pub(crate) fn ticket_flags() -> BitStringAsn1 {
    let mut bits = BitString::with_len(32);
    bits.set(FLAG_FORWARDABLE, true);
    bits.set(FLAG_RENEWABLE, true);
    bits.set(FLAG_INITIAL, true);
    bits.set(FLAG_PRE_AUTHENT, true);
    BitStringAsn1::from(bits)
}

pub(crate) fn to_generalized(dt: DateTime<Utc>) -> GeneralizedTimeAsn1 {
    GeneralizedTimeAsn1::from(
        GeneralizedTime::new(
            dt.year() as u16,
            dt.month() as u8,
            dt.day() as u8,
            dt.hour() as u8,
            dt.minute() as u8,
            dt.second() as u8,
        )
        .expect("valid calendar time"),
    )
}

pub(crate) fn within_skew(ts: &GeneralizedTime) -> bool {
    let Some(client_time) = Utc
        .with_ymd_and_hms(
            i32::from(ts.year()),
            u32::from(ts.month()),
            u32::from(ts.day()),
            u32::from(ts.hour()),
            u32::from(ts.minute()),
            u32::from(ts.second()),
        )
        .single()
    else {
        return false;
    };
    (Utc::now() - client_time).num_seconds().abs() <= MAX_SKEW_SECS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{default_salt, derive_aes256_key, PrincipalStore};
    use crate::test_support::{as_req_no_preauth, as_req_with_preauth};
    use picky_krb::data_types::{EncTicketPart, Ticket};
    use picky_krb::messages::{AsRep, EncAsRepPart, KrbError};

    const REALM: &str = "EXAMPLE.COM";

    fn test_store() -> PrincipalStore {
        let mut store = PrincipalStore::new(REALM);
        store
            .add_password_principal(&["alice"], "password12")
            .unwrap();
        store
            .add_password_principal(&["krbtgt", REALM], "krbtgt-secret")
            .unwrap();
        store
    }

    #[test]
    fn small_integer_roundtrips() {
        for v in [0i64, 5, 11, 18, 30, 255, 256, 65535] {
            assert_eq!(int_to_i64(&int(v)), v, "int roundtrip for {v}");
        }
    }

    #[test]
    fn as_req_without_preauth_demands_preauth_with_salt() {
        let store = test_store();
        let out = handle_as_req(&store, &as_req_no_preauth(REALM, &["alice"])).unwrap();
        let AsOutcome::Error(bytes) = out else {
            panic!("expected KRB-ERROR requiring pre-auth");
        };
        let err: KrbError = picky_asn1_der::from_bytes(&bytes).unwrap();
        assert_eq!(err.0.error_code.0, KDC_ERR_PREAUTH_REQUIRED);
        // The e-data must carry the salt so the client can derive its key.
        let e_data = err.0.e_data.0.as_ref().expect("e-data present");
        let text = String::from_utf8_lossy(&e_data.0 .0);
        assert!(
            text.contains("EXAMPLE.COMalice"),
            "ETYPE-INFO2 should advertise the alice salt"
        );
    }

    #[test]
    fn unknown_principal_is_rejected() {
        let store = test_store();
        let out = handle_as_req(&store, &as_req_no_preauth(REALM, &["nobody"])).unwrap();
        let AsOutcome::Error(bytes) = out else {
            panic!("expected KRB-ERROR");
        };
        let err: KrbError = picky_asn1_der::from_bytes(&bytes).unwrap();
        assert_eq!(err.0.error_code.0, KDC_ERR_C_PRINCIPAL_UNKNOWN);
    }

    #[test]
    fn wrong_password_fails_preauth() {
        let store = test_store();
        // Derive a key from the WRONG password; pre-auth decryption must fail.
        let bad_key =
            derive_aes256_key("not-the-password", &default_salt(REALM, &["alice".into()])).unwrap();
        let req = as_req_with_preauth(REALM, &["alice"], &bad_key, 4242);
        let out = handle_as_req(&store, &req).unwrap();
        let AsOutcome::Error(bytes) = out else {
            panic!("expected pre-auth failure");
        };
        let err: KrbError = picky_asn1_der::from_bytes(&bytes).unwrap();
        assert_eq!(err.0.error_code.0, KDC_ERR_PREAUTH_FAILED);
    }

    /// The full happy path: a correct pre-auth yields an AS-REP whose EncASRepPart
    /// (decryptable with the client key) and TGT (decryptable with the krbtgt key)
    /// carry the *same* session key — exactly what a client needs for the TGS.
    #[test]
    fn valid_preauth_yields_consistent_tgt() {
        let store = test_store();
        let alice_key =
            derive_aes256_key("password12", &default_salt(REALM, &["alice".into()])).unwrap();
        let krbtgt_key = store.krbtgt().unwrap().key.key.clone();
        let nonce = 987654;

        let req = as_req_with_preauth(REALM, &["alice"], &alice_key, nonce);
        let out = handle_as_req(&store, &req).unwrap();
        let AsOutcome::Rep(bytes) = out else {
            panic!("expected AS-REP");
        };
        let as_rep: AsRep = picky_asn1_der::from_bytes(&bytes).unwrap();

        let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();

        // 1. Decrypt the AS-REP enc-part with the client's key (usage 3).
        let enc_part_cipher = &as_rep.0.enc_part.0.cipher.0 .0;
        let enc_as_rep_plain = cipher
            .decrypt(&alice_key, AS_REP_ENC, enc_part_cipher)
            .expect("client must be able to decrypt the AS-REP enc-part");
        let enc_as_rep: EncAsRepPart = picky_asn1_der::from_bytes(&enc_as_rep_plain).unwrap();
        let client_session_key = enc_as_rep.0.key.0.key_value.0 .0.clone();
        // The nonce must be echoed back (anti-replay binding).
        assert_eq!(int_to_i64(&enc_as_rep.0.nonce.0), nonce);

        // 2. Decrypt the TGT with the krbtgt key (usage 2).
        let ticket: &Ticket = &as_rep.0.ticket.0;
        let ticket_cipher = &ticket.0.enc_part.0.cipher.0 .0;
        let enc_ticket_plain = cipher
            .decrypt(&krbtgt_key, TICKET_REP, ticket_cipher)
            .expect("KDC must be able to decrypt its own TGT");
        let enc_ticket: EncTicketPart = picky_asn1_der::from_bytes(&enc_ticket_plain).unwrap();
        let ticket_session_key = enc_ticket.0.key.0.key_value.0 .0.clone();

        // 3. The two must match: this is the shared session key.
        assert_eq!(
            client_session_key, ticket_session_key,
            "session key in the AS-REP must equal the one sealed in the TGT"
        );
        assert_eq!(client_session_key.len(), 32, "AES256 session key");

        // The ticket names krbtgt/REALM as its service.
        let sname: Vec<String> = enc_ticket
            .0
            .cname
            .0
            .name_string
            .0
             .0
            .iter()
            .map(|s| String::from_utf8_lossy(s.as_bytes()).into_owned())
            .collect();
        assert_eq!(
            sname,
            vec!["alice".to_string()],
            "ticket cname is the client"
        );
    }
}
