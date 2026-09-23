//! The Kerberos TGS exchange (RFC 4120 §3.3): TGS-REQ → TGS-REP or KRB-ERROR.
//!
//! Having obtained a TGT from the AS exchange, the client asks the ticket-
//! granting service for a ticket to a specific service. The TGS-REQ carries, as
//! PA-TGS-REQ pre-auth, an AP-REQ = { the TGT, an Authenticator encrypted under
//! the TGT session key }. We:
//!
//!   1. Decrypt the TGT with the `krbtgt` key (usage 2) → the TGT session key and
//!      the authenticated client identity.
//!   2. Decrypt the Authenticator with that session key (usage 7) and check it
//!      matches the ticket's client and is within clock skew — this proves the
//!      requester holds the TGT session key (i.e. really is that client).
//!   3. Mint a service ticket: a fresh session key, the client's identity, sealed
//!      under the *service's* long-term key (usage 2).
//!   4. Return EncTGSRepPart sealed under the TGT session key (usage 8), or under
//!      the authenticator subkey if one was supplied (usage 9).
//!
//! A PAC is embedded and S4U delegation (S4U2Self protocol transition + S4U2Proxy
//! constrained delegation, MS-SFU) is supported; cross-realm referrals are not.

use crate::as_exchange::{
    asn1, build_krb_error, crypto, encrypted_data, int, int_to_i64, principal_name, read_name,
    realm_string, within_skew,
};
use crate::error::{KdcError, KdcResult};
use crate::keys::{PrincipalStore, AES256_CTS_HMAC_SHA1_96};
use picky_asn1::bit_string::BitString;
use picky_asn1::wrapper::{
    BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag10,
    ExplicitContextTag2, ExplicitContextTag3, ExplicitContextTag4, ExplicitContextTag5,
    ExplicitContextTag6, ExplicitContextTag7, ExplicitContextTag9, IntegerAsn1, Optional,
};
use picky_krb::constants::error_codes::{
    KDC_ERR_BADOPTION, KDC_ERR_ETYPE_NOSUPP, KDC_ERR_PADATA_TYPE_NOSUPP,
    KDC_ERR_S_PRINCIPAL_UNKNOWN, KRB_AP_ERR_BADMATCH, KRB_AP_ERR_BAD_INTEGRITY,
    KRB_AP_ERR_MODIFIED, KRB_AP_ERR_SKEW, KRB_AP_ERR_TKT_EXPIRED, KRB_ERR_GENERIC,
};
use picky_krb::constants::key_usages::{
    TGS_REP_ENC_SESSION_KEY, TGS_REP_ENC_SUB_KEY, TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR, TICKET_REP,
};
use picky_krb::constants::types::{NT_PRINCIPAL, TGS_REP_MSG_TYPE};
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{
    Authenticator, Checksum, EncTicketPart, EncryptionKey, KerberosStringAsn1, LastReqInner,
    PrincipalName, Realm, Ticket, TicketInner, TransitedEncoding,
};
use picky_krb::messages::{ApReq, EncKdcRepPart, EncTgsRepPart, KdcRep, TgsRep, TgsReq};
use rand::RngCore;

/// PA-DATA type for PA-TGS-REQ (RFC 4120 §7.5.2): the AP-REQ authenticating the
/// TGS request with the client's TGT.
const PA_TGS_REQ_TYPE: i64 = 1;
/// PA-DATA type for PA-FOR-USER (MS-SFU §2.2.1): S4U2Self — a service asks for a
/// ticket to itself on behalf of a named user (protocol transition).
const PA_FOR_USER_TYPE: i64 = 129;
/// Key usage for the PA-FOR-USER checksum (`KERB_NON_KERB_CKSUM_SALT`, MS-SFU).
const KERB_NON_KERB_CKSUM_SALT: i32 = 17;

/// MS-SFU PA-FOR-USER: identifies the user a service impersonates in S4U2Self,
/// with a checksum (keyed by the service's TGT session key) binding the request.
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct PaForUser {
    pub user_name: ExplicitContextTag0<PrincipalName>,
    pub user_realm: ExplicitContextTag1<Realm>,
    pub cksum: ExplicitContextTag2<Checksum>,
    pub auth_package: ExplicitContextTag3<KerberosStringAsn1>,
}

// Service-ticket flags (RFC 4120 §5.3). Unlike a TGT these are NOT `initial`.
const FLAG_FORWARDABLE: usize = 1;
const FLAG_PRE_AUTHENT: usize = 10;

/// The wire response to a TGS-REQ.
pub enum TgsOutcome {
    /// A successful TGS-REP (the client obtained a service ticket).
    Rep(Vec<u8>),
    /// A KRB-ERROR.
    Error(Vec<u8>),
}

impl TgsOutcome {
    /// The DER bytes to write back, regardless of variant.
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            TgsOutcome::Rep(b) | TgsOutcome::Error(b) => b,
        }
    }
}

/// Process one TGS-REQ, always returning wire bytes (internal failures become a
/// generic KRB-ERROR).
pub fn handle_tgs_request(store: &PrincipalStore, request: &[u8]) -> Vec<u8> {
    match handle_tgs_req(store, request) {
        Ok(outcome) => outcome.into_bytes(),
        Err(e) => {
            tracing::warn!("TGS-REQ handling failed: {e}");
            let krbtgt = vec!["krbtgt".to_string(), store.realm().to_string()];
            build_krb_error(store.realm(), &krbtgt, KRB_ERR_GENERIC, None).unwrap_or_default()
        }
    }
}

/// Handle one TGS-REQ against `store`.
pub fn handle_tgs_req(store: &PrincipalStore, request: &[u8]) -> KdcResult<TgsOutcome> {
    let tgs_req: TgsReq = picky_asn1_der::from_bytes(request).map_err(asn1)?;
    let body = &tgs_req.0.req_body.0;
    let realm = store.realm();

    // The requested service (sname).
    let sname = body
        .sname
        .0
        .as_ref()
        .ok_or_else(|| KdcError::Malformed("TGS-REQ without sname".into()))?;
    let service_name = read_name(&sname.0);
    if service_name.is_empty() {
        return Err(KdcError::Malformed("empty service name".into()));
    }
    tracing::debug!("TGS-REQ for service {service_name:?}");
    let err = |code: u32| -> KdcResult<TgsOutcome> {
        tracing::warn!(
            target: "auth", proto = "kerberos", service = %service_name.join("/"), code,
            "TGS-REQ rejected"
        );
        Ok(TgsOutcome::Error(build_krb_error(
            realm,
            &service_name,
            code,
            None,
        )?))
    };

    // Only aes256 is offered.
    if !read_etypes(body).contains(&AES256_CTS_HMAC_SHA1_96) {
        return err(KDC_ERR_ETYPE_NOSUPP);
    }

    // Extract the PA-TGS-REQ (AP-REQ) pre-auth.
    let Some(pa) = tgs_req.0.padata.0.as_ref().and_then(|seq| {
        seq.0
            .iter()
            .find(|pa| int_to_i64(&pa.padata_type.0) == PA_TGS_REQ_TYPE)
    }) else {
        return err(KDC_ERR_PADATA_TYPE_NOSUPP);
    };
    let ap_req: ApReq = picky_asn1_der::from_bytes(&pa.padata_data.0 .0).map_err(asn1)?;

    // 1. Decrypt the presented TGT with the krbtgt key (usage 2).
    let krbtgt = store
        .krbtgt()
        .ok_or_else(|| KdcError::Malformed("krbtgt principal missing".into()))?;
    let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();
    let tgt = &ap_req.0.ticket.0;
    let Ok(tgt_plain) = cipher.decrypt(&krbtgt.key.key, TICKET_REP, &tgt.0.enc_part.0.cipher.0 .0)
    else {
        return err(KRB_AP_ERR_MODIFIED); // TGT not sealed by our krbtgt key
    };
    let enc_tgt: EncTicketPart = picky_asn1_der::from_bytes(&tgt_plain).map_err(asn1)?;
    let tgt_session_key = enc_tgt.0.key.0.key_value.0 .0.clone();
    let client_pname = &enc_tgt.0.cname.0;
    let client_realm_bytes = enc_tgt.0.crealm.0.as_bytes().to_vec();

    // TGT must not be expired.
    if !not_expired(&enc_tgt) {
        return err(KRB_AP_ERR_TKT_EXPIRED);
    }

    // 2. Decrypt & validate the Authenticator with the TGT session key (usage 7).
    let Ok(auth_plain) = cipher.decrypt(
        &tgt_session_key,
        TGS_REQ_PA_DATA_AP_REQ_AUTHENTICATOR,
        &ap_req.0.authenticator.0.cipher.0 .0,
    ) else {
        return err(KRB_AP_ERR_BAD_INTEGRITY);
    };
    let authenticator: Authenticator = picky_asn1_der::from_bytes(&auth_plain).map_err(asn1)?;

    // The authenticator's client must match the ticket's client.
    if read_name(&authenticator.0.cname.0) != read_name(client_pname)
        || authenticator.0.crealm.0.as_bytes() != client_realm_bytes.as_slice()
    {
        return err(KRB_AP_ERR_BADMATCH);
    }
    // And be within clock skew (freshness).
    if !within_skew(&authenticator.0.ctime.0) {
        return err(KRB_AP_ERR_SKEW);
    }

    // 3. Look up the requested service's long-term key.
    let Some(service) = store.get(&service_name) else {
        return err(KDC_ERR_S_PRINCIPAL_UNKNOWN);
    };

    // S4U delegation (MS-SFU): the requester (the TGT's client) may ask for a ticket
    // that names ANOTHER user as the client — S4U2Self (protocol transition, via
    // PA-FOR-USER) or S4U2Proxy (constrained delegation, via an additional ticket).
    // Both change the minted ticket's client to the impersonated user; a normal TGS
    // keeps the TGT's client.
    let requester = read_name(client_pname);
    let (client_pname, client_realm_bytes) =
        match resolve_impersonation(store, &tgs_req, &requester, &service_name, &tgt_session_key) {
            Ok(Some((imp_name, imp_realm))) => (imp_name, imp_realm),
            Ok(None) => (client_pname.clone(), client_realm_bytes),
            Err(code) => return err(code),
        };

    // Reply enc-part is sealed under the authenticator subkey if present, else the
    // TGT session key (RFC 4120 §3.3.3).
    let (reply_key, reply_usage) = match authenticator.0.subkey.0.as_ref() {
        Some(subkey) => (subkey.0.key_value.0 .0.clone(), TGS_REP_ENC_SUB_KEY),
        None => (tgt_session_key.clone(), TGS_REP_ENC_SESSION_KEY),
    };

    // 4. Mint the service ticket + TGS-REP. Resolve the client's PAC identity (real
    // RID + group SIDs + domain SID) from the store so the service ticket's PAC names
    // the actual user, not a fixed identity.
    let client_identity = resolve_client_identity(store, &client_pname);
    let rep = build_tgs_rep(
        realm,
        &service,
        &service_name,
        &client_pname,
        &client_realm_bytes,
        &enc_tgt,
        &krbtgt.key.key,
        &reply_key,
        reply_usage,
        &body.nonce.0,
        &client_identity,
    )?;
    let _ = KDC_ERR_BADOPTION; // reserved for renew/postdate handling (later)
    tracing::info!(
        target: "auth", proto = "kerberos",
        principal = %requester.join("/"), service = %service_name.join("/"),
        "TGS-REP issued (service ticket granted)"
    );
    Ok(TgsOutcome::Rep(rep))
}

/// Resolve S4U delegation (MS-SFU). Returns `Some((client, realm))` — the user the
/// requester impersonates — for an S4U2Self (PA-FOR-USER) or S4U2Proxy (additional
/// ticket) request, `None` for a normal TGS, or `Err(code)` to reject it.
///
/// * **S4U2Self** (protocol transition): the requester presents a PA-FOR-USER naming
///   a user, with a checksum keyed by its TGT session key; we mint a ticket TO the
///   requester itself but naming that user.
/// * **S4U2Proxy** (constrained delegation): the requester presents, as an additional
///   ticket, the S4U2Self ticket a user obtained to it (sealed under the requester's
///   own key). If the requester is on the backend's delegation allow-list, we mint a
///   ticket to the backend naming that user.
fn resolve_impersonation(
    store: &PrincipalStore,
    tgs_req: &TgsReq,
    requester: &[String],
    service_name: &[String],
    tgt_session_key: &[u8],
) -> Result<Option<(PrincipalName, Vec<u8>)>, u32> {
    let body = &tgs_req.0.req_body.0;
    let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();

    // S4U2Proxy: the additional ticket is the user's S4U2Self ticket to the requester.
    if let Some(addl) = body
        .additional_tickets
        .0
        .as_ref()
        .and_then(|t| t.0 .0.first())
    {
        let requester_principal = store.get(requester).ok_or(KDC_ERR_S_PRINCIPAL_UNKNOWN)?;
        let plain = cipher
            .decrypt(
                &requester_principal.key.key,
                TICKET_REP,
                &addl.0.enc_part.0.cipher.0 .0,
            )
            .map_err(|_| KRB_AP_ERR_MODIFIED)?;
        let addl_enc: EncTicketPart =
            picky_asn1_der::from_bytes(&plain).map_err(|_| KRB_ERR_GENERIC)?;
        // Constrained delegation: the requester must be allowed to reach this backend.
        if !store.can_delegate(requester, service_name) {
            return Err(KDC_ERR_BADOPTION);
        }
        let imp_name = addl_enc.0.cname.0.clone();
        let imp_realm = addl_enc.0.crealm.0.as_bytes().to_vec();
        return Ok(Some((imp_name, imp_realm)));
    }

    // S4U2Self: PA-FOR-USER names the impersonated user; verify its checksum.
    if let Some(pa) = tgs_req.0.padata.0.as_ref().and_then(|seq| {
        seq.0
            .iter()
            .find(|pa| int_to_i64(&pa.padata_type.0) == PA_FOR_USER_TYPE)
    }) {
        let pfu: PaForUser =
            picky_asn1_der::from_bytes(&pa.padata_data.0 .0).map_err(|_| KRB_ERR_GENERIC)?;
        let imp_name = pfu.user_name.0.clone();
        let imp_realm = pfu.user_realm.0.as_bytes().to_vec();
        let s4u = s4u_byte_array(&imp_name, &imp_realm, pfu.auth_package.0.as_bytes());
        let presented = &pfu.cksum.0.checksum.0 .0;
        // Accept either the AES keyed checksum (RFC 3962) or the legacy RC4
        // KERB_CHECKSUM_HMAC_MD5 (RFC 4757) — a real S4U client (impacket, Windows)
        // signs PA-FOR-USER with hmac-md5 even when the TGT session key is AES.
        let aes_ok = cipher
            .encryption_checksum(tgt_session_key, KERB_NON_KERB_CKSUM_SALT, &s4u)
            .map(|c| &c == presented)
            .unwrap_or(false);
        let md5_ok =
            &hmac_md5_checksum(tgt_session_key, KERB_NON_KERB_CKSUM_SALT, &s4u) == presented;
        if !aes_ok && !md5_ok {
            return Err(KDC_ERR_BADOPTION); // bad PA-FOR-USER checksum
        }
        return Ok(Some((imp_name, imp_realm)));
    }

    Ok(None)
}

/// The legacy RC4 `KERB_CHECKSUM_HMAC_MD5` keyed checksum (RFC 4757 §4): with
/// `Ksign = HMAC-MD5(key, "signaturekey\0")`, checksum = `HMAC-MD5(Ksign, MD5(
/// usage_le32 ‖ data))`. Used by S4U clients for PA-FOR-USER regardless of the
/// ticket enctype.
pub(crate) fn hmac_md5_checksum(key: &[u8], usage: i32, data: &[u8]) -> Vec<u8> {
    use hmac::{Mac, SimpleHmac};
    use md5::{Digest, Md5};
    type HmacMd5 = SimpleHmac<Md5>;

    let mut sign = <HmacMd5 as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    sign.update(b"signaturekey\0");
    let ksign = sign.finalize().into_bytes();

    let mut md5 = Md5::new();
    md5.update(usage.to_le_bytes());
    md5.update(data);
    let tmp = md5.finalize();

    let mut mac = <HmacMd5 as Mac>::new_from_slice(&ksign).expect("hmac accepts any key length");
    mac.update(&tmp);
    mac.finalize().into_bytes().to_vec()
}

/// MS-SFU §2.2.1 `S4UByteArray`: `name-type` (little-endian i32) ‖ each name
/// component ‖ realm ‖ auth-package — the input to the PA-FOR-USER checksum.
pub(crate) fn s4u_byte_array(name: &PrincipalName, realm: &[u8], auth_package: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    let name_type = int_to_i64(&name.name_type.0) as i32;
    b.extend_from_slice(&name_type.to_le_bytes());
    for comp in read_name(name) {
        b.extend_from_slice(comp.as_bytes());
    }
    b.extend_from_slice(realm);
    b.extend_from_slice(auth_package);
    b
}

/// Build the TGS-REP: a service ticket (sealed under the service key) plus the
/// EncTGSRepPart (sealed under `reply_key`).
#[allow(clippy::too_many_arguments)]
/// Build the PAC identity for the TGS client from the store (its real RID + groups),
/// defaulting to a minimal identity if the client is not a stored principal.
fn resolve_client_identity(
    store: &PrincipalStore,
    client_pname: &PrincipalName,
) -> crate::pac::PacIdentity {
    let name = read_name(client_pname);
    match store.get(&name) {
        Some(p) => crate::pac::PacIdentity {
            user_rid: p.rid,
            primary_group_rid: p.primary_group_rid,
            group_rids: p.group_rids,
            domain_sid_subauth: store.domain_sid().to_vec(),
            logon_script: String::new(),
            profile_path: String::new(),
            home_directory: String::new(),
        },
        None => crate::pac::PacIdentity::minimal(0, store.domain_sid().to_vec()),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_tgs_rep(
    realm: &str,
    service: &crate::keys::Principal,
    service_name: &[String],
    client_pname: &PrincipalName,
    client_realm_bytes: &[u8],
    enc_tgt: &EncTicketPart,
    krbtgt_key: &[u8],
    reply_key: &[u8],
    reply_usage: i32,
    nonce: &IntegerAsn1,
    client_identity: &crate::pac::PacIdentity,
) -> KdcResult<Vec<u8>> {
    let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();
    let client_realm = String::from_utf8_lossy(client_realm_bytes).into_owned();

    // Fresh session key for the client↔service association.
    let mut session_key = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut session_key);
    let enc_key = EncryptionKey {
        key_type: ExplicitContextTag0::from(int(i64::from(AES256_CTS_HMAC_SHA1_96))),
        key_value: ExplicitContextTag1::from(picky_asn1::wrapper::OctetStringAsn1::from(
            session_key.clone(),
        )),
    };

    let flags = service_ticket_flags();
    let client = principal_name(NT_PRINCIPAL, &read_name(client_pname))?;
    let service_pname = principal_name(NT_PRINCIPAL, service_name)?;

    // A PAC for the service ticket: the server signature uses the service key
    // (this ticket is sealed under it), the KDC signature uses the krbtgt key.
    let client_account = read_name(client_pname)
        .into_iter()
        .next()
        .unwrap_or_default();
    let pac = crate::pac::build_pac_authorization_data(
        &service.key.key,
        krbtgt_key,
        &client_account,
        realm,
        chrono::Utc::now().timestamp(),
        client_identity,
    )?;

    // Inherit the TGT's validity window (a derived ticket can't outlive its TGT).
    let auth_time = enc_tgt.0.auth_time.0.clone();
    let end_time = enc_tgt.0.endtime.0.clone();
    let start_time = enc_tgt.0.starttime.0.clone();

    // --- Service ticket enc-part, sealed under the service key (usage 2) ---
    let enc_ticket_part = EncTicketPart::from(picky_krb::data_types::EncTicketPartInner {
        flags: ExplicitContextTag0::from(flags.clone()),
        key: ExplicitContextTag1::from(enc_key.clone()),
        crealm: ExplicitContextTag2::from(realm_string(&client_realm)?),
        cname: ExplicitContextTag3::from(principal_name(NT_PRINCIPAL, &read_name(client_pname))?),
        transited: ExplicitContextTag4::from(TransitedEncoding {
            tr_type: ExplicitContextTag0::from(int(0)),
            contents: ExplicitContextTag1::from(picky_asn1::wrapper::OctetStringAsn1::from(
                Vec::new(),
            )),
        }),
        auth_time: ExplicitContextTag5::from(auth_time.clone()),
        starttime: Optional::from(start_time.clone()),
        endtime: ExplicitContextTag7::from(end_time.clone()),
        renew_till: Optional::from(None),
        caddr: Optional::from(None),
        authorization_data: Optional::from(Some(ExplicitContextTag10::from(pac))),
    });
    let enc_ticket_der = picky_asn1_der::to_vec(&enc_ticket_part).map_err(asn1)?;
    let ticket_cipher = cipher
        .encrypt(&service.key.key, TICKET_REP, &enc_ticket_der)
        .map_err(crypto)?;

    let ticket = Ticket::from(TicketInner {
        tkt_vno: ExplicitContextTag0::from(int(5)),
        realm: ExplicitContextTag1::from(realm_string(realm)?),
        sname: ExplicitContextTag2::from(service_pname.clone()),
        enc_part: ExplicitContextTag3::from(encrypted_data(ticket_cipher)),
    });

    // --- EncTGSRepPart, sealed under the reply key (subkey or TGT session key) ---
    let last_req = picky_asn1::wrapper::Asn1SequenceOf::from(vec![LastReqInner {
        lr_type: ExplicitContextTag0::from(int(0)),
        lr_value: ExplicitContextTag1::from(auth_time.clone()),
    }]);
    let enc_tgs_rep_part = EncTgsRepPart::from(EncKdcRepPart {
        key: ExplicitContextTag0::from(enc_key),
        last_req: ExplicitContextTag1::from(last_req),
        nonce: ExplicitContextTag2::from(nonce.clone()),
        key_expiration: Optional::from(None),
        flags: ExplicitContextTag4::from(flags),
        auth_time: ExplicitContextTag5::from(auth_time),
        start_time: Optional::from(start_time),
        end_time: ExplicitContextTag7::from(end_time),
        renew_till: Optional::from(None),
        srealm: ExplicitContextTag9::from(realm_string(realm)?),
        sname: ExplicitContextTag10::from(service_pname),
        caddr: Optional::from(None),
        encrypted_pa_data: Optional::from(None),
    });
    let enc_tgs_rep_der = picky_asn1_der::to_vec(&enc_tgs_rep_part).map_err(asn1)?;
    let enc_part_cipher = cipher
        .encrypt(reply_key, reply_usage, &enc_tgs_rep_der)
        .map_err(crypto)?;

    // --- Assemble the TGS-REP ---
    let kdc_rep = KdcRep {
        pvno: ExplicitContextTag0::from(int(5)),
        msg_type: ExplicitContextTag1::from(int(i64::from(TGS_REP_MSG_TYPE))),
        padata: Optional::from(None),
        crealm: ExplicitContextTag3::from(realm_string(&client_realm)?),
        cname: ExplicitContextTag4::from(client),
        ticket: ExplicitContextTag5::from(ticket),
        enc_part: ExplicitContextTag6::from(encrypted_data(enc_part_cipher)),
    };
    picky_asn1_der::to_vec(&TgsRep::from(kdc_rep)).map_err(asn1)
}

fn service_ticket_flags() -> BitStringAsn1 {
    let mut bits = BitString::with_len(32);
    bits.set(FLAG_FORWARDABLE, true);
    bits.set(FLAG_PRE_AUTHENT, true);
    BitStringAsn1::from(bits)
}

/// Whether the TGT's `endtime` is still in the future.
fn not_expired(enc_tgt: &EncTicketPart) -> bool {
    let t = &enc_tgt.0.endtime.0;
    chrono::Utc
        .with_ymd_and_hms(
            i32::from(t.year()),
            u32::from(t.month()),
            u32::from(t.day()),
            u32::from(t.hour()),
            u32::from(t.minute()),
            u32::from(t.second()),
        )
        .single()
        .is_some_and(|end| end > chrono::Utc::now())
}

use chrono::TimeZone;

/// The requested etypes as integers.
fn read_etypes(body: &picky_krb::messages::KdcReqBody) -> Vec<i32> {
    body.etype
        .0
         .0
        .iter()
        .map(|e| int_to_i64(e) as i32)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::as_exchange::{handle_as_req, AsOutcome};
    use crate::keys::{default_salt, derive_aes256_key, PrincipalStore};
    use crate::test_support::{as_req_with_preauth, tgs_req, tgs_req_s4u2proxy, tgs_req_s4u2self};
    use picky_krb::constants::key_usages::AS_REP_ENC;
    use picky_krb::messages::{AsRep, EncAsRepPart};

    const REALM: &str = "EXAMPLE.COM";
    const SERVICE: &[&str] = &["host", "app.example.com"];

    fn store() -> PrincipalStore {
        let mut s = PrincipalStore::new(REALM);
        s.add_password_principal(&["alice"], "password12").unwrap();
        s.add_password_principal(&["krbtgt", REALM], "krbtgt-secret")
            .unwrap();
        s.add_password_principal(SERVICE, "service-secret").unwrap();
        s
    }

    /// Run a full AS exchange and return (TGT ticket, TGT session key).
    fn obtain_tgt(store: &PrincipalStore) -> (Ticket, Vec<u8>) {
        let alice_key =
            derive_aes256_key("password12", &default_salt(REALM, &["alice".into()])).unwrap();
        let req = as_req_with_preauth(REALM, &["alice"], &alice_key, 111);
        let AsOutcome::Rep(bytes) = handle_as_req(store, &req).unwrap() else {
            panic!("AS-REP expected");
        };
        let as_rep: AsRep = picky_asn1_der::from_bytes(&bytes).unwrap();
        let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();
        let enc = cipher
            .decrypt(&alice_key, AS_REP_ENC, &as_rep.0.enc_part.0.cipher.0 .0)
            .unwrap();
        let enc_as_rep: EncAsRepPart = picky_asn1_der::from_bytes(&enc).unwrap();
        let session_key = enc_as_rep.0.key.0.key_value.0 .0.clone();
        (as_rep.0.ticket.0.clone(), session_key)
    }

    /// The happy path: a valid TGT yields a service ticket whose session key,
    /// recovered by the client from the TGS-REP enc-part, equals the one sealed in
    /// the service ticket (decryptable only with the service's key).
    #[test]
    fn valid_tgt_yields_service_ticket() {
        let store = store();
        let (tgt, tgt_session_key) = obtain_tgt(&store);
        let nonce = 55555;

        let req = tgs_req(REALM, SERVICE, &["alice"], tgt, &tgt_session_key, nonce);
        let TgsOutcome::Rep(bytes) = handle_tgs_req(&store, &req).unwrap() else {
            panic!("TGS-REP expected");
        };
        let tgs_rep: TgsRep = picky_asn1_der::from_bytes(&bytes).unwrap();

        let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();

        // Client recovers the service session key from the enc-part (usage 8,
        // sealed under the TGT session key since we sent no subkey).
        let enc_plain = cipher
            .decrypt(
                &tgt_session_key,
                TGS_REP_ENC_SESSION_KEY,
                &tgs_rep.0.enc_part.0.cipher.0 .0,
            )
            .expect("client decrypts TGS-REP enc-part");
        let enc_tgs: EncTgsRepPart = picky_asn1_der::from_bytes(&enc_plain).unwrap();
        let client_view_key = enc_tgs.0.key.0.key_value.0 .0.clone();
        assert_eq!(int_to_i64(&enc_tgs.0.nonce.0), nonce, "nonce echoed");

        // The service ticket is sealed under the service's long-term key (usage 2).
        let service_key =
            derive_aes256_key("service-secret", &default_salt(REALM, &to_owned(SERVICE))).unwrap();
        let ticket = &tgs_rep.0.ticket.0;
        let ticket_plain = cipher
            .decrypt(&service_key, TICKET_REP, &ticket.0.enc_part.0.cipher.0 .0)
            .expect("service decrypts its own ticket");
        let enc_ticket: EncTicketPart = picky_asn1_der::from_bytes(&ticket_plain).unwrap();
        let ticket_key = enc_ticket.0.key.0.key_value.0 .0.clone();

        assert_eq!(
            client_view_key, ticket_key,
            "service session key must match on both sides"
        );
        assert_eq!(client_view_key.len(), 32);
        // The ticket carries the authenticated client identity from the TGT.
        assert_eq!(read_name(&enc_ticket.0.cname.0), vec!["alice".to_string()]);
    }

    #[test]
    fn tgs_for_unknown_service_is_rejected() {
        let store = store();
        let (tgt, tgt_session_key) = obtain_tgt(&store);
        let req = tgs_req(
            REALM,
            &["host", "nope.example.com"],
            &["alice"],
            tgt,
            &tgt_session_key,
            1,
        );
        let TgsOutcome::Error(bytes) = handle_tgs_req(&store, &req).unwrap() else {
            panic!("expected KRB-ERROR");
        };
        let err: picky_krb::messages::KrbError = picky_asn1_der::from_bytes(&bytes).unwrap();
        assert_eq!(err.0.error_code.0, KDC_ERR_S_PRINCIPAL_UNKNOWN);
    }

    #[test]
    fn tgs_with_tampered_tgt_is_rejected() {
        let store = store();
        let (tgt, tgt_session_key) = obtain_tgt(&store);
        // Flip a byte in the TGT's encrypted part → krbtgt decryption must fail.
        let mut bad = tgt.clone();
        let ct = &mut bad.0.enc_part.0.cipher.0 .0;
        let last = ct.len() - 1;
        ct[last] ^= 0xff;
        let req = tgs_req(REALM, SERVICE, &["alice"], bad, &tgt_session_key, 1);
        let TgsOutcome::Error(bytes) = handle_tgs_req(&store, &req).unwrap() else {
            panic!("expected KRB-ERROR");
        };
        let err: picky_krb::messages::KrbError = picky_asn1_der::from_bytes(&bytes).unwrap();
        assert_eq!(err.0.error_code.0, KRB_AP_ERR_MODIFIED);
    }

    fn to_owned(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    const BACKEND: &[&str] = &["cifs", "backend.example.com"];

    /// Run an AS exchange for an arbitrary principal → (its TGT, TGT session key).
    fn obtain_tgt_for(store: &PrincipalStore, name: &[&str], password: &str) -> (Ticket, Vec<u8>) {
        let key = derive_aes256_key(password, &default_salt(REALM, &to_owned(name))).unwrap();
        let req = as_req_with_preauth(REALM, name, &key, 222);
        let AsOutcome::Rep(bytes) = handle_as_req(store, &req).unwrap() else {
            panic!("AS-REP expected");
        };
        let as_rep: AsRep = picky_asn1_der::from_bytes(&bytes).unwrap();
        let cipher = CipherSuite::Aes256CtsHmacSha196.cipher();
        let enc = cipher
            .decrypt(&key, AS_REP_ENC, &as_rep.0.enc_part.0.cipher.0 .0)
            .unwrap();
        let enc_as_rep: EncAsRepPart = picky_asn1_der::from_bytes(&enc).unwrap();
        let session_key = enc_as_rep.0.key.0.key_value.0 .0.clone();
        (as_rep.0.ticket.0.clone(), session_key)
    }

    /// Decrypt a service ticket with `service_key` (usage 2) → its EncTicketPart.
    fn open_ticket(ticket: &Ticket, service_key: &[u8]) -> EncTicketPart {
        let plain = CipherSuite::Aes256CtsHmacSha196
            .cipher()
            .decrypt(service_key, TICKET_REP, &ticket.0.enc_part.0.cipher.0 .0)
            .expect("decrypt service ticket");
        picky_asn1_der::from_bytes(&plain).unwrap()
    }

    fn key_for(name: &[&str], password: &str) -> Vec<u8> {
        derive_aes256_key(password, &default_salt(REALM, &to_owned(name))).unwrap()
    }

    /// S4U2Self (protocol transition): a service, authenticating with its own TGT,
    /// obtains a ticket to itself that names an arbitrary user as the client.
    #[test]
    fn s4u2self_impersonates_the_named_user() {
        let store = store();
        let (svc_tgt, svc_key) = obtain_tgt_for(&store, SERVICE, "service-secret");

        let req = tgs_req_s4u2self(REALM, SERVICE, SERVICE, &["alice"], svc_tgt, &svc_key, 777);
        let TgsOutcome::Rep(bytes) = handle_tgs_req(&store, &req).unwrap() else {
            panic!("TGS-REP expected");
        };
        let rep: TgsRep = picky_asn1_der::from_bytes(&bytes).unwrap();
        // The ticket is issued to the service but NAMES alice (the impersonated user).
        let enc = open_ticket(&rep.0.ticket.0, &key_for(SERVICE, "service-secret"));
        assert_eq!(read_name(&enc.0.cname.0), vec!["alice".to_string()]);
        assert_eq!(read_name(&rep.0.ticket.0 .0.sname.0), to_owned(SERVICE));
    }

    /// A tampered PA-FOR-USER checksum is rejected (a service can't impersonate
    /// without proving it holds the TGT session key).
    #[test]
    fn s4u2self_bad_checksum_is_rejected() {
        let store = store();
        let (svc_tgt, _svc_key) = obtain_tgt_for(&store, SERVICE, "service-secret");
        // Sign the PA-FOR-USER with the WRONG key (a random session key).
        let wrong_key = vec![7u8; 32];
        let req = tgs_req_s4u2self(
            REALM,
            SERVICE,
            SERVICE,
            &["alice"],
            svc_tgt,
            &wrong_key,
            778,
        );
        // The AP-REQ authenticator is also sealed with the wrong key, so this fails
        // at authenticator validation — either way the request is refused.
        assert!(matches!(
            handle_tgs_req(&store, &req).unwrap(),
            TgsOutcome::Error(_)
        ));
    }

    /// S4U2Proxy (constrained delegation): with the user's S4U2Self ticket as an
    /// additional ticket, an allowed service gets a ticket to the backend naming
    /// the user.
    #[test]
    fn s4u2proxy_delegates_to_allowed_backend() {
        let mut store = store();
        store
            .add_password_principal(BACKEND, "backend-secret")
            .unwrap();
        store.allow_delegation(SERVICE, BACKEND);
        let (svc_tgt, svc_key) = obtain_tgt_for(&store, SERVICE, "service-secret");

        // 1. S4U2Self → alice's ticket to the service (sealed under the service key).
        let self_req = tgs_req_s4u2self(
            REALM,
            SERVICE,
            SERVICE,
            &["alice"],
            svc_tgt.clone(),
            &svc_key,
            1,
        );
        let TgsOutcome::Rep(sb) = handle_tgs_req(&store, &self_req).unwrap() else {
            panic!("S4U2Self TGS-REP");
        };
        let self_rep: TgsRep = picky_asn1_der::from_bytes(&sb).unwrap();
        let s4u_self_ticket = self_rep.0.ticket.0.clone();

        // 2. S4U2Proxy with that additional ticket → alice's ticket to the backend.
        let proxy_req = tgs_req_s4u2proxy(
            REALM,
            BACKEND,
            SERVICE,
            svc_tgt,
            &svc_key,
            s4u_self_ticket,
            2,
        );
        let TgsOutcome::Rep(pb) = handle_tgs_req(&store, &proxy_req).unwrap() else {
            panic!("S4U2Proxy TGS-REP");
        };
        let proxy_rep: TgsRep = picky_asn1_der::from_bytes(&pb).unwrap();
        let enc = open_ticket(&proxy_rep.0.ticket.0, &key_for(BACKEND, "backend-secret"));
        assert_eq!(
            read_name(&enc.0.cname.0),
            vec!["alice".to_string()],
            "client is alice"
        );
        assert_eq!(
            read_name(&proxy_rep.0.ticket.0 .0.sname.0),
            to_owned(BACKEND)
        );
    }

    /// S4U2Proxy to a backend NOT on the delegation allow-list is refused.
    #[test]
    fn s4u2proxy_without_delegation_is_rejected() {
        let mut store = store();
        store
            .add_password_principal(BACKEND, "backend-secret")
            .unwrap();
        // NB: no `allow_delegation`.
        let (svc_tgt, svc_key) = obtain_tgt_for(&store, SERVICE, "service-secret");
        let self_req = tgs_req_s4u2self(
            REALM,
            SERVICE,
            SERVICE,
            &["alice"],
            svc_tgt.clone(),
            &svc_key,
            1,
        );
        let TgsOutcome::Rep(sb) = handle_tgs_req(&store, &self_req).unwrap() else {
            panic!("S4U2Self TGS-REP");
        };
        let self_rep: TgsRep = picky_asn1_der::from_bytes(&sb).unwrap();
        let proxy_req = tgs_req_s4u2proxy(
            REALM,
            BACKEND,
            SERVICE,
            svc_tgt,
            &svc_key,
            self_rep.0.ticket.0.clone(),
            2,
        );
        let outcome = handle_tgs_req(&store, &proxy_req).unwrap();
        let TgsOutcome::Error(bytes) = outcome else {
            panic!("expected KRB-ERROR for disallowed delegation");
        };
        let err: picky_krb::messages::KrbError = picky_asn1_der::from_bytes(&bytes).unwrap();
        assert_eq!(err.0.error_code.0, KDC_ERR_BADOPTION);
    }
}
