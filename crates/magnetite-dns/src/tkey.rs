//! TKEY (RFC 2930) GSS-API context negotiation — the first half of GSS-TSIG
//! (RFC 3645). A client establishes a Kerberos security context with the DNS
//! server by sending a TKEY query whose key data is a SPNEGO/Kerberos AP-REQ; the
//! server verifies it against its `DNS/<dc-fqdn>` service key, returns an AP-REP,
//! and both sides hold the GSS session key that then signs dynamic updates.
//!
//! hickory has no TKEY rdata, so the TKEY resource record is hand-parsed and
//! -built (it arrives as an [`RData::Unknown`] carrying the raw octets); the
//! Kerberos verification/response reuses the proven [`magnetite_krb5`] machinery
//! (`spnego::extract_ap_req` / `verify_ap_req` / `build_ap_rep` / `wrap_ap_rep`).

use hickory_proto::op::{Header, Message};
use hickory_proto::rr::rdata::NULL;
use hickory_proto::rr::{Name, RData, Record, RecordType};

/// The TKEY resource-record type code (RFC 2930).
const TKEY_TYPE: u16 = 249;
/// TKEY mode 3: GSS-API negotiation (RFC 3645 §2.1).
const MODE_GSS_API: u16 = 3;

/// The outcome of a successful TKEY negotiation.
pub struct Negotiated {
    /// The framed DNS response to send back (carries the AP-REP TKEY).
    pub response: Vec<u8>,
    /// The negotiated key name — the TKEY owner, later named by each update's TSIG.
    pub key_name: Name,
    /// The GSS session key (acceptor subkey) that signs subsequent updates.
    pub session_key: Vec<u8>,
}

/// The fields of a TKEY RR's rdata we care about.
struct TkeyRdata {
    /// The algorithm name octets (a DNS name, including the trailing root label).
    algorithm: Vec<u8>,
    inception: u32,
    expiration: u32,
    mode: u16,
    key_data: Vec<u8>,
}

/// Skip an uncompressed DNS name in `data` starting at `pos`, returning the index
/// just past the terminating root label.
fn skip_name(data: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *data.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            return Some(pos);
        }
        if len & 0xc0 != 0 {
            return None; // compression pointers do not appear inside rdata
        }
        pos += len;
    }
}

/// Parse a TKEY rdata blob (RFC 2930 §2): algorithm name, inception, expiration,
/// mode, error, key size + key data (the GSS token), other size + data (ignored).
fn parse_tkey_rdata(rdata: &[u8]) -> Option<TkeyRdata> {
    let alg_end = skip_name(rdata, 0)?;
    let algorithm = rdata[..alg_end].to_vec();
    let mut p = alg_end;
    let mut take = |n: usize| -> Option<&[u8]> {
        let s = rdata.get(p..p + n)?;
        p += n;
        Some(s)
    };
    let inception = u32::from_be_bytes(take(4)?.try_into().ok()?);
    let expiration = u32::from_be_bytes(take(4)?.try_into().ok()?);
    let mode = u16::from_be_bytes(take(2)?.try_into().ok()?);
    let _error = u16::from_be_bytes(take(2)?.try_into().ok()?);
    let key_size = u16::from_be_bytes(take(2)?.try_into().ok()?) as usize;
    let key_data = take(key_size)?.to_vec();
    Some(TkeyRdata {
        algorithm,
        inception,
        expiration,
        mode,
        key_data,
    })
}

/// Build a TKEY rdata blob with the given GSS `key_data` and `error`.
fn build_tkey_rdata(
    algorithm: &[u8],
    inception: u32,
    expiration: u32,
    error: u16,
    key_data: &[u8],
) -> Vec<u8> {
    let mut r = Vec::with_capacity(algorithm.len() + 14 + key_data.len());
    r.extend_from_slice(algorithm);
    r.extend_from_slice(&inception.to_be_bytes());
    r.extend_from_slice(&expiration.to_be_bytes());
    r.extend_from_slice(&MODE_GSS_API.to_be_bytes());
    r.extend_from_slice(&error.to_be_bytes());
    r.extend_from_slice(&(key_data.len() as u16).to_be_bytes());
    r.extend_from_slice(key_data);
    r.extend_from_slice(&0u16.to_be_bytes()); // other size = 0
    r
}

/// The raw TKEY RR carried in a TKEY query's additional section, if present.
fn find_tkey_rr(message: &Message) -> Option<(&Name, &[u8])> {
    message.additionals().iter().find_map(|r| match r.data() {
        RData::Unknown { code, rdata } if u16::from(*code) == TKEY_TYPE => {
            Some((r.name(), rdata.anything()))
        }
        _ => None,
    })
}

/// Handle a TKEY GSS-API negotiation query: verify the client's AP-REQ against the
/// DNS service key, and return the AP-REP TKEY response plus the negotiated key
/// name and GSS session key. `None` if the message is not a valid GSS-API TKEY or
/// the Kerberos verification fails.
pub fn negotiate(dns_service_key: &[u8], request_bytes: &[u8]) -> Option<Negotiated> {
    let message = Message::from_vec(request_bytes).ok()?;
    let (owner, rdata) = find_tkey_rr(&message)?;
    let key_name = owner.clone();
    let tkey = parse_tkey_rdata(rdata)?;
    if tkey.mode != MODE_GSS_API {
        return None;
    }

    // Verify the client AP-REQ, then answer with an AP-REP (mutual auth). The
    // acceptor subkey becomes the GSS session key both sides sign updates with.
    let ap_req = magnetite_krb5::spnego::extract_ap_req(&tkey.key_data)?;
    let verified = magnetite_krb5::verify_ap_req(dns_service_key, ap_req).ok()?;
    let (ap_rep, subkey) = magnetite_krb5::ap_req::build_ap_rep(
        &verified.session_key,
        verified.ctime.clone(),
        verified.cusec.clone(),
        1,
    )
    .ok()?;
    let mech = magnetite_krb5::spnego::first_mech_oid(&tkey.key_data).unwrap_or_default();
    let token = magnetite_krb5::spnego::wrap_ap_rep(&ap_rep, &mech);
    let resp_rdata = build_tkey_rdata(&tkey.algorithm, tkey.inception, tkey.expiration, 0, &token);

    let mut response = Message::new();
    response.set_header(Header::response_from_request(message.header()));
    response.add_queries(message.queries().to_vec());
    response.add_answer(Record::from_rdata(
        key_name.clone(),
        0,
        RData::Unknown {
            code: RecordType::from(TKEY_TYPE),
            rdata: NULL::with(resp_rdata),
        },
    ));

    Some(Negotiated {
        response: response.to_vec().ok()?,
        key_name,
        session_key: subkey,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `gss-tsig` algorithm name as DNS wire octets (one label + root).
    fn gss_tsig_name() -> Vec<u8> {
        let mut v = vec![8];
        v.extend_from_slice(b"gss-tsig");
        v.push(0);
        v
    }

    #[test]
    fn tkey_rdata_round_trips() {
        let alg = gss_tsig_name();
        let token = b"a-fake-gss-token-of-some-length".to_vec();
        let blob = build_tkey_rdata(&alg, 0x1111_2222, 0x3333_4444, 0, &token);
        let parsed = parse_tkey_rdata(&blob).expect("parse");
        assert_eq!(parsed.algorithm, alg);
        assert_eq!(parsed.inception, 0x1111_2222);
        assert_eq!(parsed.expiration, 0x3333_4444);
        assert_eq!(parsed.mode, MODE_GSS_API);
        assert_eq!(parsed.key_data, token);
    }

    #[test]
    fn skip_name_handles_multi_label_and_root() {
        let name = {
            let mut v = vec![3];
            v.extend_from_slice(b"foo");
            v.push(3);
            v.extend_from_slice(b"bar");
            v.push(0);
            v
        };
        assert_eq!(skip_name(&name, 0), Some(name.len()));
        // A truncated name (no root) fails.
        assert_eq!(skip_name(&name[..name.len() - 1], 0), None);
    }

    #[test]
    fn non_tkey_message_is_ignored() {
        // A plain query with no TKEY RR yields no negotiation.
        use hickory_proto::op::{OpCode, Query};
        use hickory_proto::rr::RecordType as HRecordType;
        use std::str::FromStr;
        let mut msg = Message::new();
        msg.set_op_code(OpCode::Query);
        msg.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            HRecordType::A,
        ));
        assert!(negotiate(&[0u8; 32], &msg.to_vec().unwrap()).is_none());
    }
}
