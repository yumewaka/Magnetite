//! GSS-TSIG (RFC 3645) transaction signatures for dynamic DNS updates — the same
//! TSIG RR framing as RFC 8945 (HMAC) but with the MAC produced by GSS_GetMIC over
//! a Kerberos security context instead of an HMAC key.
//!
//! The trick that makes this tractable: the *to-be-signed* digest (RFC 2845 §3.4.2
//! — the message minus its TSIG RR, plus the TSIG variables) is reconstructed by
//! hickory's [`signed_bitmessage_to_buf`], exactly as for HMAC TSIG. Only the MAC
//! computation differs, so this module reuses that digest and swaps HMAC for
//! [`magnetite_krb5::gss`]'s GSS MIC (RFC 4121), which is impacket-ground-truthed.
//!
//! The GSS session key comes from a prior TKEY negotiation (see [`crate::tkey`]).

use hickory_proto::dnssec::rdata::tsig::{
    make_tsig_record, signed_bitmessage_to_buf, TsigAlgorithm, TSIG,
};
use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RData};
use magnetite_krb5::gss::{gss_mic, gss_mic_acceptor, verify_gss_mic};

/// TSIG time fudge (max client/server clock skew), seconds.
const FUDGE: u16 = 300;

/// The result of verifying a request's GSS-TSIG: the key name (the negotiated
/// context) and the request MAC (which seeds the response signature, RFC 2845).
pub struct Verified {
    pub key_name: Name,
    pub request_mac: Vec<u8>,
}

/// Extract the GSS-TSIG record from a message's signature section, returning the
/// key name and the TSIG rdata.
fn extract_tsig(message: &Message) -> Option<(Name, TSIG)> {
    message.signature().iter().find_map(|r| match r.data() {
        RData::DNSSEC(DNSSECRData::TSIG(tsig)) if *tsig.algorithm() == TsigAlgorithm::Gss => {
            Some((r.name().clone(), tsig.clone()))
        }
        _ => None,
    })
}

/// Verify a request's GSS-TSIG against `session_key`. Returns the key name + MAC
/// when the GSS MIC authenticates the message, else `None`.
pub fn verify_request(session_key: &[u8], request_bytes: &[u8]) -> Option<Verified> {
    let message = Message::from_vec(request_bytes).ok()?;
    let (key_name, tsig) = extract_tsig(&message)?;
    // hickory reconstructs the RFC 2845 digest from the wire bytes (no prior MAC
    // for a request); the GSS MIC must authenticate exactly those bytes.
    let (tbv, _range) = signed_bitmessage_to_buf(None, request_bytes, true).ok()?;
    verify_gss_mic(session_key, &tbv, tsig.mac())?;
    Some(Verified {
        key_name,
        request_mac: tsig.mac().to_vec(),
    })
}

/// Verify a *response's* GSS-TSIG, chaining `request_mac` as the digest prefix
/// (RFC 2845 §4.4) — the client-side check, useful for a consumer/probe role.
/// Returns `true` when the server's acceptor MIC authenticates the response.
pub fn verify_response(session_key: &[u8], request_mac: &[u8], response_bytes: &[u8]) -> bool {
    let Ok(message) = Message::from_vec(response_bytes) else {
        return false;
    };
    let Some((_key_name, tsig)) = extract_tsig(&message) else {
        return false;
    };
    let Ok((tbv, _range)) = signed_bitmessage_to_buf(Some(request_mac), response_bytes, true)
    else {
        return false;
    };
    verify_gss_mic(session_key, &tbv, tsig.mac()).is_some()
}

/// Sign `message` with a GSS-TSIG under `session_key`/`key_name`, returning the wire
/// bytes. `prev_mac` is `None` for a request and the request's MAC for a response
/// (RFC 2845 §4.4). Mirrors the HMAC signer's placeholder-then-swap so the digest
/// hickory reconstructs on verify matches the one signed here.
pub fn sign(
    session_key: &[u8],
    key_name: &Name,
    message: Message,
    prev_mac: Option<&[u8]>,
    time: u64,
    sequence: u64,
) -> Option<Vec<u8>> {
    // A request is signed by the initiator (client); this path is used by tests
    // and any client role, so keep the initiator MIC.
    sign_directional(
        session_key,
        key_name,
        message,
        prev_mac,
        time,
        sequence,
        false,
    )
}

/// Sign `message`, choosing the MIC direction. `by_acceptor` selects the RFC 4121
/// acceptor usage/flag for a server→client response (the DNS server's role).
fn sign_directional(
    session_key: &[u8],
    key_name: &Name,
    mut message: Message,
    prev_mac: Option<&[u8]>,
    time: u64,
    sequence: u64,
    by_acceptor: bool,
) -> Option<Vec<u8>> {
    let placeholder = TSIG::new(
        TsigAlgorithm::Gss,
        time,
        FUDGE,
        Vec::new(),
        message.id(),
        0,
        Vec::new(),
    );
    message.add_tsig(make_tsig_record(key_name.clone(), placeholder.clone()));
    let dummy = message.to_vec().ok()?;
    let (tbv, _) = signed_bitmessage_to_buf(prev_mac, &dummy, true).ok()?;
    let mac = if by_acceptor {
        gss_mic_acceptor(session_key, sequence, &tbv).ok()?
    } else {
        gss_mic(session_key, sequence, &tbv).ok()?
    };
    // Swap the placeholder for the real MAC; the bytes before the TSIG are
    // byte-identical, so the transmitted message reproduces the same digest.
    let _ = message.take_signature();
    message.add_tsig(make_tsig_record(key_name.clone(), placeholder.set_mac(mac)));
    message.to_vec().ok()
}

/// Sign a response, chaining the request MAC as the digest prefix (RFC 2845 §4.4).
/// The server is the GSS *acceptor*, so the response MIC uses the acceptor key
/// usage + `SentByAcceptor` flag, which MIT/Windows DNS clients verify.
pub fn sign_response(
    session_key: &[u8],
    key_name: &Name,
    response: Message,
    request_mac: &[u8],
    time: u64,
) -> Option<Vec<u8>> {
    sign_directional(
        session_key,
        key_name,
        response,
        Some(request_mac),
        time,
        1,
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType as HRecordType};
    use std::str::FromStr;

    fn request() -> (Vec<u8>, Vec<u8>, Name) {
        let key: Vec<u8> = (0u8..32).collect();
        let key_name = Name::from_str("1234.example.com.").unwrap();
        let mut msg = Message::new();
        msg.set_id(0x1234);
        msg.set_op_code(OpCode::Update);
        msg.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            HRecordType::SOA,
        ));
        // A client signs the request (no prior MAC, sequence 0).
        let signed = sign(&key, &key_name, msg, None, 1_700_000_000, 0).expect("sign");
        (key, signed, key_name)
    }

    #[test]
    fn gss_tsig_request_signs_and_verifies() {
        let (key, signed, key_name) = request();
        let v = verify_request(&key, &signed).expect("valid GSS-TSIG");
        assert_eq!(v.key_name, key_name);
        assert!(!v.request_mac.is_empty());
    }

    #[test]
    fn gss_tsig_rejects_a_wrong_key() {
        let (_key, signed, _name) = request();
        let other: Vec<u8> = (1u8..33).collect();
        assert!(verify_request(&other, &signed).is_none());
    }

    #[test]
    fn gss_tsig_rejects_a_tampered_message() {
        let (key, mut signed, _name) = request();
        // Flip a byte in the DNS header (the message ID) — the MIC must fail.
        signed[2] ^= 0xff;
        assert!(verify_request(&key, &signed).is_none());
    }

    #[test]
    fn response_signs_with_the_request_mac_chained() {
        let (key, signed, key_name) = request();
        let req_mac = verify_request(&key, &signed).unwrap().request_mac;
        let mut resp = Message::new();
        resp.set_id(0x1234);
        resp.set_op_code(OpCode::Update);
        let out = sign_response(&key, &key_name, resp, &req_mac, 1_700_000_000).expect("sign resp");
        // The response carries a GSS-TSIG record.
        let parsed = Message::from_vec(&out).unwrap();
        assert!(
            extract_tsig(&parsed).is_some(),
            "response is GSS-TSIG signed"
        );
        // And the acceptor-direction MIC authenticates it against the chained MAC.
        assert!(
            verify_response(&key, &req_mac, &out),
            "response GSS-TSIG (acceptor MIC) must verify"
        );
    }

    #[test]
    fn response_mic_is_acceptor_direction() {
        // A response signed by the server (acceptor) must NOT verify as an
        // initiator MIC: the SentByAcceptor flag + usage 23 make it directional.
        let (key, signed, key_name) = request();
        let req_mac = verify_request(&key, &signed).unwrap().request_mac;
        let mut resp = Message::new();
        resp.set_id(0x1234);
        resp.set_op_code(OpCode::Update);
        let out = sign_response(&key, &key_name, resp, &req_mac, 1_700_000_000).unwrap();
        let parsed = Message::from_vec(&out).unwrap();
        let (_n, tsig) = extract_tsig(&parsed).unwrap();
        // The MIC token's Flags byte (offset 2) has bit0 SentByAcceptor set.
        assert_eq!(
            tsig.mac()[2] & 0x01,
            0x01,
            "SentByAcceptor flag set on response"
        );
    }
}
