//! A tokio codec wrapping `ldap3_proto`'s, adding **decode** support for SASL
//! `BindRequest`s.
//!
//! `ldap3_proto` 0.5.2 *encodes* SASL binds but its decoder only builds the simple
//! (`id 0`) authentication choice — a SASL bind (`id 3`) fails `LdapMsg::try_from`,
//! so a Kerberos-authenticating client (Samba `net ads join`, GSS-SPNEGO) would
//! drop the connection at the bind. The BER itself parses fine (only the
//! `Tag → LdapMsg` conversion rejects SASL), so we mirror `LdapCodec::decode` and,
//! when the conversion fails, hand-build the `LdapMsg` from the parsed BER tree.

use crate::seclayer::SecurityLayer;
use bytes::{Buf, BytesMut};
use lber::common::TagClass;
use lber::parse::Parser;
use lber::structure::{StructureTag, PL};
use ldap3_proto::proto::{LdapBindCred, LdapBindRequest, LdapMsg, LdapOp, SaslCredentials};
use ldap3_proto::LdapCodec;
use std::io;
use tokio_util::codec::{Decoder, Encoder};

/// Maximum bytes buffered for a single inbound LDAP PDU. Bounds the memory a client
/// can force the decoder to accumulate by announcing a huge frame/BER length. Real
/// requests (even a large add/modify) are well under this; 16 MiB is generous.
const MAX_LDAP_FRAME: usize = 16 * 1024 * 1024;

/// Maximum BER/DER nesting depth accepted in an inbound LDAP PDU. A real message
/// nests only a handful deep (envelope → protocolOp → filter → nested filter → …);
/// a pathologically nested filter (thousands of `and`/`or`/`not`) would otherwise
/// drive the recursive `lber` parser — and our own recursive filter matcher — into a
/// stack overflow before any request is served. Over-deep input is rejected *before*
/// parsing. 100 is far above any legitimate message yet well below a dangerous depth.
const MAX_BER_DEPTH: usize = 100;

/// The LDAP codec with SASL-bind decode support and an optional RFC 4752 GSS
/// security layer. Encoding delegates to [`LdapCodec`]; once a security layer is
/// active (after a GSS-SPNEGO bind negotiated one), every PDU on the wire is
/// `length(4) ‖ GSS_Wrap token`.
#[derive(Default)]
pub(crate) struct SaslAwareCodec {
    inner: LdapCodec,
    /// The negotiated GSS security layer; `None` until a bind establishes one.
    layer: Option<SecurityLayer>,
}

impl SaslAwareCodec {
    /// Turn on per-PDU GSS protection for the rest of the connection. Called after
    /// the bind's success response has been sent in the clear.
    pub(crate) fn activate_security_layer(&mut self, layer: SecurityLayer) {
        self.layer = Some(layer);
    }

    /// Parse exactly one LDAP message from a complete PDU byte slice (used for the
    /// unwrapped payload of a GSS-protected frame).
    fn parse_pdu(bytes: &[u8]) -> Result<LdapMsg, io::Error> {
        if !ber_depth_within(bytes, MAX_BER_DEPTH) {
            return Err(io::Error::other("ldap PDU nesting too deep"));
        }
        let mut parser = Parser::new();
        let (_, tag) = parser
            .parse(bytes)
            .map_err(|_| io::Error::other("lber parse"))?;
        match LdapMsg::try_from(tag.clone()) {
            Ok(msg) => Ok(msg),
            Err(_) => sasl_bind_from_tag(tag).ok_or_else(|| io::Error::other("ldap decode")),
        }
    }
}

impl Decoder for SaslAwareCodec {
    type Item = LdapMsg;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<LdapMsg>, io::Error> {
        // With a security layer, each PDU is `length(4) ‖ protected token`.
        if let Some(layer) = self.layer.as_mut() {
            if buf.len() < 4 {
                return Ok(None);
            }
            let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            if len > MAX_LDAP_FRAME {
                return Err(io::Error::other("ldap frame too large"));
            }
            if buf.len() < 4 + len {
                return Ok(None);
            }
            let token = buf[4..4 + len].to_vec();
            buf.advance(4 + len);
            let Some(pdu) = layer.open(&token) else {
                tracing::warn!(
                    "LDAP SASL layer unwrap failed ({} B token): {}",
                    token.len(),
                    token
                        .iter()
                        .take(64)
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                );
                return Err(io::Error::other("sasl layer unwrap"));
            };
            return Self::parse_pdu(&pdu).map(Some);
        }

        // Reject a pathologically nested PDU before the recursive BER parser (and
        // the recursive filter matcher downstream) can overflow the stack. The scan
        // is iterative and conservative: it rejects only a definitely-too-deep
        // constructed nesting, and defers a truncated/partial buffer to the parser
        // (which returns Incomplete, bounded by MAX_LDAP_FRAME above).
        if !ber_depth_within(&buf[..], MAX_BER_DEPTH) {
            return Err(io::Error::other("ldap PDU nesting too deep"));
        }

        // Parse one BER element (mirrors LdapCodec::decode).
        let mut parser = Parser::new();
        let (rem, tag) = match parser.parse(buf) {
            Ok(r) => r,
            Err(nom::Err::Incomplete(_)) => {
                // Bound how much an announced-but-unfinished BER element can buffer.
                if buf.len() > MAX_LDAP_FRAME {
                    return Err(io::Error::other("ldap frame too large"));
                }
                return Ok(None);
            }
            Err(_) => return Err(io::Error::other("lber parse")),
        };
        let size = buf.len() - rem.len();
        if size == buf.len() {
            buf.clear();
        } else {
            buf.advance(size);
        }

        // ldap3_proto builds every op except a SASL bind; fall back to our own
        // extraction only when it can't (so behaviour is otherwise identical).
        match LdapMsg::try_from(tag.clone()) {
            Ok(msg) => Ok(Some(msg)),
            Err(_) => sasl_bind_from_tag(tag)
                .map(Some)
                .ok_or_else(|| io::Error::other("ldap decode")),
        }
    }
}

impl Encoder<LdapMsg> for SaslAwareCodec {
    type Error = io::Error;

    fn encode(&mut self, item: LdapMsg, dst: &mut BytesMut) -> Result<(), io::Error> {
        // Split the borrow so the inner codec and the security layer can both be
        // used mutably (distinct fields).
        let Self { inner, layer } = self;
        let Some(layer) = layer else {
            // `ldap3_proto` 0.5.2 mis-encodes `BindResponse.serverSaslCreds` as a
            // universal OCTET STRING (tag 0x04) rather than the `[7]` context tag
            // (0x87) RFC 4511 §4.2.2 mandates, so a strict client (real Windows) can't
            // find the SASL challenge and abandons the bind. Patch the tag in place —
            // the byte value changes, the length does not.
            let sasl_len = sasl_creds_len(&item);
            let start = dst.len();
            inner.encode(item, dst)?;
            if let Some(n) = sasl_len {
                fix_sasl_creds_tag(&mut dst[start..], n);
            }
            return Ok(());
        };
        let mut plain = BytesMut::new();
        inner.encode(item, &mut plain)?;
        let token = layer
            .seal(&plain)
            .ok_or_else(|| io::Error::other("gss wrap"))?;
        dst.extend_from_slice(&(token.len() as u32).to_be_bytes());
        dst.extend_from_slice(&token);
        Ok(())
    }
}

/// `LdapCodec` with the same inbound BER nesting-depth guard the server applies, for the
/// replication **pull** side. A syncrepl / AD-DirSync / AD-USN consumer decodes responses
/// from an upstream peer with `ldap3_proto`'s codec, whose recursive `lber` parser has no
/// depth bound — so a hostile or compromised upstream could send a pathologically nested
/// BER response and overflow the consumer's stack (the mirror of the server-side crasher
/// already guarded here). This checks depth before delegating; encoding is unchanged.
///
/// An indefinite-length ([`0x80`]) length octet — never valid in LDAP's DER — is treated
/// permissively by [`ber_depth_within`] and left to the `lber` parser, which rejects it
/// as malformed rather than recursing, so it cannot slip past into a crash.
#[derive(Default)]
pub(crate) struct GuardedLdapCodec {
    inner: LdapCodec,
}

impl Decoder for GuardedLdapCodec {
    type Item = LdapMsg;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<LdapMsg>, io::Error> {
        // Bound nesting before the recursive parser sees the buffer; a truncated PDU is
        // deferred (returns Ok(None) from the inner codec) just as on the server side.
        if !ber_depth_within(&buf[..], MAX_BER_DEPTH) {
            return Err(io::Error::other("ldap response nesting too deep"));
        }
        self.inner.decode(buf)
    }
}

impl Encoder<LdapMsg> for GuardedLdapCodec {
    type Error = io::Error;

    fn encode(&mut self, item: LdapMsg, dst: &mut BytesMut) -> Result<(), io::Error> {
        self.inner.encode(item, dst)
    }
}

/// The length of a `BindResponse`'s `serverSaslCreds`, if the message is a bind
/// response carrying one — used to locate the mis-tagged octet string to patch.
fn sasl_creds_len(item: &LdapMsg) -> Option<usize> {
    match &item.op {
        LdapOp::BindResponse(r) => r.saslcreds.as_ref().map(Vec::len),
        _ => None,
    }
}

/// Rewrite the tag of the trailing `serverSaslCreds` octet string in an encoded
/// `BindResponse` from universal OCTET STRING (0x04) to `[7]` context (0x87). The
/// creds are the last element, so its `tag ‖ length ‖ content` sits at the buffer's
/// end; the tag byte precedes the length header (1 byte) and the content.
fn fix_sasl_creds_tag(encoded: &mut [u8], creds_len: usize) {
    // BER length-of-length: 1 octet short-form (<128), else 0x8n + n octets.
    let header = if creds_len < 0x80 {
        1
    } else if creds_len < 0x100 {
        2
    } else {
        3
    };
    // Element = tag(1) ‖ length header ‖ content, ending the buffer.
    let Some(tag_pos) = encoded.len().checked_sub(creds_len + header + 1) else {
        return;
    };
    if encoded[tag_pos] == 0x04 {
        encoded[tag_pos] = 0x87; // [7] context-primitive: serverSaslCreds
    }
}

/// Iteratively verify that the BER TLV nesting in `bytes` does not exceed `max`
/// levels, WITHOUT recursing (so the guard itself cannot overflow the stack).
///
/// Returns `false` only when a constructed element is nested strictly deeper than
/// `max`; a truncated or malformed header returns `true` and defers to the real
/// parser (which reports Incomplete / a parse error). Definite-length only — an
/// indefinite length (never emitted for LDAP DER) is treated permissively (`true`).
///
/// The scan tracks, in a stack, the bytes still owed by each open constructed
/// element; a level whose content is exhausted is popped, so sibling elements don't
/// accumulate depth. For well-formed input — the shape a hostile client crafts to
/// trigger the overflow — the depth is exact; for malformed input the parser rejects
/// it regardless, so the guard need only be sound for the well-formed case.
fn ber_depth_within(bytes: &[u8], max: usize) -> bool {
    // Remaining content bytes for each currently-open constructed element.
    let mut stack: Vec<usize> = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        // Close any levels whose content has been fully consumed.
        while stack.last().copied() == Some(0) {
            stack.pop();
        }
        let start = i;

        // Identifier octet(s): low 5 bits all set ⇒ high-tag-number form follows.
        let id = bytes[i];
        i += 1;
        let constructed = id & 0x20 != 0;
        if id & 0x1f == 0x1f {
            loop {
                let Some(&b) = bytes.get(i) else { return true }; // truncated
                i += 1;
                if b & 0x80 == 0 {
                    break;
                }
            }
        }

        // Length octet(s): short form (<128) or long form (0x8n + n length octets).
        let Some(&l0) = bytes.get(i) else { return true };
        i += 1;
        let content_len = if l0 & 0x80 == 0 {
            l0 as usize
        } else {
            let n = (l0 & 0x7f) as usize;
            if n == 0 || n > 4 || i + n > bytes.len() {
                return true; // indefinite / oversized / truncated length — defer
            }
            let mut v = 0usize;
            for _ in 0..n {
                v = (v << 8) | bytes[i] as usize;
                i += 1;
            }
            v
        };

        // Charge this whole element (header + content) against its parent's budget.
        let element_len = (i - start).saturating_add(content_len);
        if let Some(rem) = stack.last_mut() {
            *rem = rem.saturating_sub(element_len);
        }

        if constructed {
            if stack.len() + 1 > max {
                return false; // nested too deep
            }
            stack.push(content_len); // descend into the content
        } else {
            i = i.saturating_add(content_len); // skip primitive content
        }
    }
    true
}

/// Build an `LdapMsg` for a SASL `BindRequest` from the parsed BER tree, or `None`
/// if it is not one (in which case the original decode error stands).
///
/// `LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp CHOICE {…}, … }`,
/// where `bindRequest [APPLICATION 0] SEQUENCE { version, name, authentication }`
/// and `authentication` for SASL is `[3] SaslCredentials { mechanism, credentials
/// OPTIONAL }`.
fn sasl_bind_from_tag(tag: StructureTag) -> Option<LdapMsg> {
    let PL::C(seq) = tag.payload else { return None };
    let mut seq = seq.into_iter();
    let msgid = ber_i32(&primitive(seq.next()?)?)?;
    let op = seq.next()?;

    // protocolOp = bindRequest [APPLICATION 0].
    if op.class != TagClass::Application || op.id != 0 {
        return None;
    }
    let PL::C(bind) = op.payload else { return None };
    let mut bind = bind.into_iter();
    let _version = bind.next()?; // version INTEGER (3)
    let dn = String::from_utf8(primitive(bind.next()?)?).ok()?;
    let auth = bind.next()?;

    // authentication = SASL [3] { mechanism, credentials OPTIONAL }.
    if auth.class != TagClass::Context || auth.id != 3 {
        return None;
    }
    let PL::C(sasl) = auth.payload else {
        return None;
    };
    let mut sasl = sasl.into_iter();
    let mechanism = String::from_utf8(primitive(sasl.next()?)?).ok()?;
    let credentials = sasl.next().and_then(primitive).unwrap_or_default();

    Some(LdapMsg {
        msgid,
        op: LdapOp::BindRequest(LdapBindRequest {
            dn,
            cred: LdapBindCred::SASL(SaslCredentials {
                mechanism,
                credentials,
            }),
        }),
        ctrl: vec![],
    })
}

/// The primitive byte payload of a tag, or `None` if it is constructed.
fn primitive(tag: StructureTag) -> Option<Vec<u8>> {
    match tag.payload {
        PL::P(bytes) => Some(bytes),
        PL::C(_) => None,
    }
}

/// Decode a BER INTEGER (big-endian, two's complement) into an `i32` message id.
fn ber_i32(bytes: &[u8]) -> Option<i32> {
    if bytes.is_empty() || bytes.len() > 4 {
        return None;
    }
    let mut v: i64 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in bytes {
        v = (v << 8) | i64::from(b);
    }
    Some(v as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Wrap `inner` in one constructed SEQUENCE (`0x30`) with a definite length.
    fn wrap_seq(inner: Vec<u8>) -> Vec<u8> {
        let len = inner.len();
        let mut out = vec![0x30u8];
        if len < 0x80 {
            out.push(len as u8);
        } else if len < 0x100 {
            out.push(0x81);
            out.push(len as u8);
        } else {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push((len & 0xff) as u8);
        }
        out.extend_from_slice(&inner);
        out
    }

    /// A BER blob nested `depth` constructed SEQUENCEs deep around a NULL leaf.
    fn nested(depth: usize) -> Vec<u8> {
        let mut buf = vec![0x05u8, 0x00]; // NULL
        for _ in 0..depth {
            buf = wrap_seq(buf);
        }
        buf
    }

    #[test]
    fn ber_depth_guard_accepts_shallow_and_rejects_deep() {
        // A handful deep — like any real message — passes.
        assert!(ber_depth_within(&nested(5), MAX_BER_DEPTH));
        assert!(ber_depth_within(&nested(MAX_BER_DEPTH), MAX_BER_DEPTH));
        // One past the limit, and a pathological nesting, are rejected.
        assert!(!ber_depth_within(&nested(MAX_BER_DEPTH + 1), MAX_BER_DEPTH));
        assert!(!ber_depth_within(&nested(5000), MAX_BER_DEPTH));
    }

    #[test]
    fn ber_depth_guard_defers_on_partial_and_flat_input() {
        // Sibling elements at the same level don't accumulate depth.
        let flat = wrap_seq([nested(2), nested(2), nested(2)].concat());
        assert!(ber_depth_within(&flat, MAX_BER_DEPTH));
        // A truncated header (deep nesting cut short mid-stream) is deferred to the
        // parser rather than falsely rejected — until the received prefix itself
        // already exceeds the depth limit.
        let deep = nested(5000);
        assert!(ber_depth_within(&deep[..8], MAX_BER_DEPTH)); // only ~2 levels seen
        assert!(!ber_depth_within(&deep[..500], MAX_BER_DEPTH)); // prefix already >100 levels
                                                                 // Empty input is trivially within any limit.
        assert!(ber_depth_within(&[], MAX_BER_DEPTH));
    }

    #[test]
    fn guarded_codec_rejects_deeply_nested_response() {
        // A hostile upstream's pathologically nested response would overflow the inner
        // recursive parser; the pull-side guard rejects it as an error instead.
        let mut codec = GuardedLdapCodec::default();
        let mut buf = BytesMut::from(&nested(5000)[..]);
        let err = codec.decode(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        // A shallow, in-limit nesting is NOT rejected by the depth guard — it is handed
        // to the inner codec. An incomplete shallow PDU is deferred there (Ok(None)),
        // which proves the guard let it through (a complete nested(3) is not a valid
        // LDAPMessage, so the inner codec would legitimately error on that — a different
        // outcome from the guard's rejection).
        let mut shallow = BytesMut::from(&nested(3)[..4]); // two SEQ levels, body truncated
        assert!(matches!(codec.decode(&mut shallow), Ok(None)));
    }

    #[test]
    fn guarded_codec_indefinite_length_does_not_bypass_into_a_panic() {
        // Indefinite-length (0x80) is illegal in LDAP's DER. The depth scan treats it
        // permissively, so the inner `lber` parser must handle it (reject/defer) without
        // panicking or hanging — the guard-bypass class.
        let mut codec = GuardedLdapCodec::default();
        let mut buf = BytesMut::from(&[0x30u8, 0x80, 0x05, 0x00, 0x00, 0x00][..]);
        let _ = codec.decode(&mut buf); // returns Ok/Err, never panics
    }

    #[test]
    fn decodes_real_samba_sasl_bind_mechanism_only() {
        // The exact first SASL BindRequest a Samba `net ads join` sends: msgid 3,
        // BindRequest{ version 3, name "", authentication [3]{ "GSS-SPNEGO" } } — no
        // initial credentials. ldap3_proto's own decoder rejects this (id 3), so it
        // is the codec's fallback path that must build it.
        let frame = hex("301802010360130201030400a30c040a4753532d53504e45474f");
        let mut codec = SaslAwareCodec::default();
        let mut buf = BytesMut::from(&frame[..]);
        let msg = codec.decode(&mut buf).unwrap().expect("decoded a message");
        assert_eq!(msg.msgid, 3);
        let LdapOp::BindRequest(bind) = msg.op else {
            panic!("not a bind: {:?}", msg.op)
        };
        assert_eq!(bind.dn, "");
        let LdapBindCred::SASL(creds) = bind.cred else {
            panic!("not SASL")
        };
        assert_eq!(creds.mechanism, "GSS-SPNEGO");
        assert!(creds.credentials.is_empty());
        assert!(buf.is_empty(), "the whole frame was consumed");
    }

    /// A BER element `tag ‖ len ‖ content` (short-form length; test data is small).
    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut v = vec![tag, content.len() as u8];
        v.extend_from_slice(content);
        v
    }

    #[test]
    fn decodes_sasl_bind_with_credentials_token() {
        // A SASL bind carrying an initial-response token: authentication [3]{
        // mechanism="GSSAPI", credentials=0x0102030405 }. The token must survive.
        let mut sasl = tlv(0x04, b"GSSAPI"); // mechanism
        sasl.extend_from_slice(&tlv(0x04, &[1, 2, 3, 4, 5])); // credentials
        let mut bind = vec![0x02, 0x01, 0x03]; // version 3
        bind.extend_from_slice(&tlv(0x04, b"")); // name ""
        bind.extend_from_slice(&tlv(0xa3, &sasl)); // authentication [3] SASL
        let mut body = vec![0x02, 0x01, 0x07]; // msgid 7
        body.extend_from_slice(&tlv(0x60, &bind)); // [APPLICATION 0] BindRequest
        let frame = tlv(0x30, &body); // LDAPMessage SEQUENCE

        let mut codec = SaslAwareCodec::default();
        let mut buf = BytesMut::from(&frame[..]);
        let msg = codec.decode(&mut buf).unwrap().expect("decoded a message");
        assert_eq!(msg.msgid, 7);
        let LdapOp::BindRequest(bind) = msg.op else {
            panic!("not a bind")
        };
        let LdapBindCred::SASL(creds) = bind.cred else {
            panic!("not SASL")
        };
        assert_eq!(creds.mechanism, "GSSAPI");
        assert_eq!(creds.credentials, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn gss_security_layer_unwraps_and_frames_pdus() {
        use crate::seclayer::{GssSecurityLayer, SecurityLayer};
        use magnetite_krb5::gss::{
            gss_seal_token, gss_unseal_token, KG_USAGE_ACCEPTOR_SEAL, KG_USAGE_INITIATOR_SEAL,
        };

        let subkey: Vec<u8> = (0u8..32).collect();
        let mut codec = SaslAwareCodec::default();
        codec.activate_security_layer(SecurityLayer::Gss(GssSecurityLayer::new(
            subkey.clone(),
            true,
            1,
        )));

        // A client seals an UnbindRequest (raw BER: SEQ{ msgid 4, [APPLICATION 2] })
        // with the initiator usage and length-prefixes it — the on-wire form.
        let pdu = [0x30, 0x05, 0x02, 0x01, 0x04, 0x42, 0x00];
        let token = gss_seal_token(&subkey, KG_USAGE_INITIATOR_SEAL, 0, &pdu).unwrap();
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&(token.len() as u32).to_be_bytes());
        buf.extend_from_slice(&token);

        let msg = codec
            .decode(&mut buf)
            .unwrap()
            .expect("decoded a wrapped PDU");
        assert_eq!(msg.msgid, 4);
        assert!(matches!(msg.op, LdapOp::UnbindRequest));
        assert!(buf.is_empty(), "the whole frame was consumed");

        // A partial frame (length header only) yields no message yet.
        let mut partial = BytesMut::from(&[0, 0, 0, 8][..]);
        assert!(codec.decode(&mut partial).unwrap().is_none());

        // The server's response is length-prefixed and acceptor-sealed, and unseals
        // back to a re-decodable PDU.
        let mut out = BytesMut::new();
        codec
            .encode(
                LdapMsg {
                    msgid: 4,
                    op: LdapOp::UnbindRequest,
                    ctrl: vec![],
                },
                &mut out,
            )
            .unwrap();
        assert!(out.len() > 4, "a length-prefixed sealed frame");
        let n = u32::from_be_bytes([out[0], out[1], out[2], out[3]]) as usize;
        assert_eq!(out.len(), 4 + n, "length prefix matches the token");
        let opened = gss_unseal_token(&subkey, KG_USAGE_ACCEPTOR_SEAL, &out[4..]);
        assert!(opened.is_some(), "response must be acceptor-sealed");
    }

    #[test]
    fn sasl_creds_are_tagged_context_7_not_universal_octet_string() {
        use ldap3_proto::proto::{LdapBindResponse, LdapResult, LdapResultCode};

        // A saslBindInProgress carrying a ≥128-byte server challenge (2-byte BER
        // length header) must go on the wire tagged [7] (0x87), per RFC 4511 §4.2.2.
        let creds: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
        let msg = LdapMsg {
            msgid: 2,
            op: LdapOp::BindResponse(LdapBindResponse {
                res: LdapResult {
                    code: LdapResultCode::SaslBindInProgress,
                    matcheddn: String::new(),
                    message: String::new(),
                    referral: Vec::new(),
                },
                saslcreds: Some(creds.clone()),
            }),
            ctrl: vec![],
        };
        let mut codec = SaslAwareCodec::default();
        let mut out = BytesMut::new();
        codec.encode(msg, &mut out).unwrap();

        // The creds end the buffer, preceded by a 0x81 0xC8 length header and the tag
        // byte — which must be [7] (0x87), never the mis-encoded universal 0x04.
        let tag_pos = out.len() - creds.len() - 3; // 1 tag + 2 length-header octets
        assert_eq!(
            out[tag_pos], 0x87,
            "serverSaslCreds must be [7] context-tagged"
        );
        assert_eq!(out[tag_pos + 1], 0x81);
        assert_eq!(out[tag_pos + 2], 0xC8); // length = 200
        assert_eq!(&out[tag_pos + 3..], &creds[..]);
    }

    #[test]
    fn simple_bind_still_decodes_via_ldap3_proto() {
        // A simple bind (authentication [0] "pw") must still take the ldap3_proto
        // path unchanged: BindRequest{ version 3, name "uid", [0] "pw" }.
        let mut inner = vec![0x02, 0x01, 0x03]; // version 3
        inner.extend_from_slice(&[0x04, 0x03]); // name "uid"
        inner.extend_from_slice(b"uid");
        inner.extend_from_slice(&[0x80, 0x02]); // [0] simple "pw"
        inner.extend_from_slice(b"pw");
        let mut op = vec![0x60, inner.len() as u8];
        op.extend_from_slice(&inner);
        let mut body = vec![0x02, 0x01, 0x01]; // msgid 1
        body.extend_from_slice(&op);
        let mut frame = vec![0x30, body.len() as u8];
        frame.extend_from_slice(&body);

        let mut codec = SaslAwareCodec::default();
        let mut buf = BytesMut::from(&frame[..]);
        let msg = codec.decode(&mut buf).unwrap().expect("decoded");
        let LdapOp::BindRequest(bind) = msg.op else {
            panic!("not a bind")
        };
        assert!(matches!(bind.cred, LdapBindCred::Simple(ref p) if p == "pw"));
    }
}
