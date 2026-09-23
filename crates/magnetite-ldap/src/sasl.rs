//! GSS-SPNEGO SASL bind (RFC 4752 + RFC 4178 SPNEGO) for the embedded LDAP
//! server, so a domain-join client (Samba `net ads join`) can authenticate with a
//! Kerberos ticket for `ldap/<dc-fqdn>`.
//!
//! This mirrors the SMB server's Kerberos acceptor: extract the client AP-REQ from
//! the SPNEGO token, verify it against the LDAP service key, and return a
//! mutual-auth AP-REP wrapped in a SPNEGO `NegTokenResp`. The multi-leg SASL
//! exchange is driven by [`SaslState`]; the per-message security layer (RFC 4752
//! integrity/confidentiality wrapping of subsequent PDUs) is intentionally NOT
//! offered — we complete auth-only, so a client set to `client ldap sasl wrapping
//! = plain` proceeds without GSS-wrapping every PDU.

use crate::seclayer::{
    layer_message, selected_layer, LAYER_CONFIDENTIALITY, LAYER_INTEGRITY, MAX_WRAP_SIZE,
    OFFERED_LAYERS,
};
use magnetite_krb5::ap_req::build_ap_rep;
use magnetite_krb5::gss::{
    gss_unwrap_integrity, gss_wrap_integrity, KG_USAGE_ACCEPTOR_SEAL, KG_USAGE_INITIATOR_SEAL,
};
use magnetite_krb5::spnego::extract_ap_req;
use magnetite_krb5::verify_ap_req;
use magnetite_rpc::ntlmssp::{ldap_challenge_message, negotiate_flags, ntlm_username, NtlmContext};
use magnetite_rpc::NtHashLookup;

/// The KRB5 mechanism OID (1.2.840.113554.1.2.2) as a DER OBJECT IDENTIFIER.
const KRB5_OID: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
];
/// The GSS/KRB5 `KRB5_AP_REP` token id (RFC 4121 §4.1) preceding an AP-REP.
const AP_REP_TOK_ID: [u8; 2] = [0x02, 0x00];

/// The SPNEGO mechanism OID (1.3.6.1.5.5.2) as a DER OBJECT IDENTIFIER — its
/// presence in the client's first token distinguishes a GSS-SPNEGO bind from a
/// raw GSSAPI one, which changes how the AP-REP must be framed on the way back.
const SPNEGO_OID_DER: [u8; 8] = [0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

/// Per-connection GSS-SPNEGO SASL state, carried across the multi-leg bind.
#[derive(Default)]
pub(crate) struct SaslState {
    /// The authenticated client principal (`name@REALM`) → the bound DN.
    client: Option<String>,
    /// The GSS acceptor subkey, retained after the AP-REP to drive the RFC 4752
    /// security-layer negotiation and the per-PDU protection that follows.
    subkey: Option<Vec<u8>>,
    /// Whether the client framed its context token in SPNEGO (`GSS-SPNEGO` mech)
    /// vs raw GSSAPI (`GSSAPI` mech). The AP-REP reply must mirror this: a raw
    /// GSSAPI client (cyrus-sasl, MIT) expects the bare `02 00 ‖ AP-REP` token,
    /// not a SPNEGO `NegTokenResp`.
    spnego: bool,
    /// Whether this bind is running NTLM (a Windows join that couldn't get a
    /// Kerberos ticket sends GSS-SPNEGO carrying NTLMSSP instead of an AP-REQ).
    ntlm: bool,
    /// Multi-leg bind step.
    step: u8,
}

/// The per-message security layer a completed bind negotiated, if any. Kerberos
/// yields the acceptor subkey (+ whether the client selected sealing over signing);
/// NTLM yields the established SSP context (which carries the sign+seal keys).
// The NTLM variant carries the whole SSP context; boxing it to shrink the enum would
// add a heap allocation on every completed bind for a short-lived per-connection value.
#[allow(clippy::large_enum_variant)]
pub(crate) enum NegotiatedSecurity {
    Gss { subkey: Vec<u8>, confidential: bool },
    Ntlm(NtlmContext),
}

/// The result of one SASL bind leg.
// `Done` carries the (larger) negotiated NTLM security layer; see the note on
// `NegotiatedSecurity` — this is a short-lived per-bind value, not worth boxing.
#[allow(clippy::large_enum_variant)]
pub(crate) enum SaslOutcome {
    /// Reply `saslBindInProgress` with these `serverSaslCreds`.
    Continue(Vec<u8>),
    /// Bind complete: reply success. Carries the authenticated identity, the final
    /// `serverSaslCreds` (if any), and the negotiated security layer (RFC 4752) to
    /// apply to subsequent PDUs — `None` when the client chose no security layer.
    Done(String, Option<Vec<u8>>, Option<NegotiatedSecurity>),
    /// Bind failed with this diagnostic.
    Fail(String),
}

/// The NTLMSSP message type (1=NEGOTIATE, 2=CHALLENGE, 3=AUTHENTICATE) if `blob`
/// carries the `NTLMSSP\0` signature.
fn ntlmssp_message_type(blob: &[u8]) -> Option<u32> {
    let pos = blob.windows(8).position(|w| w == b"NTLMSSP\0")?;
    let t = blob.get(pos + 8..pos + 12)?;
    Some(u32::from_le_bytes([t[0], t[1], t[2], t[3]]))
}

/// The raw NTLMSSP message inside `blob` (from the `NTLMSSP\0` signature to the end).
fn extract_ntlmssp(blob: &[u8]) -> Option<&[u8]> {
    let pos = blob.windows(8).position(|w| w == b"NTLMSSP\0")?;
    Some(&blob[pos..])
}

/// Verify an NTLM AUTHENTICATE (type 3) against the directory NT hash and complete
/// the bind (auth only — no per-PDU security layer yet).
fn ntlm_authenticate(nt_hash_lookup: Option<&NtHashLookup>, cred: &[u8]) -> SaslOutcome {
    let Some(ntlm) = extract_ntlmssp(cred) else {
        return SaslOutcome::Fail("NTLM AUTHENTICATE missing NTLMSSP token".into());
    };
    let Some(lookup) = nt_hash_lookup else {
        return SaslOutcome::Fail("NTLM bind not configured (no NT-hash lookup)".into());
    };
    let user = ntlm_username(ntlm);
    let ctx = user
        .as_deref()
        .and_then(|u| lookup(u))
        .and_then(|h| NtlmContext::establish(&h, ntlm));
    match (user, ctx) {
        (Some(u), Some(ctx)) => {
            tracing::info!("LDAP NTLM bind OK for {u:?} (sign+seal layer on)");
            // The client negotiated SIGN|SEAL (its Type-3 echoes the CHALLENGE flags),
            // so every subsequent LDAP PDU is NTLM sign+sealed — retain the context.
            SaslOutcome::Done(u, None, Some(NegotiatedSecurity::Ntlm(ctx)))
        }
        (u, _) => SaslOutcome::Fail(format!("NTLM proof failed for {u:?}")),
    }
}

/// Handle one leg of a GSS-SPNEGO (or raw GSSAPI) SASL bind against `service_key`
/// (the `ldap/<dc-fqdn>` AES256 key). A GSS-SPNEGO bind that carries NTLMSSP (a
/// Windows join with no Kerberos ticket) is verified against `nt_hash_lookup`.
pub(crate) fn gss_spnego_step(
    st: &mut SaslState,
    service_key: &[u8],
    nt_hash_lookup: Option<&NtHashLookup>,
    cred: &[u8],
) -> SaslOutcome {
    // Once an NTLM bind is in progress, the next token is the AUTHENTICATE (type 3).
    if st.ntlm {
        return ntlm_authenticate(nt_hash_lookup, cred);
    }
    match st.step {
        0 if cred.is_empty() => {
            // The client sent the SASL mechanism with no initial response, asking the
            // server for the first challenge. GSS(-SPNEGO) is client-initiated, so we
            // reply with an EMPTY challenge (`saslBindInProgress`, no serverSaslCreds);
            // the client then sends its AP-REQ.
            st.step = 1;
            SaslOutcome::Continue(Vec::new())
        }
        0 | 1 => {
            // NTLM path: a Windows join that couldn't get a Kerberos ticket sends a
            // (raw) NTLMSSP NEGOTIATE (type 1). Reply with the NTLM CHALLENGE (type 2)
            // and expect the AUTHENTICATE next.
            if ntlmssp_message_type(cred) == Some(1) {
                st.ntlm = true;
                tracing::info!(
                    "LDAP SASL bind: NTLM NEGOTIATE (client flags {:#010x}) → sending CHALLENGE",
                    negotiate_flags(cred).unwrap_or(0)
                );
                return SaslOutcome::Continue(ldap_challenge_message());
            }
            // Otherwise the credentials carry a SPNEGO/raw GSS-KRB5 token wrapping the
            // client's AP-REQ. The framing dictates how the AP-REP is framed back.
            st.spnego = is_spnego_framed(cred);
            let Some(ap_req) = extract_ap_req(cred) else {
                return SaslOutcome::Fail("no AP-REQ in SASL/SPNEGO token".into());
            };
            let v = match verify_ap_req(service_key, ap_req) {
                Ok(v) => v,
                Err(e) => return SaslOutcome::Fail(format!("AP-REQ verify failed: {e}")),
            };
            let client = format!("{}@{}", v.client_name.join("/"), v.client_realm);
            // Retain the acceptor subkey (the GSS session key) — it drives the RFC
            // 4752 security-layer negotiation and per-PDU protection that follow.
            let (ap_rep, subkey) = match build_ap_rep(&v.session_key, v.ctime, v.cusec, 1) {
                Ok(pair) => pair,
                Err(e) => return SaslOutcome::Fail(format!("AP-REP build failed: {e}")),
            };
            st.client = Some(client);
            st.subkey = Some(subkey);
            st.step = 2;
            // Mirror the client's framing: a SPNEGO `NegTokenResp` (accept-completed)
            // for GSS-SPNEGO, or the bare `02 00 ‖ AP-REP` GSS token for raw GSSAPI
            // (RFC 4121 §4.1 — a subsequent context token carries no InitialContextToken
            // wrapper, so cyrus-sasl/MIT `GSSAPI` clients require the unwrapped form).
            let reply = if st.spnego {
                neg_token_resp_ap_rep(&ap_rep)
            } else {
                raw_gss_ap_rep(&ap_rep)
            };
            SaslOutcome::Continue(reply)
        }
        2 => {
            // The client acknowledged the AP-REP (its GSS context is complete). Send
            // the RFC 4752 security-layer offer: the supported layer bitmask + max
            // message size, integrity-`GSS_Wrap`ed under the acceptor subkey.
            let Some(subkey) = st.subkey.clone() else {
                return SaslOutcome::Fail("no GSS context for security-layer offer".into());
            };
            let offer = layer_message(OFFERED_LAYERS, MAX_WRAP_SIZE);
            match gss_wrap_integrity(&subkey, KG_USAGE_ACCEPTOR_SEAL, 0, &offer) {
                Ok(token) => {
                    st.step = 3;
                    SaslOutcome::Continue(token)
                }
                Err(e) => SaslOutcome::Fail(format!("security-layer offer failed: {e}")),
            }
        }
        _ => {
            // The client's RFC 4752 selection: its chosen layer bit + max size,
            // integrity-`GSS_Wrap`ed. Unwrap it, read the layer, and complete.
            let dn = st.client.clone().unwrap_or_default();
            let Some(subkey) = st.subkey.clone() else {
                return SaslOutcome::Done(dn, None, None);
            };
            let selection = gss_unwrap_integrity(&subkey, KG_USAGE_INITIATOR_SEAL, cred)
                .map(|(_, m)| m)
                .and_then(|m| selected_layer(&m));
            let security = match selection {
                Some(bits) if bits & LAYER_CONFIDENTIALITY != 0 => Some(NegotiatedSecurity::Gss {
                    subkey,
                    confidential: true,
                }),
                Some(bits) if bits & LAYER_INTEGRITY != 0 => Some(NegotiatedSecurity::Gss {
                    subkey,
                    confidential: false,
                }),
                // No security layer (or an unreadable selection): complete auth-only.
                _ => None,
            };
            SaslOutcome::Done(dn, None, security)
        }
    }
}

/// Whether the client's first SASL token is SPNEGO-framed (its DER carries the
/// SPNEGO mechanism OID) rather than a raw GSSAPI/KRB5 context token.
fn is_spnego_framed(cred: &[u8]) -> bool {
    cred.windows(SPNEGO_OID_DER.len())
        .any(|w| w == SPNEGO_OID_DER)
}

/// The bare Kerberos AP-REP GSS token for a raw `GSSAPI` SASL bind: the 2-octet
/// `KRB5_AP_REP` token id (`02 00`, RFC 4121 §4.1) followed by the AP-REP DER. A
/// subsequent context token gets no `[APPLICATION 0]`/OID wrapper, so this is what
/// cyrus-sasl and MIT GSSAPI clients expect from the acceptor.
fn raw_gss_ap_rep(ap_rep: &[u8]) -> Vec<u8> {
    let mut token = AP_REP_TOK_ID.to_vec();
    token.extend_from_slice(ap_rep);
    token
}

/// A SPNEGO `NegTokenResp` (accept-completed) carrying the mutual-auth AP-REP as a
/// full GSS-API context token — `[APPLICATION 0]` wrapping the KRB5 mech OID, the
/// `02 00` token id, then the AP-REP DER (the framing MIT/Heimdal require).
fn neg_token_resp_ap_rep(ap_rep: &[u8]) -> Vec<u8> {
    let neg_result = der(0xa0, &der(0x0a, &[0x00])); // [0] accept-completed(0)
    let supported_mech = der(0xa1, &KRB5_OID); // [1] supportedMech = KRB5

    let mut gss = KRB5_OID.to_vec();
    gss.extend_from_slice(&AP_REP_TOK_ID);
    gss.extend_from_slice(ap_rep);
    let mech_token = der(0x60, &gss); // [APPLICATION 0] GSS-API InitialContextToken
    let response_token = der(0xa2, &der(0x04, &mech_token)); // [2] responseToken

    let mut seq = neg_result;
    seq.extend_from_slice(&supported_mech);
    seq.extend_from_slice(&response_token);
    der(0xa1, &der(0x30, &seq)) // [1] NegTokenResp { SEQUENCE { … } }
}

/// A DER TLV: `tag ‖ length ‖ content` (short/long form length as needed).
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n < 0x100 {
        out.push(0x81);
        out.push(n as u8);
    } else {
        out.push(0x82);
        out.push((n >> 8) as u8);
        out.push((n & 0xff) as u8);
    }
    out.extend_from_slice(content);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spnego_framing_is_detected_from_the_oid() {
        // A NegTokenInit carries the SPNEGO OID; a raw GSSAPI token carries KRB5's.
        let spnego = der(0x60, &{
            let mut b = SPNEGO_OID_DER.to_vec();
            b.extend_from_slice(&der(0xa0, &[0x30, 0x00]));
            b
        });
        assert!(is_spnego_framed(&spnego));

        let mut raw = der(0x60, &{
            let mut b = KRB5_OID.to_vec();
            b.extend_from_slice(&[0x01, 0x00]); // AP-REQ token id
            b.extend_from_slice(&[0x6e, 0x00]); // (truncated) AP-REQ
            b
        });
        assert!(!is_spnego_framed(&raw));
        // A raw token must not accidentally match once we append arbitrary bytes.
        raw.extend_from_slice(&[0x2b, 0x06, 0x01]); // partial, not the full SPNEGO OID
        assert!(!is_spnego_framed(&raw));
    }

    #[test]
    fn raw_ap_rep_is_the_bare_krb5_token() {
        let ap_rep = [0x6f, 0x03, 0x30, 0x01, 0x0f]; // a stub AP-REP DER
        let token = raw_gss_ap_rep(&ap_rep);
        // 02 00 (KRB5_AP_REP token id) ‖ AP-REP — no [APPLICATION 0]/OID wrapper.
        assert_eq!(token[0..2], [0x02, 0x00]);
        assert_eq!(&token[2..], &ap_rep);
        // And it is NOT SPNEGO-framed (so a client that sent raw gets raw back).
        assert!(!is_spnego_framed(&token));
    }
}
