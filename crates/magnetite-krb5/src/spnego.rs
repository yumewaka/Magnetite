//! Minimal SPNEGO (RFC 4178) framing for Kerberos GSS tokens on a DCE/RPC bind.
//!
//! A Kerberos-authenticated RPC client sends its AP-REQ inside a SPNEGO
//! `NegTokenInit` in the BIND auth token; the server replies with the AP-REP
//! inside a `NegTokenResp` in the BIND_ACK. This module extracts the AP-REQ and
//! builds the response — just enough hand-rolled DER for the KRB5 mechanism,
//! matched byte-for-byte against impacket's `spnego` structures.

/// The KRB5 mechanism OID (1.2.840.113554.1.2.2) as a DER OBJECT IDENTIFIER.
const KRB5_OID_DER: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
];

/// The GSS/KRB5 token id preceding an AP-REQ (`KRB5_AP_REQ`).
const AP_REQ_MARKER: [u8; 3] = [0x01, 0x00, 0x6e];

/// Extract the AP-REQ DER from a SPNEGO `NegTokenInit` (or a raw GSS-KRB5) bind
/// token. Two framings occur in the wild:
///
/// * impacket / our own client wrap the AP-REQ in a GSS-KRB5 mechToken, so the
///   AP-REQ (`[APPLICATION 14]`, tag `0x6e`) follows the KRB5 GSS token id `0x0001`
///   — we scan for `01 00 6e`.
/// * **Samba** places the *raw* AP-REQ directly in the SPNEGO mechToken OCTET
///   string (`04 82 LL LL 6e 82 …`), with no inner `01 00` GSS token id — so we
///   also fall back to the first bare `6e 8x` (long-form-length) AP-REQ tag.
pub fn extract_ap_req(blob: &[u8]) -> Option<&[u8]> {
    for i in 0..blob.len().saturating_sub(AP_REQ_MARKER.len()) {
        if blob[i..i + 3] == AP_REQ_MARKER {
            let ap_req = &blob[i + 2..];
            return ap_req.get(..der_total_len(ap_req)?);
        }
    }
    // Fallback: a bare AP-REQ (Samba's SPNEGO mechToken). Take the first
    // `[APPLICATION 14]` with a long-form length whose DER element is well-formed.
    for i in 0..blob.len().saturating_sub(2) {
        if blob[i] == 0x6e && (0x81..=0x84).contains(&blob[i + 1]) {
            let ap_req = &blob[i..];
            if let Some(len) = der_total_len(ap_req) {
                if len <= ap_req.len() {
                    return ap_req.get(..len);
                }
            }
        }
    }
    None
}

/// The SPNEGO mechanism OID (1.3.6.1.5.5.2) as a DER OBJECT IDENTIFIER.
const SPNEGO_OID_DER: [u8; 8] = [0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

/// Wrap an AP-REQ DER in a **SPNEGO `NegTokenInit`** for an `RPC_C_AUTHN_GSS_NEGOTIATE`
/// BIND auth token: `[APPLICATION 0] { SPNEGO OID, NegTokenInit { mechTypes=[KRB5],
/// mechToken = <GSS-KRB5 AP-REQ token> } }`. Samba's RPC layer parses the SPNEGO
/// wrapper (a bare GSS-KRB5 token is rejected with an empty BIND_ACK); our own
/// server's [`extract_ap_req`] still finds the `01 00 6e` AP-REQ marker inside the
/// mechToken, so both accept it. Client counterpart of [`wrap_ap_rep`].
pub fn wrap_ap_req(ap_req: &[u8]) -> Vec<u8> {
    // The KRB5 GSS mechToken: [APPLICATION 0] { KRB5 OID, 01 00, AP-REQ }.
    let mut gss = KRB5_OID_DER.to_vec();
    gss.extend_from_slice(&[0x01, 0x00]);
    gss.extend_from_slice(ap_req);
    let mech_token = der(0x60, &gss);

    // NegTokenInit { mechTypes [0] SEQUENCE OF OID { KRB5 }, mechToken [2] OCTET STRING }.
    let mut nti = der(0xa0, &der(0x30, &KRB5_OID_DER)); // [0] mechTypes
    nti.extend_from_slice(&der(0xa2, &der(0x04, &mech_token))); // [2] mechToken
    let neg_token_init = der(0xa0, &der(0x30, &nti)); // [0] NegTokenInit

    // GSSAPI InitialContextToken: [APPLICATION 0] { SPNEGO OID, NegTokenInit }.
    let mut inner = SPNEGO_OID_DER.to_vec();
    inner.extend_from_slice(&neg_token_init);
    der(0x60, &inner)
}

/// The MS-KRB5 mech OID (1.2.840.48018.1.2.2), DER — Samba/Windows' preferred Kerberos
/// mechanism, listed first in a real client's SPNEGO negotiation.
const MS_KRB5_OID_DER: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02,
];

/// Wrap an AP-REQ in a SPNEGO `NegTokenInit` advertising **[MS-KRB5, KRB5]** with the
/// AP-REQ as the optimistic mechToken — the framing a real Windows / Samba client uses
/// for a **GSS-SPNEGO LDAP SASL bind**. With this two-mech list (and a non-DCE AP-REQ,
/// see [`crate::build_gss_ap_req_from_ticket`]) the acceptor completes the context in
/// ONE round (`accept-completed`), so no mechListMIC or security-layer round is needed.
/// [`wrap_ap_req`] advertises a single mech and is used for the DCE/RPC (DRSUAPI) path.
pub fn wrap_ap_req_spnego_ldap(ap_req: &[u8]) -> Vec<u8> {
    // The KRB5 GSS mechToken: [APPLICATION 0] { KRB5 OID, 01 00, AP-REQ }.
    let mut gss = KRB5_OID_DER.to_vec();
    gss.extend_from_slice(&[0x01, 0x00]);
    gss.extend_from_slice(ap_req);
    let mech_token = der(0x60, &gss);

    let mut mech_types = MS_KRB5_OID_DER.to_vec();
    mech_types.extend_from_slice(&KRB5_OID_DER);
    let mut nti = der(0xa0, &der(0x30, &mech_types)); // [0] mechTypes { MS-KRB5, KRB5 }
    nti.extend_from_slice(&der(0xa2, &der(0x04, &mech_token))); // [2] mechToken
    let neg_token_init = der(0xa0, &der(0x30, &nti)); // [0] NegTokenInit

    let mut inner = SPNEGO_OID_DER.to_vec();
    inner.extend_from_slice(&neg_token_init);
    der(0x60, &inner)
}

/// The bare GSS-KRB5 AP-REQ token (no SPNEGO wrapper): `[APPLICATION 0] { KRB5 OID,
/// 01 00, AP-REQ }`. Used with DCE/RPC auth type `RPC_C_AUTHN_GSS_KERBEROS` (16),
/// the framing Samba's own DRSUAPI client presents (as opposed to the SPNEGO
/// [`wrap_ap_req`] under auth type `RPC_C_AUTHN_GSS_NEGOTIATE`).
pub fn wrap_ap_req_raw(ap_req: &[u8]) -> Vec<u8> {
    let mut gss = KRB5_OID_DER.to_vec();
    gss.extend_from_slice(&[0x01, 0x00]);
    gss.extend_from_slice(ap_req);
    der(0x60, &gss)
}

/// Extract the AP-REP DER from a BIND_ACK auth token: the AP-REP is an
/// `[APPLICATION 15]` element (tag `0x6f`). In our [`wrap_ap_rep`] framing it is the
/// `responseToken` OCTET STRING's content (the tail DER element); a GSS-framed
/// reply carries it behind an `01 00` token id. Either way, locate the `0x6f`
/// element whose DER length reaches the end of the blob.
pub fn extract_ap_rep(blob: &[u8]) -> Option<&[u8]> {
    for i in 0..blob.len() {
        if blob[i] == 0x6f {
            if let Some(n) = der_total_len(&blob[i..]) {
                if i + n == blob.len() || blob.get(i - 1) == Some(&0x04) {
                    return blob.get(i..i + n);
                }
            }
        }
    }
    None
}

/// The first `mechType` OID (as a full `06 LL …` DER element) a client offered in a
/// SPNEGO `NegTokenInit` — its most-preferred mechanism. The acceptor must confirm
/// *this* OID in its `NegTokenResp.supportedMech`; advertising a different (even
/// equivalent) Kerberos OID makes a strict client (Samba) reject the token and
/// re-negotiate. Returns `None` if no mechType is found.
pub fn first_mech_oid(blob: &[u8]) -> Option<Vec<u8>> {
    // The mechType OIDs follow the SPNEGO OID; scan past it for the first OBJECT
    // IDENTIFIER of a plausible mechanism length (KRB5/MS-KRB5 = 9, NTLM = 10).
    let spnego = blob
        .windows(SPNEGO_OID_DER.len())
        .position(|w| w == SPNEGO_OID_DER)?;
    let rest = &blob[spnego + SPNEGO_OID_DER.len()..];
    for i in 0..rest.len().saturating_sub(2) {
        let len = rest[i + 1] as usize;
        if rest[i] == 0x06 && (8..=12).contains(&len) && i + 2 + len <= rest.len() {
            return Some(rest[i..i + 2 + len].to_vec());
        }
    }
    None
}

/// Wrap an AP-REP DER in a SPNEGO `NegTokenResp` (accept-incomplete) for a BIND_ACK
/// auth token, confirming `mech_oid_der` (the client's selected mech, from
/// [`first_mech_oid`]) as the supportedMech. An empty `mech_oid_der` falls back to
/// the standard KRB5 OID.
pub fn wrap_ap_rep(ap_rep: &[u8], mech_oid_der: &[u8]) -> Vec<u8> {
    // [0] negState = ENUMERATED 1 (accept-incomplete)
    let neg_state = der(0xa0, &der(0x0a, &[0x01]));
    // [1] supportedMech = the client's selected mech OID (echoed).
    let supported_mech = der(
        0xa1,
        if mech_oid_der.is_empty() {
            &KRB5_OID_DER
        } else {
            mech_oid_der
        },
    );
    // [2] responseToken = OCTET STRING(AP-REP)
    let response_token = der(0xa2, &der(0x04, ap_rep));

    let mut seq = neg_state;
    seq.extend_from_slice(&supported_mech);
    seq.extend_from_slice(&response_token);
    der(0xa1, &der(0x30, &seq)) // [1] NegTokenResp { SEQUENCE { … } }
}

/// Extract the `MechTypeList` (`SEQUENCE OF OID`, tag `0x30`) from a SPNEGO
/// `NegTokenInit`'s `mechTypes [0]` field — the exact bytes a SPNEGO `mechListMIC`
/// is computed over (RFC 4178 §5). Returns the `30 LL …` element.
pub fn mech_list_der(blob: &[u8]) -> Option<Vec<u8>> {
    // mechTypes is `[0] ( a0 ) { SEQUENCE ( 30 ) { OID … } }`, right after the SPNEGO
    // OID and the two NegotiationToken/NegTokenInit SEQUENCE wrappers. Find the first
    // `a0 LL 30` whose inner SEQUENCE begins with an OID (06) — the mechTypes list.
    let spnego = blob
        .windows(SPNEGO_OID_DER.len())
        .position(|w| w == SPNEGO_OID_DER)?;
    let rest = &blob[spnego + SPNEGO_OID_DER.len()..];
    for i in 0..rest.len().saturating_sub(4) {
        if rest[i] == 0xa0 {
            // Skip the a0 length header to the inner element.
            let (seq_off, _) = der_content_offset(&rest[i..])?;
            let seq = &rest[i + seq_off..];
            if seq.first() == Some(&0x30) && seq.get(der_content_offset(seq)?.0) == Some(&0x06) {
                let total = der_total_len(seq)?;
                return seq.get(..total).map(<[u8]>::to_vec);
            }
        }
    }
    None
}

/// The offset of a DER element's content (past tag + length) and its content length.
fn der_content_offset(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.get(1)?;
    if first < 0x80 {
        Some((2, first as usize))
    } else {
        let n = (first & 0x7f) as usize;
        let mut len = 0usize;
        for k in 0..n {
            len = (len << 8) | *data.get(2 + k)? as usize;
        }
        Some((2 + n, len))
    }
}

/// Wrap a GSS `mechListMIC` token in a SPNEGO `NegTokenResp` with
/// `negState = accept-completed` — the acceptor's final leg of a SPNEGO exchange
/// (`NegTokenResp { negState [0] = 0, mechListMIC [3] = OCTET STRING(mic) }`).
pub fn wrap_accept_completed_mic(mic_token: &[u8]) -> Vec<u8> {
    let neg_state = der(0xa0, &der(0x0a, &[0x00])); // accept-completed
    let mech_list_mic = der(0xa3, &der(0x04, mic_token)); // [3] mechListMIC
    let mut seq = neg_state;
    seq.extend_from_slice(&mech_list_mic);
    der(0xa1, &der(0x30, &seq))
}

/// A DER TLV: `tag ‖ length ‖ content`.
fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(content.len() + 4);
    v.push(tag);
    v.extend_from_slice(&der_len(content.len()));
    v.extend_from_slice(content);
    v
}

/// A DER length header (short form `< 0x80`, else long form).
fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
    }
}

/// The total encoded length (tag + length + content) of the DER element at the
/// start of `data`.
fn der_total_len(data: &[u8]) -> Option<usize> {
    let first = *data.get(1)?;
    if first < 0x80 {
        return Some(2 + first as usize);
    }
    let n = (first & 0x7f) as usize;
    let mut len = 0usize;
    for k in 0..n {
        len = (len << 8) | *data.get(2 + k)? as usize;
    }
    Some(2 + n + len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn ldap_spnego_neg_token_init_advertises_two_mechs_and_round_trips() {
        let ap_req = [0x6eu8, 0x03, 0x0a, 0x01, 0x05]; // a dummy AP-REQ body
        let init = wrap_ap_req_spnego_ldap(&ap_req);
        // The SPNEGO OID and BOTH Kerberos mech OIDs are present, MS-KRB5 first.
        assert!(init
            .windows(SPNEGO_OID_DER.len())
            .any(|w| w == SPNEGO_OID_DER));
        let ms = init
            .windows(MS_KRB5_OID_DER.len())
            .position(|w| w == MS_KRB5_OID_DER);
        let krb = init
            .windows(KRB5_OID_DER.len())
            .position(|w| w == KRB5_OID_DER);
        assert!(ms.is_some() && krb.is_some(), "both mech OIDs present");
        assert!(ms.unwrap() < krb.unwrap(), "MS-KRB5 is listed first");
        // The AP-REQ round-trips out of the mechToken.
        assert_eq!(extract_ap_req(&init), Some(&ap_req[..]));
    }

    #[test]
    fn extracts_ap_req_from_impacket_neg_token_init() {
        // Ground truth: impacket SPNEGO_NegTokenInit with a dummy AP-REQ (6e030a0105).
        let init = hex_to_bytes(
            "603306062b0601050502a0293027a00d300b06092a864882f712010202\
             a2160414601206092a864886f71201020201006e030a0105",
        );
        let ap_req = extract_ap_req(&init).expect("AP-REQ found");
        assert_eq!(hex(ap_req), "6e030a0105");
    }

    #[test]
    fn extracts_bare_ap_req_from_samba_neg_token_init() {
        // Ground truth (bytes observed from real Samba's DRS DCE bind): the SPNEGO
        // NegTokenInit mechToken holds the RAW AP-REQ (04 82 LL LL 6e 82 LL LL …),
        // with NO inner GSS-KRB5 `01 00` token id — the fallback path must find it.
        // AP-REQ tag 0x6e with a long-form length, ≥128 bytes of body.
        let mut ap_req = vec![0x6e, 0x81, 0x80];
        ap_req.extend(std::iter::repeat_n(0xAB, 0x80));
        // Wrap it as Samba does: [2] mechToken -> OCTET STRING -> raw AP-REQ.
        let mut octet = vec![0x04, 0x81, ap_req.len() as u8];
        octet.extend_from_slice(&ap_req);
        let mut token = vec![0xa2, 0x81, octet.len() as u8];
        token.extend_from_slice(&octet);
        let got = extract_ap_req(&token).expect("bare AP-REQ found");
        assert_eq!(got, ap_req.as_slice(), "the whole AP-REQ DER element");
    }

    #[test]
    fn wraps_ap_rep_matching_impacket_neg_token_resp() {
        // Ground truth: impacket SPNEGO_NegTokenResp(accept-incomplete) for AP-REP 6f0330010f.
        let ap_rep = hex_to_bytes("6f0330010f");
        assert_eq!(
            hex(&wrap_ap_rep(&ap_rep, &KRB5_OID_DER)),
            "a11d301ba0030a0101a10b06092a864886f712010202a20704056f0330010f",
        );
    }

    #[test]
    fn first_mech_oid_reads_the_clients_preferred_mech() {
        // Samba's NegTokenInit lists MS-KRB5 (1.2.840.48018.1.2.2) first, then KRB5.
        let init = hex_to_bytes(
            "6082000c06062b0601050502a000300aa024302206092a864882f712010202\
             06092a864886f71201020206092a864882f712010202",
        );
        let oid = first_mech_oid(&init).expect("a mechType");
        assert_eq!(hex(&oid), "06092a864882f712010202", "MS-KRB5 OID echoed");
    }

    #[test]
    fn wrap_ap_rep_echoes_a_supplied_mech() {
        let ms_krb5 = hex_to_bytes("06092a864882f712010202");
        let out = wrap_ap_rep(&hex_to_bytes("6f0330010f"), &ms_krb5);
        assert!(
            out.windows(ms_krb5.len()).any(|w| w == ms_krb5.as_slice()),
            "MS-KRB5 in supportedMech"
        );
    }

    #[test]
    fn round_trips_a_realistic_length() {
        // A longer AP-REP forces long-form DER lengths; wrap then re-extract-ish.
        let ap_rep = vec![0x6f; 300];
        let wrapped = wrap_ap_rep(&ap_rep, &KRB5_OID_DER);
        // The wrapper must contain the AP-REP intact.
        assert!(wrapped.windows(300).any(|w| w == ap_rep.as_slice()));
        assert_eq!(wrapped[0], 0xa1, "outer NegTokenResp tag");
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
            .collect()
    }
}
