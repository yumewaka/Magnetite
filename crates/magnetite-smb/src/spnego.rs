//! Minimal SPNEGO (GSS-API) + NTLMSSP token construction for SMB2 SESSION_SETUP.
//!
//! We hand-build just enough of the tokens for a client to run NTLM: the
//! NEGOTIATE response advertises NTLM (a SPNEGO `NegTokenInit`), and the first
//! SESSION_SETUP response returns an NTLMSSP CHALLENGE wrapped in a SPNEGO
//! `NegTokenResp`. The client's NTLM authenticate is then accepted without
//! verification (a PoC simplification — we are proving the SMB read path, not
//! password checking).

/// The NTLMSSP OID (1.3.6.1.4.1.311.2.2.10) as a DER OBJECT IDENTIFIER.
const NTLMSSP_OID: [u8; 12] = [
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
];
/// The Kerberos v5 mechanism OID (1.2.840.113554.1.2.2) as a DER OBJECT IDENTIFIER.
const KRB5_OID: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
];
/// The Microsoft Kerberos v5 mechanism OID (1.2.840.48018.1.2.2) — Windows
/// advertises this alongside the standard KRB5 OID.
const MSKRB5_OID: [u8; 11] = [
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x82, 0xf7, 0x12, 0x01, 0x02, 0x02,
];
/// The SPNEGO OID (1.3.6.1.5.5.2) as a DER OBJECT IDENTIFIER.
const SPNEGO_OID: [u8; 8] = [0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
/// The GSS/KRB5 token id preceding an AP-REP in a context-establishment token
/// (`KRB5_AP_REP`, little-endian `0x0002`).
const AP_REP_TOK_ID: [u8; 2] = [0x02, 0x00];

/// The 8-byte server challenge baked into our NTLM CHALLENGE (a real server
/// randomises this). The session-setup verifier must prove the client's NTLMv2
/// response against this exact value, so it is shared crate-wide.
pub(crate) const SERVER_CHALLENGE: [u8; 8] = *b"SMBSVR01";

/// DER tag+length prefix around `content`.
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

/// The SPNEGO `NegTokenInit` for a NEGOTIATE response advertising `mech_oids` (a
/// concatenation of DER OBJECT IDENTIFIERs) as the supported mechanisms.
fn neg_token_init_for(mech_oids: &[u8]) -> Vec<u8> {
    let mech_type_list = der(0x30, mech_oids); // MechTypeList SEQUENCE OF OID
    let mech_types = der(0xa0, &mech_type_list); // [0] mechTypes
    let neg_token_init = der(0x30, &mech_types); // NegTokenInit SEQUENCE
    let inner = der(0xa0, &neg_token_init); // [0] negTokenInit
    let mut spnego = SPNEGO_OID.to_vec();
    spnego.extend_from_slice(&inner);
    der(0x60, &spnego) // [APPLICATION 0] GSS-API
}

/// The SPNEGO `NegTokenInit` for a NEGOTIATE response: advertises NTLM as the
/// only supported mechanism.
pub fn neg_token_init() -> Vec<u8> {
    neg_token_init_for(&NTLMSSP_OID)
}

/// The SPNEGO `NegTokenInit` advertising Kerberos (standard + MS OIDs) ahead of
/// NTLM — what a DC presents so a Kerberos-required client (e.g. Samba
/// `smbclient`, Windows) proceeds to send an AP-REQ instead of erroring in its
/// GSS layer. NTLM stays listed as a fallback.
pub fn neg_token_init_kerberos() -> Vec<u8> {
    let mut mechs = Vec::with_capacity(KRB5_OID.len() + MSKRB5_OID.len() + NTLMSSP_OID.len());
    mechs.extend_from_slice(&KRB5_OID);
    mechs.extend_from_slice(&MSKRB5_OID);
    mechs.extend_from_slice(&NTLMSSP_OID);
    neg_token_init_for(&mechs)
}

/// A UTF-16LE encoding of `s`.
fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// An NTLM AV_PAIR (AvId, length-prefixed value).
fn av_pair(av_id: u16, value: &[u8]) -> Vec<u8> {
    let mut p = av_id.to_le_bytes().to_vec();
    p.extend_from_slice(&(value.len() as u16).to_le_bytes());
    p.extend_from_slice(value);
    p
}

/// An NTLMSSP CHALLENGE (type 2) message. The target-info AV list includes the
/// NetBIOS/DNS computer and domain names an NTLMv2 client needs.
fn ntlmssp_challenge() -> Vec<u8> {
    // Flags: UNICODE | NTLM | EXTENDED_SESSIONSECURITY | ALWAYS_SIGN |
    // TARGET_TYPE_SERVER | TARGET_INFO | VERSION.
    const FLAGS: u32 = 0x0000_0001
        | 0x0000_0200
        | 0x0008_0000
        | 0x0000_8000
        | 0x0002_0000
        | 0x0080_0000
        | 0x0200_0000;

    // Target info: NetBIOS + DNS names, terminated by MsvAvEOL.
    let mut target_info = Vec::new();
    target_info.extend(av_pair(1, &utf16le("MAGNETITE"))); // MsvAvNbComputerName
    target_info.extend(av_pair(2, &utf16le("EXAMPLE"))); // MsvAvNbDomainName
    target_info.extend(av_pair(3, &utf16le("magnetite.example.com"))); // MsvAvDnsComputerName
    target_info.extend(av_pair(4, &utf16le("example.com"))); // MsvAvDnsDomainName
    target_info.extend(av_pair(0, &[])); // MsvAvEOL

    let payload_offset: u32 = 56; // size of the fixed CHALLENGE fields

    let mut m = Vec::new();
    m.extend_from_slice(b"NTLMSSP\0"); // Signature
    m.extend_from_slice(&2u32.to_le_bytes()); // MessageType = CHALLENGE
                                              // TargetNameFields: empty (target info carries the names).
    m.extend_from_slice(&0u16.to_le_bytes()); // Len
    m.extend_from_slice(&0u16.to_le_bytes()); // MaxLen
    m.extend_from_slice(&payload_offset.to_le_bytes()); // Offset
    m.extend_from_slice(&FLAGS.to_le_bytes());
    m.extend_from_slice(&SERVER_CHALLENGE);
    m.extend_from_slice(&[0u8; 8]); // Reserved
                                    // TargetInfoFields.
    m.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
    m.extend_from_slice(&(target_info.len() as u16).to_le_bytes());
    m.extend_from_slice(&payload_offset.to_le_bytes());
    // Version (major 10, NTLM revision 15).
    m.extend_from_slice(&[10, 0, 0, 0, 0, 0, 0, 15]);
    // Payload.
    m.extend_from_slice(&target_info);
    m
}

/// The SPNEGO `NegTokenResp` for the first SESSION_SETUP response: carries the
/// NTLMSSP CHALLENGE with `negResult = accept-incomplete`.
pub fn neg_token_resp_challenge() -> Vec<u8> {
    let neg_result = [0xa0, 0x03, 0x0a, 0x01, 0x01]; // [0] ENUMERATED accept-incomplete(1)
    let supported_mech = der(0xa1, &NTLMSSP_OID); // [1] supportedMech
    let response_token = der(0xa2, &der(0x04, &ntlmssp_challenge())); // [2] responseToken

    let mut seq = Vec::new();
    seq.extend_from_slice(&neg_result);
    seq.extend_from_slice(&supported_mech);
    seq.extend_from_slice(&response_token);
    der(0xa1, &der(0x30, &seq)) // [1] NegTokenResp
}

/// Locate the Kerberos AP-REQ inside a SPNEGO/GSS-API security blob.
///
/// A GSS Kerberos token embeds `... 01 00 <AP-REQ>` (the `01 00` is the AP-REQ
/// token id; the AP-REQ itself is `[APPLICATION 14]` = `0x6e`). We find that
/// marker and return the exact DER-length-delimited AP-REQ bytes.
pub fn extract_ap_req(blob: &[u8]) -> Option<&[u8]> {
    for i in 0..blob.len().saturating_sub(3) {
        if blob[i] == 0x01 && blob[i + 1] == 0x00 && blob[i + 2] == 0x6e {
            let ap_req = &blob[i + 2..];
            let total = der_total_len(ap_req)?;
            return ap_req.get(..total);
        }
    }
    None
}

/// The total DER TLV length (tag + length octets + content) at the front of `b`.
fn der_total_len(b: &[u8]) -> Option<usize> {
    let l0 = *b.get(1)?;
    match l0 {
        0..=0x7f => Some(2 + l0 as usize),
        0x81 => Some(3 + *b.get(2)? as usize),
        0x82 => Some(4 + (((*b.get(2)? as usize) << 8) | *b.get(3)? as usize)),
        _ => None,
    }
}

/// A SPNEGO `NegTokenResp` carrying the mutual-authentication AP-REP: the
/// server's final leg (`negResult = accept-completed`, `supportedMech = KRB5`,
/// `responseToken = <GSS-framed AP-REP>`).
///
/// The response token is a full GSS-API context token — `[APPLICATION 0]` (`0x60`)
/// wrapping the KRB5 mech OID, the `02 00` `KRB5_AP_REP` token id, then the AP-REP
/// DER — mirroring the framing the client used for its AP-REQ. MIT krb5's
/// `g_verify_token_header` requires this `0x60`/OID header on the AP-REP; a bare
/// `02 00 ‖ AP-REP` fails there with an ASN.1 identifier mismatch.
pub fn neg_token_resp_ap_rep(ap_rep: &[u8]) -> Vec<u8> {
    let neg_result = der(0xa0, &der(0x0a, &[0x00])); // [0] accept-completed(0)
    let supported_mech = der(0xa1, &KRB5_OID); // [1] supportedMech = KRB5

    // GSS-API InitialContextToken: 06 09 <KRB5 OID> ‖ 02 00 ‖ AP-REP, wrapped in
    // the [APPLICATION 0] (0x60) tag.
    let mut gss = KRB5_OID.to_vec();
    gss.extend_from_slice(&AP_REP_TOK_ID);
    gss.extend_from_slice(ap_rep);
    let mech_token = der(0x60, &gss);
    let response_token = der(0xa2, &der(0x04, &mech_token)); // [2] responseToken

    let mut seq = neg_result;
    seq.extend_from_slice(&supported_mech);
    seq.extend_from_slice(&response_token);
    der(0xa1, &der(0x30, &seq)) // [1] NegTokenResp { SEQUENCE { … } }
}

/// The raw NTLMSSP message inside a SPNEGO/GSS security blob — the bytes from the
/// `NTLMSSP\0` signature to the end (the NTLM message is the last field, and its
/// internal offsets are self-relative, so trailing SPNEGO bytes are harmless).
pub fn extract_ntlmssp(security_blob: &[u8]) -> Option<&[u8]> {
    let marker = b"NTLMSSP\0";
    let pos = security_blob
        .windows(marker.len())
        .position(|w| w == marker)?;
    Some(&security_blob[pos..])
}

/// A SPNEGO `NegTokenResp` with `negResult = accept-completed` and no token — the
/// server's final leg after a successful NTLM AUTHENTICATE.
pub fn neg_token_resp_accept_completed() -> Vec<u8> {
    let neg_result = der(0xa0, &der(0x0a, &[0x00])); // [0] accept-completed(0)
    der(0xa1, &der(0x30, &neg_result)) // [1] NegTokenResp { SEQUENCE { negResult } }
}

/// The NTLMSSP message type at the start of a raw NTLMSSP blob, or `None` if the
/// `NTLMSSP\0` signature isn't found (e.g. the token is something else).
pub fn ntlmssp_message_type(security_blob: &[u8]) -> Option<u32> {
    let marker = b"NTLMSSP\0";
    let pos = security_blob
        .windows(marker.len())
        .position(|w| w == marker)?;
    let type_at = pos + 8;
    let bytes = security_blob.get(type_at..type_at + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negtokeninit_is_well_formed_der() {
        let t = neg_token_init();
        assert_eq!(t[0], 0x60, "GSS-API application tag");
        // The NTLMSSP OID must appear inside.
        assert!(t.windows(NTLMSSP_OID.len()).any(|w| w == NTLMSSP_OID));
    }

    #[test]
    fn challenge_roundtrips_message_type() {
        let resp = neg_token_resp_challenge();
        assert_eq!(resp[0], 0xa1, "NegTokenResp context tag");
        // The embedded NTLMSSP CHALLENGE is type 2.
        assert_eq!(ntlmssp_message_type(&resp), Some(2));
    }

    #[test]
    fn detects_authenticate_type() {
        let mut blob = b"NTLMSSP\0".to_vec();
        blob.extend_from_slice(&3u32.to_le_bytes());
        assert_eq!(ntlmssp_message_type(&blob), Some(3));
    }

    #[test]
    fn kerberos_negtokeninit_lists_krb5_ahead_of_ntlm() {
        let t = neg_token_init_kerberos();
        assert_eq!(t[0], 0x60, "GSS-API application tag");
        let krb5_at = t
            .windows(KRB5_OID.len())
            .position(|w| w == KRB5_OID)
            .expect("KRB5 OID advertised");
        let ntlm_at = t
            .windows(NTLMSSP_OID.len())
            .position(|w| w == NTLMSSP_OID)
            .expect("NTLM OID still advertised");
        assert!(krb5_at < ntlm_at, "Kerberos is preferred over NTLM");
        assert!(
            t.windows(MSKRB5_OID.len()).any(|w| w == MSKRB5_OID),
            "MS-KRB5 OID advertised too",
        );
    }

    #[test]
    fn ap_rep_resp_is_accept_completed_and_carries_the_tok_id() {
        let ap_rep = vec![0x6f, 0x03, 0x30, 0x01, 0x0f]; // a dummy AP-REP DER
        let resp = neg_token_resp_ap_rep(&ap_rep);
        assert_eq!(resp[0], 0xa1, "NegTokenResp context tag");
        // negResult = accept-completed(0): the ENUMERATED encoding a0 03 0a 01 00.
        assert!(
            resp.windows(5).any(|w| w == [0xa0, 0x03, 0x0a, 0x01, 0x00]),
            "negState is accept-completed(0)",
        );
        assert!(
            resp.windows(KRB5_OID.len()).any(|w| w == KRB5_OID),
            "supportedMech is KRB5",
        );
        // responseToken carries the GSS-framed AP-REP: 06 09 <KRB5 OID> 02 00 AP-REP,
        // inside the [APPLICATION 0] (0x60) tag MIT's g_verify_token_header requires.
        let mut gss = KRB5_OID.to_vec();
        gss.extend_from_slice(&AP_REP_TOK_ID);
        gss.extend_from_slice(&ap_rep);
        let framed = der(0x60, &gss);
        assert!(
            resp.windows(framed.len()).any(|w| w == framed.as_slice()),
            "responseToken is the 0x60-framed KRB5 AP-REP context token",
        );
    }
}
