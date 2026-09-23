//! CLDAP netlogon ping (MS-ADTS §6.3.3–6.3.5) — the second half of DC discovery.
//!
//! Before joining, a Windows client (after finding the DC via the DNS SRV records)
//! sends a *connectionless* LDAP (CLDAP, UDP 389) `searchRequest` with an empty
//! base and the `Netlogon` attribute, and expects a `searchResEntry` whose value
//! is a `NETLOGON_SAM_LOGON_RESPONSE_EX` blob describing the DC (domain, forest,
//! DC host, flags). This module builds that blob, frames the CLDAP response, and
//! serves it over UDP.
//!
//! Tracer-bullet scope: any well-formed `searchRequest` is answered with this DC's
//! response (the request filter — DnsDomain / Host / DomainGuid / NtVer — is not
//! matched; this DC serves a single domain).

use crate::Directory;
use std::net::SocketAddr;

/// The Active Directory site every object is placed in (single-site PoC).
const SITE_NAME: &str = "Default-First-Site-Name";

/// A stable domain GUID advertised for this DC (PoC constant).
const DC_DOMAIN_GUID: [u8; 16] = [
    0x9e, 0x2d, 0x5c, 0x84, 0x1b, 0x3a, 0x47, 0xf0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
];

/// The domain identity advertised in the netlogon response.
#[derive(Debug, Clone)]
pub struct DomainInfo {
    /// DNS domain, e.g. `example.com`.
    pub dns_domain: String,
    /// NetBIOS domain, e.g. `EXAMPLE`.
    pub netbios_domain: String,
    /// Forest DNS name (equals the domain for a single-domain forest).
    pub forest: String,
    /// The DC's DNS host name, e.g. `magnetite.example.com`.
    pub dc_dns_host: String,
    /// The DC's NetBIOS computer name, e.g. `MAGNETITE`.
    pub dc_netbios: String,
}

/// Build the netlogon [`DomainInfo`] from the shared [`Directory`]. The DC host is
/// `<dc_label>.<dns_domain>` (matching the DC's FQDN service SPNs) and its NetBIOS
/// computer name is the uppercased label (≤15 chars).
pub fn domain_info(directory: &Directory, dc_label: &str) -> DomainInfo {
    let dns_domain = directory.dns_domain().to_string();
    let dc_netbios: String = dc_label
        .chars()
        .flat_map(char::to_uppercase)
        .take(15)
        .collect();
    DomainInfo {
        forest: dns_domain.clone(),
        dc_dns_host: format!("{dc_label}.{dns_domain}"),
        dc_netbios,
        netbios_domain: directory.netbios().to_string(),
        dns_domain,
    }
}

/// Encode `name` as an uncompressed RFC 1035 name: each dotted label prefixed by
/// its length, terminated by a zero (root) byte. An empty name is just `0x00`.
fn dns_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

// NETLOGON_SAM_LOGON_RESPONSE_EX opcode (LOGON_SAM_LOGON_RESPONSE_EX).
const OPCODE_SAM_LOGON_RESPONSE_EX: u16 = 23;

// DS flags advertised (MS-ADTS §6.3.1.2): PDC | GC | LDAP | DS | KDC | WRITABLE |
// DNS_CONTROLLER | DNS_DOMAIN | DNS_FOREST.
const DS_FLAGS: u32 = 0x0000_0001
    | 0x0000_0004
    | 0x0000_0008
    | 0x0000_0010
    | 0x0000_0020
    | 0x0000_0100
    | 0x2000_0000
    | 0x4000_0000
    | 0x8000_0000;

// NtVersion echoed in the response: NETLOGON_NT_VERSION_1 | NETLOGON_NT_VERSION_5EX.
const NT_VERSION: u32 = 0x0000_0001 | 0x0000_0004;

/// Build the `NETLOGON_SAM_LOGON_RESPONSE_EX` blob (little-endian header + RFC 1035
/// names + trailing version/tokens) for `info`.
pub fn netlogon_sam_logon_response_ex(info: &DomainInfo) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&OPCODE_SAM_LOGON_RESPONSE_EX.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes()); // Sbz
    b.extend_from_slice(&DS_FLAGS.to_le_bytes());
    b.extend_from_slice(&DC_DOMAIN_GUID);
    b.extend_from_slice(&dns_name(&info.forest));
    b.extend_from_slice(&dns_name(&info.dns_domain));
    b.extend_from_slice(&dns_name(&info.dc_dns_host));
    b.extend_from_slice(&dns_name(&info.netbios_domain));
    b.extend_from_slice(&dns_name(&info.dc_netbios));
    b.extend_from_slice(&dns_name("")); // UserName (empty)
    b.extend_from_slice(&dns_name(SITE_NAME)); // DcSiteName
    b.extend_from_slice(&dns_name(SITE_NAME)); // ClientSiteName
    b.extend_from_slice(&NT_VERSION.to_le_bytes());
    b.extend_from_slice(&0xFFFFu16.to_le_bytes()); // LmNtToken
    b.extend_from_slice(&0xFFFFu16.to_le_bytes()); // Lm20Token
    b
}

// --- Minimal BER (definite-length) for the CLDAP framing ---

fn ber_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let bytes = len.to_be_bytes();
        let first = bytes
            .iter()
            .position(|&x| x != 0)
            .unwrap_or(bytes.len() - 1);
        let sig = &bytes[first..];
        let mut out = vec![0x80 | sig.len() as u8];
        out.extend_from_slice(sig);
        out
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&ber_len(content.len()));
    out.extend_from_slice(content);
    out
}

fn octet_string(s: &[u8]) -> Vec<u8> {
    tlv(0x04, s)
}

/// Encode a non-negative message id as a minimal BER INTEGER.
fn integer(v: i32) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let mut start = 0;
    while start < bytes.len() - 1 && bytes[start] == 0 && (bytes[start + 1] & 0x80) == 0 {
        start += 1;
    }
    tlv(0x02, &bytes[start..])
}

/// Frame the CLDAP response for `message_id`: a `searchResEntry` carrying the
/// `Netlogon` attribute value, followed by a success `searchResDone`, concatenated
/// into one datagram (as CLDAP clients expect).
pub fn build_cldap_response(message_id: i32, netlogon: &[u8]) -> Vec<u8> {
    // searchResEntry [APPLICATION 4]: objectName "" + one PartialAttribute.
    let partial_attr = {
        let mut c = octet_string(b"Netlogon");
        c.extend(tlv(0x31, &octet_string(netlogon))); // vals: SET OF value
        tlv(0x30, &c)
    };
    let entry_body = {
        let mut c = octet_string(b""); // objectName
        c.extend(tlv(0x30, &partial_attr)); // PartialAttributeList
        c
    };
    let entry_msg = {
        let mut c = integer(message_id);
        c.extend(tlv(0x64, &entry_body));
        tlv(0x30, &c)
    };

    // searchResDone [APPLICATION 5]: success, empty matchedDN/diagnostic.
    let done_body = {
        let mut c = tlv(0x0a, &[0x00]); // resultCode ENUMERATED success
        c.extend(octet_string(b"")); // matchedDN
        c.extend(octet_string(b"")); // diagnosticMessage
        c
    };
    let done_msg = {
        let mut c = integer(message_id);
        c.extend(tlv(0x65, &done_body));
        tlv(0x30, &c)
    };

    let mut out = entry_msg;
    out.extend(done_msg);
    out
}

/// Read a BER definite length at `p`, returning `(length, bytes_consumed)`.
fn read_len(d: &[u8], p: usize) -> Option<(usize, usize)> {
    let first = *d.get(p)?;
    if first < 0x80 {
        Some((first as usize, 1))
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *d.get(p + 1 + i)? as usize;
        }
        Some((len, 1 + n))
    }
}

/// Parse a CLDAP datagram, returning the message id if it is an LDAP
/// `searchRequest` (`LDAPMessage ::= SEQUENCE { messageID INTEGER, [APPLICATION 3]
/// searchRequest ... }`). Returns `None` for anything else, so we only answer pings.
pub fn parse_search_message_id(datagram: &[u8]) -> Option<i32> {
    let mut p = 0;
    if *datagram.get(p)? != 0x30 {
        return None;
    }
    p += 1;
    let (_len, adv) = read_len(datagram, p)?;
    p += adv;
    // messageID INTEGER
    if *datagram.get(p)? != 0x02 {
        return None;
    }
    p += 1;
    let (int_len, adv) = read_len(datagram, p)?;
    p += adv;
    let bytes = datagram.get(p..p + int_len)?;
    let mut v: i32 = 0;
    for &b in bytes {
        v = (v << 8) | b as i32;
    }
    p += int_len;
    // protocolOp must be searchRequest ([APPLICATION 3] = 0x63).
    if *datagram.get(p)? != 0x63 {
        return None;
    }
    Some(v)
}

/// Serve CLDAP netlogon pings on `addr` (UDP), answering every well-formed
/// `searchRequest` with this DC's `NETLOGON_SAM_LOGON_RESPONSE_EX`.
///
/// # Errors
/// Returns an error if the UDP socket cannot be bound.
pub async fn serve_cldap(addr: SocketAddr, info: DomainInfo) -> std::io::Result<()> {
    let socket = tokio::net::UdpSocket::bind(addr).await?;
    let blob = netlogon_sam_logon_response_ex(&info);
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = socket.recv_from(&mut buf).await?;
        if let Some(message_id) = parse_search_message_id(&buf[..n]) {
            let response = build_cldap_response(message_id, &blob);
            let _ = socket.send_to(&response, peer).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_info() -> DomainInfo {
        DomainInfo {
            dns_domain: "example.com".to_string(),
            netbios_domain: "EXAMPLE".to_string(),
            forest: "example.com".to_string(),
            dc_dns_host: "magnetite.example.com".to_string(),
            dc_netbios: "MAGNETITE".to_string(),
        }
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn netlogon_blob_has_opcode_flags_and_names() {
        let blob = netlogon_sam_logon_response_ex(&sample_info());
        // Opcode 23 (LE) then Sbz 0.
        assert_eq!(&blob[0..2], &23u16.to_le_bytes());
        assert_eq!(&blob[2..4], &0u16.to_le_bytes());
        assert_eq!(&blob[4..8], &DS_FLAGS.to_le_bytes());
        assert_eq!(&blob[8..24], &DC_DOMAIN_GUID);
        // RFC1035-encoded names appear: example.com and the NetBIOS domain.
        assert!(
            contains(&blob, b"\x07example\x03com\x00"),
            "dns domain name"
        );
        assert!(contains(&blob, b"\x07EXAMPLE\x00"), "netbios domain name");
        assert!(
            contains(&blob, b"\x09magnetite\x07example\x03com\x00"),
            "dc host"
        );
        // Trailing tokens.
        assert_eq!(&blob[blob.len() - 4..], &[0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn domain_info_from_directory_defaults() {
        let info = domain_info(&Directory::default(), "magnetite");
        assert_eq!(info.dns_domain, "example.com");
        assert_eq!(info.netbios_domain, "EXAMPLE");
        assert_eq!(info.dc_dns_host, "magnetite.example.com");
        assert_eq!(info.dc_netbios, "MAGNETITE");
    }

    #[test]
    fn domain_info_honours_a_custom_dc_label() {
        let info = domain_info(&Directory::default(), "dc2");
        assert_eq!(info.dc_dns_host, "dc2.example.com");
        assert_eq!(info.dc_netbios, "DC2");
    }

    #[test]
    fn response_framing_round_trips_message_id() {
        let blob = netlogon_sam_logon_response_ex(&sample_info());
        let resp = build_cldap_response(7, &blob);
        // The datagram starts with an LDAPMessage SEQUENCE whose id is 7.
        assert_eq!(resp[0], 0x30);
        assert_eq!(parse_search_message_id_of_entry(&resp), Some(7));
        // The Netlogon blob is embedded.
        assert!(contains(&resp, &blob), "netlogon value present");
        // A searchResEntry (0x64) and a searchResDone (0x65) are both present.
        assert!(contains(&resp, &[0x64]), "searchResEntry tag");
        assert!(contains(&resp, &[0x65]), "searchResDone tag");
    }

    // Read the message id of a response entry (protocolOp 0x64), mirroring the
    // request parser but for searchResEntry.
    fn parse_search_message_id_of_entry(d: &[u8]) -> Option<i32> {
        let mut p = 1;
        let (_len, adv) = read_len(d, p)?;
        p += adv;
        if *d.get(p)? != 0x02 {
            return None;
        }
        p += 1;
        let (int_len, adv) = read_len(d, p)?;
        p += adv;
        let mut v = 0i32;
        for &b in d.get(p..p + int_len)? {
            v = (v << 8) | b as i32;
        }
        Some(v)
    }

    #[test]
    fn parses_search_request_message_id() {
        // A minimal LDAPMessage: SEQUENCE { INTEGER 5, [APPLICATION 3] {} }.
        let datagram = [0x30, 0x05, 0x02, 0x01, 0x05, 0x63, 0x00];
        assert_eq!(parse_search_message_id(&datagram), Some(5));
        // A non-search op (e.g. bindRequest 0x60) is ignored.
        let bind = [0x30, 0x05, 0x02, 0x01, 0x05, 0x60, 0x00];
        assert_eq!(parse_search_message_id(&bind), None);
    }
}
