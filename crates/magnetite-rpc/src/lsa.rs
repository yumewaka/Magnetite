//! A minimal real LSA interface (MS-LSAD policy + MS-LSAT translation). The
//! Local Security Authority RPC interface a Windows client uses to discover the
//! domain (`LsarQueryInformationPolicy`) and to translate SIDs to names
//! (`LsarLookupSids`) — the wire behind `lsalookupsid`/`PolicyDnsDomainInfo`.
//!
//! MS-LSAD and MS-LSAT share one interface UUID (`12345778-…-0123456789AB`,
//! v0.0), so a single [`LsaInterface`] serves both opnum sets.
//!
//! Implemented opnums:
//! * `LsarClose` (0)
//! * `LsarOpenPolicy` (6) / `LsarOpenPolicy2` (44) → a policy handle
//! * `LsarQueryInformationPolicy` (7) / `LsarQueryInformationPolicy2` (46) →
//!   the `LSAPR_POLICY_INFORMATION` union (Account/Primary/DNS domain, role)
//! * `LsarLookupSids` (15) → translate SIDs to names against the local domain
//!
//! This is a PoC: handles are fixed (the interface is stateless) and every
//! request's `[in]` handle is accepted.

use crate::directory::{Directory, RidKind};
use crate::interface::RpcInterface;
use crate::ndr::{NdrReader, NdrWriter};
use crate::request::fault;
use std::sync::Arc;

/// LSA interface UUID, shared by MS-LSAD and MS-LSAT (`12345778-1234-ABCD-EF00-0123456789AB`, v0.0).
pub const LSA_UUID: &str = "12345778-1234-ABCD-EF00-0123456789AB";

const OP_CLOSE: u16 = 0;
const OP_OPEN_POLICY: u16 = 6;
const OP_QUERY_INFO_POLICY: u16 = 7;
const OP_LOOKUP_SIDS: u16 = 15;
const OP_OPEN_POLICY2: u16 = 44;
const OP_QUERY_INFO_POLICY2: u16 = 46;

// POLICY_INFORMATION_CLASS values we answer.
const POLICY_PRIMARY_DOMAIN: u16 = 3;
const POLICY_ACCOUNT_DOMAIN: u16 = 5;
const POLICY_LSA_SERVER_ROLE: u16 = 6;
const POLICY_DNS_DOMAIN: u16 = 12;

// SID_NAME_USE values.
const SID_TYPE_USER: u16 = 1;
const SID_TYPE_GROUP: u16 = 2;
const SID_TYPE_UNKNOWN: u16 = 8;

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
/// Returned when at least one SID could not be translated.
const STATUS_SOME_NOT_MAPPED: u32 = 0x0000_0107;
/// Returned when no SID could be translated.
const STATUS_NONE_MAPPED: u32 = 0xC000_0073;

const NT_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];
/// LSA server role: `PolicyServerRolePrimary` (a primary DC).
const SERVER_ROLE_PRIMARY: u16 = 3;

/// A fixed 20-byte policy handle (context handle: attributes + UUID).
const POLICY_HANDLE: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, // attributes
    0x4d, 0x41, 0x47, 0x4e, 0x45, 0x54, 0x49, 0x54, 0x45, 0x4c, 0x53, 0x41, 0x50, 0x4f, 0x4c, 0x59,
];

/// The LSA policy + translation server, answering from a shared [`Directory`].
pub struct LsaInterface {
    directory: Arc<Directory>,
}

impl Default for LsaInterface {
    fn default() -> Self {
        Self::new(Arc::new(Directory::default()))
    }
}

impl LsaInterface {
    /// An LSA server answering from `directory`.
    pub fn new(directory: Arc<Directory>) -> Self {
        Self { directory }
    }
}

impl RpcInterface for LsaInterface {
    fn call(&self, opnum: u16, stub: &[u8]) -> Result<Vec<u8>, u32> {
        self.call_authenticated(opnum, stub, None, None)
    }

    fn call_authenticated(
        &self,
        opnum: u16,
        stub: &[u8],
        _session_key: Option<&[u8]>,
        principal: Option<&str>,
    ) -> Result<Vec<u8>, u32> {
        // Attribute the sensitive lookups to the bound principal (the SMB session user
        // when this rides an authenticated pipe); `<unauthenticated>` when none is known.
        let who = principal.unwrap_or("<unauthenticated>");
        match opnum {
            OP_OPEN_POLICY | OP_OPEN_POLICY2 => Ok(open_policy_response()),
            OP_CLOSE => Ok(close_response()),
            OP_QUERY_INFO_POLICY | OP_QUERY_INFO_POLICY2 => {
                tracing::info!(target: "auth", proto = "lsa", principal = who, "LSA QueryInfoPolicy: domain/policy information queried");
                query_information_policy(&self.directory, stub)
            }
            OP_LOOKUP_SIDS => {
                tracing::info!(target: "auth", proto = "lsa", principal = who, "LSA LsarLookupSids: SID→name translation requested");
                lookup_sids(&self.directory, stub)
            }
            _ => Err(fault::OP_RNG_ERROR),
        }
    }
}

/// `LsarOpenPolicy(2)` response: the policy handle + STATUS_SUCCESS.
fn open_policy_response() -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.bytes(&POLICY_HANDLE);
    w.u32(STATUS_SUCCESS);
    w.into_bytes()
}

/// `LsarClose` response: a null handle + STATUS_SUCCESS.
fn close_response() -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.bytes(&[0u8; 20]);
    w.u32(STATUS_SUCCESS);
    w.into_bytes()
}

// --- NDR helpers (deferred-referent discipline, as in the SAMR/PAC encoders) ---

/// A deferred NDR pointer referent.
enum Deferred {
    /// A conformant+varying UTF-16 array (an `RPC_UNICODE_STRING` buffer).
    Utf16(Vec<u16>),
    /// An `RPC_SID` (identifier authority + sub-authorities).
    Sid([u8; 6], Vec<u32>),
}

/// A small NDR marshalling context tracking the next referent id and the queue
/// of deferred referents for the current scope.
struct Marshal {
    w: NdrWriter,
    deferred: Vec<Deferred>,
    next_ref: u32,
}

impl Marshal {
    fn new() -> Self {
        Self {
            w: NdrWriter::new(),
            deferred: Vec::new(),
            next_ref: 0x0002_0000,
        }
    }

    /// Emit a fresh non-null referent id.
    fn referent(&mut self) -> u32 {
        let r = self.next_ref;
        self.next_ref += 4;
        r
    }

    /// Write an `RPC_UNICODE_STRING` header (Length, MaximumLength, Buffer ptr),
    /// queuing the character data (null pointer for the empty string).
    fn unicode_string(&mut self, s: &str) {
        let chars: Vec<u16> = s.encode_utf16().collect();
        let byte_len = (chars.len() * 2) as u16;
        self.w.u16(byte_len);
        self.w.u16(byte_len);
        if chars.is_empty() {
            self.w.u32(0);
        } else {
            let r = self.referent();
            self.w.u32(r);
            self.deferred.push(Deferred::Utf16(chars));
        }
    }

    /// Write a pointer to an `RPC_SID`, queuing the SID as a deferred referent.
    fn sid_pointer(&mut self, id_auth: [u8; 6], sub: Vec<u32>) {
        let r = self.referent();
        self.w.u32(r);
        self.deferred.push(Deferred::Sid(id_auth, sub));
    }

    /// Flush all queued deferred referents (in declaration order) for this scope.
    fn flush(&mut self) {
        for d in std::mem::take(&mut self.deferred) {
            match d {
                Deferred::Utf16(chars) => {
                    self.w.u32(chars.len() as u32); // MaxCount
                    self.w.u32(0); // Offset
                    self.w.u32(chars.len() as u32); // ActualCount
                    for c in chars {
                        self.w.u16(c);
                    }
                }
                Deferred::Sid(id_auth, sub) => {
                    self.w.u32(sub.len() as u32); // conformant MaxCount = SubAuthorityCount
                    self.w.u8(1); // Revision
                    self.w.u8(sub.len() as u8); // SubAuthorityCount
                    self.w.bytes(&id_auth);
                    for s in sub {
                        self.w.u32(s);
                    }
                }
            }
        }
    }
}

/// `LsarQueryInformationPolicy(2)`: return the requested policy information
/// union. Request: `PolicyHandle[20], InformationClass[u16]`.
fn query_information_policy(dir: &Directory, stub: &[u8]) -> Result<Vec<u8>, u32> {
    let info_class = (|| {
        let mut r = NdrReader::new(stub);
        r.take(20)?; // PolicyHandle
        r.u16()
    })()
    .ok_or(fault::NDR)?;

    let domain_sid = dir.domain_sid().to_vec();
    let mut m = Marshal::new();
    // PLSAPR_POLICY_INFORMATION: a top-level pointer → its referent is inline.
    let r = m.referent();
    m.w.u32(r);
    // The union: u16 discriminant, then the arm aligned to the union alignment.
    // impacket aligns *every* arm to 4 (the union's max member alignment), so a
    // 2 pad follows the tag regardless of the selected arm.
    m.w.u16(info_class);
    m.w.align(4);

    match info_class {
        POLICY_ACCOUNT_DOMAIN | POLICY_PRIMARY_DOMAIN => {
            // { DomainName: RPC_UNICODE_STRING, DomainSid: PRPC_SID }.
            m.unicode_string(dir.netbios());
            m.sid_pointer(NT_AUTHORITY, domain_sid);
            m.flush();
        }
        POLICY_DNS_DOMAIN => {
            // { Name, DnsDomainName, DnsForestName: RPC_UNICODE_STRING,
            //   DomainGuid: GUID(16), Sid: PRPC_SID }.
            m.unicode_string(dir.netbios());
            m.unicode_string(dir.dns_domain());
            m.unicode_string(dir.dns_domain());
            m.w.bytes(&domain_guid()); // DomainGuid
            m.sid_pointer(NT_AUTHORITY, domain_sid);
            m.flush();
        }
        POLICY_LSA_SERVER_ROLE => {
            // { LsaServerRole: enum(u16) } — impacket still pads the arm to 4.
            m.w.u16(SERVER_ROLE_PRIMARY);
        }
        _ => {
            // An info class we do not model: null pointer + error.
            let mut w = NdrWriter::new();
            w.u32(0); // null PLSAPR_POLICY_INFORMATION
            w.u32(STATUS_INVALID_INFO_CLASS);
            return Ok(w.into_bytes());
        }
    }

    m.w.u32(STATUS_SUCCESS); // ErrorCode
    Ok(m.w.into_bytes())
}

/// A fixed domain GUID (`{31b2f340-…}`, reused across the PoCs for consistency).
fn domain_guid() -> [u8; 16] {
    [
        0x40, 0xf3, 0xb2, 0x31, 0x6d, 0x01, 0xd2, 0x11, 0x94, 0x5f, 0x00, 0xc0, 0x4f, 0xb9, 0x84,
        0xf9,
    ]
}

/// Resolve a domain RID to a `(name, SID_NAME_USE)` pair via the directory.
fn resolve_rid(dir: &Directory, rid: u32) -> Option<(String, u16)> {
    dir.resolve_rid(rid).map(|(name, kind)| {
        let use_ = match kind {
            RidKind::User => SID_TYPE_USER,
            RidKind::Group => SID_TYPE_GROUP,
        };
        (name.to_string(), use_)
    })
}

/// The last sub-authority (RID) of each SID in a `LsarLookupSids` request.
fn parse_request_rids(stub: &[u8]) -> Option<Vec<u32>> {
    let mut r = NdrReader::new(stub);
    r.take(20)?; // PolicyHandle
    let entries = r.u32()? as usize;
    let sid_info_ref = r.u32()?; // SidInfo pointer
    if sid_info_ref == 0 || entries == 0 {
        return Some(Vec::new());
    }
    // Conformant array of LSAPR_SID_INFORMATION (each a PRPC_SID pointer).
    let _max_count = r.u32()?;
    for _ in 0..entries {
        r.u32()?; // per-element Sid referent id
    }
    // Deferred RPC_SID referents, in order.
    let mut rids = Vec::with_capacity(entries);
    for _ in 0..entries {
        let sub_count = r.u32()? as usize; // conformant MaxCount = SubAuthorityCount
        let _revision = r.u8()?;
        let _sub_auth_count = r.u8()?;
        r.take(6)?; // IdentifierAuthority
        let mut last = 0;
        for _ in 0..sub_count {
            last = r.u32()?;
        }
        rids.push(last);
    }
    Some(rids)
}

/// `LsarLookupSids` (opnum 15): translate SIDs to names. Response:
/// `ReferencedDomains(ptr), TranslatedNames, MappedCount, ErrorCode`.
fn lookup_sids(dir: &Directory, stub: &[u8]) -> Result<Vec<u8>, u32> {
    let rids = parse_request_rids(stub).ok_or(fault::NDR)?;
    let resolved: Vec<Option<(String, u16)>> =
        rids.iter().map(|&rid| resolve_rid(dir, rid)).collect();
    let mapped = resolved.iter().filter(|r| r.is_some()).count() as u32;

    let mut m = Marshal::new();

    // --- Param 1: ReferencedDomains (PLSAPR_REFERENCED_DOMAIN_LIST, top-level
    // pointer → inline). One referenced domain: our own.
    let list_ref = m.referent();
    m.w.u32(list_ref);
    m.w.u32(1); // Entries
    let domains_ref = m.referent();
    m.w.u32(domains_ref); // Domains pointer
    m.w.u32(1); // MaxEntries
                // Deferred Domains array: MaxCount, then the inline trust-info, then its refs.
    m.w.u32(1); // MaxCount (conformant)
    m.unicode_string(dir.netbios()); // LSAPR_TRUST_INFORMATION.Name
    m.sid_pointer(NT_AUTHORITY, dir.domain_sid().to_vec()); // .Sid
    m.flush();

    // --- Param 2: TranslatedNames (LSAPR_TRANSLATED_NAMES, inline struct).
    m.w.u32(resolved.len() as u32); // Entries
    if resolved.is_empty() {
        m.w.u32(0); // Names: null pointer
    } else {
        let names_ref = m.referent();
        m.w.u32(names_ref); // Names pointer
                            // Deferred Names array: MaxCount, then each LSAPR_TRANSLATED_NAME inline
                            // { Use: enum(u16), Name: RPC_UNICODE_STRING (arm padded to 4), DomainIndex }.
        m.w.u32(resolved.len() as u32); // MaxCount
        for name in &resolved {
            let (n, use_, domain_index) = match name {
                Some((n, u)) => (n.as_str(), *u, 0u32),
                None => ("", SID_TYPE_UNKNOWN, 0xFFFF_FFFF), // DomainIndex = -1 (unmapped)
            };
            m.w.u16(use_); // Use (SID_NAME_USE)
            m.w.align(4); // align the RPC_UNICODE_STRING that follows
            m.unicode_string(n); // Name
            m.w.u32(domain_index); // DomainIndex
        }
        m.flush(); // the Name buffers, in order
    }

    // --- Param 3/4: MappedCount, ErrorCode.
    m.w.u32(mapped);
    let status = if resolved.is_empty() || mapped == resolved.len() as u32 {
        STATUS_SUCCESS
    } else if mapped == 0 {
        STATUS_NONE_MAPPED
    } else {
        STATUS_SOME_NOT_MAPPED
    };
    m.w.u32(status);
    Ok(m.w.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_and_close_return_success() {
        let lsa = LsaInterface::default();
        let open = lsa.call(OP_OPEN_POLICY2, &[]).unwrap();
        assert_eq!(&open[..20], &POLICY_HANDLE, "policy handle returned");
        assert_eq!(&open[20..24], &STATUS_SUCCESS.to_le_bytes());

        let close = lsa.call(OP_CLOSE, &[]).unwrap();
        assert_eq!(&close[..20], &[0u8; 20], "null handle on close");
        assert_eq!(&close[20..24], &STATUS_SUCCESS.to_le_bytes());
    }

    /// Build a QueryInformationPolicy request: handle + info class.
    fn query_stub(info_class: u16) -> Vec<u8> {
        let mut b = vec![0u8; 20];
        b.extend_from_slice(&info_class.to_le_bytes());
        b
    }

    #[test]
    fn query_account_domain_encodes_the_union() {
        let lsa = LsaInterface::default();
        let out = lsa
            .call(OP_QUERY_INFO_POLICY2, &query_stub(POLICY_ACCOUNT_DOMAIN))
            .unwrap();
        // referent(4) + tag(u16) + pad(2) + arm…; tag must be the info class.
        assert_ne!(&out[0..4], &[0u8; 4], "non-null policy-info referent");
        assert_eq!(
            u16::from_le_bytes([out[4], out[5]]),
            POLICY_ACCOUNT_DOMAIN,
            "union discriminant is the info class"
        );
        assert_eq!(&out[6..8], &[0, 0], "arm aligned to 4 (2 pad bytes)");
        // The domain name "EXAMPLE" must appear as UTF-16LE in the deferred buffer.
        let needle: Vec<u8> = "EXAMPLE"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert!(
            out.windows(needle.len()).any(|w| w == needle),
            "domain name present"
        );
        assert_eq!(&out[out.len() - 4..], &STATUS_SUCCESS.to_le_bytes());
    }

    #[test]
    fn query_server_role_pads_arm_to_four() {
        let lsa = LsaInterface::default();
        let out = lsa
            .call(OP_QUERY_INFO_POLICY2, &query_stub(POLICY_LSA_SERVER_ROLE))
            .unwrap();
        assert_eq!(u16::from_le_bytes([out[4], out[5]]), POLICY_LSA_SERVER_ROLE);
        // referent(4)+tag(2)+pad(2)+role(2)+pad(2)+ErrorCode(4) = 16 bytes:
        // impacket aligns the union arm to 4 even for a bare u16.
        assert_eq!(out.len(), 16, "arm padded to the union's 4-byte alignment");
        assert_eq!(u16::from_le_bytes([out[8], out[9]]), SERVER_ROLE_PRIMARY);
        assert_eq!(&out[12..16], &STATUS_SUCCESS.to_le_bytes());
    }

    #[test]
    fn unknown_info_class_returns_null_and_error() {
        let lsa = LsaInterface::default();
        let out = lsa.call(OP_QUERY_INFO_POLICY2, &query_stub(9)).unwrap();
        assert_eq!(&out[0..4], &[0u8; 4], "null policy-info pointer");
        assert_eq!(&out[4..8], &STATUS_INVALID_INFO_CLASS.to_le_bytes());
    }

    /// Build a LookupSids request for the given domain RIDs.
    fn lookup_stub(rids: &[u32]) -> Vec<u8> {
        let mut b = vec![0u8; 20]; // PolicyHandle
        b.extend_from_slice(&(rids.len() as u32).to_le_bytes()); // Entries
        b.extend_from_slice(&0x2000_0000u32.to_le_bytes()); // SidInfo referent
        b.extend_from_slice(&(rids.len() as u32).to_le_bytes()); // MaxCount
        for _ in rids {
            b.extend_from_slice(&0x2000_0004u32.to_le_bytes()); // element referent
        }
        for &rid in rids {
            let subs = [21u32, 1, 2, 3, rid];
            b.extend_from_slice(&(subs.len() as u32).to_le_bytes()); // MaxCount = sub count
            b.push(1); // Revision
            b.push(subs.len() as u8); // SubAuthorityCount
            b.extend_from_slice(&NT_AUTHORITY); // IdentifierAuthority
            for s in subs {
                b.extend_from_slice(&s.to_le_bytes());
            }
        }
        b
    }

    #[test]
    fn parse_request_rids_recovers_the_last_subauthority() {
        let rids = parse_request_rids(&lookup_stub(&[1000, 513])).unwrap();
        assert_eq!(rids, vec![1000, 513]);
    }

    #[test]
    fn lookup_sids_maps_known_rids() {
        let lsa = LsaInterface::default();
        let out = lsa.call(OP_LOOKUP_SIDS, &lookup_stub(&[1000])).unwrap();
        // "alice" must appear UTF-16LE; MappedCount and STATUS_SUCCESS trail.
        let needle: Vec<u8> = "alice".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(
            out.windows(needle.len()).any(|w| w == needle),
            "alice mapped"
        );
        assert_eq!(&out[out.len() - 4..], &STATUS_SUCCESS.to_le_bytes());
        assert_eq!(
            u32::from_le_bytes(out[out.len() - 8..out.len() - 4].try_into().unwrap()),
            1,
            "one SID mapped"
        );
    }

    #[test]
    fn lookup_sids_reports_unmapped() {
        let lsa = LsaInterface::default();
        let out = lsa.call(OP_LOOKUP_SIDS, &lookup_stub(&[4242])).unwrap();
        assert_eq!(
            &out[out.len() - 4..],
            &STATUS_NONE_MAPPED.to_le_bytes(),
            "no RID resolves"
        );
    }
}
