//! PAC (Privilege Attribute Certificate, MS-PAC) generation.
//!
//! Windows carries authorization data (user SID, group membership, …) inside the
//! Kerberos ticket as a PAC embedded in the ticket's `authorization-data`
//! (`AD-IF-RELEVANT` → `AD-WIN2K-PAC`). A PAC is a `PACTYPE` container of buffers:
//!
//! * `KerbValidationInfo` (type 1): `KERB_VALIDATION_INFO`, NDR-marshalled.
//! * `ClientInfo` (type 10): client account name + logon time (raw LE).
//! * `ServerChecksum` (type 6): keyed hash of the whole PAC under the *service*
//!   key.
//! * `KdcChecksum` (type 7): keyed hash of the server checksum under the *krbtgt*
//!   key. This chaining is what lets a KDC detect a forged/edited PAC.
//!
//! For the PoC we emit a minimal-but-valid `KERB_VALIDATION_INFO` (one primary
//! group, a fixed domain SID). Claims, UPN-DNS, device info and the Ticket
//! Signature (type 16) are out of scope.

use crate::error::{KdcError, KdcResult};
use crate::ndr::{unix_to_filetime, NdrWriter, FILETIME_NEVER};
use picky_asn1::wrapper::{ExplicitContextTag0, ExplicitContextTag1, OctetStringAsn1};
use picky_krb::crypto::ChecksumSuite;
use picky_krb::data_types::{AuthorizationData, AuthorizationDataInner};

/// AD-type for `AD-IF-RELEVANT` (RFC 4120 §5.2.6.1).
const AD_IF_RELEVANT: i64 = 1;
/// AD-type for `AD-WIN2K-PAC` (MS-PAC §2.1).
const AD_WIN2K_PAC: i64 = 128;

/// PAC buffer types (MS-PAC §2.4).
const BUF_LOGON_INFO: u32 = 1;
const BUF_CLIENT_INFO: u32 = 10;
const BUF_SERVER_CHECKSUM: u32 = 6;
const BUF_KDC_CHECKSUM: u32 = 7;

/// Signature type for HMAC-SHA1-96-AES256 checksums (RFC 3961 §8).
const SIGNATURE_TYPE_AES256: u32 = 16;
/// Key usage for PAC checksums (`KERB_NON_KERB_CKSUM_SALT`, MS-PAC §2.8).
const KEYUSAGE_PAC_CHECKSUM: i32 = 17;
/// AES256 HMAC-SHA1-96 checksum length.
const CHECKSUM_LEN: usize = 12;

/// The 6-byte identifier authority for `S-1-5-*` (NT Authority).
const NT_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];
/// Well-known RID of the `Domain Users` group — every account's default primary
/// group, and always present in the token.
pub const DOMAIN_USERS_RID: u32 = 513;
/// SE_GROUP attributes for a normal, enabled, mandatory group membership
/// (MANDATORY | ENABLED_BY_DEFAULT | ENABLED).
const SE_GROUP_DEFAULT: u32 = 7;

/// The authenticated user's identity that the PAC must carry so Windows builds a
/// per-user access token (its own SID + real group SIDs) instead of a fixed identity.
/// All RIDs are relative to `domain_sid_subauth` (`S-1-5-<subauth...>`).
#[derive(Debug, Clone)]
pub struct PacIdentity {
    /// The user's RID (its SID is `domain_sid ++ [user_rid]`).
    pub user_rid: u32,
    /// The primary group RID (usually [`DOMAIN_USERS_RID`]).
    pub primary_group_rid: u32,
    /// Every group the user belongs to (RIDs), including the primary group. An empty
    /// list emits a zero-length group array.
    pub group_rids: Vec<u32>,
    /// The domain SID's sub-authorities (e.g. `[21, a, b, c]`).
    pub domain_sid_subauth: Vec<u32>,
    /// Optional logon script / profile path / home directory (empty = unset).
    pub logon_script: String,
    pub profile_path: String,
    pub home_directory: String,
}

impl PacIdentity {
    /// A minimal identity: just a RID in the given domain, primary group Domain Users,
    /// and Domain Users as the only group. Used where only the RID is known.
    pub fn minimal(user_rid: u32, domain_sid_subauth: Vec<u32>) -> Self {
        Self {
            user_rid,
            primary_group_rid: DOMAIN_USERS_RID,
            group_rids: vec![DOMAIN_USERS_RID],
            domain_sid_subauth,
            logon_script: String::new(),
            profile_path: String::new(),
            home_directory: String::new(),
        }
    }
}

/// Build a PAC for `client_account` in `realm` carrying `identity` (the user's real
/// RID + group SIDs + domain SID), sealed for a ticket encrypted under `server_key`
/// (the service key) with the KDC signature under `kdc_key` (the krbtgt key).
/// `authtime_unix` is the ticket's auth time in Unix seconds.
///
/// Returns the ready-to-embed `AuthorizationData` (`AD-IF-RELEVANT` wrapping the
/// `AD-WIN2K-PAC`).
pub fn build_pac_authorization_data(
    server_key: &[u8],
    kdc_key: &[u8],
    client_account: &str,
    realm: &str,
    authtime_unix: i64,
    identity: &PacIdentity,
) -> KdcResult<AuthorizationData> {
    let pac = build_pac(
        server_key,
        kdc_key,
        client_account,
        realm,
        authtime_unix,
        identity,
    )?;
    wrap_pac(pac)
}

/// Assemble and sign the raw `PACTYPE` bytes (exposed for interop tooling such as
/// Samba `ndrdump`; the embedded form is [`build_pac_authorization_data`]).
pub fn build_pac(
    server_key: &[u8],
    kdc_key: &[u8],
    client_account: &str,
    realm: &str,
    authtime_unix: i64,
    identity: &PacIdentity,
) -> KdcResult<Vec<u8>> {
    let netbios_domain = netbios_name(realm);
    let logon_filetime = unix_to_filetime(authtime_unix);

    let logon_info =
        encode_kerb_validation_info(client_account, &netbios_domain, logon_filetime, identity);
    let client_info = encode_client_info(client_account, logon_filetime);

    // Signature buffers with the type filled in and the checksum zeroed.
    let zero_sig = |len: usize| {
        let mut b = SIGNATURE_TYPE_AES256.to_le_bytes().to_vec();
        b.extend(std::iter::repeat_n(0u8, len));
        b
    };

    let buffers = vec![
        (BUF_LOGON_INFO, logon_info),
        (BUF_CLIENT_INFO, client_info),
        (BUF_SERVER_CHECKSUM, zero_sig(CHECKSUM_LEN)),
        (BUF_KDC_CHECKSUM, zero_sig(CHECKSUM_LEN)),
    ];
    let (mut pac, offsets) = assemble_pactype(&buffers);

    // Server signature: keyed hash of the entire PAC (sigs still zero) under the
    // service key.
    let server_offset = offsets[2] + 4;
    let server_sig = checksum(server_key, &pac)?;
    pac[server_offset..server_offset + CHECKSUM_LEN].copy_from_slice(&server_sig);

    // KDC signature: keyed hash of the server signature bytes under the krbtgt key.
    let kdc_offset = offsets[3] + 4;
    let kdc_sig = checksum(kdc_key, &server_sig)?;
    pac[kdc_offset..kdc_offset + CHECKSUM_LEN].copy_from_slice(&kdc_sig);

    Ok(pac)
}

/// HMAC-SHA1-96-AES256 keyed checksum with the PAC key usage.
fn checksum(key: &[u8], data: &[u8]) -> KdcResult<Vec<u8>> {
    ChecksumSuite::HmacSha196Aes256
        .hasher()
        .checksum(key, KEYUSAGE_PAC_CHECKSUM, data)
        .map_err(|e| KdcError::Crypto(e.to_string()))
}

/// Assemble a `PACTYPE` from `(type, data)` buffers, 8-byte aligning each buffer.
/// Returns the bytes and each buffer's absolute data offset.
fn assemble_pactype(buffers: &[(u32, Vec<u8>)]) -> (Vec<u8>, Vec<usize>) {
    let align8 = |n: usize| n.div_ceil(8) * 8;
    let n = buffers.len();
    let header_size = 8 + n * 16;

    let mut offsets = Vec::with_capacity(n);
    let mut cursor = align8(header_size);
    for (_, data) in buffers {
        offsets.push(cursor);
        cursor = align8(cursor + data.len());
    }
    let total = cursor;

    let mut out = vec![0u8; total];
    out[0..4].copy_from_slice(&(n as u32).to_le_bytes()); // cBuffers
    out[4..8].copy_from_slice(&0u32.to_le_bytes()); // Version = 0
    for (i, (ty, data)) in buffers.iter().enumerate() {
        let ib = 8 + i * 16;
        out[ib..ib + 4].copy_from_slice(&ty.to_le_bytes());
        out[ib + 4..ib + 8].copy_from_slice(&(data.len() as u32).to_le_bytes());
        out[ib + 8..ib + 16].copy_from_slice(&(offsets[i] as u64).to_le_bytes());
        out[offsets[i]..offsets[i] + data.len()].copy_from_slice(data);
    }
    (out, offsets)
}

/// PAC_CLIENT_INFO (MS-PAC §2.7): ClientId FILETIME + NameLength + Name (UTF-16).
fn encode_client_info(client_account: &str, logon_filetime: u64) -> Vec<u8> {
    let name: Vec<u16> = client_account.encode_utf16().collect();
    let mut b = Vec::new();
    b.extend_from_slice(&logon_filetime.to_le_bytes());
    b.extend_from_slice(&((name.len() * 2) as u16).to_le_bytes());
    for c in &name {
        b.extend_from_slice(&c.to_le_bytes());
    }
    b
}

/// A deferred NDR pointer referent, emitted after the fixed struct.
enum Deferred {
    /// A conformant+varying UTF-16 array (RPC_UNICODE_STRING buffer).
    Utf16(Vec<u16>),
    /// A conformant GROUP_MEMBERSHIP array (RelativeId, Attributes).
    Groups(Vec<(u32, u32)>),
    /// An RPC_SID (identifier authority + sub-authorities).
    Sid([u8; 6], Vec<u32>),
}

/// NDR-marshal `KERB_VALIDATION_INFO` (MS-PAC §2.5) as RPC Type Serialization 1.
fn encode_kerb_validation_info(
    account: &str,
    domain: &str,
    logon_filetime: u64,
    id: &PacIdentity,
) -> Vec<u8> {
    let mut w = NdrWriter::new();
    let mut deferred: Vec<Deferred> = Vec::new();
    let mut next_ref: u32 = 0x0002_0004;

    // Root pointer referent for the top-level PKERB_VALIDATION_INFO.
    w.u32(0x0002_0000);

    // --- fixed part ---
    w.filetime(logon_filetime); // LogonTime
    w.filetime(FILETIME_NEVER); // LogoffTime
    w.filetime(FILETIME_NEVER); // KickOffTime
    w.filetime(logon_filetime); // PasswordLastSet
    w.filetime(0); // PasswordCanChange
    w.filetime(FILETIME_NEVER); // PasswordMustChange

    unicode_string(&mut w, &mut deferred, &mut next_ref, account); // EffectiveName
    unicode_string(&mut w, &mut deferred, &mut next_ref, ""); // FullName
    unicode_string(&mut w, &mut deferred, &mut next_ref, &id.logon_script); // LogonScript
    unicode_string(&mut w, &mut deferred, &mut next_ref, &id.profile_path); // ProfilePath
    unicode_string(&mut w, &mut deferred, &mut next_ref, &id.home_directory); // HomeDirectory
    unicode_string(&mut w, &mut deferred, &mut next_ref, ""); // HomeDirectoryDrive

    w.u16(0); // LogonCount
    w.u16(0); // BadPasswordCount
    w.u32(id.user_rid); // UserId
    w.u32(id.primary_group_rid); // PrimaryGroupId
    w.u32(id.group_rids.len() as u32); // GroupCount
    let groups: Option<Deferred> = if id.group_rids.is_empty() {
        None
    } else {
        Some(Deferred::Groups(
            id.group_rids
                .iter()
                .map(|r| (*r, SE_GROUP_DEFAULT))
                .collect(),
        ))
    };
    pointer(&mut w, &mut deferred, &mut next_ref, groups); // GroupIds
    w.u32(0); // UserFlags
    w.bytes(&[0u8; 16]); // UserSessionKey

    unicode_string(&mut w, &mut deferred, &mut next_ref, ""); // LogonServer
    unicode_string(&mut w, &mut deferred, &mut next_ref, domain); // LogonDomainName
    pointer(
        &mut w,
        &mut deferred,
        &mut next_ref,
        Some(Deferred::Sid(NT_AUTHORITY, id.domain_sid_subauth.clone())),
    ); // LogonDomainId

    w.u32(0); // Reserved1[0]
    w.u32(0); // Reserved1[1]
    w.u32(0x0000_0210); // UserAccountControl (NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD)
    w.u32(0); // SubAuthStatus
    w.filetime(0); // LastSuccessfulILogon
    w.filetime(0); // LastFailedILogon
    w.u32(0); // FailedILogonCount
    w.u32(0); // Reserved3
    w.u32(0); // SidCount
    pointer(&mut w, &mut deferred, &mut next_ref, None); // ExtraSids (null)
    pointer(&mut w, &mut deferred, &mut next_ref, None); // ResourceGroupDomainSid (null)
    w.u32(0); // ResourceGroupCount
    pointer(&mut w, &mut deferred, &mut next_ref, None); // ResourceGroupIds (null)

    // --- deferred referents, in declaration order ---
    for d in deferred {
        match d {
            Deferred::Utf16(chars) => {
                w.u32(chars.len() as u32); // MaxCount
                w.u32(0); // Offset
                w.u32(chars.len() as u32); // ActualCount
                for c in chars {
                    w.u16(c);
                }
            }
            Deferred::Groups(groups) => {
                w.u32(groups.len() as u32); // MaxCount
                for (rid, attrs) in groups {
                    w.u32(rid);
                    w.u32(attrs);
                }
            }
            Deferred::Sid(id_auth, sub) => {
                w.u32(sub.len() as u32); // conformant MaxCount = SubAuthorityCount
                w.u8(1); // Revision
                w.u8(sub.len() as u8); // SubAuthorityCount
                w.bytes(&id_auth); // IdentifierAuthority
                for s in sub {
                    w.u32(s);
                }
            }
        }
    }

    let body = w.into_bytes();
    // RPC Type Serialization 1: common header + private header + body.
    let mut out = Vec::with_capacity(16 + body.len());
    out.extend_from_slice(&[0x01, 0x10, 0x08, 0x00]); // Version, LE, header len 8
    out.extend_from_slice(&[0xcc, 0xcc, 0xcc, 0xcc]); // filler
    out.extend_from_slice(&(body.len() as u32).to_le_bytes()); // ObjectBufferLength
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // filler
    out.extend_from_slice(&body);
    out
}

/// Write an RPC_UNICODE_STRING (Length, MaximumLength, Buffer pointer), queuing
/// the character data as a deferred referent (null pointer for an empty string).
fn unicode_string(w: &mut NdrWriter, deferred: &mut Vec<Deferred>, next_ref: &mut u32, s: &str) {
    let chars: Vec<u16> = s.encode_utf16().collect();
    let byte_len = (chars.len() * 2) as u16;
    w.u16(byte_len); // Length
    w.u16(byte_len); // MaximumLength
    if chars.is_empty() {
        w.u32(0); // null Buffer
    } else {
        w.u32(*next_ref);
        *next_ref += 4;
        deferred.push(Deferred::Utf16(chars));
    }
}

/// Write a pointer field: a fresh referent id (queuing `item`) or null.
fn pointer(
    w: &mut NdrWriter,
    deferred: &mut Vec<Deferred>,
    next_ref: &mut u32,
    item: Option<Deferred>,
) {
    match item {
        Some(d) => {
            w.u32(*next_ref);
            *next_ref += 4;
            deferred.push(d);
        }
        None => w.u32(0),
    }
}

/// Wrap raw PAC bytes as `AD-IF-RELEVANT` → `AD-WIN2K-PAC` authorization data.
fn wrap_pac(pac: Vec<u8>) -> KdcResult<AuthorizationData> {
    // Inner: the AD-WIN2K-PAC element carrying the PAC bytes.
    let inner = AuthorizationData::from(vec![AuthorizationDataInner {
        ad_type: ExplicitContextTag0::from(crate::as_exchange::int(AD_WIN2K_PAC)),
        ad_data: ExplicitContextTag1::from(OctetStringAsn1::from(pac)),
    }]);
    let inner_der = picky_asn1_der::to_vec(&inner).map_err(|e| KdcError::Asn1(e.to_string()))?;

    // Outer: AD-IF-RELEVANT wrapping the inner sequence.
    Ok(AuthorizationData::from(vec![AuthorizationDataInner {
        ad_type: ExplicitContextTag0::from(crate::as_exchange::int(AD_IF_RELEVANT)),
        ad_data: ExplicitContextTag1::from(OctetStringAsn1::from(inner_der)),
    }]))
}

/// Derive a NetBIOS-style domain name from a realm (`EXAMPLE.COM` → `EXAMPLE`).
fn netbios_name(realm: &str) -> String {
    realm.split('.').next().unwrap_or(realm).to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::derive_aes256_key;

    const SERVICE_SALT: &str = "EXAMPLE.COMhostapp.example.com";
    const KRBTGT_SALT: &str = "EXAMPLE.COMkrbtgtEXAMPLE.COM";

    /// A test identity: RID 1000 in S-1-5-21-1-2-3, member of Domain Users + one more.
    fn test_identity() -> PacIdentity {
        PacIdentity {
            user_rid: 1000,
            primary_group_rid: DOMAIN_USERS_RID,
            group_rids: vec![DOMAIN_USERS_RID, 512],
            domain_sid_subauth: vec![21, 1, 2, 3],
            logon_script: String::new(),
            profile_path: String::new(),
            home_directory: String::new(),
        }
    }

    /// Parse the PAC_INFO_BUFFER array: `(type, size, offset)` per buffer.
    fn parse_buffers(pac: &[u8]) -> Vec<(u32, usize, usize)> {
        let n = u32::from_le_bytes(pac[0..4].try_into().unwrap()) as usize;
        (0..n)
            .map(|i| {
                let ib = 8 + i * 16;
                (
                    u32::from_le_bytes(pac[ib..ib + 4].try_into().unwrap()),
                    u32::from_le_bytes(pac[ib + 4..ib + 8].try_into().unwrap()) as usize,
                    u64::from_le_bytes(pac[ib + 8..ib + 16].try_into().unwrap()) as usize,
                )
            })
            .collect()
    }

    fn buffer_offset(pac: &[u8], want_type: u32) -> usize {
        parse_buffers(pac)
            .into_iter()
            .find(|(ty, _, _)| *ty == want_type)
            .map(|(_, _, off)| off)
            .unwrap_or_else(|| panic!("buffer type {want_type} not found"))
    }

    fn signature(pac: &[u8], buf_type: u32) -> Vec<u8> {
        let off = buffer_offset(pac, buf_type) + 4; // skip SignatureType
        pac[off..off + CHECKSUM_LEN].to_vec()
    }

    #[test]
    fn pactype_layout_is_well_formed() {
        let key = derive_aes256_key("service-secret", SERVICE_SALT).unwrap();
        let krbtgt = derive_aes256_key("krbtgt-secret", KRBTGT_SALT).unwrap();
        let pac = build_pac(
            &key,
            &krbtgt,
            "alice",
            "EXAMPLE.COM",
            1_700_000_000,
            &test_identity(),
        )
        .unwrap();

        // Version field (bytes 4..8) MUST be 0; four buffers of the expected types.
        assert_eq!(&pac[4..8], &[0, 0, 0, 0]);
        let buffers = parse_buffers(&pac);
        let types: Vec<u32> = buffers.iter().map(|(t, _, _)| *t).collect();
        assert_eq!(
            types,
            vec![
                BUF_LOGON_INFO,
                BUF_CLIENT_INFO,
                BUF_SERVER_CHECKSUM,
                BUF_KDC_CHECKSUM
            ]
        );
        // Every buffer sits on an 8-byte boundary and fits inside the blob.
        for (_, size, off) in &buffers {
            assert_eq!(off % 8, 0, "buffer not 8-aligned");
            assert!(off + size <= pac.len(), "buffer overruns the PAC");
        }
        // Both checksum buffers are SignatureType(4) + 12-byte AES256 HMAC.
        for buf in [BUF_SERVER_CHECKSUM, BUF_KDC_CHECKSUM] {
            let off = buffer_offset(&pac, buf);
            assert_eq!(
                u32::from_le_bytes(pac[off..off + 4].try_into().unwrap()),
                SIGNATURE_TYPE_AES256
            );
        }
    }

    #[test]
    fn kdc_signature_chains_from_server_signature() {
        // The chaining rule (MS-PAC §2.8): server sig = H(server_key, PAC with both
        // signatures zeroed); kdc sig = H(krbtgt_key, server_sig).
        let server_key = derive_aes256_key("service-secret", SERVICE_SALT).unwrap();
        let kdc_key = derive_aes256_key("krbtgt-secret", KRBTGT_SALT).unwrap();
        let pac = build_pac(
            &server_key,
            &kdc_key,
            "alice",
            "EXAMPLE.COM",
            1_700_000_000,
            &test_identity(),
        )
        .unwrap();

        let server_sig = signature(&pac, BUF_SERVER_CHECKSUM);
        let kdc_sig = signature(&pac, BUF_KDC_CHECKSUM);

        // Re-zero both signature fields and recompute the server signature.
        let mut zeroed = pac.clone();
        for buf in [BUF_SERVER_CHECKSUM, BUF_KDC_CHECKSUM] {
            let off = buffer_offset(&zeroed, buf) + 4;
            zeroed[off..off + CHECKSUM_LEN].fill(0);
        }
        assert_eq!(
            server_sig,
            checksum(&server_key, &zeroed).unwrap(),
            "server signature must hash the zeroed PAC under the service key"
        );
        assert_eq!(
            kdc_sig,
            checksum(&kdc_key, &server_sig).unwrap(),
            "kdc signature must chain from the server signature under the krbtgt key"
        );
    }

    #[test]
    fn authorization_data_is_if_relevant_wrapping_win2k_pac() {
        let key = derive_aes256_key("service-secret", SERVICE_SALT).unwrap();
        let krbtgt = derive_aes256_key("krbtgt-secret", KRBTGT_SALT).unwrap();
        let ad = build_pac_authorization_data(
            &key,
            &krbtgt,
            "alice",
            "EXAMPLE.COM",
            1_700_000_000,
            &test_identity(),
        )
        .unwrap();
        // Outer element is AD-IF-RELEVANT (type 1).
        assert_eq!(
            ad.0[0].ad_type.0.as_unsigned_bytes_be(),
            &[AD_IF_RELEVANT as u8]
        );
        // Its data decodes to an inner AuthorizationData whose element is AD-WIN2K-PAC (128).
        let inner: AuthorizationData = picky_asn1_der::from_bytes(&ad.0[0].ad_data.0 .0).unwrap();
        assert_eq!(
            inner.0[0].ad_type.0.as_unsigned_bytes_be(),
            &[AD_WIN2K_PAC as u8]
        );
        // And that embedded PAC has the four expected buffers.
        let embedded = &inner.0[0].ad_data.0 .0;
        assert_eq!(
            u32::from_le_bytes(embedded[0..4].try_into().unwrap()),
            4,
            "embedded PAC must carry 4 buffers"
        );
    }
}
