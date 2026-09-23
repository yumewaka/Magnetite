//! A minimal DRSUAPI interface (MS-DRSR) — the directory-replication RPC a DC
//! (or a DCSync client) uses. This tracer bullet implements the session
//! handshake and an empty replication cycle:
//!
//! * `IDL_DRSBind` (opnum 0) → a DRS handle + the server's `DRS_EXTENSIONS`.
//! * `IDL_DRSUnbind` (opnum 1) → releases the handle.
//! * `IDL_DRSGetNCChanges` (opnum 3) → a V6 reply carrying the directory users
//!   NEWER than the client's replication cursor as a chained `REPLENTINFLIST`
//!   (each `pNextEntInf` referencing the next, the last null), every object
//!   exposing `sAMAccountName`, `objectSid` and the encrypted `unicodePwd` in the
//!   `REPLENTINFLIST` → `ENTINF` → `ATTRBLOCK` → `ATTR` → `ATTRVAL` structure —
//!   the same object graph a DCSync client walks.
//!
//! The **replication cursor** is honoured: each user carries a USN (its 1-based
//! insertion order), the request's `usnvecFrom.usnHighObjUpdate` filters the reply
//! to only newer objects, and the reply's `usnvecTo.usnHighObjUpdate` reports the
//! new high-water mark. A client that replicates twice sees every object once and
//! then an empty reply (caught up) — real incremental sync. The remaining
//! simplification is `pUpToDateVecSrc` (left null) and server-side paging
//! (`fMoreData` is always 0 — the whole delta ships in one cycle).

use crate::directory::{Directory, Group, ReplMeta, User, RID_POOL_MAX, RID_POOL_SIZE};
use crate::interface::RpcInterface;
use crate::ndr::{NdrReader, NdrWriter};
use crate::request::fault;
use des::cipher::generic_array::GenericArray;
use des::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use des::Des;
use md5::{Digest, Md5};
use std::sync::Arc;

/// DRSUAPI interface UUID (`E3514235-4B06-11D1-AB04-00C04FC2DCD2`, v4.0).
pub const DRSUAPI_UUID: &str = "E3514235-4B06-11D1-AB04-00C04FC2DCD2";

const OP_BIND: u16 = 0;
const OP_UNBIND: u16 = 1;
const OP_GET_NC_CHANGES: u16 = 3;

const STATUS_SUCCESS: u32 = 0;

/// `IDL_DRSGetNCChanges` extended operations (`ulExtendedOp`, MS-DRSR §5.53). A
/// non-zero value turns the replication call into a targeted operation on the object
/// named by `pNC` — a single-object DCSync, an FSMO role transfer, or a RID pool
/// allocation.
pub mod exop {
    /// Normal replication (no extended operation).
    pub const NONE: u32 = 0x0000_0000;
    /// Transfer a generic FSMO role (Schema / Domain Naming / Infrastructure) —
    /// `pNC` names the role object; the source writes `fSMORoleOwner` to the caller.
    pub const FSMO_REQ_ROLE: u32 = 0x0000_0001;
    /// Request a RID allocation pool for the caller's DC (from the RID master).
    pub const FSMO_RID_ALLOC: u32 = 0x0000_0002;
    /// Transfer the RID master role (`pNC` = `CN=RID Manager$,CN=System,<domain>`).
    pub const FSMO_RID_REQ_ROLE: u32 = 0x0000_0003;
    /// Transfer the PDC-emulator role (`pNC` = the domain NC head).
    pub const FSMO_REQ_PDC: u32 = 0x0000_0004;
    /// Relinquish (abandon) a role held by the caller.
    pub const FSMO_ABANDON_ROLE: u32 = 0x0000_0005;
    /// Replicate a single object by GUID (the targeted-DCSync primitive).
    pub const REPL_OBJ: u32 = 0x0000_0006;
    /// Replicate a single object *with* its secrets.
    pub const REPL_SECRETS: u32 = 0x0000_0007;
}

/// The extended-operation result (`ulExtendedRet` / `dwExOpError`, MS-DRSR §5.54).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExOpErr {
    /// `EXOP_ERR_SUCCESS` (1) — the extended operation succeeded.
    Success,
    /// The source DC is not the current owner of the requested role.
    NotOwner,
    /// The source is refusing FSMO role transfers right now.
    RefusingRoles,
    /// Any other `EXOP_ERR_*` code, kept verbatim.
    Other(u32),
}

impl ExOpErr {
    /// Map a raw `ulExtendedRet` to a result code.
    #[must_use]
    pub fn from_raw(v: u32) -> Self {
        match v {
            0x0000_0001 => ExOpErr::Success,
            0x0000_0003 => ExOpErr::NotOwner,
            0x0000_000C => ExOpErr::RefusingRoles,
            other => ExOpErr::Other(other),
        }
    }

    /// Whether the operation succeeded (`EXOP_ERR_SUCCESS`).
    #[must_use]
    pub fn is_success(self) -> bool {
        self == ExOpErr::Success
    }
}

/// One of the five AD operation-master (FSMO) roles, with the extended operation
/// and directory object that request its transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsmoRole {
    /// Schema master (forest-wide). Object: `CN=Schema,CN=Configuration,<root>`.
    Schema,
    /// Domain-naming master (forest-wide). Object: `CN=Partitions,CN=Configuration,<root>`.
    DomainNaming,
    /// PDC emulator (per-domain). Object: the domain NC head.
    PdcEmulator,
    /// RID master (per-domain). Object: `CN=RID Manager$,CN=System,<domain>`.
    RidMaster,
    /// Infrastructure master (per-domain). Object: `CN=Infrastructure,<domain>`.
    Infrastructure,
}

impl FsmoRole {
    /// The `ulExtendedOp` that requests this role's transfer.
    #[must_use]
    pub fn exop(self) -> u32 {
        match self {
            FsmoRole::RidMaster => exop::FSMO_RID_REQ_ROLE,
            FsmoRole::PdcEmulator => exop::FSMO_REQ_PDC,
            FsmoRole::Schema | FsmoRole::DomainNaming | FsmoRole::Infrastructure => {
                exop::FSMO_REQ_ROLE
            }
        }
    }

    /// The DN of the role object whose `fSMORoleOwner` the transfer rewrites, given
    /// the domain NC (`DC=…`) and the Configuration NC (`CN=Configuration,DC=…`).
    #[must_use]
    pub fn object_dn(self, domain_nc: &str, config_nc: &str) -> String {
        match self {
            FsmoRole::Schema => format!("CN=Schema,{config_nc}"),
            FsmoRole::DomainNaming => format!("CN=Partitions,{config_nc}"),
            FsmoRole::PdcEmulator => domain_nc.to_string(),
            FsmoRole::RidMaster => format!("CN=RID Manager$,CN=System,{domain_nc}"),
            FsmoRole::Infrastructure => format!("CN=Infrastructure,{domain_nc}"),
        }
    }
}

/// The fixed 20-byte DRS handle we hand out on bind.
const DRS_HANDLE: [u8; 20] = [
    0x01, 0x00, 0x00, 0x00, // context attributes
    0x4d, 0x41, 0x47, 0x4e, 0x45, 0x54, 0x49, 0x54, 0x45, 0x44, 0x52, 0x53, 0x48, 0x4e, 0x44, 0x4c,
];

/// Well-known RIDs of the groups whose members hold directory-replication rights (the
/// `DS-Replication-Get-Changes[-All]` extended rights in a real AD). A DCSync requester
/// must belong to one of these; this default set mirrors AD's built-ins. A deployment can
/// override it via [`DrsuapiInterface::with_replication_groups`].
const DEFAULT_REPLICATION_GROUP_RIDS: &[u32] = &[
    512, // Domain Admins
    516, // Domain Controllers
    519, // Enterprise Admins
    521, // Read-only Domain Controllers
    544, // Administrators (built-in)
];

/// Normalize an authenticated principal to a bare sAMAccountName for a directory lookup:
/// `DOMAIN\user` → `user`, `user@REALM` → `user`, and a `/`-joined Kerberos name → its
/// first component. Case is preserved (the directory lookup is case-insensitive).
fn normalize_account_name(principal: &str) -> &str {
    let p = principal.trim();
    let p = p.rsplit('\\').next().unwrap_or(p);
    let p = p.split('@').next().unwrap_or(p);
    p.split('/').next().unwrap_or(p)
}

/// The DRSUAPI replication server, replicating from a shared [`Directory`].
pub struct DrsuapiInterface {
    directory: Arc<Directory>,
    /// This source DSA's invocation ID (its replication identity), reported in the
    /// reply header and the up-to-date vector. Defaults to the fixed PoC value;
    /// a DB-backed DC injects its **persistent** ID (stable across restarts) via
    /// [`with_invocation_id`](Self::with_invocation_id) so a partner never sees a USN
    /// rollback.
    invocation_id: [u8; 16],
    /// Whether this DC holds the **RID master** role. Only the RID master may grant
    /// RID pools (`EXOP_FSMO_RID_ALLOC`); a replica must refuse so two DCs never hand
    /// out overlapping pools. Defaults to `true` (a single-master / standalone DC);
    /// a multi-DC deployment sets it per node via
    /// [`with_rid_master`](Self::with_rid_master).
    is_rid_master: bool,
    /// Group RIDs whose members are authorized to run DCSync (GetNCChanges). Defaults to
    /// [`DEFAULT_REPLICATION_GROUP_RIDS`]; a low-privilege authenticated user in none of
    /// these is refused, closing the "authenticated ⇒ can DCSync" hole.
    replication_group_rids: Vec<u32>,
}

impl Default for DrsuapiInterface {
    fn default() -> Self {
        Self::new(Arc::new(Directory::default()))
    }
}

impl DrsuapiInterface {
    /// A DRSUAPI server replicating objects from `directory`.
    pub fn new(directory: Arc<Directory>) -> Self {
        Self {
            directory,
            invocation_id: DSA_INVOCATION_ID,
            is_rid_master: true,
            replication_group_rids: DEFAULT_REPLICATION_GROUP_RIDS.to_vec(),
        }
    }

    /// Override the group RIDs whose members may run DCSync (default:
    /// [`DEFAULT_REPLICATION_GROUP_RIDS`]).
    #[must_use]
    pub fn with_replication_groups(mut self, group_rids: Vec<u32>) -> Self {
        self.replication_group_rids = group_rids;
        self
    }

    /// Whether `principal` is authorized to run DCSync: it must resolve to a directory
    /// account that is a member of a replication-privileged group. An unresolvable
    /// principal (e.g. an unknown account) is refused — fail-closed.
    fn is_authorized_for_replication(&self, principal: &str) -> bool {
        let name = normalize_account_name(principal);
        let Some(user) = self.directory.find_user(name) else {
            return false;
        };
        self.replication_group_rids.iter().any(|&rid| {
            self.directory
                .group_members(rid)
                .is_some_and(|members| members.contains(&user.rid))
        })
    }

    /// Set whether this DC holds the RID master role. A non-master (`false`) refuses
    /// `EXOP_FSMO_RID_ALLOC` with `EXOP_ERR_FSMO_NOT_OWNER` so the requester goes to
    /// the real master instead of getting a pool that could overlap the master's.
    #[must_use]
    pub fn with_rid_master(mut self, is_rid_master: bool) -> Self {
        self.is_rid_master = is_rid_master;
        self
    }

    /// Use `invocation_id` as this source DSA's replication identity — the persistent
    /// per-store ID from `magnetite-db` (`dsa_invocation_id`). Injected rather than
    /// read from a DB here so this crate keeps no DB dependency.
    #[must_use]
    pub fn with_invocation_id(mut self, invocation_id: [u8; 16]) -> Self {
        self.invocation_id = invocation_id;
        self
    }
}

impl RpcInterface for DrsuapiInterface {
    fn call(&self, opnum: u16, stub: &[u8]) -> Result<Vec<u8>, u32> {
        self.call_with_session(opnum, stub, None)
    }

    fn call_with_session(
        &self,
        opnum: u16,
        stub: &[u8],
        session_key: Option<&[u8]>,
    ) -> Result<Vec<u8>, u32> {
        match opnum {
            OP_BIND => Ok(bind_response()),
            OP_UNBIND => Ok(unbind_response()),
            // The request stub carries the client's replication cursor (usnvecFrom);
            // the secret is encrypted under the negotiated session key when the bind
            // was authenticated, otherwise the fixed PoC key. No principal is known on
            // this lower-level entry (the server routes through `call_authenticated`,
            // which supplies and enforces it); the audit records `<unauthenticated>`.
            OP_GET_NC_CHANGES => Ok(get_nc_changes_response(
                &self.directory,
                stub,
                session_key,
                &self.invocation_id,
                self.is_rid_master,
                None,
            )),
            _ => Err(fault::OP_RNG_ERROR),
        }
    }

    fn call_authenticated(
        &self,
        opnum: u16,
        stub: &[u8],
        session_key: Option<&[u8]>,
        principal: Option<&str>,
    ) -> Result<Vec<u8>, u32> {
        // DCSync replicates credentials, so it MUST be attributable: refuse an
        // unauthenticated caller (no bound principal), and record who invoked it.
        if opnum == OP_GET_NC_CHANGES {
            let Some(principal) = principal else {
                tracing::warn!(
                    target: "auth", proto = "drsuapi",
                    "DRSUAPI IDL_DRSGetNCChanges REFUSED: unauthenticated bind (DCSync requires an authenticated principal)"
                );
                return Err(fault::ACCESS_DENIED);
            };
            // Authorization: authentication is necessary but not sufficient — the
            // principal must hold replication rights (be in a replication-privileged
            // group), else any low-privilege domain user could dump credentials.
            if !self.is_authorized_for_replication(principal) {
                tracing::warn!(
                    target: "auth", proto = "drsuapi", principal,
                    "DRSUAPI IDL_DRSGetNCChanges REFUSED: principal not authorized for replication (not in a replication-privileged group)"
                );
                return Err(fault::ACCESS_DENIED);
            }
            return Ok(get_nc_changes_response(
                &self.directory,
                stub,
                session_key,
                &self.invocation_id,
                self.is_rid_master,
                Some(principal),
            ));
        }
        self.call_with_session(opnum, stub, session_key)
    }
}

/// The 52-byte `DRS_EXTENSIONS_INT` blob advertised in the bind reply: dwFlags,
/// SiteObjGuid[16], Pid, dwReplEpoch, dwFlagsExt, ConfigObjGUID[16], dwExtCaps.
fn drs_extensions_int() -> [u8; 52] {
    let mut e = [0u8; 52];
    // dwFlags: advertise GetNCChanges V6 reply support (DRS_EXT_GETCHGREPLY_V6).
    e[0..4].copy_from_slice(&0x0400_0000u32.to_le_bytes());
    e
}

/// `IDL_DRSBind` response: `ppextServer` (pointer → DRS_EXTENSIONS) + `phDrs`
/// (20-byte handle) + ErrorCode.
fn bind_response() -> Vec<u8> {
    let ext = drs_extensions_int();
    let mut w = NdrWriter::new();
    w.u32(0x0002_0000); // ppextServer referent (top-level pointer → inline)
                        // DRS_EXTENSIONS { cb, rgb[cb] }: the conformant array's MaxCount hoists to
                        // the front of the struct, ahead of `cb`.
    w.u32(ext.len() as u32); // MaxCount (= cb)
    w.u32(ext.len() as u32); // cb
    w.bytes(&ext); // rgb
    w.bytes(&DRS_HANDLE); // phDrs
    w.u32(STATUS_SUCCESS); // ErrorCode
    w.into_bytes()
}

/// `IDL_DRSUnbind` response: a null handle + ErrorCode.
fn unbind_response() -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.bytes(&[0u8; 20]); // phDrs (nulled)
    w.u32(STATUS_SUCCESS); // ErrorCode
    w.into_bytes()
}

// Well-known ATTRTYP (attid) values, from the default MS attribute prefix (arc
// 1.2.840.113556.1.4.x): high 16 bits = prefix index 9, low 16 = OID tail.
const ATTID_SAMACCOUNTNAME: u32 = 0x0009_00DD; // OID …4.221
const ATTID_OBJECTSID: u32 = 0x0009_0092; // OID …4.146
const ATTID_UNICODEPWD: u32 = 0x0009_005A; // OID …4.90
const ATTID_OBJECTCLASS: u32 = 0x0000_0000; // OID 2.5.4.0
const ATTID_INSTANCETYPE: u32 = 0x0002_0001;
const ATTID_NAME: u32 = 0x0009_0001; // the RDN mirror
const ATTID_CN: u32 = 0x0000_0003; // OID 2.5.4.3 — the RDN attribute for CN=… DNs
const ATTID_USERACCOUNTCONTROL: u32 = 0x0009_0008; // OID …4.8
const ATTID_ISDELETED: u32 = 0x0009_01A1; // OID …4.417 (tombstone marker)

const ATTID_OBJECTCATEGORY: u32 = 0x0009_030e; // OID …4.782
const ATTID_NTSECURITYDESCRIPTOR: u32 = 0x0002_0119;

// Attids used only to CLASSIFY a generically-projected object (presence check), and a
// couple of string attributes rendered by the generic projection. All derive from a
// verified prefix index (0 = 2.5.4.x, 2 = 1.2.840.113556.1.2.x, 9 = 1.2.840.113556.1.4.x)
// so no attid is guessed — a wrong attid would project a value under the wrong name.
const ATTID_DESCRIPTION: u32 = 0x0000_000D; // OID 2.5.4.13
const ATTID_LDAPDISPLAYNAME: u32 = 0x0002_01CC; // OID 1.2.840.113556.1.2.460
const ATTID_ATTRIBUTEID: u32 = 0x0002_001E; // OID 1.2.840.113556.1.2.30 (attributeSchema marker)
const ATTID_GOVERNSID: u32 = 0x0002_0016; // OID 1.2.840.113556.1.2.22 (classSchema marker)
const ATTID_NCNAME: u32 = 0x0002_0010; // OID 1.2.840.113556.1.2.16 (crossRef marker)
                                       // Schema-object int/bool attributes (verified present on real Samba attributeSchema).
const ATTID_OMSYNTAX: u32 = 0x0002_00E7; // OID 1.2.840.113556.1.2.231 (integer)
const ATTID_ISSINGLEVALUED: u32 = 0x0002_0021; // OID 1.2.840.113556.1.2.33 (boolean)
const ATTID_SEARCHFLAGS: u32 = 0x0002_014E; // OID 1.2.840.113556.1.2.334 (integer)
const ATTID_SYSTEMFLAGS: u32 = 0x0009_0177; // OID 1.2.840.113556.1.4.375 (integer)
const ATTID_SYSTEMONLY: u32 = 0x0009_00AA; // OID 1.2.840.113556.1.4.170 (boolean)
const ATTID_RIDALLOCATIONPOOL: u32 = 0x0009_015c; // OID …4.348
const ATTID_RIDAVAILABLEPOOL: u32 = 0x0009_0172; // OID …4.370 (RID Manager$ watermark)

/// The schema `Person` class objectGUID — the `defaultObjectCategory` a replicated
/// `user` points its `objectCategory` at. (Well-known-ish; captured from the test DC.)
const PERSON_CLASS_GUID: [u8; 16] = [
    0x6a, 0xe5, 0x0c, 0x01, 0x63, 0x25, 0x34, 0x4c, 0xbc, 0x55, 0x98, 0x46, 0xf2, 0xb9, 0x29, 0x14,
];

/// Decode a UTF-16LE byte string (a DRS Unicode-string attribute value) to a `String`,
/// lossily replacing any unpaired surrogate. A trailing odd byte is ignored.
fn utf16le_to_string(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Decode the DN (`StringName`) out of a flat `DSNAME` attribute value (the inverse of
/// [`encode_flat_dsname`]): `structLen`(4), `SidLen`(4), GUID(16), Sid(28), `NameLen`(4),
/// then `NameLen` UTF-16LE code units. `None` if the blob is too short or truncated. Used
/// to render DN-valued attributes (e.g. `objectCategory`) for generic projection.
fn decode_dsname_dn(value: &[u8]) -> Option<String> {
    const NAME_LEN_OFFSET: usize = 52; // 4 + 4 + 16 + 28
    const NAME_OFFSET: usize = 56;
    let name_len =
        u32::from_le_bytes(value.get(NAME_LEN_OFFSET..NAME_OFFSET)?.try_into().ok()?) as usize;
    let end = NAME_OFFSET.checked_add(name_len.checked_mul(2)?)?;
    let s = utf16le_to_string(value.get(NAME_OFFSET..end)?);
    Some(s.trim_end_matches('\0').to_string())
}

/// Encode a flat `DSNAME` attribute value (the on-wire form of a DN-valued attribute
/// such as `objectCategory`): `structLen`, `SidLen`=0, the object GUID, a 28-byte zero
/// SID, `NameLen`, then the DN as NUL-terminated UTF-16LE.
fn encode_flat_dsname(guid: &[u8; 16], dn: &str) -> Vec<u8> {
    let chars: Vec<u16> = dn.encode_utf16().collect();
    let struct_len = 56 + 2 * (chars.len() + 1);
    let mut v = Vec::with_capacity(struct_len);
    v.extend_from_slice(&(struct_len as u32).to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes()); // SidLen
    v.extend_from_slice(guid);
    v.extend_from_slice(&[0u8; 28]); // Sid
    v.extend_from_slice(&(chars.len() as u32).to_le_bytes());
    for c in &chars {
        v.extend_from_slice(&c.to_le_bytes());
    }
    v.extend_from_slice(&0u16.to_le_bytes()); // NUL
    v
}

/// A flat DSNAME blob (as [`encode_flat_dsname`]) that ALSO embeds `sid` — the on-wire
/// target of a linked value (a group `member`), so a consumer resolves the member by
/// its SID (its RID is the last sub-authority). `sid` is left-aligned in the 28-byte
/// NT4SID buffer with `SidLen` set.
fn encode_flat_dsname_sid(guid: &[u8; 16], sid: &[u8], dn: &str) -> Vec<u8> {
    let chars: Vec<u16> = dn.encode_utf16().collect();
    let struct_len = 56 + 2 * (chars.len() + 1);
    let sid_len = sid.len().min(28);
    let mut sid_buf = [0u8; 28];
    sid_buf[..sid_len].copy_from_slice(&sid[..sid_len]);
    let mut v = Vec::with_capacity(struct_len);
    v.extend_from_slice(&(struct_len as u32).to_le_bytes());
    v.extend_from_slice(&(sid_len as u32).to_le_bytes()); // SidLen
    v.extend_from_slice(guid);
    v.extend_from_slice(&sid_buf); // Sid (NT4SID, 28 bytes)
    v.extend_from_slice(&(chars.len() as u32).to_le_bytes());
    for c in &chars {
        v.extend_from_slice(&c.to_le_bytes());
    }
    v.extend_from_slice(&0u16.to_le_bytes()); // NUL
    v
}

/// A minimal self-relative `SECURITY_DESCRIPTOR` (owner/group = Local System, a DACL
/// with one ACCESS_ALLOWED ACE granting Everyone full control) — every AD object MUST
/// carry an `nTSecurityDescriptor`; a consumer accepts any well-formed SD.
fn minimal_security_descriptor() -> Vec<u8> {
    let sid_system: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]; // S-1-5-18
    let sid_everyone: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]; // S-1-1-0
                                                                       // DACL: header(8) + one ACCESS_ALLOWED_ACE (type/flags/size/mask + SID).
    let mut ace = vec![0u8, 0]; // type=ACCESS_ALLOWED, flags=0
    let ace_size = 8 + sid_everyone.len();
    ace.extend_from_slice(&(ace_size as u16).to_le_bytes());
    ace.extend_from_slice(&0x000F_01FFu32.to_le_bytes()); // full control
    ace.extend_from_slice(&sid_everyone);
    let acl_size = 8 + ace.len();
    let mut dacl = vec![2u8, 0]; // AclRevision=2, Sbz1=0
    dacl.extend_from_slice(&(acl_size as u16).to_le_bytes());
    dacl.extend_from_slice(&1u16.to_le_bytes()); // AceCount
    dacl.extend_from_slice(&0u16.to_le_bytes()); // Sbz2
    dacl.extend_from_slice(&ace);

    let header = 20;
    let off_dacl = header;
    let off_owner = off_dacl + dacl.len();
    let off_group = off_owner + sid_system.len();
    let mut sd = Vec::new();
    sd.push(1); // Revision
    sd.push(0); // Sbz1
    sd.extend_from_slice(&0x8004u16.to_le_bytes()); // Control: SELF_RELATIVE | DACL_PRESENT
    sd.extend_from_slice(&(off_owner as u32).to_le_bytes());
    sd.extend_from_slice(&(off_group as u32).to_le_bytes());
    sd.extend_from_slice(&0u32.to_le_bytes()); // OffsetSacl (none)
    sd.extend_from_slice(&(off_dacl as u32).to_le_bytes());
    sd.extend_from_slice(&dacl);
    sd.extend_from_slice(&sid_system);
    sd.extend_from_slice(&sid_system);
    sd
}

/// `objectClass` governsID values for a `user`, derived→base (the order a source
/// replicates them): user, organizationalPerson, person, top — each a 4-byte ATTRTYP
/// resolved through the prefix table (2.5.6.* = index 1; 1.2.840.113556.1.5.* = index 10).
fn user_object_class() -> Vec<Vec<u8>> {
    [0x000A_0009u32, 0x0001_0007, 0x0001_0006, 0x0001_0000]
        .iter()
        .map(|g| g.to_le_bytes().to_vec())
        .collect()
}

/// `objectClass` governsID values for a `group`, derived→base: the AD `group` class
/// (OID 1.2.840.113556.1.5.8 → `0x000A0008`, prefix index 10) then top (2.5.6.0). NOTE:
/// `0x0001_0009` (2.5.6.9) is the X.500 `groupOfNames`, NOT the AD security-group class —
/// a real consumer (Samba) that reads the governsID literally then creates the wrong
/// class, so the AD `group` governsID must be used.
fn group_object_class() -> Vec<Vec<u8>> {
    [0x000A_0008u32, 0x0001_0000]
        .iter()
        .map(|g| g.to_le_bytes().to_vec())
        .collect()
}

/// The AD `group` classSchema `schemaIDGUID` (`bf967a9c-0de6-11d0-a285-00aa003049e2`)
/// in `objectGUID` binary form — the `objectCategory` a replicated group carries.
const GROUP_CLASS_GUID: [u8; 16] = [
    0x9c, 0x7a, 0x96, 0xbf, 0xe6, 0x0d, 0xd0, 0x11, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2,
];

/// A global security group's `groupType`: `GROUP_TYPE_ACCOUNT_GROUP` (0x2, global) |
/// `GROUP_TYPE_SECURITY_ENABLED` (0x8000_0000).
const GROUP_TYPE_GLOBAL_SECURITY: u32 = 0x8000_0002;

const ATTID_SUPPLEMENTALCREDENTIALS: u32 = 0x0009_007D; // OID …4.125
const ATTID_GROUPTYPE: u32 = 0x0009_02EE; // OID …4.750 — present only on `group` objects

// --- DRSUAPI replicated-secret encryption (MS-DRSR §5.16.4) ---
//
// A DCSync client recovers a password hash by (1) RC4-decrypting the attribute
// value with `MD5(sessionKey ‖ salt)`, then (2) removing a DES-per-RID layer.
// We produce the inverse so an authenticated replication client sees the hash.
//
// The RPC session key is normally the authenticated bind's key; this PoC binds
// unauthenticated, so we encrypt under a known shared key `SECRET_SESSION_KEY`
// (the validation client decrypts with the same key). Wiring the real
// RPC-negotiated session key is the remaining step.

/// The shared session key the PoC encrypts replicated secrets under.
const SECRET_SESSION_KEY: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
/// The fixed 16-byte salt (a real DC randomizes this per value).
const SECRET_SALT: [u8; 16] = [0xAA; 16];

/// RC4 stream cipher (symmetric — encryption and decryption are the same op).
fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) & 0xff;
        s.swap(i, j);
    }
    let (mut i, mut j) = (0usize, 0usize);
    let mut out = Vec::with_capacity(data.len());
    for &byte in data {
        i = (i + 1) & 0xff;
        j = (j + s[i] as usize) & 0xff;
        s.swap(i, j);
        let k = s[(s[i] as usize + s[j] as usize) & 0xff];
        out.push(byte ^ k);
    }
    out
}

/// Standard IEEE CRC-32 (matches Python `binascii.crc32`).
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// The MS-DRSR 7→8 byte DES key expansion (impacket `transformKey`): spread 7
/// bytes across 8 (leaving a parity bit), then shift each left by one.
fn transform_key(input: &[u8; 7]) -> [u8; 8] {
    let i = input;
    let mut o = [0u8; 8];
    o[0] = i[0] >> 1;
    o[1] = ((i[0] & 0x01) << 6) | (i[1] >> 2);
    o[2] = ((i[1] & 0x03) << 5) | (i[2] >> 3);
    o[3] = ((i[2] & 0x07) << 4) | (i[3] >> 4);
    o[4] = ((i[3] & 0x0F) << 3) | (i[4] >> 5);
    o[5] = ((i[4] & 0x1F) << 2) | (i[5] >> 6);
    o[6] = ((i[5] & 0x3F) << 1) | (i[6] >> 7);
    o[7] = i[6] & 0x7F;
    for b in &mut o {
        *b = (*b << 1) & 0xFE;
    }
    o
}

/// Derive the two DES keys from a RID (MS-DRSR §2.2.11.1.3).
fn derive_des_keys(rid: u32) -> ([u8; 8], [u8; 8]) {
    let k = rid.to_le_bytes();
    let k1 = [k[0], k[1], k[2], k[3], k[0], k[1], k[2]];
    let k2 = [k[3], k[0], k[1], k[2], k[3], k[0], k[1]];
    (transform_key(&k1), transform_key(&k2))
}

/// DES-ECB encrypt one 8-byte block.
fn des_encrypt_block(key: &[u8; 8], block: &[u8; 8]) -> [u8; 8] {
    let cipher = Des::new(GenericArray::from_slice(key));
    let mut b = *GenericArray::from_slice(block);
    cipher.encrypt_block(&mut b);
    b.into()
}

/// Apply the DES-per-RID layer to a 16-byte hash — the inverse of impacket's
/// `removeDESLayer`.
fn des_encrypt_hash(hash: &[u8; 16], rid: u32) -> [u8; 16] {
    let (k1, k2) = derive_des_keys(rid);
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&des_encrypt_block(&k1, hash[..8].try_into().unwrap()));
    out[8..].copy_from_slice(&des_encrypt_block(&k2, hash[8..].try_into().unwrap()));
    out
}

/// Wrap a replicated secret (MS-DRSR §5.16.4): `salt ‖ RC4(MD5(sessionKey ‖
/// salt)).encrypt(CRC32(data) ‖ data)`.
fn drs_encrypt_value(session_key: &[u8], salt: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let mut md5 = Md5::new();
    md5.update(session_key);
    md5.update(salt);
    let rc4_key = md5.finalize();

    let mut inner = Vec::with_capacity(4 + data.len());
    inner.extend_from_slice(&crc32(data).to_le_bytes());
    inner.extend_from_slice(data);

    let mut out = salt.to_vec();
    out.extend_from_slice(&rc4(&rc4_key, &inner));
    out
}

/// The encrypted `unicodePwd` value for a user: the NT hash under the DES-per-RID
/// layer, then the DRS secret wrap under `session_key`.
fn encrypted_unicode_pwd(nt_hash: &[u8; 16], rid: u32, session_key: &[u8]) -> Vec<u8> {
    let des_hash = des_encrypt_hash(nt_hash, rid);
    drs_encrypt_value(session_key, &SECRET_SALT, &des_hash)
}

// --- DRSUAPI replicated-secret DECRYPTION (the inbound/consumer inverse, Tier C
// C1) — the operations a real DCSync client performs, so magnetite can be a
// replication *destination* and recover a hash a source DC sends. ---

/// DES-ECB decrypt one 8-byte block (the inverse of [`des_encrypt_block`]).
fn des_decrypt_block(key: &[u8; 8], block: &[u8; 8]) -> [u8; 8] {
    let cipher = Des::new(GenericArray::from_slice(key));
    let mut b = *GenericArray::from_slice(block);
    cipher.decrypt_block(&mut b);
    b.into()
}

/// Remove the DES-per-RID layer from a 16-byte hash (impacket `removeDESLayer`);
/// the inverse of [`des_encrypt_hash`].
fn des_decrypt_hash(hash: &[u8; 16], rid: u32) -> [u8; 16] {
    let (k1, k2) = derive_des_keys(rid);
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&des_decrypt_block(&k1, hash[..8].try_into().unwrap()));
    out[8..].copy_from_slice(&des_decrypt_block(&k2, hash[8..].try_into().unwrap()));
    out
}

/// Unwrap a replicated secret (MS-DRSR §5.16.4): read the 16-byte `salt`,
/// RC4-decrypt the rest with `MD5(sessionKey ‖ salt)`, and verify the leading
/// CRC32. Returns the plaintext data (without the CRC), or `None` on a malformed
/// value or CRC mismatch. The inverse of [`drs_encrypt_value`].
fn drs_decrypt_value(session_key: &[u8], wrapped: &[u8]) -> Option<Vec<u8>> {
    if wrapped.len() < 16 + 4 {
        return None;
    }
    let (salt, enc) = wrapped.split_at(16);
    let mut md5 = Md5::new();
    md5.update(session_key);
    md5.update(salt);
    let rc4_key = md5.finalize();
    let inner = rc4(&rc4_key, enc); // RC4 is symmetric
    let (crc, data) = inner.split_at(4);
    let expected = u32::from_le_bytes(crc.try_into().ok()?);
    if crc32(data) != expected {
        return None; // wrong session key or corrupted value
    }
    Some(data.to_vec())
}

/// Recover a user's NT hash from an encrypted `unicodePwd` replication value: DRS
/// unwrap under `session_key`, then remove the DES-per-RID layer. `None` if the
/// value is malformed or the session key is wrong. The inverse of
/// [`encrypted_unicode_pwd`].
///
/// This is the consumer-side operation a replication destination performs, exposed
/// so the inbound-apply path (Tier C C1) can decode a source DC's secrets.
pub fn decrypt_unicode_pwd(value: &[u8], rid: u32, session_key: &[u8]) -> Option<[u8; 16]> {
    let des_hash = drs_decrypt_value(session_key, value)?;
    let des_hash: [u8; 16] = des_hash.try_into().ok()?;
    Some(des_decrypt_hash(&des_hash, rid))
}

/// A replicated attribute: its attid and one or more raw values.
struct ReplAttr {
    attid: u32,
    values: Vec<Vec<u8>>,
}

/// A user's object SID in binary form: the domain SID's sub-authorities plus the
/// user RID (e.g. `S-1-5-21-1-2-3-1000`). Padded to the fixed 28-byte NT4SID.
fn user_sid(domain_sid: &[u32], rid: u32) -> Vec<u8> {
    let subs: Vec<u32> = domain_sid
        .iter()
        .copied()
        .chain(std::iter::once(rid))
        .collect();
    let mut s = vec![1u8, subs.len() as u8, 0, 0, 0, 0, 0, 5]; // Revision, count, NT authority
    for sub in &subs {
        s.extend_from_slice(&sub.to_le_bytes());
    }
    s // 8 + subauth_count×4 bytes
}

/// UTF-16LE encoding of `s` (the on-wire form of a string attribute value).
fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// Emit a `DSNAME` referent (the object's distinguished name carrier): the
/// hoisted conformant `StringName` MaxCount, then structLen/SidLen/Guid/Sid/
/// NameLen/StringName. `Sid` is a fixed 28-byte buffer even when unused.
fn encode_dsname(w: &mut NdrWriter, guid: &[u8; 16], sid: &[u8], name: &str) {
    let chars: Vec<u16> = name.encode_utf16().collect();
    let max_count = chars.len() + 1; // StringName includes the NUL terminator
    let struct_len = 4 + 4 + 4 + 16 + 28 + 4 + 2 * max_count; // incl. hoisted MaxCount
                                                              // The NT4SID is a fixed 28-byte buffer with SidLen valid bytes; a consumer
                                                              // (Samba) reads the object's RID from its last sub-authority to strip the
                                                              // DES-per-RID layer off secret attributes, so the identifier MUST carry the SID.
    let sid_len = sid.len().min(28);
    let mut sid_buf = [0u8; 28];
    sid_buf[..sid_len].copy_from_slice(&sid[..sid_len]);
    w.u32(max_count as u32); // conformant MaxCount (hoisted to struct front)
    w.u32(struct_len as u32); // structLen
    w.u32(sid_len as u32); // SidLen
    w.bytes(guid); // Guid[16]
    w.bytes(&sid_buf); // Sid (NT4SID, fixed 28 bytes)
    w.u32(chars.len() as u32); // NameLen
    for c in &chars {
        w.u16(*c);
    }
    w.u16(0); // StringName NUL terminator
    w.align(4);
}

/// One object to replicate: its objectGUID, name and attributes.
struct ReplObject {
    guid: [u8; 16],
    name: String,
    /// The object's binary `objectSid` (little-endian sub-authorities), embedded in
    /// the identifier DSNAME so a consumer can recover the RID for secret decryption.
    sid: Vec<u8>,
    attrs: Vec<ReplAttr>,
    /// The object's LOCAL USN (this DC's stream position), used as the fallback
    /// `usnOriginating` and for delta filtering when no real stamp is present.
    usn: i64,
    /// The change's real replication stamp (origin DSA/version/time/USN). When set,
    /// outbound metadata reflects the TRUE origin — essential for multi-master
    /// convergence. `None` ⇒ locally originated: stamp self at version 1 (see below).
    meta: Option<ReplMeta>,
}

/// A fixed originating `DSTIME` (seconds since 1601) stamped on replicated attribute
/// metadata — a plausible recent time; a destination uses it only to break version
/// ties, so an exact value is unnecessary.
const META_TIME: i64 = 13_350_000_000;

/// The MS attribute-prefix OID `1.2.840.113556.1.4` (BER) — index 9 in the prefix
/// table, the prefix every ATTRTYP this source emits (`0x0009_xxxx`) compresses
/// against. Present in [`PREFIX_TABLE`]; kept as a witness for tests.
#[cfg(test)]
const ATTR_PREFIX_OID: [u8; 8] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x14, 0x01, 0x04];

/// The full default AD `SCHEMA_PREFIX_TABLE.pPrefixEntry` deferral (the 42 well-known
/// OID-prefix mappings), captured verbatim from a real Samba GetNCChanges reply. A
/// strict consumer (Samba's `dsdb_schema_pfm_from_drsuapi_pfm`) rejects a partial table
/// with `WERR_INVALID_PARAMETER`, so we ship its own complete table. Layout: hoisted
/// `MaxCount`, 42 inline `{ndx, OID_t.length, elements-ref}`, then each deferred
/// `elements` byte array (`MaxCount`, bytes, 4-aligned).
const PREFIX_TABLE: &[u8] = include_bytes!("../tests/fixtures/prefix_table.bin");

/// The number of entries in [`PREFIX_TABLE`] (`PrefixTableSrc.PrefixCount`).
const PREFIX_TABLE_COUNT: u32 = 42;

/// Emit the reply's `SCHEMA_PREFIX_TABLE.pPrefixEntry` deferral — the full default table
/// verbatim (see [`PREFIX_TABLE`]).
fn encode_prefix_table(w: &mut NdrWriter) {
    w.align(4);
    w.bytes(PREFIX_TABLE);
}

/// Emit a `PROPERTY_META_DATA_EXT_VECTOR` (`pMetaDataExt`): one 40-byte
/// `PROPERTY_META_DATA_EXT` per attribute, ordered parallel to the `AttrBlock`, so a
/// destination stamps each replicated value. Every attribute of one object shares the
/// object's version/time/DSA/USN. `version`/`time_dstime`/`dsa`/`usn` are the change's
/// real origin (from the store) — NOT this DC's identity — so a multi-master peer can
/// order, conflict-resolve, and recognise a change it already holds via any path.
fn encode_metadata_vector(
    w: &mut NdrWriter,
    attr_count: usize,
    version: u32,
    time_dstime: i64,
    dsa: &[u8; 16],
    usn: i64,
) {
    w.u32(attr_count as u32); // hoisted rgMetaData MaxCount
    w.align(8); // the vector struct holds hypers → cNumProps 8-aligned after MaxCount
    w.u32(attr_count as u32); // cNumProps
    w.align(8); // the element array is 8-aligned (each element leads with a hyper)
    for _ in 0..attr_count {
        w.u32(version); // dwVersion
        w.u32(0); // pad (align timeChanged to 8)
        w.bytes(&time_dstime.to_le_bytes()); // timeChanged (DSTIME)
        w.bytes(dsa); // uuidDsaOriginating
        w.bytes(&usn.to_le_bytes()); // usnOriginating
    }
}

/// Emit the `REPLENTINFLIST` chain (the `pObjects` referent target): every object's
/// inline node in forward order — each `pNextEntInf` referencing the next, the last
/// null — then every object's deferred DSNAME + attribute payload in REVERSE order.
///
/// That flat two-pass layout is exactly the byte sequence NDR's depth-first pointer
/// deferral produces for a linked list: marshalling node *N* defers its first
/// pointer (`pNextEntInf` → node *N+1*) ahead of its own `pName`/`pAttr`, so all the
/// inline nodes nest to the front and their payloads unwind from the tail back.
fn encode_objects(w: &mut NdrWriter, objects: &[ReplObject], dsa: &[u8; 16]) {
    let mut next_ref = 0x0003_0000u32;
    let mut referent = |w: &mut NdrWriter| {
        let r = next_ref;
        next_ref += 4;
        w.u32(r);
    };

    // Pass 1 — inline REPLENTINFLIST nodes, forward order. REPLENTINFLIST =
    // pNextEntInf + ENTINF{pName, ulFlags, AttrBlock} + fIsNCPrefix + pParentGuid
    // + pMetaDataExt.
    for (i, obj) in objects.iter().enumerate() {
        if i + 1 < objects.len() {
            referent(w); // pNextEntInf → next node (deferred)
        } else {
            w.u32(0); // pNextEntInf (last object → null)
        }
        referent(w); // Entinf.pName
        w.u32(0); // Entinf.ulFlags
        w.u32(obj.attrs.len() as u32); // AttrBlock.attrCount
        referent(w); // AttrBlock.pAttr
        w.u32(0); // fIsNCPrefix
        w.u32(0); // pParentGuid (null)
        referent(w); // pMetaDataExt (non-null → per-attribute metadata below)
    }

    // Pass 2 — deferred payloads, REVERSE order (the tail node's pName/pAttr are
    // reached first as the deferral stack unwinds).
    for obj in objects.iter().rev() {
        // The object name.
        encode_dsname(w, &obj.guid, &obj.sid, &obj.name);

        // The ATTR array (attrTyp + ATTRVALBLOCK{valCount, pAVal}).
        w.u32(obj.attrs.len() as u32); // conformant MaxCount
        for a in &obj.attrs {
            w.u32(a.attid); // attrTyp
            w.u32(a.values.len() as u32); // AttrVal.valCount
            referent(w); // AttrVal.pAVal
        }

        // Per-attribute deferrals (depth-first): the ATTRVAL array, then each
        // value's byte buffer immediately after it.
        for a in &obj.attrs {
            w.u32(a.values.len() as u32); // ATTRVAL array MaxCount
            for v in &a.values {
                w.u32(v.len() as u32); // valLen
                referent(w); // pVal
            }
            for v in &a.values {
                w.u32(v.len() as u32); // pVal conformant MaxCount
                w.bytes(v);
                w.align(4);
            }
        }

        // Trailing per-node deferrals, in pointer order: pParentGuid (null here) then
        // the pMetaDataExt vector — one entry per attribute. Serve the change's REAL
        // origin when known (a change replicated in from another DSA), else stamp this
        // DC at version 1 (a locally originated / in-memory object).
        let (version, time, meta_dsa, meta_usn) = match &obj.meta {
            Some(m) => (
                m.version,
                m.originating_time,
                &m.originating_dsa,
                m.originating_usn,
            ),
            None => (1, META_TIME, dsa, obj.usn),
        };
        encode_metadata_vector(w, obj.attrs.len(), version, time, meta_dsa, meta_usn);
    }
}

/// One outbound linked value to serve: a group `member` link (source group → target
/// member), present (a membership) or absent (a removed-member tombstone), with its
/// per-link stamp. The inverse of the [`ReplicatedLink`] the inbound decoder produces.
struct LinkVal {
    source_guid: [u8; 16],
    source_sid: Vec<u8>,
    source_dn: String,
    target_guid: [u8; 16],
    target_sid: Vec<u8>,
    target_dn: String,
    /// `true` = present membership; `false` = tombstone (a removed member).
    present: bool,
    /// The link's real origin stamp, or `None` to stamp self at version 1.
    meta: Option<ReplMeta>,
}

/// Emit the `rgValues` deferral: a conformant array of `REPLVALINF_V1` (MS-DRSR
/// §4.1.10.2.13) — the group memberships. Mirrors [`parse_linked_values`]: hoisted
/// `MaxCount`, then per element an inline 72-byte record (`pObject` ref, `attrTyp`=member,
/// `valLen`, `pVal` ref, `fIsPresent`, pad, `timeCreated` + a `PROPERTY_META_DATA_EXT`),
/// then per element the deferred source-group DSNAME and the target `member` value blob
/// (a flat DSNAME carrying the member's GUID + SID). `dsa` stamps each link's metadata.
fn encode_linked_values(w: &mut NdrWriter, links: &[LinkVal], dsa: &[u8; 16]) {
    let mut next_ref = 0x0004_0000u32;
    let mut referent = |w: &mut NdrWriter| {
        let r = next_ref;
        next_ref += 4;
        w.u32(r);
    };
    // Precompute each target's flat-DSNAME value blob (its length is `valLen`).
    let target_blobs: Vec<Vec<u8>> = links
        .iter()
        .map(|l| encode_flat_dsname_sid(&l.target_guid, &l.target_sid, &l.target_dn))
        .collect();

    w.u32(links.len() as u32); // rgValues conformant MaxCount
    w.align(8); // the element array is 8-aligned (each record leads with hypers)

    // Pass 1 — inline REPLVALINF_V1 records. Each carries the link's present/absent
    // flag and its REAL origin stamp (or self/v1), so a member removal replicates and a
    // consumer conflict-resolves per link.
    for (l, blob) in links.iter().zip(&target_blobs) {
        let (version, time, meta_dsa, meta_usn) = match &l.meta {
            Some(m) => (
                m.version,
                m.originating_time,
                &m.originating_dsa,
                m.originating_usn,
            ),
            None => (1, META_TIME, dsa, 0),
        };
        referent(w); // pObject referent (→ source group DSNAME, deferred)
        w.u32(LINK_ATTR_MEMBER); // attrTyp
        w.u32(blob.len() as u32); // Aval.valLen
        referent(w); // Aval.pVal referent (→ target value blob, deferred)
        w.u32(u32::from(l.present)); // fIsPresent (0 = removed-member tombstone)
        w.align(8); // pad before the VALUE_META_DATA_EXT hypers
        w.bytes(&time.to_le_bytes()); // timeCreated (DSTIME)
                                      // PROPERTY_META_DATA_EXT (40): version, pad, timeChanged, uuidDsaOriginating, usn.
        w.u32(version); // dwVersion
        w.u32(0); // pad
        w.bytes(&time.to_le_bytes()); // timeChanged
        w.bytes(meta_dsa); // uuidDsaOriginating
        w.bytes(&meta_usn.to_le_bytes()); // usnOriginating
    }

    // Pass 2 — per element: the source group's DSNAME, then the target value blob.
    for (l, blob) in links.iter().zip(&target_blobs) {
        encode_dsname(w, &l.source_guid, &l.source_sid, &l.source_dn);
        w.u32(blob.len() as u32); // pVal conformant MaxCount (= valLen)
        w.bytes(blob);
        w.align(4);
    }
}

// --- Inbound: DECODE a V6 `IDL_DRSGetNCChanges` reply (Tier C C1) — the inverse
// of `get_nc_changes_response`/`encode_objects`, so magnetite can be a replication
// *destination*. NDR marshalling is deterministic, so this decoder inverts the
// exact byte layout a source DC (or our own encoder) produces for this message. ---

/// The per-attribute replication metadata (`PROPERTY_META_DATA_EXT`, MS-DRSR
/// §5.166) a source stamps on each replicated attribute. Drives version-based
/// conflict resolution: a higher `version` wins; ties break on `originating_time`
/// then `originating_dsa`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttrMetadata {
    /// The attribute value's version — incremented on each originating write.
    pub version: u32,
    /// When the value last changed at its originating DSA (a Windows `FILETIME`-ish
    /// `DSTIME`, seconds since 1601).
    pub originating_time: i64,
    /// The invocation ID of the DSA where the change originated.
    pub originating_dsa: [u8; 16],
    /// The USN the change had at its originating DSA.
    pub originating_usn: i64,
}

impl AttrMetadata {
    /// Whether an attribute value stamped with `self` should overwrite one already
    /// held with stamp `other` (MS-DRSR §5.166 replication conflict resolution): the
    /// higher `version` wins; on a tie the later `originating_time` wins; on a further
    /// tie the higher `originating_dsa` (lexicographic) wins. Equal stamps do not win.
    pub fn wins_over(&self, other: &AttrMetadata) -> bool {
        (self.version, self.originating_time, self.originating_dsa)
            > (other.version, other.originating_time, other.originating_dsa)
    }
}

/// One decoded replicated attribute: its attid, raw values and (when the source
/// sent a `pMetaDataExt` vector) its replication metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicatedAttr {
    /// The attribute type (`ATTRTYP`).
    pub attid: u32,
    /// Its raw on-wire value buffers.
    pub values: Vec<Vec<u8>>,
    /// Per-attribute replication metadata, if the reply carried it.
    pub metadata: Option<AttrMetadata>,
}

/// One decoded replicated object: its GUID, name (DN/RDN string) and attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicatedObject {
    /// `objectGUID`.
    pub guid: [u8; 16],
    /// The object's name string (from its `DSNAME`).
    pub name: String,
    /// The replicated attributes.
    pub attrs: Vec<ReplicatedAttr>,
}

impl ReplicatedObject {
    /// The first value of attribute `attid`, if present.
    fn attr(&self, attid: u32) -> Option<&[u8]> {
        self.attrs
            .iter()
            .find(|a| a.attid == attid)
            .and_then(|a| a.values.first())
            .map(|v| v.as_slice())
    }

    /// The granted `rIDAllocationPool` decoded as `(first_rid, count)`, if this object
    /// carries one — the RID pool a RID master returns for `EXOP_FSMO_RID_ALLOC`. The
    /// wire value is a LARGE_INTEGER `(last_rid << 32) | first_rid`.
    pub fn rid_allocation_pool(&self) -> Option<(u32, u32)> {
        let v = self.attr(ATTID_RIDALLOCATIONPOOL)?;
        if v.len() < 8 {
            return None;
        }
        let raw = u64::from_le_bytes(v[..8].try_into().ok()?);
        let first = (raw & 0xFFFF_FFFF) as u32;
        let last = (raw >> 32) as u32;
        (last >= first).then_some((first, last - first + 1))
    }

    /// The `rIDAvailablePool` decoded as `(next_available_rid, max_rid)`, if present —
    /// the RID Manager$ object's global RID watermark that a real AD RID master (Samba,
    /// Windows) returns from `EXOP_FSMO_RID_ALLOC`. The wire value is a LARGE_INTEGER
    /// `(max_rid << 32) | next_available_rid`. (The caller's own *granted* pool is on its
    /// `rIDSet.rIDAllocationPool`, read separately.)
    pub fn rid_available_pool(&self) -> Option<(u32, u32)> {
        let v = self.attr(ATTID_RIDAVAILABLEPOOL)?;
        if v.len() < 8 {
            return None;
        }
        let raw = u64::from_le_bytes(v[..8].try_into().ok()?);
        Some(((raw & 0xFFFF_FFFF) as u32, (raw >> 32) as u32))
    }

    /// The `sAMAccountName` (a UTF-16LE string attribute), if present.
    pub fn sam_account_name(&self) -> Option<String> {
        let v = self.attr(ATTID_SAMACCOUNTNAME)?;
        let units: Vec<u16> = v
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        Some(String::from_utf16_lossy(&units))
    }

    /// The account RID = the last sub-authority of `objectSid`.
    pub fn object_rid(&self) -> Option<u32> {
        let sid = self.attr(ATTID_OBJECTSID)?;
        let count = *sid.get(1)? as usize;
        let last = 8 + (count.checked_sub(1)?) * 4;
        Some(u32::from_le_bytes(
            sid.get(last..last + 4)?.try_into().ok()?,
        ))
    }

    /// The raw `objectSid` bytes, if present.
    pub fn object_sid(&self) -> Option<&[u8]> {
        self.attr(ATTID_OBJECTSID)
    }

    /// The `userAccountControl` flags (a 32-bit LE value), if present. Carries the
    /// account-state bits — most importantly `ACCOUNTDISABLE` (`0x2`); see
    /// [`is_disabled`](Self::is_disabled).
    pub fn user_account_control(&self) -> Option<u32> {
        let v = self.attr(ATTID_USERACCOUNTCONTROL)?;
        Some(u32::from_le_bytes(v.get(..4)?.try_into().ok()?))
    }

    /// Whether the account's `userAccountControl` has the `ACCOUNTDISABLE` (`0x0002`)
    /// bit set — a disabled account that must not be served or allowed to authenticate.
    /// `false` when the attribute is absent (an object without UAC, e.g. a group, is not
    /// "disabled").
    pub fn is_disabled(&self) -> bool {
        const UF_ACCOUNTDISABLE: u32 = 0x0000_0002;
        self.user_account_control()
            .is_some_and(|uac| uac & UF_ACCOUNTDISABLE != 0)
    }

    /// Whether this object is a tombstone. A deleted object is replicated with
    /// `isDeleted = TRUE` and most attributes stripped, but its `objectGUID`/`objectSid`
    /// remain so it can be matched by RID/SID and removed. A **full sync** may ship a
    /// historical tombstone WITHOUT the `isDeleted` attribute, so also treat as deleted
    /// any object under the **Deleted Objects** container or carrying the mangled
    /// `…\0ADEL:<guid>` deleted-RDN — an invariant of a tombstone regardless of which
    /// attributes the reply carried. This keeps a tombstone from being served as a live
    /// object (generic projection) and matched for removal (B4b).
    pub fn is_deleted(&self) -> bool {
        if self
            .attr(ATTID_ISDELETED)
            .is_some_and(|v| v.iter().any(|&b| b != 0))
        {
            return true;
        }
        let name = self.name.to_ascii_lowercase();
        name.contains(",cn=deleted objects,")
            || name.contains("\\0adel:")
            || name.contains("\ndel:")
    }

    /// Whether this is a `group` object — it carries the `groupType` attribute (users
    /// and other classes do not). Groups replicate their SID + name but no secrets;
    /// their membership arrives as separate linked values (see [`ReplicatedLink`]).
    pub fn is_group(&self) -> bool {
        self.attrs.iter().any(|a| a.attid == ATTID_GROUPTYPE)
    }

    /// The object's DN (the DSNAME `StringName` decoded from its replicated identity).
    pub fn dn(&self) -> &str {
        &self.name
    }

    /// The `objectClass` chain to project this object under, inferred WITHOUT decoding
    /// the OID-valued `objectClass` attribute (which needs schema/prefix resolution — a
    /// later, real-Samba-validated step). Instead it keys off the RDN and a few
    /// class-defining attributes whose mere PRESENCE is unambiguous:
    /// `OU=` RDN → organizationalUnit; `attributeID` → attributeSchema; `governsID` →
    /// classSchema; `nCName` → crossRef. `None` for anything else, so a generic project
    /// only touches objects it can classify correctly. (Users/groups/computers are
    /// handled by their own paths, not here.)
    pub fn projected_object_classes(&self) -> Option<Vec<String>> {
        let rdn = self.name.split(',').next().unwrap_or("").trim();
        if rdn.len() >= 3 && rdn[..3].eq_ignore_ascii_case("OU=") {
            return Some(vec!["top".into(), "organizationalUnit".into()]);
        }
        if self.attr(ATTID_ATTRIBUTEID).is_some() {
            return Some(vec!["top".into(), "attributeSchema".into()]);
        }
        if self.attr(ATTID_GOVERNSID).is_some() {
            return Some(vec!["top".into(), "classSchema".into()]);
        }
        if self.attr(ATTID_NCNAME).is_some() {
            return Some(vec!["top".into(), "crossRef".into()]);
        }
        None
    }

    /// Render this object's replicated attributes to the `name → values` map the LDAP
    /// `entry` tree stores, for GENERIC (non-principal/group) projection. Only a verified
    /// subset of well-known attributes is rendered — each with a known DRS value syntax —
    /// so a projected object never carries a wrongly-decoded value. Attributes outside the
    /// set (including OID-valued schema attributes like `attributeID`/`governsID`, which
    /// need real-Samba-validated OID decoding) are omitted; the map is intentionally
    /// extended as more attids are verified.
    pub fn ldap_attributes(&self) -> std::collections::BTreeMap<String, Vec<String>> {
        /// The DRS value syntax of a projected attribute.
        enum Syn {
            /// UTF-16LE string.
            Str,
            /// 32-bit little-endian integer, rendered decimal.
            Int,
            /// 32-bit little-endian boolean, rendered `TRUE`/`FALSE` (the LDAP form).
            Bool,
            /// Raw `objectSid`, rendered lowercase hex (the B1 storage convention).
            SidHex,
            /// A `DSNAME` blob, rendered as its DN `StringName`.
            Dn,
        }
        // (attid, lDAPDisplayName, syntax) — verified attids only (see the constants).
        // The schema attrs below were confirmed present on real Samba attributeSchema
        // objects; each is an int/bool, so it renders correctly without OID decoding.
        const TABLE: &[(u32, &str, Syn)] = &[
            (ATTID_CN, "cn", Syn::Str),
            (ATTID_NAME, "name", Syn::Str),
            (ATTID_SAMACCOUNTNAME, "sAMAccountName", Syn::Str),
            (ATTID_LDAPDISPLAYNAME, "lDAPDisplayName", Syn::Str),
            (ATTID_DESCRIPTION, "description", Syn::Str),
            (ATTID_INSTANCETYPE, "instanceType", Syn::Int),
            (ATTID_USERACCOUNTCONTROL, "userAccountControl", Syn::Int),
            (ATTID_OMSYNTAX, "oMSyntax", Syn::Int),
            (ATTID_SEARCHFLAGS, "searchFlags", Syn::Int),
            (ATTID_SYSTEMFLAGS, "systemFlags", Syn::Int),
            (ATTID_ISSINGLEVALUED, "isSingleValued", Syn::Bool),
            (ATTID_SYSTEMONLY, "systemOnly", Syn::Bool),
            (ATTID_OBJECTSID, "objectSid", Syn::SidHex),
            (ATTID_OBJECTCATEGORY, "objectCategory", Syn::Dn),
        ];
        let mut out = std::collections::BTreeMap::new();
        for (attid, name, syn) in TABLE {
            let Some(a) = self.attrs.iter().find(|a| a.attid == *attid) else {
                continue;
            };
            let values: Vec<String> = a
                .values
                .iter()
                .filter_map(|v| match syn {
                    Syn::Str => Some(utf16le_to_string(v)),
                    Syn::Int => (v.len() >= 4)
                        .then(|| u32::from_le_bytes([v[0], v[1], v[2], v[3]]).to_string()),
                    Syn::Bool => (v.len() >= 4).then(|| {
                        if v[..4].iter().any(|&b| b != 0) {
                            "TRUE"
                        } else {
                            "FALSE"
                        }
                        .to_string()
                    }),
                    Syn::SidHex => Some(v.iter().map(|b| format!("{b:02x}")).collect()),
                    Syn::Dn => decode_dsname_dn(v),
                })
                .collect();
            if !values.is_empty() {
                out.insert((*name).to_string(), values);
            }
        }
        out
    }

    /// The recovered NT hash: decrypt the replicated `unicodePwd` under `session_key`
    /// with the object's RID. `None` if absent or undecryptable.
    pub fn nt_hash(&self, session_key: &[u8]) -> Option<[u8; 16]> {
        let enc = self.attr(ATTID_UNICODEPWD)?;
        let rid = self.object_rid()?;
        decrypt_unicode_pwd(enc, rid, session_key)
    }

    /// The most recent per-attribute replication stamp on this object — the one that
    /// wins the MS-DRSR conflict-resolution ordering over all its attributes' stamps,
    /// or `None` if the reply carried no metadata. Serves as a coarse object-level
    /// version for conflict resolution until per-attribute application lands.
    pub fn newest_metadata(&self) -> Option<AttrMetadata> {
        self.attrs
            .iter()
            .filter_map(|a| a.metadata)
            .reduce(|acc, m| if m.wins_over(&acc) { m } else { acc })
    }

    /// The replication metadata (stamp) of the attribute `attid`, if the reply carried
    /// per-attribute metadata for it — for per-attribute conflict resolution.
    pub fn attr_metadata(&self, attid: u32) -> Option<AttrMetadata> {
        self.attrs
            .iter()
            .find(|a| a.attid == attid)
            .and_then(|a| a.metadata)
    }

    /// The `unicodePwd` (secret) attribute's replication metadata, if present. Lets the
    /// secret converge on its OWN version independent of the object's other attributes,
    /// so a newer local password is not clobbered by a replicated object whose *name*
    /// (or another attribute) is newer while its password is older.
    pub fn secret_metadata(&self) -> Option<AttrMetadata> {
        self.attr_metadata(ATTID_UNICODEPWD)
    }

    /// The account's Kerberos keys (AES256/AES128/DES) recovered from the replicated
    /// `supplementalCredentials`: DRS-unwrap under `session_key`, then parse the
    /// `USER_PROPERTIES` blob's `Primary:Kerberos-Newer-Keys` property. Empty if the
    /// attribute is absent, undecryptable, or carries no newer-keys property.
    pub fn kerberos_keys(&self, session_key: &[u8]) -> Vec<KerberosKey> {
        let Some(enc) = self.attr(ATTID_SUPPLEMENTALCREDENTIALS) else {
            return Vec::new();
        };
        // Unlike unicodePwd there is no DES-per-RID layer here — the DRS unwrap yields
        // the USER_PROPERTIES structure directly.
        let Some(plain) = drs_decrypt_value(session_key, enc) else {
            return Vec::new();
        };
        parse_supplemental_kerberos_keys(&plain).unwrap_or_default()
    }
}

/// A Kerberos long-term key recovered from `supplementalCredentials`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosKey {
    /// The Kerberos encryption type (`etype`): 18 = AES256-CTS-HMAC-SHA1-96,
    /// 17 = AES128-CTS-HMAC-SHA1-96, 23 = RC4-HMAC, 3/1 = DES.
    pub key_type: u32,
    /// The raw key bytes (32 for AES256, 16 for AES128, etc.).
    pub key: Vec<u8>,
}

/// Kerberos `etype` for AES256-CTS-HMAC-SHA1-96.
pub const KERB_ETYPE_AES256: u32 = 18;
/// Kerberos `etype` for AES128-CTS-HMAC-SHA1-96.
pub const KERB_ETYPE_AES128: u32 = 17;

/// Parse a decrypted `USER_PROPERTIES` blob (MS-SAMR §2.2.10.1) and return the
/// Kerberos keys from its `Primary:Kerberos-Newer-Keys` property. `None` if the
/// blob is malformed or has no such property.
fn parse_supplemental_kerberos_keys(data: &[u8]) -> Option<Vec<KerberosKey>> {
    // USER_PROPERTIES fixed header: Reserved1(4) Length(4) Reserved2(2) Reserved3(2)
    // Reserved4(96) PropertySignature(2)=0x0050 PropertyCount(2). Properties @112.
    if data.len() < 112 || u16::from_le_bytes([data[108], data[109]]) != 0x0050 {
        return None;
    }
    let prop_count = u16::from_le_bytes([data[110], data[111]]) as usize;
    let mut pos = 112usize;
    for _ in 0..prop_count {
        // USER_PROPERTY: NameLength(2) ValueLength(2) Reserved(2), then the UTF-16LE
        // PropertyName and the PropertyValue (an ASCII-hex encoding of the value).
        let name_len = u16::from_le_bytes([*data.get(pos)?, *data.get(pos + 1)?]) as usize;
        let value_len = u16::from_le_bytes([*data.get(pos + 2)?, *data.get(pos + 3)?]) as usize;
        let name_start = pos + 6;
        let name = decode_utf16le(data.get(name_start..name_start + name_len)?);
        let value_start = name_start + name_len;
        let value_hex = data.get(value_start..value_start + value_len)?;
        if name == "Primary:Kerberos-Newer-Keys" {
            let blob = hex_decode(value_hex)?;
            return parse_kerb_stored_credential_new(&blob);
        }
        pos = value_start + value_len;
    }
    None
}

/// Parse a `KERB_STORED_CREDENTIAL_NEW` (MS-SAMR §2.2.10.8) and extract its primary
/// `Credentials` array of `KERB_KEY_DATA_NEW` (§2.2.10.7) into typed keys.
fn parse_kerb_stored_credential_new(blob: &[u8]) -> Option<Vec<KerberosKey>> {
    // Header: Revision(2) Flags(2) CredentialCount(2) ServiceCredentialCount(2)
    // OldCredentialCount(2) OlderCredentialCount(2) DefaultSaltLength(2)
    // DefaultSaltMaximumLength(2) DefaultSaltOffset(4) DefaultIterationCount(4).
    if blob.len() < 24 {
        return None;
    }
    let credential_count = u16::from_le_bytes([blob[4], blob[5]]) as usize;
    let mut keys = Vec::with_capacity(credential_count);
    for i in 0..credential_count {
        // Each KERB_KEY_DATA_NEW is 24 bytes; the primary array starts at offset 24.
        let base = 24 + i * 24;
        let entry = blob.get(base..base + 24)?;
        let key_type = u32::from_le_bytes(entry[12..16].try_into().ok()?);
        let key_len = u32::from_le_bytes(entry[16..20].try_into().ok()?) as usize;
        let key_off = u32::from_le_bytes(entry[20..24].try_into().ok()?) as usize;
        let key = blob.get(key_off..key_off + key_len)?.to_vec();
        keys.push(KerberosKey { key_type, key });
    }
    Some(keys)
}

/// Decode a little-endian UTF-16 byte slice into a `String` (lossy).
fn decode_utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16_lossy(&units)
}

/// Decode an ASCII-hex byte slice (as stored in `USER_PROPERTY.PropertyValue`) into
/// its raw bytes. `None` on odd length or a non-hex digit.
fn hex_decode(hex: &[u8]) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let nibble = |b: u8| -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    };
    hex.as_chunks::<2>()
        .0
        .iter()
        .map(|c| Some((nibble(c[0])? << 4) | nibble(c[1])?))
        .collect()
}

/// One decoded replicated **linked value** (`REPLVALINF`) — how AD replicates a
/// linked attribute such as group `member`. Each links a source object (the group)
/// to a target (the member) with a present/absent flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicatedLink {
    /// The source object's `objectGUID` (e.g. the group holding the `member` value).
    pub source_guid: [u8; 16],
    /// The link attribute id (`0x1f` = `member`, in linked-value form).
    pub attr_id: u32,
    /// The target object's `objectGUID` (e.g. the member).
    pub target_guid: [u8; 16],
    /// The target object's `objectSid` (the valid `SidLen` bytes of the target DSNAME).
    pub target_sid: Vec<u8>,
    /// `true` = the link is present (a current membership); `false` = removed.
    pub present: bool,
    /// The link value's version (from its `VALUE_META_DATA_EXT`) — bumps on each
    /// present↔absent change; the primary tiebreaker for per-link conflict resolution.
    pub version: u32,
    /// When the link last changed at its originating DSA (a `DSTIME`, secs since 1601).
    pub originating_time: i64,
    /// The invocation ID of the DSA where the link change originated.
    pub originating_dsa: [u8; 16],
    /// The originating DSA's USN for this link change.
    pub originating_usn: i64,
}

/// The `member` link attribute id as it appears in a `REPLVALINF` (the raw OID tail
/// `1.2.840.113556.1.4.31`, not the prefix-compressed `0x0009001f` object form).
pub const LINK_ATTR_MEMBER: u32 = 0x1f;

/// The decoded contents of a `GetNCChanges` reply the destination acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplicatedChanges {
    /// The source DSA's invocation ID (`uuidInvocIdSrc`) — the UTDV cursor key.
    pub source_invocation_id: [u8; 16],
    /// `usnvecTo.usnHighObjUpdate` — advance this DSA's cursor to here.
    pub usn_to: i64,
    /// Whether the source has a further page (`fMoreData`).
    pub more_data: bool,
    /// The objects in this page, in wire order.
    pub objects: Vec<ReplicatedObject>,
    /// The linked values (e.g. group memberships) in this page.
    pub links: Vec<ReplicatedLink>,
    /// `ulExtendedRet` — the extended-operation result (`EXOP_ERR_*`). For a normal
    /// replication reply this is `EXOP_ERR_SUCCESS` (1); for an FSMO transfer / RID
    /// allocation it reports whether the operation succeeded. See [`ExOpErr`].
    pub ext_op_err: u32,
}

/// Parse a V6 `IDL_DRSGetNCChanges` reply. Returns `None` if it is not a V6 reply or
/// the byte layout is malformed. Recovers the source identity, the new cursor, and
/// the `REPLENTINFLIST` object graph (each object's GUID/name/attrs).
pub fn parse_get_nc_changes_reply(reply: &[u8]) -> Option<ReplicatedChanges> {
    let mut r = NdrReader::new(reply);
    if r.u32()? != 6 || r.u32()? != 6 {
        return None; // pdwOutVersion / union tag must be V6
    }
    let _uuid_dsa_obj_src: [u8; 16] = r.array()?;
    let source_invocation_id: [u8; 16] = r.array()?;
    // `pNC` is a `[ref]` DSNAME pointer: a real source (Samba/Windows) sends a
    // non-null referent and defers the NC's DSNAME; our own lenient server sends 0.
    let p_nc = r.u32()?;
    r.align(8); // USN_VECTOR is 8-aligned
    let _usnvec_from: [u8; 24] = r.array()?;
    let usnvec_to: [u8; 24] = r.array()?;
    let usn_to = i64::from_le_bytes(usnvec_to[0..8].try_into().ok()?);
    let p_uptodate = r.u32()?; // pUpToDateVecSrc referent (0 = absent)
    let prefix_count = r.u32()? as usize; // PrefixTableSrc.PrefixCount
    let p_prefix = r.u32()?; // PrefixTableSrc.pPrefixEntry referent
    let ext_op_err = r.u32()?; // ulExtendedRet (EXOP_ERR_* for extended operations)
    let num_objects = r.u32()? as usize;
    r.u32()?; // cNumBytes
    let p_objects = r.u32()?; // pObjects referent (0 = empty page)
    let more_data = r.u32()? != 0;
    r.u32()?; // cNumNcSizeObjectsc
    r.u32()?; // cNumNcSizeValues
    let num_values = r.u32()? as usize; // cNumValues (linked values, e.g. memberships)
    let p_values = r.u32()?; // rgValues referent
    r.u32()?; // dwDRSError

    // Deferred payloads follow in struct-pointer order: pNC → pUpToDateVecSrc →
    // PrefixTableSrc.pPrefixEntry → pObjects (→ rgValues, which we ignore).
    if p_nc != 0 {
        read_dsname(&mut r)?; // the NC head DSNAME; not needed by the caller
    }
    if p_uptodate != 0 {
        skip_uptodate_vector(&mut r)?;
    }
    if p_prefix != 0 {
        skip_prefix_table(&mut r, prefix_count)?;
    }

    let objects = if p_objects != 0 && num_objects > 0 {
        parse_replentinflist(&mut r, num_objects)?
    } else {
        Vec::new()
    };
    // rgValues (linked values) is the last deferred payload, after the objects.
    let links = if p_values != 0 && num_values > 0 {
        parse_linked_values(&mut r, num_values)?
    } else {
        Vec::new()
    };
    Some(ReplicatedChanges {
        source_invocation_id,
        usn_to,
        more_data,
        objects,
        links,
        ext_op_err,
    })
}

/// Skip a `SCHEMA_PREFIX_TABLE`'s deferred `pPrefixEntry` payload: the hoisted
/// conformant `MaxCount`, then `count` `PrefixTableEntry` inline records
/// (`ndx`, `OID_t.length`, `OID_t.elements` referent), then each entry's deferred
/// `elements` byte array (`MaxCount` = length, `length` bytes, 4-aligned).
fn skip_prefix_table(r: &mut NdrReader, count: usize) -> Option<()> {
    let _max_count = r.u32()?;
    let mut entries = Vec::new() /* size bounded by the reader, not the wire count */;
    for _ in 0..count {
        r.u32()?; // ndx
        let length = r.u32()? as usize; // OID_t.length
        let elems_ref = r.u32()?; // OID_t.elements referent
        entries.push((length, elems_ref));
    }
    for (length, elems_ref) in entries {
        if elems_ref != 0 {
            let _elem_max = r.u32()?; // conformant MaxCount (= length)
            r.take(length)?;
            r.align(4);
        }
    }
    Some(())
}

/// Parse a `PROPERTY_META_DATA_EXT_VECTOR` (`pMetaDataExt` deferral): hoisted
/// `MaxCount` + `cNumProps`, then `cNumProps` × 40-byte `PROPERTY_META_DATA_EXT`
/// (`dwVersion` + pad + `timeChanged` + `uuidDsaOriginating` + `usnOriginating`).
/// The entries are ordered by ATTRTYP, parallel to the object's `AttrBlock`.
fn parse_metadata_vector(r: &mut NdrReader) -> Option<Vec<AttrMetadata>> {
    let _max_count = r.u32()?;
    r.align(8); // the vector struct holds hypers → cNumProps is 8-aligned after MaxCount
    let num_props = r.u32()? as usize; // cNumProps
    r.align(8); // the element array is 8-aligned (each element leads with a hyper)
    let mut out = Vec::new(); // size bounded by the reader, not the wire count
    for _ in 0..num_props {
        let e = r.take(40)?;
        out.push(AttrMetadata {
            version: u32::from_le_bytes(e[0..4].try_into().ok()?),
            // e[4..8] is 4 bytes of padding before the 8-aligned timeChanged.
            originating_time: i64::from_le_bytes(e[8..16].try_into().ok()?),
            originating_dsa: e[16..32].try_into().ok()?,
            originating_usn: i64::from_le_bytes(e[32..40].try_into().ok()?),
        });
    }
    Some(out)
}

/// Parse the deferred `rgValues` payload: a conformant array of `count`
/// `REPLVALINF_V1` (MS-DRSR §4.1.10.2.13). Each inline record is 72 bytes —
/// `pObject`(ref) `attrTyp` `Aval{valLen, pVal(ref)}` `fIsPresent` (pad) plus a
/// 48-byte `VALUE_META_DATA_EXT_V1` (`timeCreated` + `PROPERTY_META_DATA_EXT`). Then,
/// per element in order, the deferred `pObject` DSNAME (the source object) and the
/// `pVal` byte array (a flat DSNAME blob of the target).
fn parse_linked_values(r: &mut NdrReader, count: usize) -> Option<Vec<ReplicatedLink>> {
    let _max_count = r.u32()?;
    r.align(8); // the element array is 8-aligned (each element holds hypers)
    let mut inline = Vec::new() /* size bounded by the reader, not the wire count */;
    for _ in 0..count {
        let p_object = r.u32()?; // pObject referent
        let attr_id = r.u32()?; // attrTyp
        let val_len = r.u32()? as usize; // Aval.valLen
        let p_val = r.u32()?; // Aval.pVal referent
        let present = r.u32()? != 0; // fIsPresent
        r.align(8); // pad before the VALUE_META_DATA_EXT_V1 hypers
        r.take(8)?; // timeCreated (DSTIME)
        let meta = r.take(40)?; // PROPERTY_META_DATA_EXT: version, pad, time, dsa, usn
        let version = u32::from_le_bytes(meta[0..4].try_into().ok()?);
        let m_time = i64::from_le_bytes(meta[8..16].try_into().ok()?);
        let m_dsa: [u8; 16] = meta[16..32].try_into().ok()?;
        let m_usn = i64::from_le_bytes(meta[32..40].try_into().ok()?);
        inline.push((
            p_object, attr_id, val_len, p_val, present, version, m_time, m_dsa, m_usn,
        ));
    }
    let mut links = Vec::new() /* size bounded by the reader, not the wire count */;
    for (p_object, attr_id, val_len, p_val, present, version, m_time, m_dsa, m_usn) in inline {
        // The source object's DSNAME (same layout as an object's pName DSNAME).
        let source_guid = if p_object != 0 {
            read_dsname(r)?.0
        } else {
            [0u8; 16]
        };
        // The target value: an NDR byte array whose bytes are a flat DSNAME blob
        // (structLen, SidLen, Guid, Sid, NameLen, name). Read the GUID + SID, then
        // skip to the blob's end and 4-align.
        let (target_guid, target_sid) = if p_val != 0 {
            let _blob_max = r.u32()?; // conformant MaxCount (= valLen)
            let start = r.pos();
            r.u32()?; // structLen
            let sid_len = (r.u32()? as usize).min(28);
            let target_guid: [u8; 16] = r.array()?;
            let sid = r.take(28)?;
            let target_sid = sid[..sid_len].to_vec();
            let consumed = r.pos().saturating_sub(start);
            r.take(val_len.saturating_sub(consumed))?; // skip NameLen + name to blob end
            r.align(4);
            (target_guid, target_sid)
        } else {
            ([0u8; 16], Vec::new())
        };
        links.push(ReplicatedLink {
            source_guid,
            attr_id,
            target_guid,
            target_sid,
            present,
            version,
            originating_time: m_time,
            originating_dsa: m_dsa,
            originating_usn: m_usn,
        });
    }
    Some(links)
}

/// Read a `DSNAME`: hoisted `MaxCount`, `structLen`, `SidLen`, `Guid[16]`,
/// `Sid[28]`, `NameLen`, the UTF-16 name + NUL, then 4-align. Returns the object's
/// GUID and decoded name.
fn read_dsname(r: &mut NdrReader) -> Option<([u8; 16], String)> {
    let _max_count = r.u32()?;
    r.u32()?; // structLen
    r.u32()?; // SidLen
    let guid: [u8; 16] = r.array()?;
    r.take(28)?; // Sid (fixed 28)
    let name_len = r.u32()? as usize;
    let mut units = Vec::new(); // size bounded by the reader, not the wire count
    for _ in 0..name_len {
        units.push(r.u16()?);
    }
    r.u16()?; // NUL terminator (MaxCount = NameLen + 1)
    r.align(4);
    Some((guid, String::from_utf16_lossy(&units)))
}

/// Skip an `UPTODATE_VECTOR_V2_EXT`: hoisted MaxCount + dwVersion + 2 reserved +
/// cNumCursors, then 8-align and `cNumCursors` × 32-byte cursors.
fn skip_uptodate_vector(r: &mut NdrReader) -> Option<()> {
    let _max_count = r.u32()?;
    r.align(8); // the vector struct holds hypers → 8-aligned after the hoisted MaxCount
    r.u32()?; // dwVersion (=2)
    r.u32()?; // dwReserved1
    let cursors = r.u32()?; // cNumCursors
    r.u32()?; // dwReserved2
    r.align(8);
    for _ in 0..cursors {
        r.take(32)?; // uuidDsa(16) + usnHighPropUpdate(8) + timeLastSyncSuccess(8)
    }
    Some(())
}

/// Parse the `REPLENTINFLIST` chain: `count` inline nodes (forward) giving each
/// object's attribute count, then the deferred DSNAME + attribute payloads in
/// REVERSE object order (NDR depth-first deferral). Returns objects in wire order.
fn parse_replentinflist(r: &mut NdrReader, count: usize) -> Option<Vec<ReplicatedObject>> {
    // Pass 1: inline nodes (8 u32 each). Each `REPLENTINFLIST` embeds an `ENTINF`
    // (pName, ulFlags, AttrBlock{attrCount, pAttr}) and trails fIsNCPrefix,
    // pParentGuid, pMetaDataExt. NDR defers pNextEntInf first, so every node's inline
    // record is laid out consecutively here; each node's own payload follows later.
    let mut nodes = Vec::new() /* size bounded by the reader, not the wire count */;
    for _ in 0..count {
        r.u32()?; // pNextEntInf referent
        r.u32()?; // pName referent
        r.u32()?; // ulFlags
        let attr_count = r.u32()? as usize; // AttrBlock.attrCount
        r.u32()?; // pAttr referent
        r.u32()?; // fIsNCPrefix
        let p_parent_guid = r.u32()?; // pParentGuid referent
        let p_metadata = r.u32()?; // pMetaDataExt referent
        nodes.push((attr_count, p_parent_guid, p_metadata));
    }
    // Pass 2: payloads unwind tail-first, so decode in reverse then restore order.
    let mut rev = Vec::new() /* size bounded by the reader, not the wire count */;
    for &(attr_count, p_parent_guid, p_metadata) in nodes.iter().rev() {
        rev.push(parse_object_payload(
            r,
            attr_count,
            p_parent_guid,
            p_metadata,
        )?);
    }
    rev.reverse();
    Some(rev)
}

/// Parse one object's deferred payload: its DSNAME, its `attr_count` attributes, then
/// (in pointer order) the parent-object GUID and the per-attribute metadata vector
/// when those pointers are non-null — a real source (Samba) sends both.
fn parse_object_payload(
    r: &mut NdrReader,
    attr_count: usize,
    p_parent_guid: u32,
    p_metadata: u32,
) -> Option<ReplicatedObject> {
    let (guid, name) = read_dsname(r)?;

    // ATTR array: MaxCount then (attid, valCount, pAVal) per attribute.
    let arr_max = r.u32()? as usize;
    if arr_max != attr_count {
        return None;
    }
    let mut descs = Vec::new() /* size bounded by the reader, not the wire count */;
    for _ in 0..attr_count {
        let attid = r.u32()?;
        let val_count = r.u32()? as usize;
        let p_aval = r.u32()?; // pAVal referent
        descs.push((attid, val_count, p_aval));
    }
    // Per-attribute deferrals: the ATTRVAL descriptor array, then the value buffers.
    let mut attrs = Vec::new() /* size bounded by the reader, not the wire count */;
    for &(attid, val_count, p_aval) in &descs {
        // A null `pAVal` (valCount == 0) defers no ATTRVAL array — Samba emits such
        // empty-valued attributes (e.g. a cleared/linked attribute). Reading a
        // descriptor here would consume the next attribute's bytes.
        if p_aval == 0 {
            attrs.push(ReplicatedAttr {
                attid,
                values: Vec::new(),
                metadata: None,
            });
            continue;
        }
        let mut lens = Vec::new() /* size bounded by the reader, not the wire count */;
        let dv_max = r.u32()? as usize; // ATTRVAL array MaxCount
        if dv_max != val_count {
            return None;
        }
        for _ in 0..val_count {
            let val_len = r.u32()? as usize; // valLen
            r.u32()?; // pVal referent
            lens.push(val_len);
        }
        let mut values = Vec::new() /* size bounded by the reader, not the wire count */;
        for &len in &lens {
            let buf_max = r.u32()? as usize; // pVal conformant MaxCount
            if buf_max != len {
                return None;
            }
            values.push(r.take(len)?.to_vec());
            r.align(4);
        }
        attrs.push(ReplicatedAttr {
            attid,
            values,
            metadata: None,
        });
    }

    // Trailing per-node deferrals, in pointer order: the parent-object GUID (a fixed
    // 16-byte referent) then the per-attribute metadata vector. Both are absent from
    // our own server's replies (null referents) but present from Samba.
    if p_parent_guid != 0 {
        r.take(16)?;
    }
    if p_metadata != 0 {
        // The metadata entries are ordered by ATTRTYP, exactly parallel to the
        // AttrBlock, so zip them onto the attributes when the counts line up.
        let meta = parse_metadata_vector(r)?;
        if meta.len() == attrs.len() {
            for (a, m) in attrs.iter_mut().zip(meta) {
                a.metadata = Some(m);
            }
        }
    }
    Some(ReplicatedObject { guid, name, attrs })
}

/// The domain NC DN for a DNS domain (`magtest.local` → `DC=magtest,DC=local`) — the
/// suffix a replicated object's distinguished name hangs off.
fn dns_domain_to_nc(dns_domain: &str) -> String {
    dns_domain
        .split('.')
        .map(|l| format!("DC={l}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// A distinct 16-byte objectGUID per user (RID-seeded, deterministic for the PoC).
fn object_guid(rid: u32) -> [u8; 16] {
    let mut g = [0x11u8; 16];
    g[0..4].copy_from_slice(&rid.to_le_bytes());
    g
}

/// This source DSA's invocation ID (fixed for the PoC): reported in the reply
/// header (`uuidInvocIdSrc`) and as the sole up-to-date-vector cursor's `uuidDsa`.
const DSA_INVOCATION_ID: [u8; 16] = [
    0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81, 0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09,
];

/// Emit the `pUpToDateVecSrc` referent as an `UPTODATE_VECTOR_V2_EXT`: a single
/// cursor for this source DSA (`uuidDsa` = its invocation ID, `usnHighPropUpdate` =
/// the high-water mark) that tells the destination how current the source's
/// knowledge is. The trailing `rgCursors` conformant array hoists its MaxCount to
/// the struct front (like `DRS_EXTENSIONS`); the V2 cursor is `uuidDsa` +
/// `usnHighPropUpdate` + `timeLastSyncSuccess` (32 bytes) — the shape the client's
/// decoder expects (a V1 cursor would leave it reading 8 bytes short per cursor).
fn encode_uptodate_vector(w: &mut NdrWriter, invocation_id: &[u8; 16], high_usn: u64) {
    w.u32(1); // rgCursors conformant MaxCount (hoisted) = cNumCursors
    w.align(8); // the vector struct holds hypers → 8-aligned after the hoisted MaxCount
    w.u32(2); // dwVersion = 2
    w.u32(0); // dwReserved1
    w.u32(1); // cNumCursors
    w.u32(0); // dwReserved2
    w.align(8); // UPTODATE_CURSOR_V2 is u64-aligned (usnHighPropUpdate)
    w.bytes(invocation_id); // rgCursors[0].uuidDsa
    w.bytes(&high_usn.to_le_bytes()); // rgCursors[0].usnHighPropUpdate (i64)
    w.bytes(&[0u8; 8]); // rgCursors[0].timeLastSyncSuccess (DSTIME, i64)
}

/// The parts of a V8 `IDL_DRSGetNCChanges` request the server acts on: the client's
/// replication cursor and its page-size limit.
struct ChangeRequest {
    /// `usnvecFrom.usnHighObjUpdate` — replicate objects with a higher USN.
    from: u64,
    /// `cMaxObjects` — the most objects to return this cycle (0 = no client limit).
    max_objects: u32,
    /// `ulExtendedOp` — the extended operation (0 = normal replication;
    /// `EXOP_FSMO_RID_ALLOC` = a RID-pool request, etc.).
    ext_op: u32,
}

/// Parse a V8 `IDL_DRSGetNCChanges` request stub. The `[in]` marshalling is
/// fixed-layout — `hDrs`(20), `dwInVersion`(4), `pmsgIn` referent(4), union tag(4),
/// `uuidDsaObjDest`(16), `uuidInvocIdSrc`(16), `pNC` referent(4), 4 pad bytes
/// (USN_VECTOR is 8-aligned), `usnvecFrom`(24), `pUpToDateVecDest` referent(4),
/// `ulFlags`(4), then `cMaxObjects`(4) — so `usnvecFrom` lands at byte 72 and
/// `cMaxObjects` at byte 104. A `DsReplicaHighWaterMark` is three hypers
/// {`tmp_highest_usn`(+0), `reserved_usn`(+8), `highest_usn`(+16)}; Samba's server
/// authoritatively resumes from `highwatermark.highest_usn`, and a well-behaved
/// client echoes the reply's `new_highwatermark` (which sets tmp == highest), so we
/// take the max of both fields to honour whichever the client populated. Defaults
/// (replicate from scratch, no page limit) when the stub is too short or not V8.
fn parse_change_request(stub: &[u8]) -> ChangeRequest {
    const VERSION_OFFSET: usize = 20;
    const USNVEC_FROM_OFFSET: usize = 72;
    const MAX_OBJECTS_OFFSET: usize = 104;
    // ulExtendedOp follows cMaxObjects(104) + cMaxBytes(108): usnvecFrom(72..96),
    // pUpToDateVecDest(96), ulFlags(100), cMaxObjects(104), cMaxBytes(108), then
    // ulExtendedOp at 112.
    const EXT_OP_OFFSET: usize = 112;
    let mut req = ChangeRequest {
        from: 0,
        max_objects: 0,
        ext_op: 0,
    };
    if stub.len() < VERSION_OFFSET + 4
        || u32::from_le_bytes(stub[VERSION_OFFSET..VERSION_OFFSET + 4].try_into().unwrap()) != 8
    {
        return req;
    }
    if stub.len() >= USNVEC_FROM_OFFSET + 24 {
        let tmp_highest = u64::from_le_bytes(
            stub[USNVEC_FROM_OFFSET..USNVEC_FROM_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        let highest = u64::from_le_bytes(
            stub[USNVEC_FROM_OFFSET + 16..USNVEC_FROM_OFFSET + 24]
                .try_into()
                .unwrap(),
        );
        req.from = tmp_highest.max(highest);
    }
    if stub.len() >= MAX_OBJECTS_OFFSET + 4 {
        req.max_objects = u32::from_le_bytes(
            stub[MAX_OBJECTS_OFFSET..MAX_OBJECTS_OFFSET + 4]
                .try_into()
                .unwrap(),
        );
    }
    if stub.len() >= EXT_OP_OFFSET + 4 {
        req.ext_op = u32::from_le_bytes(stub[EXT_OP_OFFSET..EXT_OP_OFFSET + 4].try_into().unwrap());
    }
    req
}

/// Consume the destination's up-to-date vector (`pUpToDateVecDest`) in the request:
/// return this source DSA's cursor USN, i.e. the highest object USN the destination
/// already holds from us, so those objects can be skipped (true incremental sync).
///
/// The UTDV is a deferred, variable-length conformant struct behind a pointer;
/// rather than walk the request NDR to it, we locate this DSA's cursor robustly by
/// finding our own `DSA_INVOCATION_ID` (the cursor's `uuidDsa`) and reading the
/// `usnHighPropUpdate` (a little-endian i64) that immediately follows it.
///
/// The scan starts past the fixed request header (byte 64): a real client (Samba)
/// sets `uuidInvocIdSrc` at offset 48 to *this same* source invocation id, and matching
/// there would misread the following request bytes as a cursor (yielding a huge USN and
/// an empty reply). The UTDV is a deferred payload well past the header, so skipping the
/// header avoids that false positive while still finding a genuine cursor.
fn utdv_dest_cursor(stub: &[u8], invocation_id: &[u8; 16]) -> Option<u64> {
    const HEADER_SKIP: usize = 64; // past uuidDsaObjDest (32) + uuidInvocIdSrc (48)
    let region = stub.get(HEADER_SKIP..)?;
    let pos = region.windows(16).position(|w| w == invocation_id)?;
    let usn = region.get(pos + 16..pos + 24)?;
    Some(u64::from_le_bytes(usn.try_into().ok()?))
}

/// Write a `USN_VECTOR` (three little-endian i64s) with `usnHighObjUpdate` = `high`
/// and the reserved / property USNs zeroed.
fn write_usn_vector(w: &mut NdrWriter, high: u64) {
    // A `DsReplicaHighWaterMark` is three hypers {tmp_highest_usn, reserved_usn,
    // highest_usn}. A consumer resumes from `highest_usn` (Samba's server reads
    // `req.highwatermark.highest_usn`), so set BOTH tmp and highest to `high`
    // (matching Samba, which stamps both with its max USN) — else the client
    // echoes highest_usn=0 and re-pulls every object each cycle.
    w.bytes(&high.to_le_bytes()); // tmp_highest_usn
    w.bytes(&[0u8; 8]); // reserved_usn
    w.bytes(&high.to_le_bytes()); // highest_usn (the authoritative resume cursor)
}

/// `IDL_DRSGetNCChanges` response: `pdwOutVersion`, then a V6 reply carrying up to
/// one page of the users NEWER than the client's cursor as a chained
/// `REPLENTINFLIST` (each with `sAMAccountName`, `objectSid` and encrypted
/// `unicodePwd`), then ErrorCode.
///
/// Build the replicable object for a directory `user`: its identity attributes and
/// the DCSync secret (`unicodePwd`), stamped at `usn` with the user's real origin
/// (`repl_meta`) or self/version 1. Attributes are emitted in ascending ATTRTYP order.
fn build_user_object(
    user: &User,
    usn: u64,
    domain_nc: &str,
    domain_sid: &[u32],
    secret_key: &[u8],
) -> ReplObject {
    let mut attrs = vec![
        ReplAttr {
            attid: ATTID_OBJECTCLASS,
            values: user_object_class(),
        },
        ReplAttr {
            attid: ATTID_INSTANCETYPE,
            values: vec![4u32.to_le_bytes().to_vec()], // IT_WRITE
        },
        ReplAttr {
            attid: ATTID_NAME,
            values: vec![utf16le(&user.sam_account_name)],
        },
        ReplAttr {
            attid: ATTID_CN,
            values: vec![utf16le(&user.sam_account_name)],
        },
        ReplAttr {
            attid: ATTID_USERACCOUNTCONTROL,
            values: vec![0x0000_0200u32.to_le_bytes().to_vec()], // NORMAL_ACCOUNT
        },
        ReplAttr {
            attid: ATTID_SAMACCOUNTNAME,
            values: vec![utf16le(&user.sam_account_name)],
        },
        ReplAttr {
            attid: ATTID_OBJECTSID,
            values: vec![user_sid(domain_sid, user.rid)],
        },
        // The DCSync secret: the NT hash, DES-per-RID + DRS-wrapped under the connection
        // key. A consumer recovers the RID from the identifier DSNAME's SID (see
        // `encode_dsname`) to strip the DES layer.
        ReplAttr {
            attid: ATTID_UNICODEPWD,
            values: vec![encrypted_unicode_pwd(&user.nt_hash, user.rid, secret_key)],
        },
        ReplAttr {
            attid: ATTID_NTSECURITYDESCRIPTOR,
            values: vec![minimal_security_descriptor()],
        },
        ReplAttr {
            attid: ATTID_OBJECTCATEGORY,
            values: vec![encode_flat_dsname(
                &PERSON_CLASS_GUID,
                &format!("CN=Person,CN=Schema,CN=Configuration,{domain_nc}"),
            )],
        },
    ];
    attrs.sort_by_key(|a| a.attid);
    ReplObject {
        guid: object_guid(user.rid),
        name: format!("CN={},CN=Users,{domain_nc}", user.sam_account_name),
        sid: user_sid(domain_sid, user.rid),
        usn: usn as i64,
        meta: user.repl_meta,
        attrs,
    }
}

/// Build the replicable object for a directory `group`: its identity attributes and
/// `groupType` (a global security group). Membership replicates SEPARATELY as linked
/// values (Tier C item 5b), not as an attribute here. Self/version-1 stamped for now.
fn build_group_object(group: &Group, usn: u64, domain_nc: &str, domain_sid: &[u32]) -> ReplObject {
    let mut attrs = vec![
        ReplAttr {
            attid: ATTID_OBJECTCLASS,
            values: group_object_class(),
        },
        ReplAttr {
            attid: ATTID_INSTANCETYPE,
            values: vec![4u32.to_le_bytes().to_vec()], // IT_WRITE
        },
        ReplAttr {
            attid: ATTID_NAME,
            values: vec![utf16le(&group.sam_account_name)],
        },
        ReplAttr {
            attid: ATTID_CN,
            values: vec![utf16le(&group.sam_account_name)],
        },
        ReplAttr {
            attid: ATTID_SAMACCOUNTNAME,
            values: vec![utf16le(&group.sam_account_name)],
        },
        ReplAttr {
            attid: ATTID_OBJECTSID,
            values: vec![user_sid(domain_sid, group.rid)],
        },
        ReplAttr {
            attid: ATTID_GROUPTYPE,
            values: vec![GROUP_TYPE_GLOBAL_SECURITY.to_le_bytes().to_vec()],
        },
        ReplAttr {
            attid: ATTID_NTSECURITYDESCRIPTOR,
            values: vec![minimal_security_descriptor()],
        },
        ReplAttr {
            attid: ATTID_OBJECTCATEGORY,
            values: vec![encode_flat_dsname(
                &GROUP_CLASS_GUID,
                &format!("CN=Group,CN=Schema,CN=Configuration,{domain_nc}"),
            )],
        },
    ];
    attrs.sort_by_key(|a| a.attid);
    ReplObject {
        guid: object_guid(group.rid),
        name: format!("CN={},CN=Users,{domain_nc}", group.sam_account_name),
        sid: user_sid(domain_sid, group.rid),
        usn: usn as i64,
        meta: group.repl_meta,
        attrs,
    }
}

/// A user's USN is its 1-based insertion order; `usnvecFrom` (parsed from `stub`)
/// filters the reply to `usn > from`, `cMaxObjects` caps the page, `fMoreData`
/// signals a further page remains, and `usnvecTo` reports the USN of the last
/// object shipped so the next call resumes after it. Each secret is wrapped under
/// `session_key` (the negotiated RPC key when authenticated, else the fixed PoC key).
fn get_nc_changes_response(
    dir: &Directory,
    stub: &[u8],
    session_key: Option<&[u8]>,
    invocation_id: &[u8; 16],
    is_rid_master: bool,
    principal: Option<&str>,
) -> Vec<u8> {
    // Extended-operation result codes (MS-DRSR §5.54, `dwExOpError`).
    const EXOP_ERR_FSMO_NOT_OWNER: u32 = 0x0000_0003;
    const EXOP_ERR_FSMO_REFUSING: u32 = 0x0000_000C;

    let secret_key = session_key.unwrap_or(&SECRET_SESSION_KEY);
    let request = parse_change_request(stub);
    // A RID-pool request (EXOP_FSMO_RID_ALLOC) is an extended operation, not a delta:
    // grant the next pool from this DC's RID-Master watermark — but only if this DC IS
    // the RID master. A replica refuses (EXOP_ERR_FSMO_NOT_OWNER) so it never hands out
    // a pool overlapping the real master's watermark; the requester retries the master.
    if request.ext_op == exop::FSMO_RID_ALLOC {
        return if is_rid_master {
            rid_alloc_reply(dir, invocation_id)
        } else {
            exop_error_reply(invocation_id, EXOP_ERR_FSMO_NOT_OWNER)
        };
    }
    // FSMO *role transfer* requests (RID/PDC/generic role, or abandon). magnetite manages
    // FSMO ownership out of band (the `fSMORoleOwner` attribute over LDAP / the
    // `FSMO_OWNERS` config), not via a DRS role handoff, so reply with a defined refusal
    // rather than silently returning replication deltas the caller would misread.
    if matches!(
        request.ext_op,
        exop::FSMO_REQ_ROLE
            | exop::FSMO_RID_REQ_ROLE
            | exop::FSMO_REQ_PDC
            | exop::FSMO_ABANDON_ROLE
    ) {
        return exop_error_reply(invocation_id, EXOP_ERR_FSMO_REFUSING);
    }
    // The effective cursor is the higher of the request's usnvecFrom and what the
    // destination's up-to-date vector (pUpToDateVecDest) says it already holds for
    // this source DSA — so a destination that is already current skips those objects.
    let from = request
        .from
        .max(utdv_dest_cursor(stub, invocation_id).unwrap_or(0));
    // Users and groups share ONE USN stream: users at USN 1..=U, groups at U+1..=U+G,
    // so both replicate through the same delta/paging path (Tier C item 5a).
    #[derive(Clone, Copy)]
    enum Cand<'a> {
        User(&'a User),
        Group(&'a Group),
    }
    let users = dir.users();
    let groups = dir.groups();
    let high_water = (users.len() + groups.len()) as u64;
    // Audit the credential-replicating pull (DCSync). This is the path that ships
    // account password hashes, so it must leave a trace naming the requesting principal
    // (the authenticated bind identity, threaded in here). NC scope is the default NC.
    tracing::info!(
        target: "auth", proto = "drsuapi", from_usn = from,
        principal = principal.unwrap_or("<unauthenticated>"),
        users = users.len(), groups = groups.len(),
        "DRSUAPI IDL_DRSGetNCChanges served: replicating directory objects (DCSync — replicates credentials)"
    );
    let candidates: Vec<(u64, Cand)> = users
        .iter()
        .enumerate()
        .map(|(i, u)| (i as u64 + 1, Cand::User(u)))
        .chain(
            groups
                .iter()
                .enumerate()
                .map(|(j, g)| ((users.len() + j) as u64 + 1, Cand::Group(g))),
        )
        .collect();
    // The objects past the cursor (USN = 1-based position in that stream).
    let pending: Vec<(u64, Cand)> = candidates
        .iter()
        .copied()
        .filter(|(usn, _)| *usn > from)
        .collect();
    // Cap this cycle at cMaxObjects (0 = no client limit → the whole delta).
    let page_len = if request.max_objects == 0 {
        pending.len()
    } else {
        pending.len().min(request.max_objects as usize)
    };
    let more_data = page_len < pending.len();
    // usnvecTo resumes AFTER the last object shipped; when caught up, the high-water.
    let usn_to = if page_len > 0 {
        pending[page_len - 1].0
    } else {
        high_water.max(from)
    };

    let domain_nc = dns_domain_to_nc(dir.dns_domain());
    let domain_sid = dir.domain_sid();
    let surviving: Vec<(u64, Cand)> = pending
        .into_iter()
        .take(page_len)
        .filter(|(_usn, cand)| {
            // Tier C item 3 — loop dampening. Skip a change the destination ALREADY holds
            // from its origin via ANY replication path: compare the object's originating
            // DSA/USN (preserved by item 1) against the destination's up-to-dateness
            // vector. Without this, a change A received from B and re-serves would boomerang
            // back to B (and ping-pong), because the `from` high-water only tracks THIS
            // source's own USN stream. Applied ONLY to FOREIGN-originated changes: a
            // self-originated object's `originating_usn` lives in a different counter than
            // the high-water, so the `from` filter (not this) governs those.
            let meta = match cand {
                Cand::User(u) => u.repl_meta,
                Cand::Group(g) => g.repl_meta,
            };
            match meta {
                Some(m) if m.originating_dsa != *invocation_id => {
                    let held = utdv_dest_cursor(stub, &m.originating_dsa).unwrap_or(0);
                    (m.originating_usn.max(0) as u64) > held
                }
                _ => true,
            }
        })
        .collect();
    let objects: Vec<ReplObject> = surviving
        .iter()
        .map(|(usn, cand)| match cand {
            Cand::User(u) => build_user_object(u, *usn, &domain_nc, domain_sid, secret_key),
            Cand::Group(g) => build_group_object(g, *usn, &domain_nc, domain_sid),
        })
        .collect();
    // Tier C item 5b — group memberships as present `member` linked values: one link
    // per member of every group in this page, so a peer replicates the memberships.
    let links: Vec<LinkVal> = surviving
        .iter()
        .filter_map(|(_, cand)| {
            if let Cand::Group(g) = *cand {
                Some(g)
            } else {
                None
            }
        })
        .flat_map(|g| {
            let source_guid = object_guid(g.rid);
            let source_sid = user_sid(domain_sid, g.rid);
            let source_dn = format!("CN={},CN=Users,{domain_nc}", g.sam_account_name);
            let nc = domain_nc.clone(); // owned copy for the inner `move` closure
                                        // Serve every link — present AND absent (tombstones) — with its own stamp, so
                                        // a member removal replicates and a peer conflict-resolves per link (item 5d).
            g.member_links.iter().map(move |link| {
                let m = link.member_rid;
                LinkVal {
                    source_guid,
                    source_sid: source_sid.clone(),
                    source_dn: source_dn.clone(),
                    target_guid: object_guid(m),
                    target_sid: user_sid(domain_sid, m),
                    target_dn: format!("CN=member-{m},CN=Users,{nc}"),
                    present: link.present,
                    meta: link.repl_meta,
                }
            })
        })
        .collect();

    write_getncchanges_reply(
        &objects,
        &links,
        from,
        usn_to,
        high_water,
        more_data,
        invocation_id,
        0,
    )
}

/// Build the reply to an `EXOP_FSMO_RID_ALLOC` request: allocate the next RID pool from
/// this DC's RID-Master watermark and return it as a single object carrying
/// `rIDAllocationPool` — a LARGE_INTEGER `(last_rid << 32) | first_rid` (the AD wire form,
/// so the low DWORD is the first RID and the high DWORD is the last) — with the
/// extended-operation result set to success. The requesting DC reads the granted pool
/// from that attribute (see [`crate::client::parse_rid_allocation_pool`]).
/// A GetNCChanges reply carrying only an extended-operation error (no object, no
/// delta) — used to refuse an extended op the source will not perform.
fn exop_error_reply(invocation_id: &[u8; 16], err_code: u32) -> Vec<u8> {
    write_getncchanges_reply(&[], &[], 0, 1, 1, false, invocation_id, err_code)
}

fn rid_alloc_reply(dir: &Directory, invocation_id: &[u8; 16]) -> Vec<u8> {
    const EXOP_ERR_SUCCESS: u32 = 0x0000_0001;
    // A durable pool is momentarily unavailable (a refill is in flight): reply with a
    // non-success extended-op result and no object; the requesting DC retries.
    const EXOP_ERR_DIR_ERROR: u32 = 0x0000_0006;
    let Some((base, count)) = dir.allocate_rid_pool(RID_POOL_SIZE) else {
        return write_getncchanges_reply(
            &[],
            &[],
            0,
            1,
            1,
            false,
            invocation_id,
            EXOP_ERR_DIR_ERROR,
        );
    };
    let last = base.saturating_add(count).saturating_sub(1);
    let next_available = base.saturating_add(count);
    // The granted pool as a LARGE_INTEGER (last << 32) | first — the value a real AD
    // client reads from its rIDSet.rIDAllocationPool.
    let allocation_pool: u64 = (u64::from(last) << 32) | u64::from(base);
    // The RID Manager$ watermark as a real RID master returns it in the reply:
    // rIDAvailablePool = (max_rid << 32) | next_available.
    let available_pool: u64 = (u64::from(RID_POOL_MAX) << 32) | u64::from(next_available);
    let nc = dns_domain_to_nc(dir.dns_domain());
    // Match Samba's reply shape: the RID Manager$ object carrying rIDAvailablePool. It
    // also carries rIDAllocationPool as the caller's granted pool — a magnetite
    // convenience a real client ignores (it reads its own rIDSet instead).
    let obj = ReplObject {
        guid: [0u8; 16],
        name: format!("CN=RID Manager$,CN=System,{nc}"),
        sid: Vec::new(),
        attrs: vec![
            ReplAttr {
                attid: ATTID_RIDALLOCATIONPOOL,
                values: vec![allocation_pool.to_le_bytes().to_vec()],
            },
            ReplAttr {
                attid: ATTID_RIDAVAILABLEPOOL,
                values: vec![available_pool.to_le_bytes().to_vec()],
            },
        ],
        usn: 1,
        meta: None,
    };
    // usnvecFrom/To and high_water are nominal (1) — a RID grant is not a delta page.
    write_getncchanges_reply(&[obj], &[], 0, 1, 1, false, invocation_id, EXOP_ERR_SUCCESS)
}

/// Marshal a `DRS_MSG_GETCHGREPLY_V6`: the fixed header, USN vectors, prefix table,
/// up-to-date vector, objects and linked values. `ext_op_err` is the extended-op
/// result (`EXOP_ERR_SUCCESS` for a RID allocation / FSMO transfer, 0 for a plain
/// replication reply). Shared by the normal replication path and the RID-allocation
/// extended operation.
#[allow(clippy::too_many_arguments)]
fn write_getncchanges_reply(
    objects: &[ReplObject],
    links: &[LinkVal],
    from: u64,
    usn_to: u64,
    high_water: u64,
    more_data: bool,
    invocation_id: &[u8; 16],
    ext_op_err: u32,
) -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.u32(6); // pdwOutVersion
    w.u32(6); // pmsgOut union tag = 6 (DWORD discriminant)
    w.bytes(&[0u8; 16]); // uuidDsaObjSrc
    w.bytes(invocation_id); // uuidInvocIdSrc (this source DSA)
    w.u32(0); // pNC (null)
    w.align(8); // USN_VECTOR is u64-aligned → 4 pad bytes here
    write_usn_vector(&mut w, from); // usnvecFrom (the cursor we resumed from)
    write_usn_vector(&mut w, usn_to); // usnvecTo (the new high-water mark)
    w.u32(0x0002_0000); // pUpToDateVecSrc referent (deferred below)
    w.u32(PREFIX_TABLE_COUNT); // PrefixTableSrc.PrefixCount (full default table)
    w.u32(0x0002_0080); // PrefixTableSrc.pPrefixEntry referent (deferred below)
    w.u32(ext_op_err); // ulExtendedRet (EXOP_ERR_* for an extended op; 0 otherwise)
    w.u32(objects.len() as u32); // cNumObjects
    w.u32(0); // cNumBytes
              // pObjects referent: null when this page is empty (client already caught up).
    w.u32(if objects.is_empty() { 0 } else { 0x0002_0004 });
    w.u32(u32::from(more_data)); // fMoreData: another page remains
    w.u32(0); // cNumNcSizeObjects
    w.u32(0); // cNumNcSizeValues
    w.u32(links.len() as u32); // cNumValues (linked values, e.g. memberships)
                               // rgValues referent: null when there are no links this page.
    w.u32(if links.is_empty() { 0 } else { 0x0002_0008 });
    w.u32(0); // dwDRSError
              // Deferred referents in field order: pUpToDateVecSrc first (field 6), then
              // pObjects (field 11). The up-to-date vector always ships (it reports the
              // source's TOTAL knowledge — the high-water mark, not this page's end); the
              // object graph is omitted when the page is empty.
    encode_uptodate_vector(&mut w, invocation_id, high_water);
    // PrefixTableSrc.pPrefixEntry deferral (field order: after pUpToDateVecSrc,
    // before pObjects) — the ATTRTYP prefix map a destination needs to decode attids.
    encode_prefix_table(&mut w);
    if !objects.is_empty() {
        encode_objects(&mut w, objects, invocation_id);
    }
    // rgValues (linked values) is the LAST deferred payload, after the objects.
    if !links.is_empty() {
        encode_linked_values(&mut w, links, invocation_id);
    }
    w.u32(STATUS_SUCCESS); // ErrorCode (after all pmsgOut referents)
    w.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory with ONLY the user `alice` (no groups), for tests that assert user
    /// counts / USN mechanics in isolation from the group objects the outbound now also
    /// serves (`Directory::default()` seeds two well-known groups).
    fn users_only() -> Directory {
        let mut d = Directory::new("EXAMPLE", "example.com", "EXAMPLE.COM", vec![21, 1, 2, 3]);
        d.add_user("alice", 1000, "password12").expect("alice key");
        d
    }

    #[test]
    fn bind_returns_extensions_handle_and_success() {
        let out = DrsuapiInterface::default().call(OP_BIND, &[]).unwrap();
        // referent(4) + MaxCount(4)=52 + cb(4)=52 + rgb(52) + handle(20) + status(4).
        assert_eq!(out.len(), 4 + 4 + 4 + 52 + 20 + 4);
        assert_ne!(&out[0..4], &[0u8; 4], "non-null ppextServer referent");
        assert_eq!(
            u32::from_le_bytes(out[4..8].try_into().unwrap()),
            52,
            "cb MaxCount"
        );
        assert_eq!(u32::from_le_bytes(out[8..12].try_into().unwrap()), 52, "cb");
        assert_eq!(&out[out.len() - 4..], &STATUS_SUCCESS.to_le_bytes());
        // phDrs is echoed just before the trailing ErrorCode.
        let handle = &out[out.len() - 24..out.len() - 4];
        assert_eq!(handle, &DRS_HANDLE);
    }

    #[test]
    fn get_nc_changes_returns_one_object() {
        let out = DrsuapiInterface::new(Arc::new(users_only()))
            .call(OP_GET_NC_CHANGES, &[])
            .unwrap();
        assert_eq!(
            u32::from_le_bytes(out[0..4].try_into().unwrap()),
            6,
            "pdwOutVersion"
        );
        assert_eq!(
            u32::from_le_bytes(out[4..8].try_into().unwrap()),
            6,
            "V6 union tag"
        );
        // cNumObjects at 0x70 = 1; ErrorCode trailing = 0.
        assert_eq!(
            u32::from_le_bytes(out[0x70..0x74].try_into().unwrap()),
            1,
            "cNumObjects"
        );
        assert_eq!(&out[out.len() - 4..], &STATUS_SUCCESS.to_le_bytes());
        // The sAMAccountName attid and the UTF-16 value "alice" both appear.
        let attid = ATTID_SAMACCOUNTNAME.to_le_bytes();
        assert!(
            out.windows(4).any(|w| w == attid),
            "sAMAccountName attid present"
        );
        let alice: Vec<u8> = "alice".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(
            out.windows(alice.len()).any(|w| w == alice),
            "alice value present"
        );
    }

    #[test]
    fn reply_carries_overridden_domain_sid_for_foreign_outbound() {
        // Serving outbound replication into a foreign domain: replicated objects must
        // carry THAT domain's SID. `Directory::set_domain_sid` overrides the default,
        // and the override must reach the object's objectSid (and the identifier
        // DSNAME's embedded SID, from which a consumer derives the RID to decrypt).
        let mut dir = Directory::new("MAG", "mag.test", "MAG.TEST", vec![21, 1, 2, 3]);
        dir.add_user("carol", 3200, "carolpass123").unwrap();
        dir.set_domain_sid(vec![21, 111, 222, 333]);
        let out = DrsuapiInterface::new(Arc::new(dir))
            .call(OP_GET_NC_CHANGES, &[])
            .unwrap();

        // S-1-5-21-111-222-333-3200 (little-endian sub-authorities) appears in the reply.
        let overridden = user_sid(&[21, 111, 222, 333], 3200);
        assert!(
            out.windows(overridden.len()).any(|w| w == overridden),
            "reply carries the overridden domain SID"
        );
        // The default SID it was constructed with must NOT survive the override.
        let default_sid = user_sid(&[21, 1, 2, 3], 3200);
        assert!(
            !out.windows(default_sid.len()).any(|w| w == default_sid),
            "the default domain SID was replaced"
        );
    }

    #[test]
    fn outbound_metadata_preserves_the_real_origin() {
        // A change that reached this DC by replication from ANOTHER DSA must be served
        // outbound with THAT origin (DSA/version/USN/time), not re-stamped as locally
        // originated — the prerequisite for magnetite↔magnetite convergence and loop
        // dampening. A user WITHOUT a stamp still falls back to self / version 1.
        let origin_dsa: [u8; 16] = [0xAB; 16];
        let mut dir = Directory::new("MAG", "mag.test", "MAG.TEST", vec![21, 1, 2, 3]);
        dir.add_user("carol", 3300, "carolpass123").unwrap(); // no stamp → self/v1
        dir.add_user("dave", 3301, "davepass123").unwrap();
        dir.set_user_repl_meta(
            "dave",
            ReplMeta {
                version: 7,
                originating_time: META_TIME + 500,
                originating_dsa: origin_dsa,
                originating_usn: 4242,
            },
        );
        let out = DrsuapiInterface::new(Arc::new(dir))
            .call(OP_GET_NC_CHANGES, &[])
            .unwrap();
        let parsed = parse_get_nc_changes_reply(&out).expect("decodes");

        let carol = parsed
            .objects
            .iter()
            .find(|o| o.sam_account_name().as_deref() == Some("carol"))
            .unwrap();
        let carol_md = carol.newest_metadata().expect("carol has metadata");
        assert_eq!(
            carol_md.version, 1,
            "unstamped user falls back to version 1"
        );
        assert_eq!(
            carol_md.originating_dsa, parsed.source_invocation_id,
            "unstamped user is stamped as originated by THIS DC"
        );

        let dave = parsed
            .objects
            .iter()
            .find(|o| o.sam_account_name().as_deref() == Some("dave"))
            .unwrap();
        let dave_md = dave.newest_metadata().expect("dave has metadata");
        assert_eq!(dave_md.version, 7, "the real originating version is served");
        assert_eq!(
            dave_md.originating_usn, 4242,
            "the real originating USN is served"
        );
        assert_eq!(
            dave_md.originating_time,
            META_TIME + 500,
            "the real originating time is served"
        );
        assert_eq!(
            dave_md.originating_dsa, origin_dsa,
            "the real origin DSA is served"
        );
        assert_ne!(
            dave_md.originating_dsa, parsed.source_invocation_id,
            "a replicated-in change is NOT re-stamped as originated by this DC"
        );
    }

    #[test]
    fn outbound_dampens_a_change_the_destination_already_holds() {
        // Tier C item 3: a change that originated at ANOTHER DSA (B) must not be re-served
        // to a destination whose up-to-dateness vector already covers B up to that USN —
        // otherwise the change boomerangs and two magnetite nodes ping-pong.
        let origin_dsa = [0xBBu8; 16];
        let mut dir = Directory::new("MAG", "mag.test", "MAG.TEST", vec![21, 1, 2, 3]);
        dir.add_user("carol", 3400, "carolpass123").unwrap();
        dir.set_user_repl_meta(
            "carol",
            ReplMeta {
                version: 3,
                originating_time: META_TIME,
                originating_dsa: origin_dsa,
                originating_usn: 5,
            },
        );
        let iface = DrsuapiInterface::new(Arc::new(dir));

        // Destination's UTDV cursor: it already holds DSA B up to USN 5 → dampened.
        // (utdv_dest_cursor scans for the DSA bytes past the header and reads the USN that
        // follows, so appending {B, high_usn} to a valid request stub forms one cursor.)
        let mut held = request_stub(0);
        held.extend_from_slice(&origin_dsa);
        held.extend_from_slice(&5u64.to_le_bytes());
        let out = iface
            .call_with_session(OP_GET_NC_CHANGES, &held, Some(&SECRET_SESSION_KEY))
            .unwrap();
        assert_eq!(
            cnum_objects(&out),
            0,
            "the destination already holds carol's change from B — do not re-serve it"
        );

        // If the destination only holds B up to USN 4 (< 5), the change IS newer → sent.
        let mut stale = request_stub(0);
        stale.extend_from_slice(&origin_dsa);
        stale.extend_from_slice(&4u64.to_le_bytes());
        let out2 = iface
            .call_with_session(OP_GET_NC_CHANGES, &stale, Some(&SECRET_SESSION_KEY))
            .unwrap();
        assert_eq!(
            cnum_objects(&out2),
            1,
            "a change newer than the destination holds from B is still served"
        );
    }

    #[test]
    fn get_nc_changes_requires_authentication_and_replication_rights() {
        let mut dir = Directory::new("MAG", "mag.test", "MAG.TEST", vec![21, 5, 6, 7]);
        dir.add_user("admin", 1000, "password12").unwrap(); // a replication-privileged user
        dir.add_user("bob", 1001, "bobpass123").unwrap(); // an ordinary user
                                                          // `admin` is a member of Domain Admins (RID 512) → holds replication rights.
        dir.add_group_with_members("Domain Admins", 512, vec![1000]);
        let iface = DrsuapiInterface::new(Arc::new(dir));

        // DCSync replicates credentials: an unauthenticated caller (no bound principal)
        // is refused with ACCESS_DENIED.
        assert_eq!(
            iface.call_authenticated(OP_GET_NC_CHANGES, &[], Some(&SECRET_SESSION_KEY), None),
            Err(fault::ACCESS_DENIED),
            "unauthenticated DCSync must be refused"
        );

        // Authenticated but NOT replication-privileged (ordinary user) → refused (authZ).
        assert_eq!(
            iface.call_authenticated(
                OP_GET_NC_CHANGES,
                &[],
                Some(&SECRET_SESSION_KEY),
                Some("MAG\\bob"),
            ),
            Err(fault::ACCESS_DENIED),
            "an authenticated but unprivileged user must not be able to DCSync"
        );

        // Authenticated AND in a replication-privileged group → served (audit records who).
        // The realm-qualified form normalizes to the same account.
        assert!(
            iface
                .call_authenticated(
                    OP_GET_NC_CHANGES,
                    &[],
                    Some(&SECRET_SESSION_KEY),
                    Some("admin@MAG.TEST"),
                )
                .is_ok(),
            "a replication-privileged principal's DCSync is served"
        );

        // BIND is part of the auth handshake and precedes a principal — still allowed.
        assert!(iface.call_authenticated(OP_BIND, &[], None, None).is_ok());
    }

    #[test]
    fn account_name_normalization_strips_domain_realm_and_service() {
        assert_eq!(normalize_account_name("MAG\\alice"), "alice");
        assert_eq!(normalize_account_name("alice@MAG.TEST"), "alice");
        assert_eq!(normalize_account_name("host/dc1.mag.test"), "host");
        assert_eq!(normalize_account_name("  bob  "), "bob");
    }

    #[test]
    fn group_object_class_uses_the_ad_group_governs_id() {
        // A real consumer (Samba) creates the class named by the governsID literally:
        // 0x000A0008 = OID 1.2.840.113556.1.5.8 = the AD security-group class, NOT
        // 0x00010009 = 2.5.6.9 = X.500 groupOfNames. Then top (0x00010000).
        let ids: Vec<u32> = group_object_class()
            .iter()
            .map(|v| u32::from_le_bytes(v.clone().try_into().unwrap()))
            .collect();
        assert_eq!(ids, vec![0x000A_0008, 0x0001_0000]);
    }

    #[test]
    fn outbound_serves_group_objects() {
        // Tier C item 5a: groups replicate outbound as `group` objects (identity +
        // groupType), alongside users, in one USN stream.
        let mut dir = Directory::new("MAG", "mag.test", "MAG.TEST", vec![21, 5, 6, 7]);
        dir.add_user("alice", 1000, "password12").unwrap();
        dir.add_group("Engineers", 1200);
        let out = DrsuapiInterface::new(Arc::new(dir))
            .call(OP_GET_NC_CHANGES, &[])
            .unwrap();
        let parsed = parse_get_nc_changes_reply(&out).expect("reply decodes");
        assert_eq!(
            parsed.objects.len(),
            2,
            "the user AND the group both replicate"
        );

        let group = parsed
            .objects
            .iter()
            .find(|o| o.is_group())
            .expect("the group replicates as a group object");
        assert_eq!(group.sam_account_name().as_deref(), Some("Engineers"));
        assert_eq!(group.object_rid(), Some(1200));

        let user = parsed
            .objects
            .iter()
            .find(|o| !o.is_group())
            .expect("the user replicates");
        assert_eq!(user.sam_account_name().as_deref(), Some("alice"));
    }

    #[test]
    fn outbound_serves_group_memberships_as_linked_values() {
        // Tier C item 5b: group `member` memberships replicate outbound as present
        // REPLVALINF linked values, sourced from the group and targeting each member by
        // GUID + SID. Round-trip through our own decoder to prove the wire format.
        let mut dir = Directory::new("MAG", "mag.test", "MAG.TEST", vec![21, 5, 6, 7]);
        dir.add_user("alice", 1000, "password12").unwrap();
        dir.add_user("bob", 1001, "bobpass123").unwrap();
        dir.add_group_with_members("Engineers", 1200, vec![1000, 1001]);
        let out = DrsuapiInterface::new(Arc::new(dir))
            .call(OP_GET_NC_CHANGES, &[])
            .unwrap();
        let parsed = parse_get_nc_changes_reply(&out).expect("reply decodes");

        assert_eq!(
            parsed.links.len(),
            2,
            "both memberships replicate as linked values"
        );
        let group_guid = object_guid(1200);
        for l in &parsed.links {
            assert_eq!(l.source_guid, group_guid, "the link sources from the group");
            assert_eq!(l.attr_id, LINK_ATTR_MEMBER, "the `member` link attribute");
            assert!(l.present, "a current membership is present");
        }
        // Targets are alice (RID 1000) and bob (RID 1001), recoverable by SID and GUID.
        let member_rids: Vec<u32> = parsed
            .links
            .iter()
            .map(|l| u32::from_le_bytes(l.target_sid[l.target_sid.len() - 4..].try_into().unwrap()))
            .collect();
        assert!(member_rids.contains(&1000) && member_rids.contains(&1001));
        let target_guids: Vec<[u8; 16]> = parsed.links.iter().map(|l| l.target_guid).collect();
        assert!(
            target_guids.contains(&object_guid(1000)) && target_guids.contains(&object_guid(1001))
        );
    }

    #[test]
    fn outbound_serves_absent_member_tombstones() {
        // Tier C item 5d: a removed member is served as an ABSENT link carrying its real
        // stamp, so the removal replicates and a peer conflict-resolves it per link.
        let mut dir = Directory::new("MAG", "mag.test", "MAG.TEST", vec![21, 5, 6, 7]);
        dir.add_user("alice", 1000, "password12").unwrap();
        dir.add_group("Engineers", 1200);
        dir.set_group_member_links(
            "Engineers",
            vec![
                crate::directory::GroupLink {
                    member_rid: 1000,
                    present: true,
                    repl_meta: None,
                },
                crate::directory::GroupLink {
                    member_rid: 1001,
                    present: false, // bob was removed
                    repl_meta: Some(ReplMeta {
                        version: 2,
                        originating_time: META_TIME,
                        originating_dsa: [0xBB; 16],
                        originating_usn: 5,
                    }),
                },
            ],
        );
        let out = DrsuapiInterface::new(Arc::new(dir))
            .call(OP_GET_NC_CHANGES, &[])
            .unwrap();
        let parsed = parse_get_nc_changes_reply(&out).expect("reply decodes");

        let rid_of = |sid: &[u8]| u32::from_le_bytes(sid[sid.len() - 4..].try_into().unwrap());
        let bob = parsed
            .links
            .iter()
            .find(|l| !l.target_sid.is_empty() && rid_of(&l.target_sid) == 1001)
            .expect("bob's link is served");
        assert!(
            !bob.present,
            "bob's removal is served as an absent tombstone"
        );
        assert_eq!(bob.version, 2, "the removal's link version is served");
        assert_eq!(
            bob.originating_dsa, [0xBB; 16],
            "the removal's origin is served"
        );

        let alice = parsed
            .links
            .iter()
            .find(|l| !l.target_sid.is_empty() && rid_of(&l.target_sid) == 1000)
            .expect("alice's link is served");
        assert!(alice.present, "alice remains a present membership");
    }

    #[test]
    fn reply_carries_prefix_table_and_per_attribute_metadata() {
        // A destination needs the SCHEMA_PREFIX_TABLE (to decode attids) and the
        // PROPERTY_META_DATA_EXT vector (to apply/conflict-resolve). Round-trip the
        // reply through our own decoder and assert both survived.
        let out = DrsuapiInterface::default()
            .call(OP_GET_NC_CHANGES, &[])
            .unwrap();
        // Header PrefixCount is 1; the MS attr-prefix OID bytes appear in the table.
        assert_eq!(
            u32::from_le_bytes(out[0x64..0x68].try_into().unwrap()),
            PREFIX_TABLE_COUNT,
            "PrefixTableSrc.PrefixCount"
        );
        assert!(
            out.windows(8).any(|w| w == ATTR_PREFIX_OID),
            "attr-prefix OID in table"
        );

        let changes = parse_get_nc_changes_reply(&out).expect("decodable enriched reply");
        let obj = changes.objects.first().expect("one object");
        // Every attribute now carries metadata stamped with this source's DSA.
        assert!(
            obj.attrs.iter().all(|a| a.metadata.is_some()),
            "per-attr metadata present"
        );
        let md = obj.newest_metadata().expect("object-level metadata");
        assert_eq!(md.version, 1);
        assert_eq!(
            md.originating_dsa, DSA_INVOCATION_ID,
            "stamped with our invocation id"
        );
    }

    #[test]
    fn get_nc_changes_replicates_every_user_as_a_chain() {
        // A directory with two users → a two-node REPLENTINFLIST chain.
        let mut dir = users_only(); // alice (RID 1000)
        dir.add_user("bob", 1001, "bobpass123").unwrap();
        let out = DrsuapiInterface::new(Arc::new(dir))
            .call(OP_GET_NC_CHANGES, &[])
            .unwrap();

        // cNumObjects == 2.
        assert_eq!(
            u32::from_le_bytes(out[0x70..0x74].try_into().unwrap()),
            2,
            "cNumObjects"
        );
        // The pObjects graph begins at 0xC8 (after the deferred up-to-date vector);
        // the first node's pNextEntInf (its first field) is a non-null referent
        // chaining to the second object.
        assert_ne!(
            &out[0xC8..0xCC],
            &[0u8; 4],
            "first pNextEntInf links to next node"
        );
        // Both users' sAMAccountName values are present.
        for name in ["alice", "bob"] {
            let v: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
            assert!(out.windows(v.len()).any(|w| w == v), "{name} value present");
        }
        // One encrypted secret per object → at least two salts on the wire.
        let salts = out.windows(16).filter(|w| *w == [0xAAu8; 16]).count();
        assert!(salts >= 2, "an encrypted unicodePwd per object");
    }

    #[test]
    fn parse_reply_round_trips_the_encoded_objects() {
        // Encode a 2-object reply, then decode it back to the same objects — the
        // consumer path (Tier C C1) inverts our (impacket-validated) encoder.
        let mut dir = users_only(); // alice (RID 1000, pw password12)
        dir.add_user("bob", 1001, "bobpass123").unwrap();
        let out = DrsuapiInterface::new(Arc::new(dir))
            .call(OP_GET_NC_CHANGES, &[])
            .unwrap();

        let parsed = parse_get_nc_changes_reply(&out).expect("reply decodes");
        assert_eq!(parsed.source_invocation_id, DSA_INVOCATION_ID);
        assert_eq!(parsed.usn_to, 2, "high-water = 2 users");
        assert!(!parsed.more_data);
        assert_eq!(parsed.objects.len(), 2);

        let alice = &parsed.objects[0];
        assert_eq!(alice.sam_account_name().as_deref(), Some("alice"));
        assert_eq!(alice.object_rid(), Some(1000));
        assert_eq!(alice.guid, object_guid(1000));
        assert_eq!(
            alice.nt_hash(&SECRET_SESSION_KEY),
            Some(crate::directory::nt_hash("password12")),
            "decrypted NT hash round-trips"
        );

        let bob = &parsed.objects[1];
        assert_eq!(bob.sam_account_name().as_deref(), Some("bob"));
        assert_eq!(bob.object_rid(), Some(1001));
        assert_eq!(
            bob.nt_hash(&SECRET_SESSION_KEY),
            Some(crate::directory::nt_hash("bobpass123"))
        );

        // An empty (caught-up) reply decodes to zero objects, not an error.
        let empty = DrsuapiInterface::default()
            .call(OP_GET_NC_CHANGES, &request_stub_max(99, 0))
            .unwrap();
        let parsed_empty = parse_get_nc_changes_reply(&empty).expect("empty decodes");
        assert!(parsed_empty.objects.is_empty());
    }

    /// Build a minimal V8 GetNCChanges request stub carrying `from` as the cursor
    /// (`usnvecFrom.usnHighObjUpdate` at byte 72) and `max_objects` as `cMaxObjects`
    /// (byte 104) — the layout the server parses.
    fn request_stub_max(from: u64, max_objects: u32) -> Vec<u8> {
        let mut s = vec![0u8; 120];
        s[20..24].copy_from_slice(&8u32.to_le_bytes()); // dwInVersion = 8
        s[28..32].copy_from_slice(&8u32.to_le_bytes()); // union tag = 8
        s[72..80].copy_from_slice(&from.to_le_bytes()); // usnvecFrom.usnHighObjUpdate
        s[104..108].copy_from_slice(&max_objects.to_le_bytes()); // cMaxObjects
        s
    }

    /// A request stub with no page limit (`cMaxObjects` = 0 → the whole delta).
    fn request_stub(from: u64) -> Vec<u8> {
        request_stub_max(from, 0)
    }

    use crate::directory::RID_POOL_START;

    /// A request stub carrying an extended operation (`ulExtendedOp` at byte 112).
    fn request_stub_exop(ext_op: u32) -> Vec<u8> {
        let mut s = request_stub(0);
        s[112..116].copy_from_slice(&ext_op.to_le_bytes());
        s
    }

    #[test]
    fn is_disabled_and_is_deleted_read_uac_and_tombstone_marker() {
        let disabled = ReplicatedObject {
            guid: [0u8; 16],
            name: "CN=dave".to_string(),
            attrs: vec![ReplicatedAttr {
                attid: ATTID_USERACCOUNTCONTROL,
                // NORMAL_ACCOUNT (0x200) | ACCOUNTDISABLE (0x2).
                values: vec![0x0000_0202u32.to_le_bytes().to_vec()],
                metadata: None,
            }],
        };
        assert!(disabled.is_disabled());
        assert!(!disabled.is_deleted());

        let enabled = ReplicatedObject {
            guid: [0u8; 16],
            name: "CN=eve".to_string(),
            attrs: vec![ReplicatedAttr {
                attid: ATTID_USERACCOUNTCONTROL,
                values: vec![0x0000_0200u32.to_le_bytes().to_vec()],
                metadata: None,
            }],
        };
        assert!(!enabled.is_disabled());

        let tombstone = ReplicatedObject {
            guid: [0u8; 16],
            name: "CN=dave\\0ADEL:...".to_string(),
            attrs: vec![ReplicatedAttr {
                attid: ATTID_ISDELETED,
                values: vec![vec![1, 0, 0, 0]], // isDeleted = TRUE
                metadata: None,
            }],
        };
        assert!(tombstone.is_deleted());
        // A full-sync tombstone that carries NO isDeleted attribute (as real Samba ships
        // it) is still detected by its Deleted Objects container / mangled RDN — the case
        // that leaked a deleted OU into the projection before this guard.
        let full_sync_tombstone = ReplicatedObject {
            guid: [0u8; 16],
            name: "OU=probe\\0ADEL:58bbf300,CN=Deleted Objects,DC=ex,DC=com".to_string(),
            attrs: vec![ReplicatedAttr {
                attid: ATTID_NAME,
                values: vec![vec![1, 2]],
                metadata: None,
            }],
        };
        assert!(
            full_sync_tombstone.is_deleted(),
            "a Deleted Objects tombstone is deleted even without isDeleted"
        );
        // An object with neither marker is live and enabled.
        let live = ReplicatedObject {
            guid: [0u8; 16],
            name: "CN=frank".to_string(),
            attrs: Vec::new(),
        };
        assert!(!live.is_deleted());
        assert!(!live.is_disabled());
    }

    #[test]
    fn generic_projection_classifies_and_renders_safe_attributes() {
        fn utf16(s: &str) -> Vec<u8> {
            s.encode_utf16().flat_map(u16::to_le_bytes).collect()
        }
        // An attributeSchema object (classified by the PRESENCE of attributeID), with a
        // few safe-syntax attributes to render.
        let obj = ReplicatedObject {
            guid: [0u8; 16],
            name: "CN=ms-DS-Custom,CN=Schema,CN=Configuration,DC=ex,DC=com".to_string(),
            attrs: vec![
                ReplicatedAttr {
                    attid: ATTID_CN,
                    values: vec![utf16("ms-DS-Custom")],
                    metadata: None,
                },
                ReplicatedAttr {
                    attid: ATTID_LDAPDISPLAYNAME,
                    values: vec![utf16("msDSCustom")],
                    metadata: None,
                },
                ReplicatedAttr {
                    attid: ATTID_INSTANCETYPE,
                    values: vec![4u32.to_le_bytes().to_vec()],
                    metadata: None,
                },
                ReplicatedAttr {
                    attid: ATTID_OMSYNTAX,
                    values: vec![64u32.to_le_bytes().to_vec()],
                    metadata: None,
                },
                ReplicatedAttr {
                    attid: ATTID_ISSINGLEVALUED,
                    values: vec![1u32.to_le_bytes().to_vec()],
                    metadata: None,
                },
                // Presence-only classifier (its OID value is NOT rendered in this slice).
                ReplicatedAttr {
                    attid: ATTID_ATTRIBUTEID,
                    values: vec![vec![1, 2, 3, 4]],
                    metadata: None,
                },
                ReplicatedAttr {
                    attid: ATTID_OBJECTCATEGORY,
                    values: vec![encode_flat_dsname(
                        &[0u8; 16],
                        "CN=Attribute-Schema,CN=Schema,CN=Configuration,DC=ex,DC=com",
                    )],
                    metadata: None,
                },
            ],
        };
        assert_eq!(
            obj.projected_object_classes(),
            Some(vec!["top".to_string(), "attributeSchema".to_string()])
        );
        let attrs = obj.ldap_attributes();
        assert_eq!(attrs.get("cn"), Some(&vec!["ms-DS-Custom".to_string()]));
        assert_eq!(
            attrs.get("lDAPDisplayName"),
            Some(&vec!["msDSCustom".to_string()])
        );
        assert_eq!(attrs.get("instanceType"), Some(&vec!["4".to_string()]));
        assert_eq!(attrs.get("oMSyntax"), Some(&vec!["64".to_string()]));
        assert_eq!(attrs.get("isSingleValued"), Some(&vec!["TRUE".to_string()]));
        assert_eq!(
            attrs.get("objectCategory"),
            Some(&vec![
                "CN=Attribute-Schema,CN=Schema,CN=Configuration,DC=ex,DC=com".to_string()
            ])
        );
        // The OID-valued attributeID is NOT rendered (deferred, needs real-Samba validation).
        assert!(!attrs.contains_key("attributeID"));

        // An OU is classified by its RDN.
        let ou = ReplicatedObject {
            guid: [0u8; 16],
            name: "OU=Sales,DC=ex,DC=com".to_string(),
            attrs: vec![ReplicatedAttr {
                attid: ATTID_NAME,
                values: vec![utf16("Sales")],
                metadata: None,
            }],
        };
        assert_eq!(
            ou.projected_object_classes(),
            Some(vec!["top".to_string(), "organizationalUnit".to_string()])
        );
        assert_eq!(ou.dn(), "OU=Sales,DC=ex,DC=com");

        // An unclassifiable object (a plain container) returns None → never projected.
        let container = ReplicatedObject {
            guid: [0u8; 16],
            name: "CN=Foo,DC=ex,DC=com".to_string(),
            attrs: vec![ReplicatedAttr {
                attid: ATTID_CN,
                values: vec![utf16("Foo")],
                metadata: None,
            }],
        };
        assert_eq!(container.projected_object_classes(), None);
    }

    #[test]
    fn decodes_sambas_rid_available_pool_wire_value() {
        // The exact 8-byte rIDAvailablePool value real Samba returned from
        // EXOP_FSMO_RID_ALLOC (attid 0x00090172): (max_rid << 32) | next_available.
        // 0x3fffffff000011f8 -> next=4600, max=0x3fffffff.
        let obj = ReplicatedObject {
            guid: [0u8; 16],
            name: "CN=RID Manager$".to_string(),
            attrs: vec![ReplicatedAttr {
                attid: ATTID_RIDAVAILABLEPOOL,
                values: vec![0x3fff_ffff_0000_11f8u64.to_le_bytes().to_vec()],
                metadata: None,
            }],
        };
        assert_eq!(obj.rid_available_pool(), Some((4600, 0x3fff_ffff)));
    }

    #[test]
    fn rid_alloc_extended_op_grants_disjoint_climbing_pools() {
        let iface = DrsuapiInterface::new(Arc::new(users_only()));
        let stub = request_stub_exop(exop::FSMO_RID_ALLOC);

        // The first grant hands out the pool starting at the RID watermark.
        let reply1 = iface
            .call_with_session(OP_GET_NC_CHANGES, &stub, None)
            .unwrap();
        let changes1 = parse_get_nc_changes_reply(&reply1).expect("decodable reply");
        assert_eq!(
            ExOpErr::from_raw(changes1.ext_op_err),
            ExOpErr::Success,
            "extended-op result is success"
        );
        let obj1 = changes1.objects.first().expect("one RID Manager$ object");
        assert_eq!(
            obj1.rid_allocation_pool(),
            Some((RID_POOL_START, RID_POOL_SIZE)),
            "first granted pool"
        );
        // The reply carries the RID Manager$ watermark in Samba's shape:
        // rIDAvailablePool = (max << 32) | next_available.
        assert_eq!(
            obj1.rid_available_pool(),
            Some((RID_POOL_START + RID_POOL_SIZE, RID_POOL_MAX)),
            "rIDAvailablePool watermark after the first grant"
        );

        // A second request hands out the NEXT disjoint pool (watermark advanced).
        let reply2 = iface
            .call_with_session(OP_GET_NC_CHANGES, &stub, None)
            .unwrap();
        let changes2 = parse_get_nc_changes_reply(&reply2).expect("decodable reply");
        let obj2 = changes2.objects.first().expect("one RID Manager$ object");
        assert_eq!(
            obj2.rid_allocation_pool(),
            Some((RID_POOL_START + RID_POOL_SIZE, RID_POOL_SIZE)),
            "second pool does not overlap the first"
        );
        assert_eq!(
            obj2.rid_available_pool(),
            Some((RID_POOL_START + 2 * RID_POOL_SIZE, RID_POOL_MAX)),
            "watermark advanced by one pool"
        );
    }

    #[test]
    fn rid_replica_refuses_to_grant_pools() {
        // A DC that is NOT the RID master must refuse EXOP_FSMO_RID_ALLOC, so it never
        // hands out a pool overlapping the real master's watermark.
        let iface = DrsuapiInterface::new(Arc::new(users_only())).with_rid_master(false);
        let reply = iface
            .call_with_session(
                OP_GET_NC_CHANGES,
                &request_stub_exop(exop::FSMO_RID_ALLOC),
                None,
            )
            .unwrap();
        let changes = parse_get_nc_changes_reply(&reply).expect("decodable reply");
        assert_eq!(
            ExOpErr::from_raw(changes.ext_op_err),
            ExOpErr::NotOwner,
            "a replica reports FSMO_NOT_OWNER"
        );
        assert!(changes.objects.is_empty(), "no pool granted");
    }

    #[test]
    fn fsmo_role_transfer_requests_are_refused() {
        // magnetite manages FSMO ownership out of band, so a DRS role-transfer request
        // gets a defined refusal — not the replication deltas a normal request returns.
        let iface = DrsuapiInterface::new(Arc::new(users_only()));
        for op in [
            exop::FSMO_RID_REQ_ROLE,
            exop::FSMO_REQ_PDC,
            exop::FSMO_REQ_ROLE,
            exop::FSMO_ABANDON_ROLE,
        ] {
            let reply = iface
                .call_with_session(OP_GET_NC_CHANGES, &request_stub_exop(op), None)
                .unwrap();
            let changes = parse_get_nc_changes_reply(&reply).expect("decodable reply");
            assert_eq!(
                ExOpErr::from_raw(changes.ext_op_err),
                ExOpErr::RefusingRoles,
                "role transfer op {op:#x} is refused"
            );
            assert!(
                changes.objects.is_empty(),
                "a refusal carries no object (op {op:#x})"
            );
        }
    }

    fn cnum_objects(out: &[u8]) -> u32 {
        u32::from_le_bytes(out[0x70..0x74].try_into().unwrap())
    }

    fn usn_to(out: &[u8]) -> u64 {
        // usnvecTo.usnHighObjUpdate sits at byte 72 of the reply.
        u64::from_le_bytes(out[72..80].try_into().unwrap())
    }

    fn fmoredata(out: &[u8]) -> u32 {
        // fMoreData sits at reply byte 0x7C (after cNumObjects, cNumBytes, pObjects).
        u32::from_le_bytes(out[0x7c..0x80].try_into().unwrap())
    }

    #[test]
    fn get_nc_changes_honours_usn_cursor() {
        let mut dir = users_only(); // alice (USN 1)
        dir.add_user("bob", 1001, "bobpass123").unwrap(); // bob (USN 2)
        let iface = DrsuapiInterface::new(Arc::new(dir));

        // Cursor 0 → both objects, high-water mark reported as 2.
        let all = iface
            .call_with_session(OP_GET_NC_CHANGES, &request_stub(0), None)
            .unwrap();
        assert_eq!(cnum_objects(&all), 2, "from 0 replicates both users");
        assert_eq!(usn_to(&all), 2, "usnvecTo is the high-water mark");

        // Cursor 1 → only bob (USN 2 > 1) remains.
        let after_alice = iface
            .call_with_session(OP_GET_NC_CHANGES, &request_stub(1), None)
            .unwrap();
        assert_eq!(cnum_objects(&after_alice), 1, "from 1 replicates only bob");
        let bob: Vec<u8> = "bob".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(
            after_alice.windows(bob.len()).any(|w| w == bob),
            "bob present"
        );

        // Cursor 2 → caught up: no objects, pObjects null, watermark still 2.
        let caught_up = iface
            .call_with_session(OP_GET_NC_CHANGES, &request_stub(2), None)
            .unwrap();
        assert_eq!(cnum_objects(&caught_up), 0, "from 2 is caught up");
        assert_eq!(usn_to(&caught_up), 2, "watermark holds when caught up");
        // pObjects referent (byte 0x78) is null when the delta is empty.
        assert_eq!(
            &caught_up[0x78..0x7c],
            &[0u8; 4],
            "pObjects null when empty"
        );
    }

    /// A real consumer resumes from `usnvecFrom.highest_usn` — the THIRD hyper of the
    /// high-water mark (offset 72 + 16 = 88), which is the field Samba's server reads.
    /// magnetite must honour it even when `tmp_highest_usn` (offset 72) is left zero,
    /// else a caught-up destination re-pulls every object and hits a GUID conflict.
    #[test]
    fn get_nc_changes_resumes_from_highest_usn_field() {
        let mut dir = users_only(); // alice (USN 1)
        dir.add_user("bob", 1001, "bobpass123").unwrap(); // bob (USN 2)
        let iface = DrsuapiInterface::new(Arc::new(dir));

        // Cursor carried ONLY in highest_usn; tmp_highest_usn stays 0.
        let mut stub = request_stub(0);
        stub[88..96].copy_from_slice(&2u64.to_le_bytes());
        let caught_up = iface
            .call_with_session(OP_GET_NC_CHANGES, &stub, None)
            .unwrap();
        assert_eq!(
            cnum_objects(&caught_up),
            0,
            "highest_usn=2 means the destination is caught up"
        );

        // And the reply's usnvecTo stamps the high-water mark in highest_usn too, so a
        // consumer that reads that field advances correctly next cycle.
        let all = iface
            .call_with_session(OP_GET_NC_CHANGES, &request_stub(0), None)
            .unwrap();
        assert_eq!(
            u64::from_le_bytes(all[88..96].try_into().unwrap()),
            2,
            "usnvecTo.highest_usn is the high-water mark"
        );
    }

    #[test]
    fn get_nc_changes_pages_with_fmoredata() {
        let mut dir = users_only(); // alice (USN 1)
        dir.add_user("bob", 1001, "bobpass123").unwrap(); // bob (USN 2)
        let iface = DrsuapiInterface::new(Arc::new(dir));

        // Page 1: cursor 0, cMaxObjects 1 → alice only, more data pending, resume @1.
        let p1 = iface
            .call_with_session(OP_GET_NC_CHANGES, &request_stub_max(0, 1), None)
            .unwrap();
        assert_eq!(cnum_objects(&p1), 1, "page 1 capped at one object");
        assert_eq!(fmoredata(&p1), 1, "fMoreData set — another page remains");
        assert_eq!(usn_to(&p1), 1, "usnvecTo resumes after alice");
        let alice: Vec<u8> = "alice".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(
            p1.windows(alice.len()).any(|w| w == alice),
            "alice on page 1"
        );

        // Page 2: cursor 1, cMaxObjects 1 → bob only, no more data, resume @2.
        let p2 = iface
            .call_with_session(OP_GET_NC_CHANGES, &request_stub_max(1, 1), None)
            .unwrap();
        assert_eq!(cnum_objects(&p2), 1, "page 2 has the last object");
        assert_eq!(fmoredata(&p2), 0, "fMoreData clear — final page");
        assert_eq!(usn_to(&p2), 2, "usnvecTo at the high-water mark");
        let bob: Vec<u8> = "bob".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(p2.windows(bob.len()).any(|w| w == bob), "bob on page 2");
    }

    #[test]
    fn get_nc_changes_consumes_destination_uptodate_vector() {
        let mut dir = users_only(); // alice (USN 1)
        dir.add_user("bob", 1001, "bobpass123").unwrap(); // bob (USN 2)
        let iface = DrsuapiInterface::new(Arc::new(dir));

        // usnvecFrom is 0, but the destination's pUpToDateVecDest carries a cursor
        // for THIS source DSA saying it already holds up to USN 1 — so alice (USN 1)
        // is skipped and only bob (USN 2) is replicated.
        let mut stub = request_stub(0);
        stub.extend_from_slice(&DSA_INVOCATION_ID); // rgCursors[0].uuidDsa
        stub.extend_from_slice(&1u64.to_le_bytes()); // usnHighPropUpdate

        let out = iface
            .call_with_session(OP_GET_NC_CHANGES, &stub, None)
            .unwrap();
        assert_eq!(
            cnum_objects(&out),
            1,
            "only the object newer than the dest cursor"
        );
        let bob: Vec<u8> = "bob".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(out.windows(bob.len()).any(|w| w == bob), "bob replicated");
        let alice: Vec<u8> = "alice".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(
            !out.windows(alice.len()).any(|w| w == alice),
            "alice already held by the destination → skipped"
        );
    }

    #[test]
    fn get_nc_changes_includes_uptodate_vector() {
        let out = DrsuapiInterface::default()
            .call(OP_GET_NC_CHANGES, &[])
            .unwrap();
        // pUpToDateVecSrc referent (reply byte 0x60) is now non-null.
        assert_ne!(
            &out[0x60..0x64],
            &[0u8; 4],
            "pUpToDateVecSrc referent present"
        );
        // Its deferred UPTODATE_VECTOR_V2_EXT starts at 0x94: MaxCount=1, dwVersion=2.
        assert_eq!(
            u32::from_le_bytes(out[0x94..0x98].try_into().unwrap()),
            1,
            "cursor MaxCount"
        );
        assert_eq!(
            u32::from_le_bytes(out[0x98..0x9c].try_into().unwrap()),
            2,
            "dwVersion=2"
        );
        // The single cursor carries this source DSA's invocation ID.
        assert!(
            out.windows(16).any(|w| w == DSA_INVOCATION_ID),
            "cursor uuidDsa = source DSA invocation ID"
        );
        // The header's uuidInvocIdSrc (byte 0x18) is the same invocation ID.
        assert_eq!(
            &out[0x18..0x28],
            &DSA_INVOCATION_ID,
            "header uuidInvocIdSrc"
        );
    }

    #[test]
    fn unknown_opnum_faults() {
        assert_eq!(
            DrsuapiInterface::default().call(9, &[]),
            Err(fault::OP_RNG_ERROR)
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn secret_encryption_matches_impacket_ground_truth() {
        // Vectors captured from impacket (MD4/deriveKey/removeDESLayer/RC4):
        // password "password12", RID 1000, sessionKey 0..15, salt 0xAA×16.
        assert_eq!(
            hex(&crate::directory::nt_hash("password12")),
            "1b62018f0d05c737d06402294ce24236"
        );
        let des = des_encrypt_hash(&crate::directory::nt_hash("password12"), 1000);
        assert_eq!(hex(&des), "5ec549fa28f21b0dfa8f9f063da0d70d");
        // The full 36-byte encrypted unicodePwd attribute value must match exactly.
        let value = encrypted_unicode_pwd(
            &crate::directory::nt_hash("password12"),
            1000,
            &SECRET_SESSION_KEY,
        );
        assert_eq!(
            hex(&value),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa63ef1d1b88ade2360fe6f9fdb029eea83e721fcb",
        );
    }

    #[test]
    fn decrypt_unicode_pwd_recovers_the_nt_hash() {
        // The consumer inverse (Tier C C1): the same encrypted value decrypts back
        // to the original NT hash under the same session key + RID.
        let nt = crate::directory::nt_hash("password12");
        let value = encrypted_unicode_pwd(&nt, 1000, &SECRET_SESSION_KEY);
        let recovered =
            decrypt_unicode_pwd(&value, 1000, &SECRET_SESSION_KEY).expect("decrypt succeeds");
        assert_eq!(recovered, nt, "recovered NT hash matches the original");

        // A wrong session key fails the CRC check rather than returning garbage.
        assert!(decrypt_unicode_pwd(&value, 1000, &[9u8; 16]).is_none());
        // A wrong RID unwraps (CRC is over the DES layer) but yields a different hash.
        assert_ne!(
            decrypt_unicode_pwd(&value, 1001, &SECRET_SESSION_KEY),
            Some(nt)
        );
    }

    #[test]
    fn reply_carries_encrypted_unicode_pwd() {
        let out = DrsuapiInterface::new(Arc::new(users_only()))
            .call(OP_GET_NC_CHANGES, &[])
            .unwrap();
        assert_eq!(
            u32::from_le_bytes(out[0x70..0x74].try_into().unwrap()),
            1,
            "one object"
        );
        let attid = ATTID_UNICODEPWD.to_le_bytes();
        assert!(
            out.windows(4).any(|w| w == attid),
            "unicodePwd attid present"
        );
        // The salt (0xAA×16) marks the encrypted value on the wire.
        assert!(
            out.windows(16).any(|w| w == [0xAAu8; 16]),
            "encrypted value present"
        );
    }

    #[test]
    fn attr_metadata_conflict_resolution_follows_version_then_time_then_dsa() {
        let base = AttrMetadata {
            version: 1,
            originating_time: 100,
            originating_dsa: [1u8; 16],
            originating_usn: 10,
        };
        // A higher version wins; the lower one does not.
        let higher_ver = AttrMetadata { version: 2, ..base };
        assert!(higher_ver.wins_over(&base));
        assert!(!base.wins_over(&higher_ver));
        // Same version → the later originating_time wins.
        let later = AttrMetadata {
            originating_time: 200,
            ..base
        };
        assert!(later.wins_over(&base));
        // Same version + time → the higher originating_dsa wins.
        let higher_dsa = AttrMetadata {
            originating_dsa: [2u8; 16],
            ..base
        };
        assert!(higher_dsa.wins_over(&base));
        // An identical stamp does not win (idempotent re-apply).
        assert!(!base.wins_over(&base));
    }

    #[test]
    fn parses_kerberos_newer_keys_from_supplemental_credentials() {
        // Build a KERB_STORED_CREDENTIAL_NEW with one AES256 and one AES128 key, then
        // wrap it in a USER_PROPERTIES / Primary:Kerberos-Newer-Keys property and check
        // the parser recovers both (byte layout per MS-SAMR §2.2.10).
        let aes256 = [0xABu8; 32];
        let aes128 = [0xCDu8; 16];
        let mut blob = Vec::new();
        blob.extend_from_slice(&[0, 0]); // Revision
        blob.extend_from_slice(&[0, 0]); // Flags
        blob.extend_from_slice(&2u16.to_le_bytes()); // CredentialCount
        blob.extend_from_slice(&[0u8; 10]); // Service/Old/Older counts (3×2) + salt len/maxlen (2×2)
        blob.extend_from_slice(&0u32.to_le_bytes()); // DefaultSaltOffset
        blob.extend_from_slice(&4096u32.to_le_bytes()); // DefaultIterationCount
                                                        // Two KERB_KEY_DATA_NEW (24 bytes each); keys placed right after them.
        let key_off_256 = 24 + 2 * 24;
        let key_off_128 = key_off_256 + aes256.len();
        for (etype, len, off) in [
            (KERB_ETYPE_AES256, aes256.len(), key_off_256),
            (KERB_ETYPE_AES128, aes128.len(), key_off_128),
        ] {
            blob.extend_from_slice(&[0u8; 8]); // Reserved1/2/3
            blob.extend_from_slice(&4096u32.to_le_bytes()); // IterationCount
            blob.extend_from_slice(&etype.to_le_bytes()); // KeyType
            blob.extend_from_slice(&(len as u32).to_le_bytes()); // KeyLength
            blob.extend_from_slice(&(off as u32).to_le_bytes()); // KeyOffset
        }
        blob.extend_from_slice(&aes256);
        blob.extend_from_slice(&aes128);

        let hex: Vec<u8> = blob
            .iter()
            .flat_map(|b| format!("{b:02x}").into_bytes())
            .collect();
        let name: Vec<u8> = "Primary:Kerberos-Newer-Keys"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut props = vec![0u8; 108]; // Reserved1..Reserved4
        props.extend_from_slice(&0x50u16.to_le_bytes()); // PropertySignature
        props.extend_from_slice(&1u16.to_le_bytes()); // PropertyCount
        props.extend_from_slice(&(name.len() as u16).to_le_bytes()); // NameLength
        props.extend_from_slice(&(hex.len() as u16).to_le_bytes()); // ValueLength
        props.extend_from_slice(&[0, 0]); // Reserved
        props.extend_from_slice(&name);
        props.extend_from_slice(&hex);

        let keys = parse_supplemental_kerberos_keys(&props).expect("must parse");
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].key_type, KERB_ETYPE_AES256);
        assert_eq!(keys[0].key, aes256);
        assert_eq!(keys[1].key_type, KERB_ETYPE_AES128);
        assert_eq!(keys[1].key, aes128);
    }
}
