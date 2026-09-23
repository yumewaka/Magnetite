//! A real SAMR interface (MS-SAMR) over the RPC transport — enough for a client
//! to connect, open the domain, and enumerate its users. This exercises the three
//! capabilities a real interface needs beyond a bare transport:
//!
//! * **request-side NDR input**: we read the caller's handle from each request,
//! * **stateful handles**: `SamrConnect`/`SamrOpenDomain` issue handles we track
//!   and later validate,
//! * **array output NDR**: `SAMPR_ENUMERATION_BUFFER` (a conformant array of
//!   `{RID, RPC_UNICODE_STRING}` with deferred string buffers).
//!
//! Implemented opnums (MS-SAMR):
//! * 0  `SamrConnect` → server handle,
//! * 1  `SamrCloseHandle`,
//! * 5  `SamrLookupDomainInSamServer` → domain SID,
//! * 6  `SamrEnumerateDomainsInSamServer` → `[EXAMPLE]`,
//! * 7  `SamrOpenDomain` → domain handle,
//! * 13 `SamrEnumerateUsersInDomain` → the directory users **plus any created accounts**,
//! * 50 `SamrCreateUser2InDomain` → creates an account (e.g. a machine account
//!   during domain join), allocating a RID and returning a user handle.
//!
//! Most requests are parsed only as far as the leading 20-byte handle; the write
//! path (opnum 50) additionally parses the `RPC_UNICODE_STRING` account name.
//! Created accounts live in the SAMR state (visible to enumeration); wiring their
//! keys through to the KDC/LSA/DRSUAPI (so a machine can then authenticate) is a
//! later slice.

use crate::directory::Directory;
use crate::interface::RpcInterface;
use crate::ndr::NdrWriter;
use crate::request::fault;
use magnetite_krb5::keys::PrincipalStore;
use md5::{Digest, Md5};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

/// SAMR interface UUID (`12345778-1234-ABCD-EF00-0123456789AC`, v1.0), for
/// reference — the transport dispatches by opnum, not the bound interface.
pub const SAMR_UUID: &str = "12345778-1234-ABCD-EF00-0123456789AC";

const OP_CONNECT: u16 = 0;
const OP_CLOSE_HANDLE: u16 = 1;
const OP_LOOKUP_DOMAIN: u16 = 5;
const OP_ENUM_DOMAINS: u16 = 6;
const OP_OPEN_DOMAIN: u16 = 7;
const OP_ENUM_DOMAIN_GROUPS: u16 = 11;
const OP_ENUM_USERS: u16 = 13;
const OP_OPEN_GROUP: u16 = 19;
const OP_GET_MEMBERS_IN_GROUP: u16 = 25;
/// `SamrQueryInformationUser` (MS-SAMR 3.1.5.5.6) — the v1 query. Same request and
/// response shape as `SamrQueryInformationUser2`; the domain-join client calls this
/// one right after `SamrCreateUser2InDomain` to read the account's `userAccountControl`.
const OP_QUERY_USER_INFO: u16 = 36;
/// `SamrSetInformationUser` (MS-SAMR 3.1.5.6.5) — the v1 setter, same request shape
/// as `SamrSetInformationUser2`. The domain-join client uses this (not the "2" form)
/// to write the machine password + `userAccountControl` after creating the account.
const OP_SET_USER_INFO: u16 = 37;
/// `SamrGetUserDomainPasswordInformation` (MS-SAMR 3.1.5.13.1) — the join client reads
/// the domain password policy before generating the machine password. We advertise an
/// unrestricted policy (min length 0, no properties) so any generated password passes.
const OP_GET_USER_DOMAIN_PWD_INFO: u16 = 44;
const OP_QUERY_USER_INFO2: u16 = 47;
const OP_CREATE_USER2: u16 = 50;
const OP_SET_USER_INFO2: u16 = 58;

/// `USER_INFORMATION_CLASS::UserControlInformation` (MS-SAMR 2.2.1.9) — the
/// `userAccountControl` flags carried by `SamrSet/QueryInformationUser2`.
const USER_CONTROL_INFORMATION: u16 = 16;

// userAccountControl bits.
const UAC_ACCOUNTDISABLE: u32 = 0x0000_0002;
const UAC_WORKSTATION_TRUST_ACCOUNT: u32 = 0x0000_1000;
/// A freshly-created machine account: a disabled workstation-trust account (the
/// join then clears ACCOUNTDISABLE via SamrSetInformationUser2).
const DEFAULT_MACHINE_UAC: u32 = UAC_WORKSTATION_TRUST_ACCOUNT | UAC_ACCOUNTDISABLE;

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

/// The fixed size of `SAMPR_ENCRYPTED_USER_PASSWORD` (a 512-byte password buffer
/// plus a 4-byte length), session-key-encrypted.
const SAMPR_ENCRYPTED_PASSWORD_LEN: usize = 516;

/// The first RID handed out to a runtime-created account (above the seeded users).
const FIRST_CREATED_RID: u32 = 1100;
/// Full access (`USER_ALL_ACCESS`) granted on the returned user handle.
const USER_ALL_ACCESS: u32 = 0x000F_07FF;
/// `MAXIMUM_ALLOWED` desired-access sentinel — resolved to full access.
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

const NT_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 5];

/// A sink for persisting accounts created or repassworded through SAMR, so they
/// survive a restart. Implemented by the host (`magnetite-addc`) over the database
/// — keeping `magnetite-rpc` free of a database dependency. Fire-and-forget: the
/// implementation persists asynchronously.
/// Allocates domain RIDs for accounts SAMR creates. Backed by the host
/// (`magnetite-addc`) over the shared database, so DC front-ends that share a store
/// hand out non-overlapping RIDs (Tier B multi-DC) and RIDs persist across restarts.
/// `allocate` is synchronous (the SAMR call path is); the implementation hands out
/// from a locally-held block and refills it in the background.
pub trait RidAllocator: Send + Sync {
    /// The next unallocated RID, or `None` if the local block is momentarily exhausted
    /// (a refill is in flight). SAMR falls back to its in-memory counter then.
    fn allocate(&self) -> Option<u32>;

    /// Allocate a **contiguous pool** of `size` RIDs, returning `(first_rid, size)`, or
    /// `None` if a durable pool is momentarily unavailable (a refill is in flight). Used
    /// by the DRSUAPI RID master to grant a peer DC a RID pool (`EXOP_FSMO_RID_ALLOC`)
    /// from the SAME durable counter that mints local accounts, so grants and local RIDs
    /// never overlap and survive restarts. The default returns `None` — an allocator
    /// that only mints single RIDs does not serve pools.
    fn allocate_pool(&self, size: u32) -> Option<(u32, u32)> {
        let _ = size;
        None
    }
}

pub trait AccountStore: Send + Sync {
    /// Persist (create or replace) `sam_account_name` (RID `rid`). `nt_hash` is the
    /// authoritative NT hash (taken over the raw UTF-16LE password, so it is correct
    /// even for a random machine password `password` cannot losslessly represent).
    /// `kerberos_key` is the authoritative AES256 long-term key when non-empty (the AD
    /// computer-account derivation for a machine account); when empty the store derives
    /// it from `password` (the ordinary user convention).
    fn persist_account(
        &self,
        sam_account_name: &str,
        rid: u32,
        password: &str,
        nt_hash: [u8; 16],
        kerberos_key: &[u8],
    );
}

/// What an issued handle refers to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HandleKind {
    Server,
    Domain,
    User,
    Group,
}

#[derive(Default)]
struct SamrState {
    next_id: u32,
    handles: HashMap<[u8; 20], HandleKind>,
    /// The next RID to allocate for a created account.
    next_rid: u32,
    /// Accounts created at runtime (e.g. machine accounts during a join), as
    /// `(rid, sAMAccountName)` — merged into enumeration alongside the directory.
    created: Vec<(u32, String)>,
    /// Maps an issued user handle to its account name, so `SamrSetInformationUser2`
    /// can resolve which account a password change targets.
    user_names: HashMap<[u8; 20], String>,
    /// The `userAccountControl` flags of each open user handle (settable via
    /// `SamrSetInformationUser2` UserControlInformation, readable via Query).
    uac: HashMap<[u8; 20], u32>,
    /// Maps an issued group handle to the group RID it was opened for, so
    /// `SamrGetMembersInGroup` knows which group to return members of.
    group_rids: HashMap<[u8; 20], u32>,
}

/// A stateful SAMR server backed by a shared [`Directory`]. When a KDC principal
/// store is attached, creating a machine account also registers it with the KDC
/// (so the machine can then authenticate).
pub struct SamrInterface {
    directory: Arc<Directory>,
    kdc: Option<Arc<PrincipalStore>>,
    persist: Option<Arc<dyn AccountStore>>,
    rid_allocator: Option<Arc<dyn RidAllocator>>,
    state: Mutex<SamrState>,
}

impl Default for SamrInterface {
    fn default() -> Self {
        Self::new(Arc::new(Directory::default()))
    }
}

impl SamrInterface {
    /// A SAMR server answering from `directory`, with an empty handle table and no
    /// KDC attached (created accounts are visible to enumeration only).
    pub fn new(directory: Arc<Directory>) -> Self {
        Self::build(directory, None)
    }

    /// A SAMR server that also registers created machine accounts with `kdc`, so a
    /// joined machine can obtain Kerberos tickets.
    pub fn new_with_kdc(directory: Arc<Directory>, kdc: Arc<PrincipalStore>) -> Self {
        Self::build(directory, Some(kdc))
    }

    /// Attach an [`AccountStore`] so created/repassworded accounts are persisted.
    pub fn with_account_store(mut self, store: Arc<dyn AccountStore>) -> Self {
        self.persist = Some(store);
        self
    }

    /// Attach a [`RidAllocator`] so created accounts draw RIDs from the shared store
    /// (multi-DC-safe + persistent) instead of the in-memory counter.
    pub fn with_rid_allocator(mut self, allocator: Arc<dyn RidAllocator>) -> Self {
        self.rid_allocator = Some(allocator);
        self
    }

    /// Persist an account through the attached store, if any. `kerberos_key` is the
    /// authoritative AES256 key (empty → the store derives it from `password`).
    fn persist(
        &self,
        name: &str,
        rid: u32,
        password: &str,
        nt_hash: [u8; 16],
        kerberos_key: &[u8],
    ) {
        if let Some(store) = &self.persist {
            store.persist_account(name, rid, password, nt_hash, kerberos_key);
        }
    }

    fn build(directory: Arc<Directory>, kdc: Option<Arc<PrincipalStore>>) -> Self {
        Self {
            directory,
            kdc,
            persist: None,
            rid_allocator: None,
            state: Mutex::new(SamrState {
                next_id: 1,
                handles: HashMap::new(),
                next_rid: FIRST_CREATED_RID,
                created: Vec::new(),
                user_names: HashMap::new(),
                uac: HashMap::new(),
                group_rids: HashMap::new(),
            }),
        }
    }

    /// Create an account (SamrCreateUser2InDomain): allocate a RID, record the
    /// account (so enumeration reflects it) and issue a user handle.
    fn create_user(&self, name: &str) -> ([u8; 20], u32) {
        let handle = self.open(HandleKind::User);
        // Draw the RID from the shared DB-backed allocator when attached (multi-DC-safe
        // + persistent); otherwise fall back to the in-memory counter (tests / no
        // store). Acquire the allocator's RID before taking the state lock — never nest.
        let allocated = self.rid_allocator.as_ref().and_then(|a| a.allocate());
        let mut st = self.state.lock();
        let rid = allocated.unwrap_or_else(|| {
            let r = st.next_rid;
            st.next_rid += 1;
            r
        });
        st.created.push((rid, name.to_string()));
        st.user_names.insert(handle, name.to_string());
        st.uac.insert(handle, DEFAULT_MACHINE_UAC);
        (handle, rid)
    }

    /// `SamrQueryInformationUser2` (opnum 47), UserControlInformation: return the
    /// account's `userAccountControl` flags for the given user handle.
    fn query_user_info2(&self, stub: &[u8]) -> Vec<u8> {
        let class = info_class(stub);
        if class != Some(USER_CONTROL_INFORMATION) {
            tracing::warn!(
                "SamrQueryInformationUser: unsupported UserInformationClass {:?}",
                class
            );
            return status_response(STATUS_INVALID_PARAMETER);
        }
        let Some(handle) = handle_bytes(stub) else {
            return status_response(STATUS_INVALID_HANDLE);
        };
        let uac = self.state.lock().uac.get(&handle).copied();
        match uac {
            Some(value) => user_control_response(value),
            None => status_response(STATUS_INVALID_HANDLE),
        }
    }

    /// The account name a user handle refers to (for `SamrSetInformationUser2`).
    fn user_name(&self, handle: &[u8]) -> Option<String> {
        if handle.len() < 20 {
            return None;
        }
        let mut h = [0u8; 20];
        h.copy_from_slice(&handle[0..20]);
        self.state.lock().user_names.get(&h).cloned()
    }

    /// `SamrSetInformationUser2` (opnum 58): decrypt the client-supplied machine
    /// password (a `SAMPR_ENCRYPTED_USER_PASSWORD` sealed with the RPC session key)
    /// and re-register the account with the KDC under the new password — the real
    /// domain-join password-set. Requires an authenticated bind (a session key).
    fn set_user_info2(&self, stub: &[u8], session_key: Option<&[u8]>) -> Vec<u8> {
        tracing::debug!(
            "SamrSetInformationUser: UserInformationClass {:?}, stub {} B, session_key={}",
            info_class(stub),
            stub.len(),
            session_key.is_some()
        );
        // UserControlInformation (userAccountControl) is a plain u32 — no session
        // key needed. Everything else is treated as a password (Internal5).
        if info_class(stub) == Some(USER_CONTROL_INFORMATION) {
            let (Some(handle), Some(uac)) = (
                handle_bytes(stub),
                stub.get(24..28)
                    .and_then(|b| b.try_into().ok())
                    .map(u32::from_le_bytes),
            ) else {
                return status_response(STATUS_INVALID_PARAMETER);
            };
            self.state.lock().uac.insert(handle, uac);
            return status_response(STATUS_SUCCESS);
        }
        let Some(name) = self.user_name(stub) else {
            return status_response(STATUS_INVALID_HANDLE);
        };
        let Some(key) = session_key else {
            return status_response(STATUS_ACCESS_DENIED); // needs an authenticated bind
        };
        // A domain join sends UserInternal4InformationNew (class 25): a salted
        // `SAMPR_ENCRYPTED_USER_PASSWORD_NEW`. Older callers send the unsalted
        // `SAMPR_ENCRYPTED_USER_PASSWORD`. Try the salted form first, then legacy.
        let Some(pw_utf16le) =
            decrypt_sampr_password_new(stub, key).or_else(|| decrypt_sampr_password(stub, key))
        else {
            tracing::warn!("SamrSetInformationUser: could not decrypt the password buffer");
            return status_response(STATUS_INVALID_PARAMETER);
        };
        // The NT hash is taken over the RAW UTF-16LE bytes (fidelity-preserving — the
        // Netlogon secure channel authenticates with it). The lossy `String` is only
        // for persistence's best-effort Kerberos key of non-machine accounts.
        let nt = crate::directory::nt_hash_utf16le(&pw_utf16le);
        let password = String::from_utf16_lossy(
            &pw_utf16le
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect::<Vec<_>>(),
        );
        // A machine account (`HOST$`): register its Kerberos key from the raw UTF-16
        // password with the AD computer salt + host/cifs SPN aliases, so a logon's
        // TGS-REQ for `host/<fqdn>` resolves and the ticket decrypts at the workstation.
        // Keep the derived key to persist (the copy that re-seeds the KDC after a
        // restart). Other accounts take the ordinary string path (empty key → derived).
        let kerberos_key: Vec<u8> = match &self.kdc {
            Some(kdc) if name.ends_with('$') => {
                match kdc.register_machine_utf16(&name, &pw_utf16le) {
                    Ok(key) => key,
                    Err(_) => return status_response(STATUS_INVALID_PARAMETER),
                }
            }
            Some(kdc) => {
                if kdc.register_machine(&[name.as_str()], &password).is_err() {
                    return status_response(STATUS_INVALID_PARAMETER);
                }
                Vec::new()
            }
            None => Vec::new(),
        };
        // The account's RID (from the created list).
        let rid = self
            .state
            .lock()
            .created
            .iter()
            .find(|(_, n)| *n == name)
            .map(|(r, _)| *r)
            .unwrap_or(0);
        // Publish the account into the shared directory NOW (not only after the next
        // restart's DB reload), so the Netlogon secure channel resolves this machine's
        // NT hash immediately.
        self.directory.upsert_runtime_user(crate::directory::User {
            sam_account_name: name.clone(),
            rid,
            nt_hash: nt,
            kerberos_key: kerberos_key.clone(),
            disabled: false,
            repl_meta: None,
        });
        // Persist the new NT hash + Kerberos key so the account survives a restart
        // (the KDC re-seeds machine SPN aliases from the stored key — see spawn_servers).
        self.persist(&name, rid, &password, nt, &kerberos_key);
        status_response(STATUS_SUCCESS)
    }

    /// Issue a fresh 20-byte handle of `kind` and record it.
    fn open(&self, kind: HandleKind) -> [u8; 20] {
        let mut st = self.state.lock();
        let id = st.next_id;
        st.next_id += 1;
        let mut h = [0u8; 20];
        h[0..4].copy_from_slice(&id.to_le_bytes());
        h[4..8].copy_from_slice(b"SAMR");
        st.handles.insert(h, kind);
        h
    }

    /// Open a group handle bound to `rid`, so a later `SamrGetMembersInGroup` on it
    /// knows which group to enumerate.
    fn open_group(&self, rid: u32) -> [u8; 20] {
        let h = self.open(HandleKind::Group);
        self.state.lock().group_rids.insert(h, rid);
        h
    }

    /// The group RID a group handle was opened for.
    fn group_rid(&self, handle: &[u8]) -> Option<u32> {
        let h: [u8; 20] = handle.get(0..20)?.try_into().ok()?;
        self.state.lock().group_rids.get(&h).copied()
    }

    /// Whether `stub` begins with a handle of `kind`.
    fn valid(&self, stub: &[u8], kind: HandleKind) -> bool {
        if stub.len() < 20 {
            return false;
        }
        let mut h = [0u8; 20];
        h.copy_from_slice(&stub[0..20]);
        self.state.lock().handles.get(&h) == Some(&kind)
    }

    /// Forget the handle at the front of `stub`.
    fn close(&self, stub: &[u8]) {
        if stub.len() >= 20 {
            let mut h = [0u8; 20];
            h.copy_from_slice(&stub[0..20]);
            self.state.lock().handles.remove(&h);
        }
    }
}

impl RpcInterface for SamrInterface {
    fn call(&self, opnum: u16, stub: &[u8]) -> Result<Vec<u8>, u32> {
        match opnum {
            OP_CONNECT => Ok(handle_response(
                self.open(HandleKind::Server),
                STATUS_SUCCESS,
            )),
            OP_CLOSE_HANDLE => {
                self.close(stub);
                Ok(handle_response([0u8; 20], STATUS_SUCCESS))
            }
            OP_LOOKUP_DOMAIN => Ok(domain_sid_response(self.directory.domain_sid())),
            OP_ENUM_DOMAINS => Ok(if self.valid(stub, HandleKind::Server) {
                enumeration_response(&[(0, self.directory.netbios())], STATUS_SUCCESS)
            } else {
                enumeration_response(&[], STATUS_INVALID_HANDLE)
            }),
            OP_OPEN_DOMAIN => Ok(if self.valid(stub, HandleKind::Server) {
                handle_response(self.open(HandleKind::Domain), STATUS_SUCCESS)
            } else {
                handle_response([0u8; 20], STATUS_INVALID_HANDLE)
            }),
            OP_ENUM_DOMAIN_GROUPS => Ok(if self.valid(stub, HandleKind::Domain) {
                // The domain groups the directory serves — static plus any replicated
                // at runtime from an upstream DC (`net group /domain` enumerates these).
                let owned = self.directory.all_groups();
                let groups: Vec<(u32, &str)> = owned
                    .iter()
                    .map(|g| (g.rid, g.sam_account_name.as_str()))
                    .collect();
                enumeration_response(&groups, STATUS_SUCCESS)
            } else {
                enumeration_response(&[], STATUS_INVALID_HANDLE)
            }),
            OP_OPEN_GROUP => Ok(if self.valid(stub, HandleKind::Domain) {
                // SamrOpenGroup(hDomain, DesiredAccess, GroupId): the RID follows the
                // 20-byte handle and the 4-byte DesiredAccess.
                let rid = stub
                    .get(24..28)
                    .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
                    .unwrap_or(0);
                handle_response(self.open_group(rid), STATUS_SUCCESS)
            } else {
                handle_response([0u8; 20], STATUS_INVALID_HANDLE)
            }),
            OP_GET_MEMBERS_IN_GROUP => Ok(if self.valid(stub, HandleKind::Group) {
                let members = self
                    .group_rid(stub)
                    .and_then(|rid| self.directory.group_members(rid))
                    .unwrap_or_default();
                get_members_response(&members, STATUS_SUCCESS)
            } else {
                get_members_response(&[], STATUS_INVALID_HANDLE)
            }),
            OP_ENUM_USERS => Ok(if self.valid(stub, HandleKind::Domain) {
                // The directory users (static + replicated-at-runtime) plus any
                // accounts created at runtime via SAMR.
                let mut owned: Vec<(u32, String)> = self
                    .directory
                    .all_users()
                    .iter()
                    .map(|u| (u.rid, u.sam_account_name.clone()))
                    .collect();
                owned.extend(self.state.lock().created.iter().cloned());
                let users: Vec<(u32, &str)> = owned
                    .iter()
                    .map(|(rid, name)| (*rid, name.as_str()))
                    .collect();
                enumeration_response(&users, STATUS_SUCCESS)
            } else {
                enumeration_response(&[], STATUS_INVALID_HANDLE)
            }),
            OP_QUERY_USER_INFO | OP_QUERY_USER_INFO2 => Ok(self.query_user_info2(stub)),
            OP_GET_USER_DOMAIN_PWD_INFO => Ok(if self.valid(stub, HandleKind::User) {
                user_domain_password_info_response()
            } else {
                status_response(STATUS_INVALID_HANDLE)
            }),
            OP_SET_USER_INFO | OP_SET_USER_INFO2 => Ok(self.set_user_info2(stub, None)),
            OP_CREATE_USER2 => Ok(if self.valid(stub, HandleKind::Domain) {
                let name = parse_unicode_string_arg(stub).unwrap_or_else(|| "MACHINE$".to_string());
                let granted = create_user_desired_access(stub);
                let (handle, rid) = self.create_user(&name);
                // Register the account with the KDC using the initial machine
                // password (AD's pre-created-account convention), so the machine can
                // immediately obtain Kerberos tickets, and persist it. A later
                // SamrSetInformationUser2 replaces this with the client-chosen password.
                let initial_password = machine_initial_password(&name);
                // Register under the AD computer-account convention (host/cifs SPNs +
                // salt) from the start; a later SamrSetInformationUser2 replaces the key
                // with the client-chosen password. Keep the key to persist.
                let initial_utf16: Vec<u8> = initial_password
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect();
                let kerberos_key = self
                    .kdc
                    .as_ref()
                    .and_then(|kdc| kdc.register_machine_utf16(&name, &initial_utf16).ok())
                    .unwrap_or_default();
                let nt = crate::directory::nt_hash(&initial_password);
                self.persist(&name, rid, &initial_password, nt, &kerberos_key);
                create_user_response(handle, granted, rid, STATUS_SUCCESS)
            } else {
                create_user_response([0u8; 20], 0, 0, STATUS_INVALID_HANDLE)
            }),
            _ => Err(fault::OP_RNG_ERROR),
        }
    }

    /// Authenticated dispatch: `SamrSetInformationUser2` decrypts its password
    /// buffer with the negotiated RPC session key. All other opnums are unaffected
    /// by authentication and delegate to [`RpcInterface::call`].
    fn call_with_session(
        &self,
        opnum: u16,
        stub: &[u8],
        session_key: Option<&[u8]>,
    ) -> Result<Vec<u8>, u32> {
        match opnum {
            OP_SET_USER_INFO | OP_SET_USER_INFO2 => Ok(self.set_user_info2(stub, session_key)),
            _ => self.call(opnum, stub),
        }
    }
}

/// The byte offset of the `Name.Buffer` array's `ActualCount`. impacket serializes
/// the `RPC_UNICODE_STRING` as a unit — its embedded Buffer referent follows the
/// struct's inline part immediately, ahead of the later scalar arguments. Layout:
/// `DomainHandle`(20) + `Name`{Length u16 @20, MaximumLength u16 @22, Buffer
/// referent u32 @24} + Buffer array{MaxCount u32 @28, Offset u32 @32, ActualCount
/// u32 @36, chars @40}.
const NAME_ACTUAL_COUNT_OFFSET: usize = 36;
const NAME_CHARS_OFFSET: usize = 40;

/// The initial password of a freshly-created (pre-created) computer account: the
/// lowercased account name without the trailing `$`, truncated to 14 characters —
/// the well-known Active Directory convention. A Windows client then changes it.
fn machine_initial_password(name: &str) -> String {
    name.trim_end_matches('$')
        .to_lowercase()
        .chars()
        .take(14)
        .collect()
}

/// Parse the `Name` (`RPC_UNICODE_STRING`) argument of `SamrCreateUser2InDomain`.
/// Returns `None` if the stub is too short or the Buffer pointer is null.
fn parse_unicode_string_arg(stub: &[u8]) -> Option<String> {
    if stub.len() < NAME_CHARS_OFFSET {
        return None;
    }
    let buffer_ref = u32::from_le_bytes(stub[24..28].try_into().ok()?);
    if buffer_ref == 0 {
        return None;
    }
    let actual = u32::from_le_bytes(
        stub[NAME_ACTUAL_COUNT_OFFSET..NAME_ACTUAL_COUNT_OFFSET + 4]
            .try_into()
            .ok()?,
    ) as usize;
    let end = NAME_CHARS_OFFSET.checked_add(actual.checked_mul(2)?)?;
    if stub.len() < end {
        return None;
    }
    let mut name = String::with_capacity(actual);
    for i in 0..actual {
        let at = NAME_CHARS_OFFSET + i * 2;
        let c = u16::from_le_bytes(stub[at..at + 2].try_into().ok()?);
        name.push(char::from_u32(c as u32)?);
    }
    Some(name)
}

/// Read the `DesiredAccess` argument, which follows the (4-aligned) name buffer and
/// the `AccountType` scalar. Falls back to `USER_ALL_ACCESS` when the request is
/// short or requests `MAXIMUM_ALLOWED`.
fn create_user_desired_access(stub: &[u8]) -> u32 {
    let actual = stub
        .get(NAME_ACTUAL_COUNT_OFFSET..NAME_ACTUAL_COUNT_OFFSET + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or(0) as usize;
    let chars_end = NAME_CHARS_OFFSET + actual * 2;
    let account_type_off = chars_end.div_ceil(4) * 4; // 4-align past the string
    let desired_off = account_type_off + 4; // skip AccountType
    stub.get(desired_off..desired_off + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .filter(|&a| a != 0 && a != MAXIMUM_ALLOWED)
        .unwrap_or(USER_ALL_ACCESS)
}

/// NDR for `SamrCreateUser2InDomainResponse`: `UserHandle`(20) + `GrantedAccess`(4)
/// + `RelativeId`(4) + `NTSTATUS`(4). The two `[out]` `[ref]` scalars are inline.
fn create_user_response(user_handle: [u8; 20], granted: u32, rid: u32, status: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(32);
    b.extend_from_slice(&user_handle);
    b.extend_from_slice(&granted.to_le_bytes());
    b.extend_from_slice(&rid.to_le_bytes());
    b.extend_from_slice(&status.to_le_bytes());
    b
}

/// A response carrying only an `NTSTATUS` (e.g. `SamrSetInformationUser2`).
fn status_response(status: u32) -> Vec<u8> {
    status.to_le_bytes().to_vec()
}

/// The 20-byte handle at the front of a request stub.
fn handle_bytes(stub: &[u8]) -> Option<[u8; 20]> {
    stub.get(0..20)?.try_into().ok()
}

/// The `UserInformationClass` (u16) of a `SamrSet/QueryInformationUser2` request —
/// it follows the 20-byte handle.
fn info_class(stub: &[u8]) -> Option<u16> {
    stub.get(20..22)
        .and_then(|b| b.try_into().ok())
        .map(u16::from_le_bytes)
}

/// `SamrQueryInformationUser2` response for UserControlInformation: a non-null
/// `SAMPR_USER_INFO_BUFFER` pointer, the union discriminant (u16, padded), the
/// `SAMPR_USER_CONTROL_INFORMATION { ULONG UserAccountControl }`, then NTSTATUS.
fn user_control_response(uac: u32) -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.u32(0x0002_0000); // Buffer referent (non-null)
    w.u16(USER_CONTROL_INFORMATION); // union discriminant
    w.u16(0); // pad — arm aligns to 4
    w.u32(uac); // SAMPR_USER_CONTROL_INFORMATION.UserAccountControl
    w.u32(STATUS_SUCCESS); // ErrorCode
    w.into_bytes()
}

/// `SamrGetUserDomainPasswordInformation` response: a `USER_DOMAIN_PASSWORD_INFORMATION`
/// `{ USHORT MinPasswordLength; ULONG PasswordProperties }` (the `[out]` ref pointer is
/// inline, no referent id) followed by NTSTATUS. We advertise an unrestricted policy so
/// the client's auto-generated machine password always satisfies it.
fn user_domain_password_info_response() -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.u16(0); // MinPasswordLength
    w.u16(0); // pad — PasswordProperties aligns to 4
    w.u32(0); // PasswordProperties (no restrictions)
    w.u32(STATUS_SUCCESS); // ErrorCode
    w.into_bytes()
}

/// RC4 stream cipher (symmetric — used to unseal the encrypted password buffer).
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

/// Decrypt the `SAMPR_ENCRYPTED_USER_PASSWORD` near the tail of a
/// `SamrSetInformationUser2` request stub and extract the cleartext password. The
/// 516-byte buffer sits just before the struct's trailing `PasswordExpired` byte
/// (+NDR padding); RC4 with the session key yields `SAMPR_USER_PASSWORD { WCHAR
/// Buffer[256]; ULONG Length }`, where the password occupies the LAST `Length`
/// bytes of the 512-byte buffer.
///
/// The buffer's exact offset depends on how the client marshals the enclosing
/// union/struct (which fields precede it), so we scan every candidate start and
/// accept the one whose RC4-decrypted `Length` is valid and whose password is all
/// printable — a strict gate that only the correct alignment satisfies (RC4 at any
/// other offset yields random bytes that fail these checks).
/// Interpret a decrypted 516-byte `SAMPR_USER_PASSWORD` (512-byte data buffer with the
/// password's UTF-16LE bytes right-aligned, then a u32 byte-length) as a string.
///
/// The gate is the `Length` field alone (`0 < Length <= 512`, even): a machine account
/// password is **120 random UTF-16 code units**, so it routinely contains control
/// characters and lone surrogates — rejecting those (an earlier bug) discarded every
/// real join password. We decode lossily since a random blob need not be valid UTF-16;
/// the `Length` gate at a wrong RC4 offset is satisfied with vanishing probability, so
/// it alone reliably picks the correct alignment.
fn password_from_plain(plain: &[u8]) -> Option<Vec<u8>> {
    let length = u32::from_le_bytes(plain.get(512..516)?.try_into().ok()?) as usize;
    if length == 0 || length > 512 || !length.is_multiple_of(2) {
        return None;
    }
    // The raw UTF-16LE password bytes (right-aligned in the 512-byte buffer). Kept as
    // bytes, not a `String`: a random machine password can contain lone surrogates.
    Some(plain[512 - length..512].to_vec())
}

/// Decrypt a `SAMPR_ENCRYPTED_USER_PASSWORD` (UserInternal5Information / legacy):
/// a 516-byte buffer RC4-encrypted directly with the RPC session key. We scan candidate
/// offsets tail-first (the buffer is the struct's final fixed field).
fn decrypt_sampr_password(stub: &[u8], session_key: &[u8]) -> Option<Vec<u8>> {
    let max_start = stub.len().checked_sub(SAMPR_ENCRYPTED_PASSWORD_LEN)?;
    (0..=max_start).rev().find_map(|start| {
        let plain = rc4(
            session_key,
            &stub[start..start + SAMPR_ENCRYPTED_PASSWORD_LEN],
        );
        password_from_plain(&plain)
    })
}

/// Decrypt a `SAMPR_ENCRYPTED_USER_PASSWORD_NEW` (UserInternal4InformationNew, class 25 —
/// what a Windows domain-join sends): a 516-byte RC4-encrypted `SAMPR_USER_PASSWORD`
/// followed by a 16-byte confounder (salt). The RC4 key is `MD5(salt || SessionKey)`
/// (Samba `samr_CryptPasswordEx`). We scan the 532-byte block's offset tail-first (it is
/// the struct's final fixed field, so the join's block sits at the very end of the stub).
fn decrypt_sampr_password_new(stub: &[u8], session_key: &[u8]) -> Option<Vec<u8>> {
    const BLOCK: usize = SAMPR_ENCRYPTED_PASSWORD_LEN + 16; // 516 encrypted + 16 salt
    let max_start = stub.len().checked_sub(BLOCK)?;
    (0..=max_start).rev().find_map(|start| {
        let salt = &stub[start + SAMPR_ENCRYPTED_PASSWORD_LEN..start + BLOCK];
        let mut md5 = Md5::new();
        md5.update(salt);
        md5.update(session_key);
        let key = md5.finalize();
        let plain = rc4(&key, &stub[start..start + SAMPR_ENCRYPTED_PASSWORD_LEN]);
        password_from_plain(&plain)
    })
}

/// Response for calls returning `(SAMPR_HANDLE, NTSTATUS)`.
fn handle_response(handle: [u8; 20], status: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(24);
    b.extend_from_slice(&handle);
    b.extend_from_slice(&status.to_le_bytes());
    b
}

/// NDR for `SamrLookupDomainInSamServerResponse`: `(PRPC_SID DomainId, NTSTATUS)`.
fn domain_sid_response(domain_sid: &[u32]) -> Vec<u8> {
    let mut w = NdrWriter::new();
    w.u32(0x0002_0000); // PRPC_SID referent (non-null)
    w.u32(domain_sid.len() as u32); // conformant MaxCount
    w.u8(1); // Revision
    w.u8(domain_sid.len() as u8); // SubAuthorityCount
    w.bytes(&NT_AUTHORITY); // IdentifierAuthority
    for sub in domain_sid {
        w.u32(*sub);
    }
    w.u32(STATUS_SUCCESS); // ErrorCode
    w.into_bytes()
}

/// NDR for a `SamrGetMembersInGroup` response: `(PSAMPR_GET_MEMBERS_BUFFER*, NTSTATUS)`.
/// The buffer is `{ MemberCount, [size_is] Members(RID array), [size_is] Attributes }`.
/// The top-level out-pointer's referent is inline; the two `[size_is]` arrays defer to
/// the end. Attributes are `SE_GROUP_MANDATORY | ENABLED_BY_DEFAULT | ENABLED` (0x7).
fn get_members_response(member_rids: &[u32], status: u32) -> Vec<u8> {
    let mut w = NdrWriter::new();
    let count = member_rids.len() as u32;
    w.u32(0x0002_0000); // buffer pointer referent (inline)
    w.u32(count); // MemberCount
    if member_rids.is_empty() {
        w.u32(0); // Members pointer (null)
        w.u32(0); // Attributes pointer (null)
        w.u32(status);
        return w.into_bytes();
    }
    w.u32(0x0002_0004); // Members array referent
    w.u32(0x0002_0008); // Attributes array referent
    w.u32(count); // Members MaxCount
    for rid in member_rids {
        w.u32(*rid);
    }
    w.u32(count); // Attributes MaxCount
    for _ in member_rids {
        w.u32(0x0000_0007); // SE_GROUP_MANDATORY | ENABLED_BY_DEFAULT | ENABLED
    }
    w.u32(status); // ErrorCode
    w.into_bytes()
}

/// NDR for a `Samr*Enumerate*` response: `(EnumerationContext, PSAMPR_ENUMERATION_BUFFER,
/// CountReturned, NTSTATUS)`.
///
/// A top-level pointer's referent is marshalled **inline** (only pointers
/// *embedded* in a struct/array are deferred to the end). So the buffer's whole
/// content follows its referent id, and `CountReturned`/`ErrorCode` come after it.
/// Inside the array, the entries' fixed parts precede their deferred name strings.
fn enumeration_response(entries: &[(u32, &str)], status: u32) -> Vec<u8> {
    let mut w = NdrWriter::new();
    let count = entries.len() as u32;

    w.u32(count); // EnumerationContext (resume handle; we return everything)

    if entries.is_empty() {
        w.u32(0); // null Buffer pointer → no inline content
        w.u32(0); // CountReturned
        w.u32(status); // ErrorCode
        return w.into_bytes();
    }

    // Buffer pointer + its inline referent (SAMPR_ENUMERATION_BUFFER).
    w.u32(0x0002_0000); // Buffer pointer referent
    w.u32(count); // EntriesRead
    w.u32(0x0002_0004); // array pointer referent

    // Array referent: conformant array of SAMPR_RID_ENUMERATION.
    w.u32(count); // MaxCount
    let mut string_ref = 0x0002_0008u32;
    for (rid, name) in entries {
        let n = name.encode_utf16().count();
        w.u32(*rid); // RelativeId
        w.u16((n * 2) as u16); // Name.Length
        w.u16((n * 2) as u16); // Name.MaximumLength
        if n == 0 {
            w.u32(0);
        } else {
            w.u32(string_ref); // Name.Buffer referent
            string_ref += 4;
        }
    }
    // Deferred (within the array): each name's conformant+varying UTF-16 buffer.
    for (_, name) in entries {
        let chars: Vec<u16> = name.encode_utf16().collect();
        if !chars.is_empty() {
            w.u32(chars.len() as u32); // MaxCount
            w.u32(0); // Offset
            w.u32(chars.len() as u32); // ActualCount
            for c in chars {
                w.u16(c);
            }
        }
    }

    // Back at the top level, after the buffer's inline content.
    w.u32(count); // CountReturned
    w.u32(status); // ErrorCode
    w.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_open_domain_enumerate_users_flow() {
        let samr = SamrInterface::default();

        // Connect → a server handle.
        let connect = samr.call(OP_CONNECT, &[]).unwrap();
        assert_eq!(
            &connect[20..24],
            &[0, 0, 0, 0],
            "SamrConnect STATUS_SUCCESS"
        );
        let server_handle = &connect[0..20];

        // Enumerating users with a *server* handle must be rejected (wrong kind).
        let bad = samr.call(OP_ENUM_USERS, server_handle).unwrap();
        assert_eq!(
            u32::from_le_bytes(bad[bad.len() - 4..].try_into().unwrap()),
            STATUS_INVALID_HANDLE
        );

        // Open the domain with the server handle → a domain handle.
        let opened = samr.call(OP_OPEN_DOMAIN, server_handle).unwrap();
        assert_eq!(
            &opened[20..24],
            &[0, 0, 0, 0],
            "SamrOpenDomain STATUS_SUCCESS"
        );
        let domain_handle = opened[0..20].to_vec();

        // Enumerate users under the domain handle → one entry, RID 1000 "alice".
        let users = samr.call(OP_ENUM_USERS, &domain_handle).unwrap();
        let n = users.len();
        // With inline referents, CountReturned and ErrorCode are the trailing two
        // u32s (after the buffer's inline content).
        assert_eq!(
            u32::from_le_bytes(users[n - 4..].try_into().unwrap()),
            STATUS_SUCCESS
        );
        assert_eq!(
            u32::from_le_bytes(users[n - 8..n - 4].try_into().unwrap()),
            1
        );
        // The RID 1000 appears in the element's RelativeId.
        assert!(
            users.windows(4).any(|w| w == 1000u32.to_le_bytes()),
            "enumeration must carry RID 1000"
        );
    }

    #[test]
    fn enumerate_domain_groups_returns_the_directory_groups() {
        let samr = SamrInterface::default();
        let connect = samr.call(OP_CONNECT, &[]).unwrap();
        let server_handle = &connect[0..20];
        let opened = samr.call(OP_OPEN_DOMAIN, server_handle).unwrap();
        let domain_handle = opened[0..20].to_vec();

        // A server handle is the wrong kind for a domain enumeration.
        let bad = samr.call(OP_ENUM_DOMAIN_GROUPS, server_handle).unwrap();
        assert_eq!(
            u32::from_le_bytes(bad[bad.len() - 4..].try_into().unwrap()),
            STATUS_INVALID_HANDLE
        );

        // Under the domain handle, the directory's groups enumerate (default: Domain
        // Admins RID 512, Domain Users RID 513).
        let groups = samr.call(OP_ENUM_DOMAIN_GROUPS, &domain_handle).unwrap();
        let n = groups.len();
        assert_eq!(
            u32::from_le_bytes(groups[n - 4..].try_into().unwrap()),
            STATUS_SUCCESS
        );
        assert_eq!(
            u32::from_le_bytes(groups[n - 8..n - 4].try_into().unwrap()),
            2,
            "two groups"
        );
        assert!(
            groups.windows(4).any(|w| w == 512u32.to_le_bytes()),
            "Domain Admins RID 512"
        );
    }

    #[test]
    fn open_group_then_get_members_returns_the_member_rids() {
        let mut src = Directory::default(); // alice RID 1000
        src.add_group_with_members("Engineers", 4200, vec![1000, 1001]);
        let samr = SamrInterface::new(Arc::new(src));

        let connect = samr.call(OP_CONNECT, &[]).unwrap();
        let opened = samr.call(OP_OPEN_DOMAIN, &connect[0..20]).unwrap();
        let domain_handle = opened[0..20].to_vec();

        // Open the group by RID (handle | DesiredAccess | GroupId=4200).
        let mut open_req = domain_handle.clone();
        open_req.extend_from_slice(&0x0002_0000u32.to_le_bytes()); // DesiredAccess
        open_req.extend_from_slice(&4200u32.to_le_bytes()); // GroupId
        let og = samr.call(OP_OPEN_GROUP, &open_req).unwrap();
        assert_eq!(&og[20..24], &[0, 0, 0, 0], "SamrOpenGroup STATUS_SUCCESS");
        let group_handle = og[0..20].to_vec();

        // Get its members → RIDs 1000 and 1001.
        let resp = samr.call(OP_GET_MEMBERS_IN_GROUP, &group_handle).unwrap();
        assert_eq!(
            u32::from_le_bytes(resp[resp.len() - 4..].try_into().unwrap()),
            STATUS_SUCCESS
        );
        assert_eq!(
            u32::from_le_bytes(resp[4..8].try_into().unwrap()),
            2,
            "MemberCount = 2"
        );
        assert!(
            resp.windows(4).any(|w| w == 1000u32.to_le_bytes()),
            "member RID 1000"
        );
        assert!(
            resp.windows(4).any(|w| w == 1001u32.to_le_bytes()),
            "member RID 1001"
        );

        // A group handle is not a domain handle (kind is enforced).
        assert!(!samr.valid(&group_handle, HandleKind::Domain));
    }

    /// Build a `SamrCreateUser2InDomain` request stub for `name` under `handle`,
    /// matching impacket's marshalling: the `RPC_UNICODE_STRING` serializes as a
    /// unit (its Buffer array immediately after the struct's inline part), then the
    /// 4-aligned `AccountType` and `DesiredAccess` scalars.
    fn create_user_request(handle: &[u8], name: &str, account_type: u32, access: u32) -> Vec<u8> {
        let chars: Vec<u16> = name.encode_utf16().collect();
        let n = chars.len();
        let mut s = Vec::new();
        s.extend_from_slice(&handle[0..20]); // DomainHandle
        s.extend_from_slice(&((n * 2) as u16).to_le_bytes()); // Name.Length
        s.extend_from_slice(&((n * 2) as u16).to_le_bytes()); // Name.MaximumLength
        s.extend_from_slice(&0x0002_0000u32.to_le_bytes()); // Name.Buffer referent
        s.extend_from_slice(&(n as u32).to_le_bytes()); // Buffer MaxCount
        s.extend_from_slice(&0u32.to_le_bytes()); // Offset
        s.extend_from_slice(&(n as u32).to_le_bytes()); // ActualCount
        for c in &chars {
            s.extend_from_slice(&c.to_le_bytes());
        }
        while s.len() % 4 != 0 {
            s.push(0); // align past the string
        }
        s.extend_from_slice(&account_type.to_le_bytes()); // AccountType
        s.extend_from_slice(&access.to_le_bytes()); // DesiredAccess
        s
    }

    #[test]
    fn create_user2_allocates_rid_and_appears_in_enumeration() {
        let samr = SamrInterface::default();
        let server = samr.call(OP_CONNECT, &[]).unwrap()[0..20].to_vec();
        let domain = samr.call(OP_OPEN_DOMAIN, &server).unwrap()[0..20].to_vec();

        // Create a machine account (WORKSTATION_TRUST 0x1000, MAXIMUM_ALLOWED access).
        let req = create_user_request(&domain, "TESTPC$", 0x1000, 0x0200_0000);
        let out = samr.call(OP_CREATE_USER2, &req).unwrap();
        assert_eq!(out.len(), 32);
        assert_eq!(
            u32::from_le_bytes(out[28..32].try_into().unwrap()),
            STATUS_SUCCESS
        );
        assert_eq!(
            u32::from_le_bytes(out[24..28].try_into().unwrap()),
            FIRST_CREATED_RID
        );
        // MAXIMUM_ALLOWED is granted as USER_ALL_ACCESS.
        assert_eq!(
            u32::from_le_bytes(out[20..24].try_into().unwrap()),
            USER_ALL_ACCESS
        );

        // Enumeration now includes the created machine account (RID 1100 + name).
        let users = samr.call(OP_ENUM_USERS, &domain).unwrap();
        assert!(
            users
                .windows(4)
                .any(|w| w == FIRST_CREATED_RID.to_le_bytes()),
            "RID 1100 present"
        );
        let pc: Vec<u8> = "TESTPC$"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert!(users.windows(pc.len()).any(|w| w == pc), "TESTPC$ present");
    }

    #[test]
    fn create_user2_draws_rid_from_attached_allocator() {
        use std::sync::atomic::{AtomicU32, Ordering};
        // A fixed-sequence allocator standing in for the DB-backed one.
        struct SeqAllocator(AtomicU32);
        impl RidAllocator for SeqAllocator {
            fn allocate(&self) -> Option<u32> {
                Some(self.0.fetch_add(1, Ordering::Relaxed))
            }
        }
        let samr = SamrInterface::default()
            .with_rid_allocator(Arc::new(SeqAllocator(AtomicU32::new(4321))));
        let server = samr.call(OP_CONNECT, &[]).unwrap()[0..20].to_vec();
        let domain = samr.call(OP_OPEN_DOMAIN, &server).unwrap()[0..20].to_vec();

        // The allocator's RID is used, not the in-memory FIRST_CREATED_RID counter.
        let req = create_user_request(&domain, "TESTPC$", 0x1000, 0x0200_0000);
        let out = samr.call(OP_CREATE_USER2, &req).unwrap();
        assert_eq!(u32::from_le_bytes(out[24..28].try_into().unwrap()), 4321);
        let req2 = create_user_request(&domain, "OTHER$", 0x1000, 0x0200_0000);
        let out2 = samr.call(OP_CREATE_USER2, &req2).unwrap();
        assert_eq!(u32::from_le_bytes(out2[24..28].try_into().unwrap()), 4322);
    }

    #[test]
    fn machine_initial_password_follows_ad_convention() {
        assert_eq!(machine_initial_password("TESTPC$"), "testpc");
        assert_eq!(machine_initial_password("WKS01$"), "wks01");
        // Truncated to 14 characters.
        assert_eq!(machine_initial_password("VERYLONGCOMPUTERNAME$").len(), 14);
    }

    #[test]
    fn create_user2_registers_machine_in_kdc() {
        let store = Arc::new(PrincipalStore::new("EXAMPLE.COM"));
        let samr = SamrInterface::new_with_kdc(Arc::new(Directory::default()), store.clone());
        let server = samr.call(OP_CONNECT, &[]).unwrap()[0..20].to_vec();
        let domain = samr.call(OP_OPEN_DOMAIN, &server).unwrap()[0..20].to_vec();

        let req = create_user_request(&domain, "TESTPC$", 0x1000, 0x0200_0000);
        samr.call(OP_CREATE_USER2, &req).unwrap();

        // The KDC now has the machine principal with a derived AES256 key, so it can
        // issue it tickets (the initial password is "testpc").
        let principal = store
            .get(&["TESTPC$".to_string()])
            .expect("machine registered");
        assert_eq!(principal.key.key.len(), 32);
    }

    /// Build a `SamrSetInformationUser2` request stub carrying `password` in an
    /// RC4-sealed `SAMPR_ENCRYPTED_USER_PASSWORD` at the tail, under `handle`.
    fn set_info_request(handle: &[u8], password: &str, key: &[u8]) -> Vec<u8> {
        let pw: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut plain = vec![0u8; 512];
        let start = 512 - pw.len();
        plain[start..].copy_from_slice(&pw);
        plain.extend_from_slice(&(pw.len() as u32).to_le_bytes()); // Length @512 → 516 bytes
        let sealed = rc4(key, &plain);

        let mut stub = handle[0..20].to_vec();
        stub.extend_from_slice(&[0u8; 8]); // InformationClass + union ptr (ignored)
        stub.extend_from_slice(&sealed); // SAMPR_ENCRYPTED_USER_PASSWORD
        stub.extend_from_slice(&[0u8; 4]); // PasswordExpired + padding
        stub
    }

    /// Build a `SamrSetInformationUser2` request carrying `password` in a
    /// `SAMPR_ENCRYPTED_USER_PASSWORD_NEW` — the salted RC4 form a real domain join
    /// sends (UserInternal4InformationNew). Mirrors Samba `samr_CryptPasswordEx`:
    /// key = `MD5(salt || session_key)`, then the 16-byte salt is appended.
    fn set_info_request_new(handle: &[u8], password: &str, key: &[u8], salt: &[u8; 16]) -> Vec<u8> {
        let pw: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut plain = vec![0u8; 512];
        let start = 512 - pw.len();
        plain[start..].copy_from_slice(&pw);
        plain.extend_from_slice(&(pw.len() as u32).to_le_bytes()); // Length @512 → 516 bytes
        let mut md5 = Md5::new();
        md5.update(salt);
        md5.update(key);
        let rc4_key = md5.finalize();
        let sealed = rc4(&rc4_key, &plain);

        let mut stub = handle[0..20].to_vec();
        stub.extend_from_slice(&[0u8; 8]); // InformationClass + union ptr (ignored)
        stub.extend_from_slice(&sealed); // 516 encrypted bytes
        stub.extend_from_slice(salt); // 16-byte confounder → 532-byte block
        stub
    }

    #[test]
    fn set_information_user2_decrypts_salted_new_password_buffer() {
        let store = Arc::new(PrincipalStore::new("EXAMPLE.COM"));
        let samr = SamrInterface::new_with_kdc(Arc::new(Directory::default()), store.clone());
        let server = samr.call(OP_CONNECT, &[]).unwrap()[0..20].to_vec();
        let domain = samr.call(OP_OPEN_DOMAIN, &server).unwrap()[0..20].to_vec();
        let create = samr
            .call(
                OP_CREATE_USER2,
                &create_user_request(&domain, "JOINPC$", 0x1000, 0),
            )
            .unwrap();
        let user_handle = create[0..20].to_vec();

        let session_key = [0x42u8; 16];
        let salt = [0x99u8; 16];
        let new_password = "NewMachineP@ss1";
        let stub = set_info_request_new(&user_handle, new_password, &session_key, &salt);

        let out = samr
            .call_with_session(OP_SET_USER_INFO2, &stub, Some(&session_key))
            .unwrap();
        assert_eq!(
            u32::from_le_bytes(out[0..4].try_into().unwrap()),
            STATUS_SUCCESS
        );
        // A `$` account registers via the AD computer-account convention: key over the
        // WTF-8 password + the `host/<fqdn>` salt, resolvable by SAM and host/ SPN.
        let host_spn = vec!["host".to_string(), "joinpc.example.com".to_string()];
        let host_salt = magnetite_krb5::keys::default_salt("EXAMPLE.COM", &host_spn);
        let units: Vec<u16> = new_password.encode_utf16().collect();
        let expected = magnetite_krb5::keys::derive_aes256_key_bytes(
            &magnetite_krb5::keys::wtf8(&units),
            host_salt.as_bytes(),
        )
        .unwrap();
        assert_eq!(
            store.get(&["JOINPC$".to_string()]).unwrap().key.key,
            expected
        );
        assert_eq!(store.get(&host_spn).unwrap().key.key, expected);
    }

    #[test]
    fn decrypts_a_random_machine_password_with_control_characters() {
        // A real machine account password is random UTF-16 code units, so it contains
        // control characters — the decrypt must not reject those (regression guard).
        let handle = [0u8; 20];
        let session_key = [0x37u8; 16];
        let salt = [0x5au8; 16];
        let units: Vec<u16> = (0u16..120)
            .map(|i| i.wrapping_mul(2551).wrapping_add(1))
            .collect();
        let password = String::from_utf16_lossy(&units);
        let stub = set_info_request_new(&handle, &password, &session_key, &salt);
        // Decryption returns the raw UTF-16LE password bytes (fidelity-preserving).
        let expected: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(
            decrypt_sampr_password_new(&stub, &session_key),
            Some(expected)
        );
    }

    #[test]
    fn set_information_user2_decrypts_and_updates_kdc_key() {
        let store = Arc::new(PrincipalStore::new("EXAMPLE.COM"));
        let samr = SamrInterface::new_with_kdc(Arc::new(Directory::default()), store.clone());
        let server = samr.call(OP_CONNECT, &[]).unwrap()[0..20].to_vec();
        let domain = samr.call(OP_OPEN_DOMAIN, &server).unwrap()[0..20].to_vec();
        let create = samr
            .call(
                OP_CREATE_USER2,
                &create_user_request(&domain, "JOINPC$", 0x1000, 0),
            )
            .unwrap();
        let user_handle = create[0..20].to_vec();

        // Setting the password requires the session key; without it → access denied.
        let session_key = [0x42u8; 16];
        let new_password = "NewMachineP@ss1";
        let stub = set_info_request(&user_handle, new_password, &session_key);
        assert_eq!(
            u32::from_le_bytes(
                samr.call(OP_SET_USER_INFO2, &stub).unwrap()[0..4]
                    .try_into()
                    .unwrap()
            ),
            STATUS_ACCESS_DENIED,
        );

        // With the session key, the password decrypts and the KDC key is updated.
        let out = samr
            .call_with_session(OP_SET_USER_INFO2, &stub, Some(&session_key))
            .unwrap();
        assert_eq!(
            u32::from_le_bytes(out[0..4].try_into().unwrap()),
            STATUS_SUCCESS
        );
        let host_salt = magnetite_krb5::keys::default_salt(
            "EXAMPLE.COM",
            &["host".to_string(), "joinpc.example.com".to_string()],
        );
        let units: Vec<u16> = new_password.encode_utf16().collect();
        let expected = magnetite_krb5::keys::derive_aes256_key_bytes(
            &magnetite_krb5::keys::wtf8(&units),
            host_salt.as_bytes(),
        )
        .unwrap();
        assert_eq!(
            store.get(&["JOINPC$".to_string()]).unwrap().key.key,
            expected
        );
    }

    fn query_request(handle: &[u8], class: u16) -> Vec<u8> {
        let mut s = handle[0..20].to_vec();
        s.extend_from_slice(&class.to_le_bytes());
        s
    }

    fn control_request(handle: &[u8], uac: u32) -> Vec<u8> {
        let mut s = handle[0..20].to_vec();
        s.extend_from_slice(&USER_CONTROL_INFORMATION.to_le_bytes()); // InfoClass
        s.extend_from_slice(&USER_CONTROL_INFORMATION.to_le_bytes()); // union discriminant
        s.extend_from_slice(&uac.to_le_bytes());
        s
    }

    fn read_uac(response: &[u8]) -> u32 {
        // referent(4) + discriminant(2) + pad(2) + UserAccountControl(4).
        u32::from_le_bytes(response[8..12].try_into().unwrap())
    }

    #[test]
    fn set_and_query_user_account_control() {
        let samr = SamrInterface::default();
        let server = samr.call(OP_CONNECT, &[]).unwrap()[0..20].to_vec();
        let domain = samr.call(OP_OPEN_DOMAIN, &server).unwrap()[0..20].to_vec();
        let create = samr
            .call(
                OP_CREATE_USER2,
                &create_user_request(&domain, "PC$", 0x1000, 0),
            )
            .unwrap();
        let handle = create[0..20].to_vec();

        // A freshly created machine account is a disabled workstation-trust account.
        let q1 = samr
            .call(
                OP_QUERY_USER_INFO2,
                &query_request(&handle, USER_CONTROL_INFORMATION),
            )
            .unwrap();
        assert_eq!(read_uac(&q1), DEFAULT_MACHINE_UAC);

        // The join enables it (clears ACCOUNTDISABLE).
        let set = samr
            .call(
                OP_SET_USER_INFO2,
                &control_request(&handle, UAC_WORKSTATION_TRUST_ACCOUNT),
            )
            .unwrap();
        assert_eq!(
            u32::from_le_bytes(set[0..4].try_into().unwrap()),
            STATUS_SUCCESS
        );

        let q2 = samr
            .call(
                OP_QUERY_USER_INFO2,
                &query_request(&handle, USER_CONTROL_INFORMATION),
            )
            .unwrap();
        assert_eq!(read_uac(&q2), UAC_WORKSTATION_TRUST_ACCOUNT);
        assert_eq!(read_uac(&q2) & UAC_ACCOUNTDISABLE, 0, "account enabled");
    }

    #[test]
    fn create_user2_requires_domain_handle() {
        let samr = SamrInterface::default();
        let server = samr.call(OP_CONNECT, &[]).unwrap()[0..20].to_vec();
        // A server handle (wrong kind) must be rejected.
        let req = create_user_request(&server, "X$", 0x1000, 0);
        let out = samr.call(OP_CREATE_USER2, &req).unwrap();
        assert_eq!(
            u32::from_le_bytes(out[28..32].try_into().unwrap()),
            STATUS_INVALID_HANDLE
        );
    }

    #[test]
    fn unknown_opnum_faults() {
        assert_eq!(
            SamrInterface::default().call(99, &[]).unwrap_err(),
            fault::OP_RNG_ERROR
        );
    }

    #[test]
    fn lookup_domain_encodes_expected_sid() {
        let out = SamrInterface::default()
            .call(OP_LOOKUP_DOMAIN, &[])
            .unwrap();
        assert_eq!(out.len(), 4 + 4 + 8 + 16 + 4);
        assert_eq!(u32::from_le_bytes(out[4..8].try_into().unwrap()), 4); // MaxCount
        assert_eq!(out[8], 1); // Revision
        assert_eq!(u32::from_le_bytes(out[16..20].try_into().unwrap()), 21);
    }
}
