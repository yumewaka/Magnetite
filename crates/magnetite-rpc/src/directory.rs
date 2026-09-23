//! A shared directory: one source of truth for the domain identity, users and
//! groups, consumed by the SAMR, LSA and DRSUAPI interfaces (and used to seed the
//! KDC). Every interface answers from this one structure, so adding a user makes
//! it enumerable (SAMR), resolvable (LSA), replicable (DRSUAPI) and — via its
//! key material — able to authenticate (Kerberos/NTLM) consistently.
//!
//! Each user carries **derived key material** (the NT hash and the Kerberos
//! AES256 long-term key), not a cleartext password — the same shape whether the
//! source is an in-memory seed or `magnetite-db`'s `list_ad_principals`. That
//! makes the directory the seam between the AD DC interfaces and a live database.

use magnetite_krb5::keys::{default_salt, derive_aes256_key};
use magnetite_krb5::KdcResult;
use md4::{Digest, Md4};
use parking_lot::RwLock;
use std::sync::Arc;

/// UTF-16LE encoding of `s`.
fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// The NT hash (`NTOWFv1`) of a password: MD4 of its UTF-16LE encoding.
pub fn nt_hash(password: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&Md4::digest(utf16le(password)));
    out
}

/// The NT hash of a password already in UTF-16LE bytes: MD4 of the raw bytes. A
/// machine account password is 120 random UTF-16 code units (often with lone
/// surrogates that a `String` cannot hold), so its NT hash must be taken over the raw
/// bytes — never a lossily-decoded `String` — for the secure channel to authenticate.
pub fn nt_hash_utf16le(pw_utf16le: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&Md4::digest(pw_utf16le));
    out
}

/// A user's replication stamp — where a change originated, for outbound DRS. When a
/// change reached this DC by replication from another DSA, the outbound reply must
/// carry that ORIGINAL origin (DSA/version/time/USN), not re-stamp it as locally
/// originated: preserving it is what lets multi-master peers converge and dampens
/// replication loops. `None` ⇒ locally originated / in-memory (the source falls back
/// to stamping itself, version 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplMeta {
    /// Originating-change version (the primary conflict tiebreaker).
    pub version: u32,
    /// Originating time as a `DSTIME` (seconds since 1601-01-01), the on-wire form.
    pub originating_time: i64,
    /// The invocation ID of the DSA where the change originated.
    pub originating_dsa: [u8; 16],
    /// The originating DSA's USN for this change.
    pub originating_usn: i64,
}

/// A directory user account with its derived key material.
#[derive(Clone)]
pub struct User {
    /// The `sAMAccountName` (login name).
    pub sam_account_name: String,
    /// The account's RID (its SID is the domain SID + this RID).
    pub rid: u32,
    /// The NT hash (NTLM, DRSUAPI `unicodePwd`).
    pub nt_hash: [u8; 16],
    /// The Kerberos AES256-CTS-HMAC-SHA1-96 long-term key (32 bytes).
    pub kerberos_key: Vec<u8>,
    /// Whether the account is disabled (`userAccountControl` `ACCOUNTDISABLE`). A
    /// disabled account is still visible in the directory but must not authenticate —
    /// the KDC seed skips it and revokes any runtime key (see the addc replication
    /// refresh).
    pub disabled: bool,
    /// The replication stamp served in outbound DRS metadata. `None` for a locally
    /// originated / in-memory user (the source stamps itself, version 1).
    pub repl_meta: Option<ReplMeta>,
}

/// One of a group's membership links, with its per-link replication state. A `member`
/// link is present (a current membership) or absent (a tombstone of a removed member);
/// serving BOTH, each with its own stamp, is what lets a member REMOVAL replicate and
/// concurrent add/remove of different members merge per-link (Tier C item 5d).
#[derive(Clone, Copy, Debug)]
pub struct GroupLink {
    /// The member's RID.
    pub member_rid: u32,
    /// `true` = a current membership; `false` = a removed-member tombstone.
    pub present: bool,
    /// The link's origin stamp (version/DSA/USN/time), or `None` for a self/v1 link.
    pub repl_meta: Option<ReplMeta>,
}

/// A directory group.
#[derive(Clone)]
pub struct Group {
    pub sam_account_name: String,
    pub rid: u32,
    /// The RIDs of this group's PRESENT members (users or nested groups) — the current
    /// membership SAMR/LSA answer from. Derived from the present [`Self::member_links`].
    pub members: Vec<u32>,
    /// The full per-link membership state (present + absent tombstones), for outbound
    /// linked-value replication. Empty for an in-memory group with no tracked history.
    pub member_links: Vec<GroupLink>,
    /// The replication stamp served in outbound DRS metadata (like [`User::repl_meta`]).
    /// `None` for a locally originated / seeded group (the source stamps self, v1).
    pub repl_meta: Option<ReplMeta>,
}

/// How a resolved RID is classified (SID_NAME_USE, the values LSA reports).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RidKind {
    User,
    Group,
}

/// The shared directory: one domain with its users and groups.
#[derive(Clone)]
pub struct Directory {
    netbios: String,
    dns_domain: String,
    realm: String,
    domain_sid: Vec<u32>,
    users: Vec<User>,
    groups: Vec<Group>,
    /// Users discovered at runtime (a machine account SAMR creates during a live
    /// join). Behind an `Arc<RwLock>` so they can be added through `&self` while the
    /// directory is shared, and seen by lookups (e.g. the Netlogon secure channel's
    /// NT-hash resolution) WITHOUT a restart. Cloning the directory shares this set.
    runtime_users: Arc<RwLock<Vec<User>>>,
    /// Groups discovered at runtime (e.g. replicated inbound from an upstream DC while
    /// the DC is running). Like [`runtime_users`](Self::runtime_users), behind an
    /// `Arc<RwLock>` so they can be added through `&self` and seen by SAMR enumeration
    /// / LSA resolution / SAMR membership WITHOUT a restart; cloning shares the set.
    runtime_groups: Arc<RwLock<Vec<Group>>>,
    /// The RID Master watermark: the next unallocated RID this DC (when it holds the
    /// RID Master role) will hand out. Behind an `Arc<RwLock>` so a RID-pool request
    /// (`EXOP_FSMO_RID_ALLOC`) advances it through `&self` and the advance is shared
    /// across the directory's clones. Used only as the in-memory fallback when no
    /// durable [`rid_source`](Self::rid_source) is injected (e.g. in-memory mode/tests).
    rid_pool_next: Arc<RwLock<u32>>,
    /// The durable RID source that backs RID-pool grants when the daemon injects one
    /// (via [`set_rid_source`](Self::set_rid_source)): the SAME allocator that mints
    /// local accounts, so served pools and local RIDs draw from one persistent counter
    /// and never overlap. `None` ⇒ fall back to the in-memory `rid_pool_next`.
    rid_source: Arc<RwLock<Option<Arc<dyn crate::samr::RidAllocator>>>>,
}

/// The first RID the RID Master hands out, above the well-known RIDs (< 1000).
pub const RID_POOL_START: u32 = 1100;

/// The default size of a RID pool granted to a requesting DC (matches AD's default).
pub const RID_POOL_SIZE: u32 = 500;

/// The maximum allocatable RID (`2^30 - 1`) — the high DWORD of `rIDAvailablePool`,
/// matching a real AD RID master (Samba/Windows return `0x3fffffff`).
pub const RID_POOL_MAX: u32 = 0x3fff_ffff;

impl Directory {
    /// A directory for a domain (NetBIOS/DNS names, Kerberos realm, SID).
    pub fn new(netbios: &str, dns_domain: &str, realm: &str, domain_sid: Vec<u32>) -> Self {
        Self {
            netbios: netbios.to_string(),
            dns_domain: dns_domain.to_string(),
            realm: realm.to_string(),
            domain_sid,
            users: Vec::new(),
            groups: Vec::new(),
            runtime_users: Arc::new(RwLock::new(Vec::new())),
            runtime_groups: Arc::new(RwLock::new(Vec::new())),
            rid_pool_next: Arc::new(RwLock::new(RID_POOL_START)),
            rid_source: Arc::new(RwLock::new(None)),
        }
    }

    /// Inject the durable RID source that backs RID-pool grants — the daemon wires the
    /// same DB-backed allocator SAMR uses to mint accounts, so a pool served over
    /// DRSUAPI and a locally minted RID come from one persistent counter (never
    /// overlapping, surviving restarts). Shared across the directory's clones.
    pub fn set_rid_source(&self, source: Arc<dyn crate::samr::RidAllocator>) {
        *self.rid_source.write() = Some(source);
    }

    /// Seed the RID Master watermark (the next RID to hand out) — the daemon calls this
    /// with the durable value so pool grants survive restarts and never regress.
    pub fn set_rid_pool_next(&self, next: u32) {
        *self.rid_pool_next.write() = next.max(RID_POOL_START);
    }

    /// The next RID the RID Master would hand out (the current watermark).
    pub fn rid_pool_next(&self) -> u32 {
        *self.rid_pool_next.read()
    }

    /// Allocate the next contiguous RID pool of `size` RIDs to a requesting DC, returning
    /// `(base, size)`. This is the RID Master's grant for `EXOP_FSMO_RID_ALLOC`;
    /// successive grants never overlap.
    ///
    /// When a durable [`rid_source`](Self::rid_source) is injected the pool comes from it
    /// (shared with local account mint, persisted across restarts); its `None` — a
    /// momentary refill — is propagated so the caller can signal a retry rather than
    /// hand out a non-durable range that could overlap. Without a source (in-memory
    /// mode) the in-memory watermark always yields a pool.
    pub fn allocate_rid_pool(&self, size: u32) -> Option<(u32, u32)> {
        let size = size.max(1);
        if let Some(source) = self.rid_source.read().as_ref() {
            return source.allocate_pool(size);
        }
        let mut next = self.rid_pool_next.write();
        let base = *next;
        *next = next.saturating_add(size);
        Some((base, size))
    }

    /// Add or replace (by sAMAccountName, case-insensitive) a user discovered at
    /// runtime — a machine account a live domain join creates through SAMR — so
    /// lookups resolve it before the next restart reloads the directory from the DB.
    pub fn upsert_runtime_user(&self, user: User) {
        let mut rt = self.runtime_users.write();
        match rt.iter_mut().find(|u| {
            u.sam_account_name
                .eq_ignore_ascii_case(&user.sam_account_name)
        }) {
            Some(existing) => *existing = user,
            None => rt.push(user),
        }
    }

    /// Drop any runtime user whose `sAMAccountName` is not in `keep` (case-insensitive),
    /// returning the removed names. Used by the inbound-replication refresh to purge a
    /// tombstoned (deleted) account from the live directory — `keep` is the set the DB
    /// still holds, so anything the runtime set has beyond it was deleted upstream (B4b).
    pub fn retain_runtime_users(&self, keep: &std::collections::HashSet<String>) -> Vec<String> {
        let keep_lc: std::collections::HashSet<String> =
            keep.iter().map(|s| s.to_lowercase()).collect();
        let mut rt = self.runtime_users.write();
        let mut removed = Vec::new();
        rt.retain(|u| {
            let live = keep_lc.contains(&u.sam_account_name.to_lowercase());
            if !live {
                removed.push(u.sam_account_name.clone());
            }
            live
        });
        removed
    }

    /// Drop any runtime group whose RID is not in `keep`, returning the removed RIDs.
    /// The group counterpart of [`retain_runtime_users`](Self::retain_runtime_users) for
    /// applying a tombstoned group (B4b).
    pub fn retain_runtime_groups(&self, keep: &std::collections::HashSet<u32>) -> Vec<u32> {
        let mut rt = self.runtime_groups.write();
        let mut removed = Vec::new();
        rt.retain(|g| {
            let live = keep.contains(&g.rid);
            if !live {
                removed.push(g.rid);
            }
            live
        });
        removed
    }

    /// Add or replace (by RID) a group discovered at runtime — e.g. one replicated
    /// inbound while the DC is running — so SAMR/LSA reflect it before the next restart
    /// reloads the directory from the DB.
    pub fn upsert_runtime_group(&self, group: Group) {
        let mut rt = self.runtime_groups.write();
        match rt.iter_mut().find(|g| g.rid == group.rid) {
            Some(existing) => *existing = group,
            None => rt.push(group),
        }
    }

    /// Find a user by sAMAccountName (case-insensitive), across the static and runtime
    /// sets. Used by the Netlogon secure channel to resolve a machine account's NT hash.
    pub fn find_user(&self, sam_account_name: &str) -> Option<User> {
        if let Some(u) = self
            .users
            .iter()
            .find(|u| u.sam_account_name.eq_ignore_ascii_case(sam_account_name))
        {
            return Some(u.clone());
        }
        self.runtime_users
            .read()
            .iter()
            .find(|u| u.sam_account_name.eq_ignore_ascii_case(sam_account_name))
            .cloned()
    }

    /// Add a user from a cleartext password (an in-memory seed), deriving the NT
    /// hash and the Kerberos AES256 key. The cleartext is not retained.
    ///
    /// # Errors
    /// Propagates a Kerberos key-derivation failure.
    pub fn add_user(&mut self, sam_account_name: &str, rid: u32, password: &str) -> KdcResult<()> {
        let salt = default_salt(&self.realm, &[sam_account_name.to_string()]);
        let kerberos_key = derive_aes256_key(password, &salt)?;
        self.users.push(User {
            sam_account_name: sam_account_name.to_string(),
            rid,
            nt_hash: nt_hash(password),
            kerberos_key,
            disabled: false,
            repl_meta: None,
        });
        Ok(())
    }

    /// Add a user from stored key material (a database source, e.g.
    /// `magnetite-db::list_ad_principals`). `disabled` reflects the account's
    /// `userAccountControl` `ACCOUNTDISABLE` bit so the KDC seed can skip it.
    pub fn add_user_with_keys(
        &mut self,
        sam_account_name: &str,
        rid: u32,
        nt_hash: [u8; 16],
        kerberos_key: Vec<u8>,
        disabled: bool,
    ) {
        self.users.push(User {
            sam_account_name: sam_account_name.to_string(),
            rid,
            nt_hash,
            kerberos_key,
            disabled,
            repl_meta: None,
        });
    }

    /// Attach a replication stamp to an already-added user (by `sAMAccountName`), so
    /// outbound DRS serves that change's real origin instead of re-stamping it locally.
    /// No-op if no such user exists.
    pub fn set_user_repl_meta(&mut self, sam_account_name: &str, meta: ReplMeta) {
        if let Some(u) = self
            .users
            .iter_mut()
            .find(|u| u.sam_account_name == sam_account_name)
        {
            u.repl_meta = Some(meta);
        }
    }

    /// Add a group.
    pub fn add_group(&mut self, sam_account_name: &str, rid: u32) {
        self.add_group_with_members(sam_account_name, rid, Vec::new());
    }

    /// Add a group with its member RIDs (users or nested groups). All members are
    /// present (no tombstones) and unstamped — the in-memory / seed shape.
    pub fn add_group_with_members(&mut self, sam_account_name: &str, rid: u32, members: Vec<u32>) {
        let member_links = members
            .iter()
            .map(|&member_rid| GroupLink {
                member_rid,
                present: true,
                repl_meta: None,
            })
            .collect();
        self.groups.push(Group {
            sam_account_name: sam_account_name.to_string(),
            rid,
            members,
            member_links,
            repl_meta: None,
        });
    }

    /// Set a group's full per-link membership state (present + absent tombstones), from
    /// the store; the present links become its current `members`. Used by
    /// `build_directory_from_db` so outbound serves removals and per-link stamps.
    pub fn set_group_member_links(&mut self, sam_account_name: &str, links: Vec<GroupLink>) {
        if let Some(g) = self
            .groups
            .iter_mut()
            .find(|g| g.sam_account_name == sam_account_name)
        {
            g.members = links
                .iter()
                .filter(|l| l.present)
                .map(|l| l.member_rid)
                .collect();
            g.member_links = links;
        }
    }

    /// Attach a replication stamp to an already-added group (by `sAMAccountName`), so
    /// outbound DRS serves that group's real origin and it dampens/converges like a user.
    pub fn set_group_repl_meta(&mut self, sam_account_name: &str, meta: ReplMeta) {
        if let Some(g) = self
            .groups
            .iter_mut()
            .find(|g| g.sam_account_name == sam_account_name)
        {
            g.repl_meta = Some(meta);
        }
    }

    /// The member RIDs of the group with RID `rid` (static or runtime set), if it exists.
    pub fn group_members(&self, rid: u32) -> Option<Vec<u32>> {
        if let Some(g) = self.groups.iter().find(|g| g.rid == rid) {
            return Some(g.members.clone());
        }
        self.runtime_groups
            .read()
            .iter()
            .find(|g| g.rid == rid)
            .map(|g| g.members.clone())
    }

    /// The NetBIOS domain name (e.g. `EXAMPLE`).
    pub fn netbios(&self) -> &str {
        &self.netbios
    }

    /// The DNS domain name (e.g. `example.com`).
    pub fn dns_domain(&self) -> &str {
        &self.dns_domain
    }

    /// The Kerberos realm (e.g. `EXAMPLE.COM`).
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// The domain SID's sub-authorities (e.g. `[21, 1, 2, 3]` for S-1-5-21-1-2-3).
    pub fn domain_sid(&self) -> &[u32] {
        &self.domain_sid
    }

    /// Override the domain SID's sub-authorities. Used when this DC serves outbound
    /// DRS replication into a foreign domain (e.g. a Samba domain during migration):
    /// replicated objects must carry that domain's real SID, not the local default.
    pub fn set_domain_sid(&mut self, domain_sid: Vec<u32>) {
        self.domain_sid = domain_sid;
    }

    /// The users, in insertion order.
    pub fn users(&self) -> &[User] {
        &self.users
    }

    /// The groups, in insertion order.
    pub fn groups(&self) -> &[Group] {
        &self.groups
    }

    /// Resolve a RID to a `(name, kind)` pair (a user or group in this domain).
    pub fn resolve_rid(&self, rid: u32) -> Option<(String, RidKind)> {
        if let Some(u) = self.users.iter().find(|u| u.rid == rid) {
            return Some((u.sam_account_name.clone(), RidKind::User));
        }
        if let Some(u) = self.runtime_users.read().iter().find(|u| u.rid == rid) {
            return Some((u.sam_account_name.clone(), RidKind::User));
        }
        if let Some(g) = self.groups.iter().find(|g| g.rid == rid) {
            return Some((g.sam_account_name.clone(), RidKind::Group));
        }
        self.runtime_groups
            .read()
            .iter()
            .find(|g| g.rid == rid)
            .map(|g| (g.sam_account_name.clone(), RidKind::Group))
    }

    /// All users — the static set plus any added at runtime (deduped by RID). SAMR
    /// enumeration answers from this so replicated users appear without a restart.
    pub fn all_users(&self) -> Vec<User> {
        let mut all = self.users.clone();
        for u in self.runtime_users.read().iter() {
            if !all.iter().any(|x| x.rid == u.rid) {
                all.push(u.clone());
            }
        }
        all
    }

    /// All groups — the static set plus any added at runtime (deduped by RID).
    pub fn all_groups(&self) -> Vec<Group> {
        let mut all = self.groups.clone();
        for g in self.runtime_groups.read().iter() {
            if !all.iter().any(|x| x.rid == g.rid) {
                all.push(g.clone());
            }
        }
        all
    }
}

impl Default for Directory {
    /// The PoC domain `EXAMPLE`/`example.com` (realm `EXAMPLE.COM`, SID
    /// `S-1-5-21-1-2-3`) with the user `alice` (RID 1000) and the standard groups.
    fn default() -> Self {
        let mut d = Directory::new("EXAMPLE", "example.com", "EXAMPLE.COM", vec![21, 1, 2, 3]);
        d.add_user("alice", 1000, "password12")
            .expect("alice key derivation");
        d.add_group("Domain Admins", 512);
        d.add_group("Domain Users", 513);
        d
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rid_master_allocates_disjoint_climbing_pools() {
        let d = Directory::default();
        assert_eq!(d.rid_pool_next(), RID_POOL_START);
        let p1 = d.allocate_rid_pool(RID_POOL_SIZE);
        let p2 = d.allocate_rid_pool(RID_POOL_SIZE);
        assert_eq!(p1, Some((RID_POOL_START, RID_POOL_SIZE)));
        assert_eq!(p2, Some((RID_POOL_START + RID_POOL_SIZE, RID_POOL_SIZE)));
        assert_eq!(d.rid_pool_next(), RID_POOL_START + 2 * RID_POOL_SIZE);
        // Seeding never regresses below the floor and advances the watermark.
        d.set_rid_pool_next(50_000);
        assert_eq!(d.allocate_rid_pool(100), Some((50_000, 100)));
        d.set_rid_pool_next(10); // below the floor
        assert_eq!(d.rid_pool_next(), RID_POOL_START);
    }

    #[test]
    fn default_directory_has_alice_with_key_material() {
        let d = Directory::default();
        assert_eq!(d.netbios(), "EXAMPLE");
        assert_eq!(d.realm(), "EXAMPLE.COM");
        assert_eq!(d.domain_sid(), &[21, 1, 2, 3]);
        assert_eq!(d.users().len(), 1);
        let alice = &d.users()[0];
        assert_eq!(alice.sam_account_name, "alice");
        // alice's NT hash matches MD4(UTF16LE("password12")); Kerberos key is 32 B.
        assert_eq!(
            alice.nt_hash,
            [
                0x1b, 0x62, 0x01, 0x8f, 0x0d, 0x05, 0xc7, 0x37, 0xd0, 0x64, 0x02, 0x29, 0x4c, 0xe2,
                0x42, 0x36
            ]
        );
        assert_eq!(alice.kerberos_key.len(), 32);
        assert!(matches!(d.resolve_rid(1000), Some((n, RidKind::User)) if n == "alice"));
        assert!(matches!(d.resolve_rid(512), Some((n, RidKind::Group)) if n == "Domain Admins"));
        assert!(d.resolve_rid(9999).is_none());
    }

    #[test]
    fn runtime_group_upsert_is_seen_live_and_shared_across_clones() {
        let d = Directory::new("EXAMPLE", "example.com", "EXAMPLE.COM", vec![21, 1, 2, 3]);
        // A group added at runtime (as an inbound replication would) is immediately
        // enumerable, resolvable and has queryable membership — no restart.
        d.upsert_runtime_group(Group {
            sam_account_name: "Engineers".into(),
            rid: 4200,
            members: vec![1000, 1001],
            member_links: Vec::new(),
            repl_meta: None,
        });
        assert!(d.all_groups().iter().any(|g| g.rid == 4200), "enumerable");
        assert!(matches!(d.resolve_rid(4200), Some((n, RidKind::Group)) if n == "Engineers"));
        assert_eq!(d.group_members(4200), Some(vec![1000, 1001]));

        // A clone shares the runtime set (interfaces hold clones of one directory).
        let clone = d.clone();
        clone.upsert_runtime_group(Group {
            sam_account_name: "Ops".into(),
            rid: 4300,
            members: vec![],
            member_links: Vec::new(),
            repl_meta: None,
        });
        assert!(
            d.all_groups().iter().any(|g| g.rid == 4300),
            "clone's upsert visible via original"
        );

        // An upsert by RID replaces, not duplicates.
        d.upsert_runtime_group(Group {
            sam_account_name: "Engineers".into(),
            rid: 4200,
            members: vec![7],
            member_links: Vec::new(),
            repl_meta: None,
        });
        assert_eq!(d.all_groups().iter().filter(|g| g.rid == 4200).count(), 1);
        assert_eq!(d.group_members(4200), Some(vec![7]));
    }

    #[test]
    fn add_user_with_keys_matches_password_derivation() {
        // A user added from stored key material equals one seeded from a password.
        let mut d = Directory::new("EXAMPLE", "example.com", "EXAMPLE.COM", vec![21, 1, 2, 3]);
        d.add_user("alice", 1000, "password12").unwrap();
        let salt = default_salt("EXAMPLE.COM", &["alice".to_string()]);
        let key = derive_aes256_key("password12", &salt).unwrap();
        d.add_user_with_keys("alice2", 1001, nt_hash("password12"), key, false);
        assert_eq!(d.users()[0].nt_hash, d.users()[1].nt_hash);
        assert_eq!(d.users()[0].kerberos_key, d.users()[1].kerberos_key);
    }
}
