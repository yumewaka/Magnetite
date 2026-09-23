//! AD principal store: the **reversible** key material a domain controller's KDB
//! keeps for each domain user — the NT hash (NTLM, DRSUAPI `unicodePwd`) and the
//! Kerberos AES256 long-term key. Unlike local accounts (Argon2, one-way), these
//! must be reversible so the KDC can mint tickets and NTLM/DRSUAPI can answer; the
//! cleartext password is derived-from at create time, then discarded.
//!
//! This is the database side of the [`Directory`](../../magnetite-rpc) the AD DC
//! interfaces answer from: `list_ad_principals` supplies the users a live DC
//! serves, sourced from the directory instead of a fixed in-memory list.

use crate::error::{DbError, DbResult};
use crate::store::Db;
use magnetite_krb5::keys::{default_salt, derive_aes256_key};
use md4::{Digest, Md4};
use serde::{Deserialize, Serialize};
use surrealdb::types::{RecordId, SurrealValue};

/// On-disk AD principal record: NT hash + Kerberos AES256 key (no cleartext).
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub(crate) struct AdPrincipalRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<RecordId>,
    pub sam_account_name: String,
    pub rid: u32,
    pub nt_hash: Vec<u8>,
    pub kerberos_key: Vec<u8>,
    /// Whether the account is disabled (`userAccountControl` `ACCOUNTDISABLE`).
    /// `#[serde(default)]` so records written before this field existed load as enabled.
    #[serde(default)]
    pub disabled: bool,
}

/// An AD principal (domain user) with its NTLM/Kerberos key material.
#[derive(Debug, Clone)]
pub struct AdPrincipal {
    /// The `sAMAccountName` (login name).
    pub sam_account_name: String,
    /// The account RID.
    pub rid: u32,
    /// The NT hash (`NTOWFv1`), 16 bytes.
    pub nt_hash: Vec<u8>,
    /// The Kerberos AES256-CTS-HMAC-SHA1-96 long-term key, 32 bytes.
    pub kerberos_key: Vec<u8>,
    /// Whether the account is disabled (`userAccountControl` `ACCOUNTDISABLE`) — it
    /// must not authenticate, though it stays visible in the directory.
    pub disabled: bool,
}

/// The NT hash (`NTOWFv1`): MD4 of the UTF-16LE password.
fn nt_hash(password: &str) -> Vec<u8> {
    let utf16: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
    Md4::digest(utf16).to_vec()
}

/// The domain-global RID counter: a single DB record whose `next` field is the
/// lowest unallocated RID. Advancing it atomically (below) is how DC front-ends that
/// share one store hand out non-overlapping RID blocks.
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct RidPoolRecord {
    id: Option<RecordId>,
    next: u32,
}

impl Db {
    /// Atomically reserve a contiguous block of `block` RIDs, returning its base (the
    /// first RID of the block; the caller owns `[base, base+block)`). The `rid_pool`
    /// counter is a single record advanced under the store's serialisation, so
    /// concurrent front-ends sharing one store never hand out the same RID — and
    /// because it is persisted, RIDs keep climbing across restarts (the old in-memory
    /// counter reset to 1100 each boot). The pool starts at `first` on first use.
    /// Reserving blocks rather than single RIDs keeps DB round-trips rare.
    ///
    /// # Errors
    /// A store error.
    pub async fn reserve_rid_block(&self, first: u32, block: u32) -> DbResult<u32> {
        // Create the counter on first use; a racing create (or an existing record)
        // simply fails this statement, which we ignore — the UPDATE below is the
        // atomic, serialised step that actually reserves.
        let _ = self
            .inner
            .query("CREATE rid_pool:main SET next = $first")
            .bind(("first", first))
            .await;
        let before: Option<RidPoolRecord> = self
            .inner
            .query("UPDATE rid_pool:main SET next = next + $block RETURN BEFORE")
            .bind(("block", block))
            .await?
            .take(0)?;
        Ok(before.map(|p| p.next).unwrap_or(first))
    }
}

impl Db {
    /// Create an AD principal, deriving and storing the NT hash and the Kerberos
    /// AES256 long-term key from `password` for `realm` (the cleartext is not
    /// stored). `realm` and `sam_account_name` form the Kerberos salt.
    ///
    /// # Errors
    /// [`DbError::Constraint`] if the Kerberos key derivation fails, or a store
    /// error.
    pub async fn create_ad_principal(
        &self,
        sam_account_name: &str,
        rid: u32,
        password: &str,
        realm: &str,
    ) -> DbResult<()> {
        let mut nt = [0u8; 16];
        nt.copy_from_slice(&nt_hash(password));
        // A locally originated create: persist the object AND its version-1 stamp
        // atomically (see `upsert_local_principal`). A change replicated IN from a peer
        // instead keeps its origin via `apply_replicated_principal`.
        self.upsert_local_principal(sam_account_name, rid, password, &nt, None, realm)
            .await?;
        Ok(())
    }

    /// Create a **disabled**, credential-less AD principal for `sam_account_name` with
    /// `rid`. Used when a user is added over LDAP WITHOUT a password (e.g. a migration
    /// LDIF exported by `ldapsearch`, which cannot carry the cleartext): deriving a
    /// credential from the empty password would leave a logon-able account with a
    /// well-known key, so instead the principal is stored disabled — the KDC seed skips it
    /// (both on `disabled` and on the empty Kerberos key) — with its RID preserved for
    /// group membership and later activation (set a password to enable it). This REPLACES
    /// any existing record for the name, so callers must not use it to clobber an enabled
    /// account.
    ///
    /// # Errors
    /// A store error.
    pub async fn create_disabled_ad_principal(
        &self,
        sam_account_name: &str,
        rid: u32,
    ) -> DbResult<()> {
        let stamp = self.next_local_stamp(sam_account_name).await?;
        let principal = AdPrincipalRecord {
            id: None,
            sam_account_name: sam_account_name.to_string(),
            rid,
            nt_hash: vec![0u8; 16],
            kerberos_key: Vec::new(),
            disabled: true,
        };
        self.write_principal_stamped(principal, &stamp).await?;
        Ok(())
    }

    /// Create or replace an AD principal (keyed by `sam_account_name`), deriving
    /// the NT hash and Kerberos key from `password`. Used to persist accounts a
    /// client creates/repasswords through SAMR during a domain join, so they
    /// survive a restart.
    ///
    /// # Errors
    /// [`DbError::Constraint`] on key-derivation failure, or a store error.
    pub async fn upsert_ad_principal(
        &self,
        sam_account_name: &str,
        rid: u32,
        password: &str,
        realm: &str,
    ) -> DbResult<()> {
        let mut nt = [0u8; 16];
        nt.copy_from_slice(&nt_hash(password));
        // A locally originated write (create or password reset): persist the object AND
        // its bumped stamp atomically, so this change replicates out and wins over a
        // peer's prior value.
        self.upsert_local_principal(sam_account_name, rid, password, &nt, None, realm)
            .await?;
        Ok(())
    }

    /// Upsert a principal as a LOCAL originating change, ATOMICALLY with its bumped
    /// replication stamp (version = prior + 1, this DSA, a fresh USN, now). The object
    /// record and the stamp commit together in one transaction, so a crash can never
    /// leave the object un-stamped or with a stale version. Returns the new stamp.
    ///
    /// `kerberos_key` is stored verbatim when `Some` (a machine account's authoritative
    /// AD key); when `None` it is derived from `password` with the ordinary user salt.
    /// The REPLICATED-apply path uses [`Self::apply_replicated_principal`] instead, which
    /// keeps the source's origin stamp.
    ///
    /// # Errors
    /// [`DbError::Constraint`] on key derivation, or a store error (rolls back).
    pub async fn upsert_local_principal(
        &self,
        sam_account_name: &str,
        rid: u32,
        password: &str,
        nt_hash: &[u8; 16],
        kerberos_key: Option<&[u8]>,
        realm: &str,
    ) -> DbResult<crate::replication::ReplStamp> {
        let kerberos_key = match kerberos_key {
            Some(k) => k.to_vec(),
            None => {
                let salt = default_salt(realm, &[sam_account_name.to_string()]);
                derive_aes256_key(password, &salt).map_err(|e| {
                    DbError::Constraint(format!("Kerberos key derivation failed: {e}"))
                })?
            }
        };
        let stamp = self.next_local_stamp(sam_account_name).await?;
        let principal = AdPrincipalRecord {
            id: None,
            sam_account_name: sam_account_name.to_string(),
            rid,
            nt_hash: nt_hash.to_vec(),
            kerberos_key,
            disabled: false, // a locally created/updated account is enabled
        };
        self.write_principal_stamped(principal, &stamp).await?;
        Ok(stamp)
    }

    /// As [`Self::upsert_ad_principal`], but with an explicit, authoritative `nt_hash`
    /// (taken over the raw UTF-16LE password — a random machine password can contain
    /// lone surrogates a `String` cannot hold) and an optional authoritative
    /// `kerberos_key`. When `kerberos_key` is `Some`, it is stored verbatim (the AD
    /// computer-account derivation for a machine account, so a `host/` service ticket
    /// decrypts after a restart); when `None`, the key is derived from `password` with
    /// the ordinary user salt.
    pub async fn upsert_ad_principal_with_hash(
        &self,
        sam_account_name: &str,
        rid: u32,
        password: &str,
        nt_hash: &[u8; 16],
        kerberos_key: Option<&[u8]>,
        realm: &str,
    ) -> DbResult<()> {
        let kerberos_key = match kerberos_key {
            Some(k) => k.to_vec(),
            None => {
                let salt = default_salt(realm, &[sam_account_name.to_string()]);
                derive_aes256_key(password, &salt).map_err(|e| {
                    DbError::Constraint(format!("Kerberos key derivation failed: {e}"))
                })?
            }
        };
        // Replace any existing record for this name (the unique index forbids two).
        self.inner
            .query("DELETE ad_principal WHERE sam_account_name = $n")
            .bind(("n", sam_account_name.to_string()))
            .await?;
        let record = AdPrincipalRecord {
            id: None,
            sam_account_name: sam_account_name.to_string(),
            rid,
            nt_hash: nt_hash.to_vec(),
            kerberos_key,
            disabled: false, // a locally created/updated account is enabled
        };
        let _: Option<AdPrincipalRecord> =
            self.inner.create("ad_principal").content(record).await?;
        Ok(())
    }

    /// List all AD principals (their NTLM/Kerberos key material) — the users the
    /// AD DC directory serves.
    pub async fn list_ad_principals(&self) -> DbResult<Vec<AdPrincipal>> {
        let mut resp = self.inner.query("SELECT * FROM ad_principal").await?;
        // A never-written table does not exist yet in SurrealDB; for a read path that is
        // an empty result (a brand-new store), not an error — see `list_ad_groups`.
        let records: Vec<AdPrincipalRecord> = match resp.take(0) {
            Ok(r) => r,
            Err(e) if e.to_string().contains("does not exist") => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(records
            .into_iter()
            .map(|r| AdPrincipal {
                sam_account_name: r.sam_account_name,
                rid: r.rid,
                nt_hash: r.nt_hash,
                kerberos_key: r.kerberos_key,
                disabled: r.disabled,
            })
            .collect())
    }

    /// Fetch one AD principal by `sam_account_name` (case-insensitive), or `None`. Used
    /// by the Web password-reset path to reuse an existing account's RID.
    ///
    /// # Errors
    /// A store error.
    pub async fn get_ad_principal(&self, sam_account_name: &str) -> DbResult<Option<AdPrincipal>> {
        let mut resp = self
            .inner
            .query("SELECT * FROM ad_principal WHERE string::lowercase(sam_account_name) = string::lowercase($s) LIMIT 1")
            .bind(("s", sam_account_name.to_string()))
            .await?;
        let records: Vec<AdPrincipalRecord> = match resp.take(0) {
            Ok(r) => r,
            Err(e) if e.to_string().contains("does not exist") => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(records.into_iter().next().map(|r| AdPrincipal {
            sam_account_name: r.sam_account_name,
            rid: r.rid,
            nt_hash: r.nt_hash,
            kerberos_key: r.kerberos_key,
            disabled: r.disabled,
        }))
    }

    /// Delete a replicated principal matched by its **RID** (a tombstone replicates the
    /// retained `objectSid` — hence RID — but often strips `sAMAccountName`), removing
    /// its `ad_principal` row and its object + secret replication metadata. Returns the
    /// removed `sAMAccountName` (so the caller can purge the live directory + KDC), or
    /// `None` if no principal held that RID. Used to apply a tombstone (B4b).
    ///
    /// # Errors
    /// A store error.
    pub async fn delete_replicated_principal(&self, rid: u32) -> DbResult<Option<String>> {
        let removed: Option<AdPrincipalRecord> = self
            .inner
            .query("SELECT * FROM ad_principal WHERE rid = $r LIMIT 1")
            .bind(("r", rid))
            .await?
            .take(0)
            .unwrap_or_default();
        let Some(record) = removed else {
            return Ok(None);
        };
        let sam = record.sam_account_name;
        let secret_key = format!("{sam}#unicodePwd");
        self.inner
            .query(
                "BEGIN TRANSACTION; \
                 DELETE ad_principal WHERE rid = $r; \
                 DELETE repl_metadata WHERE object_key = $sam OR object_key = $secret; \
                 COMMIT TRANSACTION;",
            )
            .bind(("r", rid))
            .bind(("sam", sam.clone()))
            .bind(("secret", secret_key))
            .await?
            // Surface a per-statement/commit failure: the caller purges the live
            // directory + KDC on Ok, so a silently-failed delete must not report success.
            .check()?;
        Ok(Some(sam))
    }

    /// Delete a replicated group matched by its `objectSid` (hex; retained on a
    /// tombstone), removing its `ad_group` row and its replication metadata. Returns the
    /// removed group's `sAMAccountName`, or `None` if no group held that SID. Used to
    /// apply a tombstone (B4b).
    ///
    /// # Errors
    /// A store error.
    pub async fn delete_replicated_group(&self, sid_hex: &str) -> DbResult<Option<String>> {
        let removed: Option<AdGroupRecord> = self
            .inner
            .query("SELECT * FROM ad_group WHERE sid = $s LIMIT 1")
            .bind(("s", sid_hex.to_string()))
            .await?
            .take(0)
            .unwrap_or_default();
        let Some(record) = removed else {
            return Ok(None);
        };
        self.inner
            .query(
                "BEGIN TRANSACTION; \
                 DELETE ad_group WHERE sid = $s; \
                 DELETE repl_metadata WHERE object_key = $s; \
                 COMMIT TRANSACTION;",
            )
            .bind(("s", sid_hex.to_string()))
            .await?
            // Surface a per-statement/commit failure: the caller purges the live
            // directory + KDC on Ok, so a silently-failed delete must not report success.
            .check()?;
        Ok(Some(record.sam_account_name))
    }

    /// Upsert a replicated AD **group** by its `objectSid` (hex): its name, RID, and
    /// members (each member's `objectSid`, hex). Replaces any existing record for the
    /// same SID, so re-applying a replication page is idempotent.
    ///
    /// # Errors
    /// A store error.
    pub async fn upsert_ad_group(
        &self,
        sam_account_name: &str,
        rid: u32,
        sid_hex: &str,
        member_sids_hex: &[String],
    ) -> DbResult<()> {
        // A locally created group: each present member is a self-originated, version-1
        // link (so it replicates out with a real origin the peer can conflict-resolve).
        let dsa = self.dsa_invocation_id().await?;
        let now = chrono::Utc::now().timestamp();
        let mut member_links = Vec::with_capacity(member_sids_hex.len());
        for member_sid in member_sids_hex {
            let usn = self.allocate_usn().await?;
            member_links.push(StoredLink {
                member_sid: member_sid.clone(),
                present: true,
                version: 1,
                originating_dsa: dsa.to_vec(),
                originating_usn: usn,
                originating_time: now,
            });
        }
        self.inner
            .query("DELETE ad_group WHERE sid = $s")
            .bind(("s", sid_hex.to_string()))
            .await?;
        let record = AdGroupRecord {
            id: None,
            sam_account_name: sam_account_name.to_string(),
            rid,
            sid: sid_hex.to_string(),
            member_links,
        };
        let _: Option<AdGroupRecord> = self.inner.create("ad_group").content(record).await?;
        Ok(())
    }

    /// Apply one replicated AD group (Tier C item 5c): upsert it AND record its remote
    /// origin stamp atomically, keyed by the group's SID hex (so it dampens/converges
    /// like a replicated principal). The counterpart of [`Self::apply_replicated_principal`].
    ///
    /// # Errors
    /// A store error (rolls back).
    pub async fn apply_replicated_group(
        &self,
        sam_account_name: &str,
        rid: u32,
        sid_hex: &str,
        incoming: &[IncomingLink],
        remote_stamp: &crate::replication::ReplStamp,
    ) -> DbResult<()> {
        use crate::replication::ReplStamp;
        let to16 = |b: &[u8]| -> [u8; 16] {
            let mut o = [0u8; 16];
            let n = b.len().min(16);
            o[..n].copy_from_slice(&b[..n]);
            o
        };
        // Merge each incoming link into the stored links PER LINK (MS-DRSR §5.166): a
        // link's present/absent state is taken only if the incoming stamp wins, so a
        // member removal (absent link) survives, and concurrent add-on-A / remove-on-B of
        // DIFFERENT members both apply — the core of item 5d.
        let existing = self.read_group_links(sid_hex).await?;
        let mut by_member: std::collections::HashMap<String, StoredLink> = existing
            .into_iter()
            .map(|l| (l.member_sid.clone(), l))
            .collect();
        for inc in incoming {
            let inc_stamp = ReplStamp {
                version: inc.version,
                originating_time: inc.originating_time,
                originating_dsa: inc.originating_dsa,
                originating_usn: inc.originating_usn,
                local_usn: 0,
            };
            let take = match by_member.get(&inc.member_sid) {
                Some(cur) => inc_stamp.wins_over(&ReplStamp {
                    version: cur.version,
                    originating_time: cur.originating_time,
                    originating_dsa: to16(&cur.originating_dsa),
                    originating_usn: cur.originating_usn,
                    local_usn: 0,
                }),
                None => true,
            };
            if take {
                by_member.insert(
                    inc.member_sid.clone(),
                    StoredLink {
                        member_sid: inc.member_sid.clone(),
                        present: inc.present,
                        version: inc.version,
                        originating_dsa: inc.originating_dsa.to_vec(),
                        originating_usn: inc.originating_usn,
                        originating_time: inc.originating_time,
                    },
                );
            }
        }
        let mut member_links: Vec<StoredLink> = by_member.into_values().collect();
        member_links.sort_by(|a, b| a.member_sid.cmp(&b.member_sid)); // deterministic
                                                                      // The group OBJECT stamp must NOT regress on a link-only change (a membership edit
                                                                      // doesn't bump the object version): keep the existing stamp unless the incoming
                                                                      // object stamp actually wins. Links above merge independently, per link.
        let stamp = match self.repl_stamp(sid_hex).await? {
            Some(cur) if !remote_stamp.wins_over(&cur) => cur,
            _ => {
                let local_usn = self.allocate_usn().await?;
                ReplStamp {
                    local_usn,
                    ..remote_stamp.clone()
                }
            }
        };
        let group = AdGroupRecord {
            id: None,
            sam_account_name: sam_account_name.to_string(),
            rid,
            sid: sid_hex.to_string(),
            member_links,
        };
        self.write_group_stamped(group, sid_hex, &stamp).await
    }

    /// Locally add (`present=true`) or remove (`present=false`) a member of the group
    /// with SID `sid_hex`, stamping the LINK as a self-originated change with a bumped
    /// version — so the add/removal replicates out and wins over a peer's prior link
    /// state (Tier C item 5e). A removal keeps the member as an absent tombstone. The
    /// group OBJECT stamp is untouched (a membership edit is a link-only change).
    ///
    /// # Errors
    /// [`DbError::NotFound`] if no such group exists, or a store error.
    pub async fn set_group_member_local(
        &self,
        sid_hex: &str,
        member_sid_hex: &str,
        present: bool,
    ) -> DbResult<()> {
        use crate::replication::ReplStamp;
        let mut resp = self
            .inner
            .query("SELECT * FROM ad_group WHERE sid = $s LIMIT 1")
            .bind(("s", sid_hex.to_string()))
            .await?;
        let rec: Option<AdGroupRecord> = match resp.take(0) {
            Ok(r) => r,
            Err(e) if e.to_string().contains("does not exist") => None,
            Err(e) => return Err(e.into()),
        };
        let mut rec = rec.ok_or(DbError::NotFound)?;

        let dsa = self.dsa_invocation_id().await?;
        let usn = self.allocate_usn().await?;
        let now = chrono::Utc::now().timestamp();
        let version = rec
            .member_links
            .iter()
            .find(|l| l.member_sid == member_sid_hex)
            .map(|l| l.version + 1)
            .unwrap_or(1);
        let link = StoredLink {
            member_sid: member_sid_hex.to_string(),
            present,
            version,
            originating_dsa: dsa.to_vec(),
            originating_usn: usn,
            originating_time: now,
        };
        match rec
            .member_links
            .iter_mut()
            .find(|l| l.member_sid == member_sid_hex)
        {
            Some(l) => *l = link,
            None => rec.member_links.push(link),
        }
        rec.member_links
            .sort_by(|a, b| a.member_sid.cmp(&b.member_sid));

        // Keep the existing OBJECT stamp (a link-only change); self/v1 if the group had none.
        let obj_stamp = self.repl_stamp(sid_hex).await?.unwrap_or(ReplStamp {
            version: 1,
            originating_time: now,
            originating_dsa: dsa,
            originating_usn: usn,
            local_usn: usn,
        });
        let group = AdGroupRecord {
            id: None,
            sam_account_name: rec.sam_account_name,
            rid: rec.rid,
            sid: rec.sid,
            member_links: rec.member_links,
        };
        self.write_group_stamped(group, sid_hex, &obj_stamp).await
    }

    /// List all replicated AD groups and their memberships (member `objectSid`s, hex).
    ///
    /// # Errors
    /// A store error.
    pub async fn list_ad_groups(&self) -> DbResult<Vec<AdGroup>> {
        let mut resp = self.inner.query("SELECT * FROM ad_group").await?;
        // A table that has never been written does not exist yet in SurrealDB and a
        // SELECT over it errors; for a read path that simply means "none yet" (a DC
        // whose upstream has no custom groups, or a principal-only replica), so treat
        // the missing table as an empty result rather than failing DC startup.
        let records: Vec<AdGroupRecord> = match resp.take(0) {
            Ok(r) => r,
            Err(e) if e.to_string().contains("does not exist") => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(records
            .into_iter()
            .map(|r| {
                let member_sids = r
                    .member_links
                    .iter()
                    .filter(|l| l.present)
                    .map(|l| l.member_sid.clone())
                    .collect();
                AdGroup {
                    sam_account_name: r.sam_account_name,
                    rid: r.rid,
                    sid: r.sid,
                    member_sids,
                    member_links: r.member_links,
                }
            })
            .collect())
    }

    /// The stored membership links (present + absent) of the group with SID `sid_hex`.
    async fn read_group_links(&self, sid_hex: &str) -> DbResult<Vec<StoredLink>> {
        let mut resp = self
            .inner
            .query("SELECT * FROM ad_group WHERE sid = $s LIMIT 1")
            .bind(("s", sid_hex.to_string()))
            .await?;
        let rec: Option<AdGroupRecord> = match resp.take(0) {
            Ok(r) => r,
            Err(e) if e.to_string().contains("does not exist") => None,
            Err(e) => return Err(e.into()),
        };
        Ok(rec.map(|r| r.member_links).unwrap_or_default())
    }

    /// Fetch one AD group by `sam_account_name` (case-insensitive), or `None`. Used by
    /// the Web group paths to reuse an existing group's RID/SID and mutate its members.
    ///
    /// # Errors
    /// A store error.
    pub async fn get_ad_group(&self, sam_account_name: &str) -> DbResult<Option<AdGroup>> {
        let mut resp = self
            .inner
            .query("SELECT * FROM ad_group WHERE string::lowercase(sam_account_name) = string::lowercase($s) LIMIT 1")
            .bind(("s", sam_account_name.to_string()))
            .await?;
        let records: Vec<AdGroupRecord> = match resp.take(0) {
            Ok(r) => r,
            Err(e) if e.to_string().contains("does not exist") => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(records.into_iter().next().map(|r| {
            let member_sids = r
                .member_links
                .iter()
                .filter(|l| l.present)
                .map(|l| l.member_sid.clone())
                .collect();
            AdGroup {
                sam_account_name: r.sam_account_name,
                rid: r.rid,
                sid: r.sid,
                member_sids,
                member_links: r.member_links,
            }
        }))
    }

    /// The persisted domain SID sub-authorities (e.g. `[21, 1, 2, 3]` for
    /// `S-1-5-21-1-2-3`), or `None` if none has been seeded. This is the single source
    /// of truth shared across processes over the DB, so the KDC / SAMR / LDAP / netlogon
    /// paths all agree on one domain identity.
    ///
    /// # Errors
    /// A store error.
    pub async fn get_domain_sid(&self) -> DbResult<Option<Vec<u32>>> {
        let mut resp = self
            .inner
            .query("SELECT * FROM domain_sid_state LIMIT 1")
            .await?;
        let recs: Vec<DomainSidRecord> = match resp.take(0) {
            Ok(r) => r,
            Err(e) if e.to_string().contains("does not exist") => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(recs.into_iter().next().map(|r| r.subauth))
    }

    /// Seed the domain SID sub-authorities on first run, returning the effective value.
    /// The persisted value wins, so a later config change cannot silently re-SID a live
    /// domain (mirrors [`Self::ensure_ldap_base`]).
    ///
    /// # Errors
    /// A store error.
    pub async fn ensure_domain_sid(&self, subauth: &[u32], actor: &str) -> DbResult<Vec<u32>> {
        if let Some(existing) = self.get_domain_sid().await? {
            return Ok(existing);
        }
        self.set_domain_sid(subauth, actor).await?;
        Ok(subauth.to_vec())
    }

    /// Force-set the domain SID sub-authorities (singleton upsert). Used by the
    /// `DOMAIN_SID` override, which must win over any previously seeded value.
    ///
    /// # Errors
    /// A store error.
    pub async fn set_domain_sid(&self, subauth: &[u32], actor: &str) -> DbResult<()> {
        // Replace any existing singleton (the table exists once it has been written; the
        // DELETE is skipped on a fresh store where the table does not exist yet).
        if self.get_domain_sid().await?.is_some() {
            self.inner.query("DELETE domain_sid_state").await?;
        }
        let rec = DomainSidRecord {
            id: None,
            subauth: subauth.to_vec(),
            updated_by: actor.to_string(),
        };
        let _: Option<DomainSidRecord> = self.inner.create("domain_sid_state").content(rec).await?;
        Ok(())
    }
}

/// Singleton record holding the domain SID sub-authorities (`[21, 1, 2, 3]` for
/// `S-1-5-21-1-2-3`) — the domain identity shared across every AD DC interface.
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub(crate) struct DomainSidRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<RecordId>,
    pub subauth: Vec<u32>,
    pub updated_by: String,
}

/// On-disk replicated AD group record: keyed by `objectSid` (hex), with member SIDs.
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub(crate) struct AdGroupRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<RecordId>,
    pub sam_account_name: String,
    pub rid: u32,
    pub sid: String,
    /// The full per-link membership state (present + absent tombstones), each with its
    /// own origin stamp — enables member-removal replication and per-link conflict
    /// resolution (Tier C item 5d).
    #[serde(default)]
    pub member_links: Vec<StoredLink>,
}

/// One stored group membership link with its per-link replication state. `present`
/// distinguishes a current membership from a removed-member tombstone; the stamp fields
/// (`version`/DSA/USN/`time`, time in internal Unix seconds) drive conflict resolution.
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub struct StoredLink {
    pub member_sid: String,
    pub present: bool,
    pub version: u32,
    pub originating_dsa: Vec<u8>,
    pub originating_usn: i64,
    pub originating_time: i64,
}

/// An incoming replicated group link to merge (the apply→store boundary). `originating_time`
/// is Unix seconds (converted from the wire `DSTIME` by the caller).
#[derive(Debug, Clone)]
pub struct IncomingLink {
    pub member_sid: String,
    pub present: bool,
    pub version: u32,
    pub originating_dsa: [u8; 16],
    pub originating_usn: i64,
    pub originating_time: i64,
}

/// A replicated AD group: its name/RID/SID and the `objectSid`s of its members.
#[derive(Debug, Clone)]
pub struct AdGroup {
    /// The group's `sAMAccountName`.
    pub sam_account_name: String,
    /// The group RID.
    pub rid: u32,
    /// The group's `objectSid`, hex-encoded.
    pub sid: String,
    /// The `objectSid` (hex) of each PRESENT member (derived from [`Self::member_links`]).
    pub member_sids: Vec<String>,
    /// The full per-link membership state (present + absent tombstones) with stamps.
    pub member_links: Vec<StoredLink>,
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_db() -> (Db, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        (db, dir)
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[tokio::test]
    async fn upsert_ad_group_stores_membership_and_is_idempotent_by_sid() {
        let (db, _dir) = test_db().await;
        let sid = "0105000000000005150000000102030400020000"; // ...-512 (Domain Admins)
        let admin = "010500000000000515000000010203041f010000"; // ...-500 (Administrator)
        db.upsert_ad_group("Domain Admins", 512, sid, &[admin.to_string()])
            .await
            .unwrap();

        let groups = db.list_ad_groups().await.unwrap();
        let g = groups.iter().find(|g| g.sid == sid).expect("group stored");
        assert_eq!(g.sam_account_name, "Domain Admins");
        assert_eq!(g.rid, 512);
        assert_eq!(g.member_sids, vec![admin.to_string()]);

        // Re-applying (same SID) replaces, not duplicates — idempotent replication.
        db.upsert_ad_group("Domain Admins", 512, sid, &[admin.to_string()])
            .await
            .unwrap();
        assert_eq!(
            db.list_ad_groups()
                .await
                .unwrap()
                .iter()
                .filter(|g| g.sid == sid)
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn tombstone_delete_removes_principal_by_rid_and_group_by_sid() {
        let (db, _dir) = test_db().await;
        // A replicated user (matched on delete by its retained RID, not sAMAccountName).
        db.upsert_ad_principal_with_hash(
            "dave",
            1200,
            "pw",
            &[1u8; 16],
            Some(&[2u8; 32]),
            "EXAMPLE.COM",
        )
        .await
        .unwrap();
        assert!(db
            .list_ad_principals()
            .await
            .unwrap()
            .iter()
            .any(|p| p.rid == 1200));

        let removed = db.delete_replicated_principal(1200).await.unwrap();
        assert_eq!(removed.as_deref(), Some("dave"));
        assert!(!db
            .list_ad_principals()
            .await
            .unwrap()
            .iter()
            .any(|p| p.rid == 1200));
        // Deleting a RID no principal holds is a no-op (returns None).
        assert_eq!(db.delete_replicated_principal(1200).await.unwrap(), None);

        // A replicated group (matched on delete by its retained objectSid).
        let sid = "0105000000000005150000000102030400040000"; // ...-1028
        db.upsert_ad_group("Eng", 1028, sid, &[]).await.unwrap();
        assert!(db
            .list_ad_groups()
            .await
            .unwrap()
            .iter()
            .any(|g| g.sid == sid));
        let removed = db.delete_replicated_group(sid).await.unwrap();
        assert_eq!(removed.as_deref(), Some("Eng"));
        assert!(!db
            .list_ad_groups()
            .await
            .unwrap()
            .iter()
            .any(|g| g.sid == sid));
        assert_eq!(db.delete_replicated_group(sid).await.unwrap(), None);
    }

    #[tokio::test]
    async fn reserve_rid_block_hands_out_disjoint_climbing_blocks() {
        let (db, _dir) = test_db().await;
        // Successive reservations are contiguous and never overlap; `first` seeds the
        // pool only on the first call.
        assert_eq!(db.reserve_rid_block(1100, 100).await.unwrap(), 1100); // [1100,1200)
        assert_eq!(db.reserve_rid_block(1100, 100).await.unwrap(), 1200); // [1200,1300)
        assert_eq!(db.reserve_rid_block(1100, 50).await.unwrap(), 1300); //  [1300,1350)
        assert_eq!(db.reserve_rid_block(9999, 10).await.unwrap(), 1350); //  first ignored
                                                                         // The counter is persisted, so a fresh handle to the same store continues.
        assert_eq!(db.reserve_rid_block(1100, 1).await.unwrap(), 1360);
    }

    #[tokio::test]
    async fn ad_principal_stores_reversible_key_material() {
        let (db, _dir) = test_db().await;
        db.create_ad_principal("alice", 1000, "password12", "EXAMPLE.COM")
            .await
            .unwrap();
        db.create_ad_principal("bob", 1001, "bobpass123", "EXAMPLE.COM")
            .await
            .unwrap();

        let mut principals = db.list_ad_principals().await.unwrap();
        principals.sort_by_key(|p| p.rid);
        assert_eq!(principals.len(), 2);

        let alice = &principals[0];
        assert_eq!(alice.sam_account_name, "alice");
        assert_eq!(alice.rid, 1000);
        // NT hash is MD4(UTF16LE("password12")).
        assert_eq!(hex(&alice.nt_hash), "1b62018f0d05c737d06402294ce24236");
        // The Kerberos AES256 key is 32 bytes and matches the KDC's own derivation
        // (so a ticket the KDC mints verifies against this stored key).
        assert_eq!(alice.kerberos_key.len(), 32);
        assert_eq!(
            alice.kerberos_key,
            derive_aes256_key(
                "password12",
                &default_salt("EXAMPLE.COM", &["alice".to_string()])
            )
            .unwrap()
        );
        assert_eq!(principals[1].sam_account_name, "bob");
    }

    #[tokio::test]
    async fn upsert_replaces_key_material_for_an_existing_name() {
        let (db, _dir) = test_db().await;
        // First create with an initial password, then repassword the same account.
        db.upsert_ad_principal("PC$", 1100, "initialpw", "EXAMPLE.COM")
            .await
            .unwrap();
        db.upsert_ad_principal("PC$", 1100, "N3wPass!", "EXAMPLE.COM")
            .await
            .unwrap();

        let principals = db.list_ad_principals().await.unwrap();
        let pc: Vec<_> = principals
            .iter()
            .filter(|p| p.sam_account_name == "PC$")
            .collect();
        assert_eq!(pc.len(), 1, "no duplicate after upsert");
        // The stored key matches the NEW password.
        assert_eq!(
            pc[0].kerberos_key,
            derive_aes256_key(
                "N3wPass!",
                &default_salt("EXAMPLE.COM", &["PC$".to_string()])
            )
            .unwrap()
        );
    }

    #[tokio::test]
    async fn local_writes_climb_the_replication_version() {
        let (db, _dir) = test_db().await;
        // A local create stamps version 1, originated by THIS DSA.
        db.create_ad_principal("alice", 1000, "password12", "EXAMPLE.COM")
            .await
            .unwrap();
        let s1 = db
            .repl_stamp("alice")
            .await
            .unwrap()
            .expect("a local create is stamped");
        assert_eq!(s1.version, 1);
        assert_eq!(
            s1.originating_dsa,
            db.dsa_invocation_id().await.unwrap(),
            "a local change is originated by this DSA"
        );

        // A local edit (repassword) bumps the version and takes a fresh USN, so it wins
        // over the prior value on a replication peer (Tier C item 2).
        db.upsert_ad_principal("alice", 1000, "N3wPass!", "EXAMPLE.COM")
            .await
            .unwrap();
        let s2 = db
            .repl_stamp("alice")
            .await
            .unwrap()
            .expect("still stamped after an edit");
        assert_eq!(s2.version, 2, "version climbs on a local edit");
        assert!(
            s2.originating_usn > s1.originating_usn,
            "each originating write takes a fresh USN"
        );
        assert!(
            s2.wins_over(&s1),
            "the newer version wins conflict resolution"
        );
    }

    #[tokio::test]
    async fn local_write_commits_object_and_stamp_atomically() {
        let (db, _dir) = test_db().await;
        let dave_count =
            |ps: &[AdPrincipal]| ps.iter().filter(|p| p.sam_account_name == "dave").count();

        // A single write commits BOTH the object and its stamp (one transaction).
        db.create_ad_principal("dave", 1300, "pw1", "EXAMPLE.COM")
            .await
            .unwrap();
        assert_eq!(
            dave_count(&db.list_ad_principals().await.unwrap()),
            1,
            "object present"
        );
        assert_eq!(
            db.repl_stamp("dave").await.unwrap().unwrap().version,
            1,
            "stamp committed together with the object"
        );

        // An edit atomically REPLACES both: still exactly one object (no orphan), and the
        // stamp advanced — proving the DELETE+CREATE on both tables ran in one unit.
        db.upsert_ad_principal("dave", 1300, "pw2", "EXAMPLE.COM")
            .await
            .unwrap();
        assert_eq!(
            dave_count(&db.list_ad_principals().await.unwrap()),
            1,
            "no orphaned object record"
        );
        assert_eq!(
            db.repl_stamp("dave").await.unwrap().unwrap().version,
            2,
            "stamp updated in the same transaction as the object"
        );
    }

    #[tokio::test]
    async fn group_membership_merges_per_link_with_tombstones() {
        use crate::replication::ReplStamp;
        let (db, _dir) = test_db().await;
        let sid_hex = |rid: u32| -> String {
            let mut v = vec![1u8, 5, 0, 0, 0, 0, 0, 5];
            for s in [21u32, 1, 2, 3, rid] {
                v.extend_from_slice(&s.to_le_bytes());
            }
            v.iter().map(|x| format!("{x:02x}")).collect()
        };
        let (grp, alice, bob, carol) = (sid_hex(1200), sid_hex(1000), sid_hex(1001), sid_hex(1002));
        let a_dsa = [0xAAu8; 16];
        let b_dsa = [0xBBu8; 16];
        let gstamp = ReplStamp {
            version: 1,
            originating_time: 100,
            originating_dsa: a_dsa,
            originating_usn: 1,
            local_usn: 0,
        };
        let link = |sid: &str, present: bool, ver: u32, dsa: [u8; 16]| IncomingLink {
            member_sid: sid.to_string(),
            present,
            version: ver,
            originating_dsa: dsa,
            originating_usn: ver as i64,
            originating_time: 100,
        };
        let present_of = |g: &AdGroup| -> Vec<String> {
            let mut m = g.member_sids.clone();
            m.sort();
            m
        };
        async fn load(db: &Db, grp: &str) -> AdGroup {
            db.list_ad_groups()
                .await
                .unwrap()
                .into_iter()
                .find(|g| g.sid == grp)
                .unwrap()
        }

        // A originates the group with {alice, bob} present (v1@A).
        db.apply_replicated_group(
            "Eng",
            1200,
            &grp,
            &[link(&alice, true, 1, a_dsa), link(&bob, true, 1, a_dsa)],
            &gstamp,
        )
        .await
        .unwrap();
        // A adds carol (v1@A); B removes bob (absent, v2@B — a higher version wins).
        db.apply_replicated_group("Eng", 1200, &grp, &[link(&carol, true, 1, a_dsa)], &gstamp)
            .await
            .unwrap();
        db.apply_replicated_group("Eng", 1200, &grp, &[link(&bob, false, 2, b_dsa)], &gstamp)
            .await
            .unwrap();

        let g = load(&db, &grp).await;
        assert_eq!(
            present_of(&g),
            vec![alice.clone(), carol.clone()],
            "add + remove of DIFFERENT members both applied"
        );
        assert!(
            g.member_links
                .iter()
                .any(|l| l.member_sid == bob && !l.present),
            "bob remains as an absent tombstone"
        );

        // A stale re-add of bob (v1@A) must NOT resurrect him — the v2 removal wins.
        db.apply_replicated_group("Eng", 1200, &grp, &[link(&bob, true, 1, a_dsa)], &gstamp)
            .await
            .unwrap();
        let g2 = load(&db, &grp).await;
        assert_eq!(
            present_of(&g2),
            vec![alice, carol],
            "a stale, lower-version re-add did not resurrect bob"
        );
    }

    #[tokio::test]
    async fn domain_sid_is_a_seed_once_singleton_that_the_override_replaces() {
        let (db, _tmp) = test_db().await;

        // A fresh store has no domain SID (the table does not exist yet).
        assert_eq!(db.get_domain_sid().await.unwrap(), None);

        // First seed wins; a second seed does NOT overwrite it (persisted value stays).
        assert_eq!(
            db.ensure_domain_sid(&[21, 1, 2, 3], "system")
                .await
                .unwrap(),
            vec![21, 1, 2, 3]
        );
        assert_eq!(
            db.ensure_domain_sid(&[21, 9, 9, 9], "system")
                .await
                .unwrap(),
            vec![21, 1, 2, 3],
            "ensure is seed-once: the persisted value wins over a later config change"
        );
        assert_eq!(db.get_domain_sid().await.unwrap(), Some(vec![21, 1, 2, 3]));

        // The explicit override (DOMAIN_SID) replaces it, and stays a singleton.
        db.set_domain_sid(&[21, 111, 222, 333], "system")
            .await
            .unwrap();
        assert_eq!(
            db.get_domain_sid().await.unwrap(),
            Some(vec![21, 111, 222, 333])
        );
    }

    #[tokio::test]
    async fn get_ad_group_reads_back_a_locally_upserted_group() {
        let (db, _tmp) = test_db().await;
        assert!(db.get_ad_group("Eng").await.unwrap().is_none());

        let sid = "0105000000000005150000001500000058020000"; // arbitrary hex objectSid
        db.upsert_ad_group("Eng", 1200, sid, &[]).await.unwrap();

        let g = db
            .get_ad_group("eng")
            .await
            .unwrap()
            .expect("group present");
        assert_eq!(g.sam_account_name, "Eng");
        assert_eq!(g.rid, 1200);
        assert_eq!(g.sid, sid);
    }

    #[tokio::test]
    async fn disabled_ad_principal_is_not_logon_able_but_keeps_its_rid() {
        let (db, _tmp) = test_db().await;
        // A password-less LDAP import creates a DISABLED, credential-less placeholder.
        db.create_disabled_ad_principal("bob", 1234).await.unwrap();
        let p = db.get_ad_principal("bob").await.unwrap().expect("present");
        assert_eq!(
            p.rid, 1234,
            "RID preserved for group membership + later activation"
        );
        assert!(p.disabled, "must be disabled (the KDC seed skips it)");
        assert!(
            p.kerberos_key.is_empty(),
            "no usable Kerberos key (skipped on the empty-key gate too)"
        );

        // Setting a password later activates it, reusing the SAME RID.
        db.upsert_ad_principal("bob", p.rid, "RealPass123", "EXAMPLE.COM")
            .await
            .unwrap();
        let e = db.get_ad_principal("bob").await.unwrap().expect("present");
        assert!(!e.disabled, "a password set enables the account");
        assert!(
            !e.kerberos_key.is_empty(),
            "and derives a real Kerberos key"
        );
        assert_eq!(e.rid, 1234, "the RID is unchanged after activation");
    }
}
