//! Directory-replication metadata — the persistent state a DC needs to be a real
//! replication partner (MS-DRSR), the Tier C foundation. Tier B shares one store so
//! there is nothing to replicate; Tier C gives each DC its own store that converges
//! with others, and convergence needs three durable things this module owns:
//!
//! * a stable **DSA invocation ID** (this store's replication identity — it must
//!   survive restarts, or a partner sees the USN counter jump backwards and treats
//!   it as a rolled-back/​restored DC);
//! * a monotonic **USN** counter (every originating change gets a higher one, so a
//!   partner can ask "everything above USN N");
//! * per-object **replication stamps** (version + originating DSA/USN/time) and an
//!   **up-to-dateness vector** (per-DSA high-water marks) so conflicts resolve
//!   deterministically and already-seen changes are not re-sent.
//!
//! This is the DB layer only; `magnetite-rpc`'s DRSUAPI source is handed the
//! invocation ID + UTDV to report (inversion of control — the RPC crate stays free
//! of a DB dependency).

use crate::error::{DbError, DbResult};
use crate::store::Db;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use surrealdb::types::{RecordId, SurrealValue};
use uuid::Uuid;

/// This DSA's durable replication state: its invocation ID and the highest USN it
/// has ever handed out. A single record (`dsa_state:main`).
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct DsaStateRecord {
    id: Option<RecordId>,
    /// 16-byte DSA invocation ID (a v4 UUID), stable across restarts.
    invocation_id: Vec<u8>,
    /// Highest USN allocated so far (monotonic; AD USNs are `i64`).
    highest_usn: i64,
}

/// A per-object replication stamp (MS-ADTS metadata): who last originated the
/// change and when, used to resolve conflicts deterministically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplStamp {
    /// Bumps on every originating write; the primary conflict tiebreaker.
    pub version: u32,
    /// Originating time (Unix seconds) — the second tiebreaker.
    pub originating_time: i64,
    /// The invocation ID of the DSA where the change originated.
    pub originating_dsa: [u8; 16],
    /// The originating DSA's USN for this change.
    pub originating_usn: i64,
    /// This DSA's local USN for the change (its position in *our* stream).
    pub local_usn: i64,
}

impl ReplStamp {
    /// Whether a change stamped with `self` should overwrite one already held with
    /// stamp `other` (MS-DRSR §5.166 conflict resolution): the higher `version` wins;
    /// on a tie the later `originating_time` wins; on a further tie the higher
    /// `originating_dsa` wins. `local_usn`/`originating_usn` are not tiebreakers. An
    /// identical stamp does not win, so re-applying the same change is idempotent.
    pub fn wins_over(&self, other: &ReplStamp) -> bool {
        (self.version, self.originating_time, self.originating_dsa)
            > (other.version, other.originating_time, other.originating_dsa)
    }
}

/// One up-to-dateness-vector cursor: "I hold every change originated by `dsa` up to
/// `high_usn`." A destination sends its UTDV so the source can skip changes the
/// destination already has (from any replication path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtdvCursor {
    /// The originating DSA's invocation ID.
    pub dsa: [u8; 16],
    /// The highest originating USN from `dsa` that is held.
    pub high_usn: i64,
    /// Time of last successful sync from `dsa` (Unix seconds; 0 if never).
    pub last_sync: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct ReplMetadataRecord {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<RecordId>,
    object_key: String,
    version: u32,
    originating_time: i64,
    originating_dsa: Vec<u8>,
    originating_usn: i64,
    local_usn: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
struct ReplCursorRecord {
    id: Option<RecordId>,
    /// The DSA invocation ID as a lowercase hex string — a string key indexes and
    /// compares cleanly, unlike a raw bytes column.
    dsa: String,
    high_usn: i64,
    last_sync: i64,
}

fn to_uuid16(bytes: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let n = bytes.len().min(16);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

/// Lowercase hex of a 16-byte DSA invocation ID (the repl-cursor key).
fn dsa_hex(dsa: &[u8; 16]) -> String {
    dsa.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a 32-char lowercase-hex DSA key back to 16 bytes (0 on malformed).
fn dsa_from_hex(s: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, chunk) in s.as_bytes().chunks(2).take(16).enumerate() {
        if let Ok(h) = std::str::from_utf8(chunk) {
            out[i] = u8::from_str_radix(h, 16).unwrap_or(0);
        }
    }
    out
}

impl Db {
    /// This store's DSA invocation ID, creating it (a fresh v4 UUID) on first use and
    /// returning the same value forever after. Stable across restarts so replication
    /// partners never see a USN rollback.
    ///
    /// # Errors
    /// A store error.
    pub async fn dsa_invocation_id(&self) -> DbResult<[u8; 16]> {
        if let Some(state) = self.read_dsa_state().await? {
            return Ok(to_uuid16(&state.invocation_id));
        }
        // First use: mint and persist. A racing create simply loses (the unique
        // singleton id makes the second CREATE fail); re-read to get the winner.
        let id = Uuid::new_v4().into_bytes().to_vec();
        let _ = self
            .inner
            .query("CREATE dsa_state:main SET invocation_id = $id, highest_usn = 0")
            .bind(("id", id))
            .await;
        self.read_dsa_state()
            .await?
            .map(|s| to_uuid16(&s.invocation_id))
            .ok_or_else(|| DbError::Constraint("dsa_state not created".into()))
    }

    async fn read_dsa_state(&self) -> DbResult<Option<DsaStateRecord>> {
        Ok(self
            .inner
            .query("SELECT * FROM dsa_state:main")
            .await?
            .take(0)?)
    }

    /// Atomically allocate the next USN (the previous highest + 1), advancing the
    /// persistent counter. Monotonic across restarts and serialised by the store, so
    /// concurrent front-ends on a shared store never hand out the same USN.
    ///
    /// # Errors
    /// A store error.
    pub async fn allocate_usn(&self) -> DbResult<i64> {
        // Ensure the singleton exists (mints the invocation ID too on first use).
        self.dsa_invocation_id().await?;
        let after: Option<DsaStateRecord> = self
            .inner
            .query("UPDATE dsa_state:main SET highest_usn = highest_usn + 1 RETURN AFTER")
            .await?
            .take(0)?;
        after
            .map(|s| s.highest_usn)
            .ok_or_else(|| DbError::Constraint("dsa_state missing on USN allocation".into()))
    }

    /// The current highest allocated USN (0 before any allocation).
    ///
    /// # Errors
    /// A store error.
    pub async fn highest_usn(&self) -> DbResult<i64> {
        Ok(self
            .read_dsa_state()
            .await?
            .map(|s| s.highest_usn)
            .unwrap_or(0))
    }

    /// Record a **local** originating change to `object_key`: bump its version,
    /// allocate a fresh USN, and stamp it with this DSA as the originator. Returns the
    /// new stamp. This is what an LDAP/SAMR write will call so the change is
    /// replicable; a *remote* change instead carries its origin stamp (Tier C C1).
    ///
    /// # Errors
    /// A store error.
    pub async fn stamp_local_change(&self, object_key: &str) -> DbResult<ReplStamp> {
        let stamp = self.next_local_stamp(object_key).await?;
        self.write_repl_metadata(object_key, &stamp).await?;
        Ok(stamp)
    }

    /// Compute (but do not persist) the stamp a local originating change to `object_key`
    /// would receive: version = prior + 1 (or 1), this DSA, a freshly allocated USN, now.
    /// Split out so a principal write can commit the object AND this stamp in one
    /// transaction (see [`Self::write_principal_stamped`]).
    ///
    /// # Errors
    /// A store error.
    pub(crate) async fn next_local_stamp(&self, object_key: &str) -> DbResult<ReplStamp> {
        let dsa = self.dsa_invocation_id().await?;
        let usn = self.allocate_usn().await?;
        let now = Utc::now().timestamp();
        let prev = self.read_repl_metadata(object_key).await?;
        let version = prev.map(|m| m.version + 1).unwrap_or(1);
        Ok(ReplStamp {
            version,
            originating_time: now,
            originating_dsa: dsa,
            originating_usn: usn,
            local_usn: usn,
        })
    }

    /// Persist a principal record AND its replication stamp in ONE transaction, so a
    /// crash can never leave the object without a matching stamp — or with a stale one.
    /// The caller computes `stamp` first (local via [`Self::next_local_stamp`], or from a
    /// replicated source). All four statements commit atomically or roll back together.
    ///
    /// # Errors
    /// A store error (which rolls the transaction back).
    pub(crate) async fn write_principal_stamped(
        &self,
        principal: crate::ad::AdPrincipalRecord,
        stamp: &ReplStamp,
    ) -> DbResult<()> {
        let sam = principal.sam_account_name.clone();
        let meta = ReplMetadataRecord {
            id: None,
            object_key: sam.clone(),
            version: stamp.version,
            originating_time: stamp.originating_time,
            originating_dsa: stamp.originating_dsa.to_vec(),
            originating_usn: stamp.originating_usn,
            local_usn: stamp.local_usn,
        };
        self.inner
            .query(
                "BEGIN TRANSACTION; \
                 DELETE ad_principal WHERE sam_account_name = $sam; \
                 CREATE ad_principal CONTENT $principal; \
                 DELETE repl_metadata WHERE object_key = $sam; \
                 CREATE repl_metadata CONTENT $meta; \
                 COMMIT TRANSACTION;",
            )
            .bind(("sam", sam))
            .bind(("principal", principal))
            .bind(("meta", meta))
            .await?
            .check()?;
        Ok(())
    }

    /// Persist a group record AND its replication stamp (keyed by `object_key`, the
    /// group's SID hex) in ONE transaction — the group counterpart of
    /// [`Self::write_principal_stamped`], so a group and its origin stamp commit together.
    ///
    /// # Errors
    /// A store error (which rolls the transaction back).
    pub(crate) async fn write_group_stamped(
        &self,
        group: crate::ad::AdGroupRecord,
        object_key: &str,
        stamp: &ReplStamp,
    ) -> DbResult<()> {
        let sid = group.sid.clone();
        let meta = ReplMetadataRecord {
            id: None,
            object_key: object_key.to_string(),
            version: stamp.version,
            originating_time: stamp.originating_time,
            originating_dsa: stamp.originating_dsa.to_vec(),
            originating_usn: stamp.originating_usn,
            local_usn: stamp.local_usn,
        };
        self.inner
            .query(
                "BEGIN TRANSACTION; \
                 DELETE ad_group WHERE sid = $sid; \
                 CREATE ad_group CONTENT $group; \
                 DELETE repl_metadata WHERE object_key = $key; \
                 CREATE repl_metadata CONTENT $meta; \
                 COMMIT TRANSACTION;",
            )
            .bind(("sid", sid))
            .bind(("group", group))
            .bind(("key", object_key.to_string()))
            .bind(("meta", meta))
            .await?
            .check()?;
        Ok(())
    }

    /// The replication stamp for `object_key`, or `None` if it has never been
    /// stamped.
    ///
    /// # Errors
    /// A store error.
    pub async fn repl_stamp(&self, object_key: &str) -> DbResult<Option<ReplStamp>> {
        Ok(self
            .read_repl_metadata(object_key)
            .await?
            .map(|m| ReplStamp {
                version: m.version,
                originating_time: m.originating_time,
                originating_dsa: to_uuid16(&m.originating_dsa),
                originating_usn: m.originating_usn,
                local_usn: m.local_usn,
            }))
    }

    async fn read_repl_metadata(&self, object_key: &str) -> DbResult<Option<ReplMetadataRecord>> {
        Ok(self
            .inner
            .query("SELECT * FROM repl_metadata WHERE object_key = $k LIMIT 1")
            .bind(("k", object_key.to_string()))
            .await?
            .take(0)?)
    }

    async fn write_repl_metadata(&self, object_key: &str, stamp: &ReplStamp) -> DbResult<()> {
        self.inner
            .query("DELETE repl_metadata WHERE object_key = $k")
            .bind(("k", object_key.to_string()))
            .await?;
        let record = ReplMetadataRecord {
            id: None,
            object_key: object_key.to_string(),
            version: stamp.version,
            originating_time: stamp.originating_time,
            originating_dsa: stamp.originating_dsa.to_vec(),
            originating_usn: stamp.originating_usn,
            local_usn: stamp.local_usn,
        };
        let _: Option<ReplMetadataRecord> =
            self.inner.create("repl_metadata").content(record).await?;
        Ok(())
    }

    /// Apply one replicated AD principal received from a source DC (Tier C C1): upsert
    /// its `sam_account_name`/`rid`/`nt_hash` and record the remote origin stamp.
    /// `kerberos_key` is the account's AES256 key recovered from the replicated
    /// `supplementalCredentials`; pass it so the replicated user can authenticate via
    /// AES Kerberos (empty when the source sent no such key, leaving NTLM-only).
    /// `object_key` is the `sam_account_name`. The caller advances the source's UTDV
    /// cursor ([`record_cursor`](Self::record_cursor)) once per reply.
    ///
    /// # Errors
    /// A store error, or a key-material failure in the upsert.
    pub async fn apply_replicated_principal(
        &self,
        sam_account_name: &str,
        rid: u32,
        nt_hash: &[u8; 16],
        kerberos_key: &[u8],
        realm: &str,
        remote_stamp: &ReplStamp,
    ) -> DbResult<()> {
        // Keep the source's origin (version/DSA/USN/time) but take a fresh LOCAL USN so
        // the change also advances our own stream; commit the object and this stamp
        // atomically. The Kerberos key is stored verbatim (recovered from the replicated
        // supplementalCredentials, not derived from a password we don't have).
        let local_usn = self.allocate_usn().await?;
        let stamp = ReplStamp {
            local_usn,
            ..remote_stamp.clone()
        };
        let principal = crate::ad::AdPrincipalRecord {
            id: None,
            sam_account_name: sam_account_name.to_string(),
            rid,
            nt_hash: nt_hash.to_vec(),
            kerberos_key: kerberos_key.to_vec(),
            disabled: false,
        };
        let _ = realm; // key is stored verbatim; no per-realm derivation needed here
        self.write_principal_stamped(principal, &stamp).await
    }

    /// Read the stored principal record for `sam_account_name`, if any.
    async fn read_principal(
        &self,
        sam_account_name: &str,
    ) -> DbResult<Option<crate::ad::AdPrincipalRecord>> {
        let mut resp = self
            .inner
            .query("SELECT * FROM ad_principal WHERE sam_account_name = $s LIMIT 1")
            .bind(("s", sam_account_name.to_string()))
            .await?;
        match resp.take(0) {
            Ok(r) => Ok(r),
            Err(e) if e.to_string().contains("does not exist") => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Apply a replicated principal with **per-attribute** conflict resolution: the
    /// object identity (RID) converges on `object_stamp` while the **secret** (NT hash +
    /// Kerberos key, i.e. `unicodePwd`) converges on its own `secret_stamp`, stored under
    /// the attribute key `<sam>#unicodePwd`. So a newer local password is not clobbered by
    /// a replicated object whose *name* (or another attribute) is newer while its password
    /// is older — the realistic Samba-migration case, where a user's `sAMAccountName` and
    /// `unicodePwd` carry distinct originating stamps. Returns `true` if anything changed.
    ///
    /// # Errors
    /// A store error.
    #[allow(clippy::too_many_arguments)]
    pub async fn apply_replicated_principal_merged(
        &self,
        sam_account_name: &str,
        rid: u32,
        nt_hash: &[u8; 16],
        kerberos_key: &[u8],
        disabled: bool,
        realm: &str,
        object_stamp: &ReplStamp,
        secret_stamp: &ReplStamp,
    ) -> DbResult<bool> {
        let _ = realm; // keys stored verbatim; no per-realm derivation here
        let secret_key = format!("{sam_account_name}#unicodePwd");
        let current = self.read_principal(sam_account_name).await?;
        let cur_obj = self.repl_stamp(sam_account_name).await?;
        let cur_secret = self.repl_stamp(&secret_key).await?;

        let object_wins = cur_obj.as_ref().is_none_or(|c| object_stamp.wins_over(c));
        let secret_wins = cur_secret
            .as_ref()
            .is_none_or(|c| secret_stamp.wins_over(c));
        if !object_wins && !secret_wins {
            return Ok(false); // we already hold both attributes at a winning stamp
        }

        // Merge per attribute: take the incoming value only for the attribute whose
        // stamp wins; otherwise keep what we already hold. `disabled`
        // (`userAccountControl`) is an object-level attribute, so it converges with the
        // object stamp alongside the RID — a disable/enable upstream propagates.
        let final_rid = if object_wins {
            rid
        } else {
            current.as_ref().map_or(rid, |c| c.rid)
        };
        let final_disabled = if object_wins {
            disabled
        } else {
            current.as_ref().is_some_and(|c| c.disabled)
        };
        let (final_nt, final_kerb) = if secret_wins {
            (nt_hash.to_vec(), kerberos_key.to_vec())
        } else {
            current
                .as_ref()
                .map(|c| (c.nt_hash.clone(), c.kerberos_key.clone()))
                .unwrap_or_else(|| (nt_hash.to_vec(), kerberos_key.to_vec()))
        };

        let local_usn = self.allocate_usn().await?;
        let store_obj = if object_wins {
            ReplStamp {
                local_usn,
                ..object_stamp.clone()
            }
        } else {
            cur_obj.expect("object not winning ⇒ a current object stamp exists")
        };
        let store_secret = if secret_wins {
            ReplStamp {
                local_usn,
                ..secret_stamp.clone()
            }
        } else {
            cur_secret.expect("secret not winning ⇒ a current secret stamp exists")
        };

        let principal = crate::ad::AdPrincipalRecord {
            id: None,
            sam_account_name: sam_account_name.to_string(),
            rid: final_rid,
            nt_hash: final_nt,
            kerberos_key: final_kerb,
            disabled: final_disabled,
        };
        self.write_principal_merged(principal, &store_obj, &secret_key, &store_secret)
            .await?;
        Ok(true)
    }

    /// Atomically write the merged `principal` plus its object stamp (keyed by
    /// `sam_account_name`) and its secret stamp (keyed by `secret_key`).
    async fn write_principal_merged(
        &self,
        principal: crate::ad::AdPrincipalRecord,
        object_stamp: &ReplStamp,
        secret_key: &str,
        secret_stamp: &ReplStamp,
    ) -> DbResult<()> {
        let sam = principal.sam_account_name.clone();
        let obj_meta = ReplMetadataRecord {
            id: None,
            object_key: sam.clone(),
            version: object_stamp.version,
            originating_time: object_stamp.originating_time,
            originating_dsa: object_stamp.originating_dsa.to_vec(),
            originating_usn: object_stamp.originating_usn,
            local_usn: object_stamp.local_usn,
        };
        let secret_meta = ReplMetadataRecord {
            id: None,
            object_key: secret_key.to_string(),
            version: secret_stamp.version,
            originating_time: secret_stamp.originating_time,
            originating_dsa: secret_stamp.originating_dsa.to_vec(),
            originating_usn: secret_stamp.originating_usn,
            local_usn: secret_stamp.local_usn,
        };
        self.inner
            .query(
                "BEGIN TRANSACTION; \
                 DELETE ad_principal WHERE sam_account_name = $sam; \
                 CREATE ad_principal CONTENT $principal; \
                 DELETE repl_metadata WHERE object_key = $sam; \
                 CREATE repl_metadata CONTENT $obj_meta; \
                 DELETE repl_metadata WHERE object_key = $skey; \
                 CREATE repl_metadata CONTENT $secret_meta; \
                 COMMIT TRANSACTION;",
            )
            .bind(("sam", sam))
            .bind(("skey", secret_key.to_string()))
            .bind(("principal", principal))
            .bind(("obj_meta", obj_meta))
            .bind(("secret_meta", secret_meta))
            .await?
            .check()?;
        Ok(())
    }

    /// Record (or advance) the UTDV cursor for `dsa`: we now hold its changes up to
    /// `high_usn`. Never moves a cursor backwards. Used when applying inbound changes
    /// (Tier C C1) so we don't re-request what we already have.
    ///
    /// # Errors
    /// A store error.
    pub async fn record_cursor(&self, dsa: [u8; 16], high_usn: i64) -> DbResult<()> {
        let existing = self.read_cursor(&dsa).await?;
        if existing.as_ref().is_some_and(|c| c.high_usn >= high_usn) {
            return Ok(()); // never regress a cursor
        }
        let now = Utc::now().timestamp();
        let key = dsa_hex(&dsa);
        self.inner
            .query("DELETE repl_cursor WHERE dsa = $d")
            .bind(("d", key.clone()))
            .await?;
        let record = ReplCursorRecord {
            id: None,
            dsa: key,
            high_usn,
            last_sync: now,
        };
        let _: Option<ReplCursorRecord> = self.inner.create("repl_cursor").content(record).await?;
        Ok(())
    }

    async fn read_cursor(&self, dsa: &[u8; 16]) -> DbResult<Option<ReplCursorRecord>> {
        Ok(self
            .inner
            .query("SELECT * FROM repl_cursor WHERE dsa = $d LIMIT 1")
            .bind(("d", dsa_hex(dsa)))
            .await?
            .take(0)?)
    }

    /// This DSA's up-to-dateness vector: a cursor for every DSA whose changes it
    /// holds, **including its own** (own invocation ID at the current highest USN).
    /// A destination sends this so a source can skip already-held changes.
    ///
    /// # Errors
    /// A store error.
    pub async fn up_to_date_vector(&self) -> DbResult<Vec<UtdvCursor>> {
        let own = self.dsa_invocation_id().await?;
        let own_high = self.highest_usn().await?;
        let records: Vec<ReplCursorRecord> = self
            .inner
            .query("SELECT * FROM repl_cursor")
            .await?
            .take(0)?;
        let mut out: Vec<UtdvCursor> = records
            .into_iter()
            .map(|r| UtdvCursor {
                dsa: dsa_from_hex(&r.dsa),
                high_usn: r.high_usn,
                last_sync: r.last_sync,
            })
            .filter(|c| c.dsa != own) // own comes from live state, not a stored cursor
            .collect();
        out.push(UtdvCursor {
            dsa: own,
            high_usn: own_high,
            last_sync: 0,
        });
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_db() -> (Db, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        (db, dir)
    }

    #[tokio::test]
    async fn invocation_id_is_stable_and_nonzero() {
        let (db, _d) = test_db().await;
        let a = db.dsa_invocation_id().await.unwrap();
        let b = db.dsa_invocation_id().await.unwrap();
        assert_eq!(a, b, "invocation ID must be stable within a store");
        assert_ne!(a, [0u8; 16], "invocation ID must be a real UUID");
    }

    #[tokio::test]
    async fn usn_is_monotonic_and_persists() {
        let (db, _d) = test_db().await;
        assert_eq!(db.highest_usn().await.unwrap(), 0);
        assert_eq!(db.allocate_usn().await.unwrap(), 1);
        assert_eq!(db.allocate_usn().await.unwrap(), 2);
        assert_eq!(db.allocate_usn().await.unwrap(), 3);
        assert_eq!(db.highest_usn().await.unwrap(), 3);
    }

    #[tokio::test]
    async fn local_change_stamp_bumps_version_and_climbs_usn() {
        let (db, _d) = test_db().await;
        let own = db.dsa_invocation_id().await.unwrap();

        let s1 = db.stamp_local_change("cn=alice").await.unwrap();
        assert_eq!(s1.version, 1);
        assert_eq!(s1.originating_dsa, own);
        assert_eq!(
            s1.originating_usn, s1.local_usn,
            "a local change originates here"
        );

        let s2 = db.stamp_local_change("cn=alice").await.unwrap();
        assert_eq!(s2.version, 2, "second write bumps version");
        assert!(s2.originating_usn > s1.originating_usn, "USN climbs");

        // A different object starts its own version at 1.
        let sb = db.stamp_local_change("cn=bob").await.unwrap();
        assert_eq!(sb.version, 1);

        assert_eq!(db.repl_stamp("cn=alice").await.unwrap(), Some(s2));
        assert_eq!(db.repl_stamp("cn=missing").await.unwrap(), None);
    }

    #[tokio::test]
    async fn per_attribute_merge_keeps_a_newer_local_password_when_only_the_name_is_newer() {
        let (db, _d) = test_db().await;
        let source = [9u8; 16];
        let pw_a = [0xAAu8; 16]; // an earlier password
        let pw_b = [0xBBu8; 16]; // the current, newer password held locally
        let key_a = vec![0xA0u8; 32];
        let key_b = vec![0xB0u8; 32];

        // v2 object + v2 secret: password pw_a lands with secret stamp v2.
        let s2 = ReplStamp {
            version: 2,
            originating_time: 1_700_000_000,
            originating_dsa: source,
            originating_usn: 20,
            local_usn: 20,
        };
        assert!(db
            .apply_replicated_principal_merged(
                "U",
                1600,
                &pw_a,
                &key_a,
                false,
                "EXAMPLE.COM",
                &s2,
                &s2
            )
            .await
            .unwrap());

        // A newer password pw_b arrives at secret v5 (object v5 too).
        let s5 = ReplStamp {
            version: 5,
            originating_usn: 50,
            ..s2.clone()
        };
        assert!(db
            .apply_replicated_principal_merged(
                "U",
                1600,
                &pw_b,
                &key_b,
                false,
                "EXAMPLE.COM",
                &s5,
                &s5
            )
            .await
            .unwrap());

        // Now a replicated object with a NEWER object (name) stamp v9 but an OLDER
        // secret stamp v3 carrying the stale password pw_a. Object-level resolution would
        // apply the whole object (v9 > v5) and clobber pw_b; per-attribute merge keeps
        // pw_b because the secret's v3 does NOT beat the local secret v5.
        let obj9 = ReplStamp {
            version: 9,
            originating_usn: 90,
            ..s2.clone()
        };
        let sec3 = ReplStamp {
            version: 3,
            originating_usn: 30,
            ..s2.clone()
        };
        assert!(db
            .apply_replicated_principal_merged(
                "U",
                1600,
                &pw_a,
                &key_a,
                false,
                "EXAMPLE.COM",
                &obj9,
                &sec3
            )
            .await
            .unwrap());

        let ps = db.list_ad_principals().await.unwrap();
        let u = ps
            .iter()
            .find(|p| p.sam_account_name == "U")
            .expect("present");
        assert_eq!(
            u.nt_hash,
            pw_b.to_vec(),
            "the newer local password survived"
        );
        assert_eq!(u.kerberos_key, key_b, "its Kerberos key survived too");
        // The object stamp advanced to v9; the secret stamp stayed at v5.
        assert_eq!(db.repl_stamp("U").await.unwrap().unwrap().version, 9);
        assert_eq!(
            db.repl_stamp("U#unicodePwd")
                .await
                .unwrap()
                .unwrap()
                .version,
            5
        );

        // Conversely, a secret v12 wins and updates the password.
        let sec12 = ReplStamp {
            version: 12,
            originating_usn: 120,
            ..s2.clone()
        };
        assert!(db
            .apply_replicated_principal_merged(
                "U",
                1600,
                &pw_a,
                &key_a,
                false,
                "EXAMPLE.COM",
                &obj9,
                &sec12
            )
            .await
            .unwrap());
        let ps = db.list_ad_principals().await.unwrap();
        let u = ps.iter().find(|p| p.sam_account_name == "U").unwrap();
        assert_eq!(
            u.nt_hash,
            pw_a.to_vec(),
            "a winning secret stamp updates the password"
        );

        // Re-applying an already-held change is a no-op (both stamps lose).
        assert!(!db
            .apply_replicated_principal_merged(
                "U",
                1600,
                &pw_a,
                &key_a,
                false,
                "EXAMPLE.COM",
                &obj9,
                &sec12
            )
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn applying_a_remote_principal_upserts_it_and_keeps_the_origin_stamp() {
        let (db, _d) = test_db().await;
        let source = [7u8; 16];
        let nt = [
            0x1bu8, 0x62, 0x01, 0x8f, 0x0d, 0x05, 0xc7, 0x37, 0xd0, 0x64, 0x02, 0x29, 0x4c, 0xe2,
            0x42, 0x36,
        ];
        // A change that originated at `source` with version 5, USN 99.
        let remote = ReplStamp {
            version: 5,
            originating_time: 1_700_000_000,
            originating_dsa: source,
            originating_usn: 99,
            local_usn: 99, // the source's local USN — irrelevant to us
        };

        let aes256 = vec![0x42u8; 32]; // the replicated Kerberos AES256 key
        db.apply_replicated_principal("REMOTEUSER", 1500, &nt, &aes256, "EXAMPLE.COM", &remote)
            .await
            .unwrap();
        db.record_cursor(source, 99).await.unwrap();

        // The principal now exists locally with the replicated NT hash + Kerberos key.
        let ps = db.list_ad_principals().await.unwrap();
        let u = ps
            .iter()
            .find(|p| p.sam_account_name == "REMOTEUSER")
            .expect("applied");
        assert_eq!(u.rid, 1500);
        assert_eq!(u.nt_hash, nt.to_vec());
        assert_eq!(u.kerberos_key, aes256, "replicated AES256 key is stored");

        // The stored stamp keeps the source origin but gets a fresh LOCAL usn.
        let s = db.repl_stamp("REMOTEUSER").await.unwrap().expect("stamped");
        assert_eq!(s.version, 5);
        assert_eq!(s.originating_dsa, source);
        assert_eq!(s.originating_usn, 99);
        assert!(
            s.local_usn > 0,
            "assigned a local USN so our own stream advances"
        );

        // The source's cursor is now in our UTDV.
        let utdv = db.up_to_date_vector().await.unwrap();
        assert!(utdv.iter().any(|c| c.dsa == source && c.high_usn == 99));
    }

    #[tokio::test]
    async fn utdv_includes_own_cursor_and_recorded_partners() {
        let (db, _d) = test_db().await;
        let own = db.dsa_invocation_id().await.unwrap();
        db.allocate_usn().await.unwrap();
        db.allocate_usn().await.unwrap(); // own high = 2

        let partner = [7u8; 16];
        db.record_cursor(partner, 42).await.unwrap();
        // A stale (lower) cursor must not regress a recorded one.
        db.record_cursor(partner, 10).await.unwrap();
        db.record_cursor(partner, 50).await.unwrap();

        let utdv = db.up_to_date_vector().await.unwrap();
        let own_c = utdv
            .iter()
            .find(|c| c.dsa == own)
            .expect("own cursor present");
        assert_eq!(own_c.high_usn, 2, "own cursor reflects live highest USN");
        let part_c = utdv
            .iter()
            .find(|c| c.dsa == partner)
            .expect("partner cursor present");
        assert_eq!(part_c.high_usn, 50, "cursor advanced, never regressed");
        assert_eq!(utdv.len(), 2);
    }

    #[test]
    fn stamp_conflict_resolution_orders_by_version_then_time_then_dsa() {
        let base = ReplStamp {
            version: 3,
            originating_time: 1_000,
            originating_dsa: [1u8; 16],
            originating_usn: 7,
            local_usn: 42, // not a tiebreaker
        };
        // Higher version wins regardless of a lower local_usn.
        assert!(ReplStamp {
            version: 4,
            local_usn: 0,
            ..base
        }
        .wins_over(&base));
        assert!(!base.wins_over(&ReplStamp { version: 4, ..base }));
        // Same version → later originating_time wins.
        assert!(ReplStamp {
            originating_time: 2_000,
            ..base
        }
        .wins_over(&base));
        // Same version + time → higher originating_dsa wins.
        assert!(ReplStamp {
            originating_dsa: [2u8; 16],
            ..base
        }
        .wins_over(&base));
        // Identical stamp does not win: re-applying the same change is a no-op.
        assert!(!base.wins_over(&base));
    }
}
