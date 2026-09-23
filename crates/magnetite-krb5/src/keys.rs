//! Kerberos long-term keys and a minimal in-memory principal store.
//!
//! For this tracer-bullet PoC the KDC database is an in-memory map from a
//! principal's name components to its AES256-CTS-HMAC-SHA1-96 long-term key,
//! derived from a password via RFC 3961 string-to-key (delegated to `picky-krb`).
//! Later phases replace this with the directory (`magnetite-db`), where the key
//! material lives on the principal object.

use crate::error::{KdcError, KdcResult};
use picky_krb::crypto::CipherSuite;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// Encryption type number for `aes256-cts-hmac-sha1-96` (RFC 3961 §8).
pub const AES256_CTS_HMAC_SHA1_96: i32 = 18;

/// The RFC 3961 default salt for AES principals: the realm concatenated with the
/// principal's name components, no separators. For user `p3` in realm
/// `EXAMPLE.COM` this is `EXAMPLE.COMp3`; for `krbtgt/EXAMPLE.COM` it is
/// `EXAMPLE.COMkrbtgtEXAMPLE.COM`.
pub fn default_salt(realm: &str, name_components: &[String]) -> String {
    let mut salt = realm.to_string();
    for component in name_components {
        salt.push_str(component);
    }
    salt
}

/// Derive an AES256 long-term key from `password` and `salt` (RFC 3961 s2k).
pub fn derive_aes256_key(password: &str, salt: &str) -> KdcResult<Vec<u8>> {
    derive_aes256_key_bytes(password.as_bytes(), salt.as_bytes())
}

/// Derive an AES256 long-term key from raw `password` bytes (RFC 3961 s2k). A machine
/// account's random UTF-16 password is fed to the KDF as its WTF-8 bytes (see
/// [`wtf8`]) — which a `&str` cannot represent when it contains lone surrogates — so
/// key derivation must accept bytes, not a `&str`.
pub fn derive_aes256_key_bytes(password: &[u8], salt: &[u8]) -> KdcResult<Vec<u8>> {
    CipherSuite::Aes256CtsHmacSha196
        .cipher()
        .generate_key_from_password(password, salt)
        .map_err(|e| KdcError::Crypto(e.to_string()))
}

/// Encode UTF-16 code units to WTF-8: UTF-8 that also encodes lone surrogates (as
/// their 3-byte form). Windows feeds a machine account's random UTF-16 password to the
/// Kerberos string-to-key this way, so the DC must match it to derive the same key.
pub fn wtf8(units: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(units.len() * 3);
    let mut i = 0;
    while i < units.len() {
        let u = units[i] as u32;
        let cp = if (0xD800..0xDC00).contains(&u)
            && i + 1 < units.len()
            && (0xDC00..0xE000).contains(&(units[i + 1] as u32))
        {
            // A valid surrogate pair → the supplementary code point.
            let lo = units[i + 1] as u32;
            i += 2;
            0x1_0000 + ((u - 0xD800) << 10) + (lo - 0xDC00)
        } else {
            // A BMP unit or a LONE surrogate (encoded as its 3-byte form).
            i += 1;
            u
        };
        match cp {
            0..=0x7F => out.push(cp as u8),
            0x80..=0x7FF => {
                out.push(0xC0 | (cp >> 6) as u8);
                out.push(0x80 | (cp & 0x3F) as u8);
            }
            0x800..=0xFFFF => {
                out.push(0xE0 | (cp >> 12) as u8);
                out.push(0x80 | ((cp >> 6) & 0x3F) as u8);
                out.push(0x80 | (cp & 0x3F) as u8);
            }
            _ => {
                out.push(0xF0 | (cp >> 18) as u8);
                out.push(0x80 | ((cp >> 12) & 0x3F) as u8);
                out.push(0x80 | ((cp >> 6) & 0x3F) as u8);
                out.push(0x80 | (cp & 0x3F) as u8);
            }
        }
    }
    out
}

/// A principal's long-term key (single etype for the PoC).
#[derive(Clone)]
pub struct PrincipalKey {
    /// Encryption type number (always [`AES256_CTS_HMAC_SHA1_96`] here).
    pub etype: i32,
    /// The derived key bytes.
    pub key: Vec<u8>,
    /// The salt used to derive the key (echoed to clients in ETYPE-INFO2).
    pub salt: String,
}

/// A stored principal: its name components, its long-term key, and the identity
/// (RID + group memberships) the PAC needs so Windows builds a per-user token. For
/// non-user principals (krbtgt, services) the identity fields are unused defaults.
#[derive(Clone)]
pub struct Principal {
    /// Name components (e.g. `["alice"]` or `["krbtgt", "EXAMPLE.COM"]`).
    pub name: Vec<String>,
    /// The long-term key.
    pub key: PrincipalKey,
    /// The account's RID (0 when unknown, e.g. a bare password/service principal).
    pub rid: u32,
    /// The primary group RID (Domain Users = 513 by default).
    pub primary_group_rid: u32,
    /// Group RIDs this account belongs to (includes the primary group).
    pub group_rids: Vec<u32>,
}

/// Default primary group / sole group for a principal with no known membership.
const DOMAIN_USERS_RID: u32 = 513;

impl Principal {
    /// Construct with the default identity (RID 0, Domain Users only) — for principals
    /// whose RID/groups are not modelled (krbtgt, service keys, bare passwords).
    fn with_default_identity(name: Vec<String>, key: PrincipalKey) -> Self {
        Self {
            name,
            key,
            rid: 0,
            primary_group_rid: DOMAIN_USERS_RID,
            group_rids: vec![DOMAIN_USERS_RID],
        }
    }
}

/// An in-memory KDC principal database for one realm.
///
/// `principals` are the statically-seeded accounts (built once at startup).
/// `dynamic` holds principals registered at runtime (e.g. machine accounts created
/// through SAMR during a domain join) — behind a `Mutex` so it can be added to via
/// `&self` while the store is shared (`Arc<PrincipalStore>`) between the KDC and the
/// SAMR interface. Lookups consult both.
pub struct PrincipalStore {
    realm: String,
    principals: HashMap<String, Principal>,
    dynamic: Mutex<HashMap<String, Principal>>,
    /// Runtime-revoked lookup keys (a disabled or deleted account, replicated in while
    /// the DC runs). Checked FIRST by [`get`](Self::get) so a revocation shadows even a
    /// statically-seeded principal — a dynamic-map removal alone would let `get` fall
    /// back to the startup seed and keep authenticating. Re-registering a key clears it.
    revoked: Mutex<HashSet<String>>,
    /// Constrained-delegation allow-list (`msDS-AllowedToDelegateTo`): pairs of
    /// `(delegating service, permitted backend SPN)` as normalised lookup keys. A
    /// service may request an S4U2Proxy ticket to a backend only if the pair is here.
    delegation: Vec<(String, String)>,
    /// The domain SID's sub-authorities (`S-1-5-<...>`), so PAC SIDs are built for the
    /// real domain. Defaults to the PoC `S-1-5-21-1-2-3`; overridden from the
    /// directory at seed time.
    domain_sid: Vec<u32>,
}

/// Normalise name components to a case-insensitive lookup key.
fn lookup_key(name_components: &[String]) -> String {
    name_components.join("/").to_lowercase()
}

impl PrincipalStore {
    /// Create an empty store for `realm` (conventionally upper-case).
    pub fn new(realm: &str) -> Self {
        Self {
            realm: realm.to_string(),
            principals: HashMap::new(),
            dynamic: Mutex::new(HashMap::new()),
            revoked: Mutex::new(HashSet::new()),
            delegation: Vec::new(),
            domain_sid: vec![21, 1, 2, 3],
        }
    }

    /// The realm this store serves.
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// The domain SID sub-authorities used to build PAC SIDs.
    pub fn domain_sid(&self) -> &[u32] {
        &self.domain_sid
    }

    /// Set the domain SID sub-authorities (from the directory) so PAC SIDs match the
    /// real domain.
    pub fn set_domain_sid(&mut self, sub_authorities: Vec<u32>) {
        if !sub_authorities.is_empty() {
            self.domain_sid = sub_authorities;
        }
    }

    /// Permit `from` (a delegating service) to obtain S4U2Proxy tickets to the
    /// backend SPN `to` on a user's behalf (constrained delegation).
    pub fn allow_delegation(&mut self, from: &[&str], to: &[&str]) {
        let from: Vec<String> = from.iter().map(|c| c.to_string()).collect();
        let to: Vec<String> = to.iter().map(|c| c.to_string()).collect();
        self.delegation.push((lookup_key(&from), lookup_key(&to)));
    }

    /// Whether `from` is allowed to delegate to the backend `to` (constrained
    /// delegation / `msDS-AllowedToDelegateTo`).
    pub fn can_delegate(&self, from: &[String], to: &[String]) -> bool {
        let (from_key, to_key) = (lookup_key(from), lookup_key(to));
        self.delegation
            .iter()
            .any(|(f, t)| *f == from_key && *t == to_key)
    }

    /// Add a principal whose key is derived from `password` using the default
    /// AES256 salt for its name.
    pub fn add_password_principal(
        &mut self,
        name_components: &[&str],
        password: &str,
    ) -> KdcResult<()> {
        let components: Vec<String> = name_components.iter().map(|c| c.to_string()).collect();
        let salt = default_salt(&self.realm, &components);
        let key = derive_aes256_key(password, &salt)?;
        let principal = Principal::with_default_identity(
            components.clone(),
            PrincipalKey {
                etype: AES256_CTS_HMAC_SHA1_96,
                key,
                salt,
            },
        );
        self.principals.insert(lookup_key(&components), principal);
        Ok(())
    }

    /// Add a principal whose AES256 long-term key is supplied directly — the key
    /// material as stored in the directory database (`magnetite-db`), where the
    /// derived key, not the cleartext, lives. The salt is the default AES256 salt
    /// for the principal's name (matching how the key was derived at create time).
    pub fn add_key_principal(&mut self, name_components: &[&str], aes256_key: Vec<u8>) {
        let components: Vec<String> = name_components.iter().map(|c| c.to_string()).collect();
        let salt = default_salt(&self.realm, &components);
        let principal = Principal::with_default_identity(
            components.clone(),
            PrincipalKey {
                etype: AES256_CTS_HMAC_SHA1_96,
                key: aes256_key,
                salt,
            },
        );
        self.principals.insert(lookup_key(&components), principal);
    }

    /// Add a user principal with its supplied AES256 key AND its PAC identity (RID,
    /// primary group, group memberships) — so a logon ticket carries the real user
    /// SID and group SIDs instead of a fixed identity. The seed loop uses this for
    /// every directory user.
    pub fn add_user_principal(
        &mut self,
        sam_account_name: &str,
        aes256_key: Vec<u8>,
        rid: u32,
        primary_group_rid: u32,
        group_rids: Vec<u32>,
    ) {
        let components = vec![sam_account_name.to_string()];
        let salt = default_salt(&self.realm, &components);
        let principal = Principal {
            name: components.clone(),
            key: PrincipalKey {
                etype: AES256_CTS_HMAC_SHA1_96,
                key: aes256_key,
                salt,
            },
            rid,
            primary_group_rid,
            group_rids,
        };
        self.principals.insert(lookup_key(&components), principal);
    }

    /// The `krbtgt/REALM` service principal (the ticket-granting service key).
    pub fn krbtgt(&self) -> Option<Principal> {
        self.get(&["krbtgt".to_string(), self.realm.clone()])
    }

    /// Look up a principal by its name components (case-insensitive). Consults the
    /// dynamic store **first** so a runtime password change (`kpasswd`, machine
    /// rotation) shadows the seeded key; falls back to the static store. Returns an
    /// owned clone (dynamic principals live behind a `Mutex`).
    pub fn get(&self, name_components: &[String]) -> Option<Principal> {
        let key = lookup_key(name_components);
        // A runtime revocation (disabled/deleted upstream) shadows both maps, so a
        // statically-seeded principal stops authenticating without a restart.
        if self.revoked.lock().expect("principal store").contains(&key) {
            return None;
        }
        if let Some(p) = self.dynamic.lock().expect("principal store").get(&key) {
            return Some(p.clone());
        }
        self.principals.get(&key).cloned()
    }

    /// Register a machine account at runtime so the KDC can issue it tickets. The
    /// AES256 key is derived from `password` with the default salt for `name`. Used
    /// when SAMR creates a computer account during a domain join.
    ///
    /// # Errors
    /// Propagates a key-derivation failure.
    pub fn register_machine(&self, name_components: &[&str], password: &str) -> KdcResult<()> {
        self.set_password(name_components, password)
    }

    /// Set (or change) a principal's password at runtime, deriving its AES256 key
    /// with the default salt for `name` and storing it in the dynamic map — which
    /// [`get`](Self::get) consults first, so this shadows any seeded key. Backs the
    /// `kpasswd` change-password operation and machine-account rotation.
    ///
    /// # Errors
    /// Propagates a key-derivation failure.
    pub fn set_password(&self, name_components: &[&str], password: &str) -> KdcResult<()> {
        let components: Vec<String> = name_components.iter().map(|c| c.to_string()).collect();
        let salt = default_salt(&self.realm, &components);
        let key = derive_aes256_key(password, &salt)?;
        let principal = Principal::with_default_identity(
            components.clone(),
            PrincipalKey {
                etype: AES256_CTS_HMAC_SHA1_96,
                key,
                salt,
            },
        );
        self.dynamic
            .lock()
            .expect("principal store")
            .insert(lookup_key(&components), principal);
        Ok(())
    }

    /// Register a machine account from its **raw UTF-16LE password**, the way a Windows
    /// domain member's Kerberos service key must be derived so tickets the KDC issues
    /// to the member's own SPNs decrypt at the workstation:
    ///
    /// * key = AES256 s2k over the **WTF-8** password (fidelity for random UTF-16) and
    ///   the AD computer-account salt `REALM + "host" + <fqdn>`;
    /// * the one key is registered under the `sAMAccountName` (`HOST$`) **and** the
    ///   `host/<fqdn>` and `cifs/<fqdn>` SPNs, so a TGS-REQ for any of them resolves.
    ///
    /// `fqdn` is `<hostname>.<lowercase realm>` (hostname = the name minus `$`, lower).
    ///
    /// Returns the derived AES256 key so the caller can also persist it (the DB copy
    /// that seeds the KDC after a restart — see [`machine_spn_aliases`]).
    ///
    /// # Errors
    /// Propagates a key-derivation failure.
    pub fn register_machine_utf16(
        &self,
        sam_account_name: &str,
        pw_utf16le: &[u8],
    ) -> KdcResult<Vec<u8>> {
        let salt = machine_salt(&self.realm, sam_account_name);
        let key = machine_kerberos_key(&self.realm, sam_account_name, pw_utf16le)?;
        let mut dynamic = self.dynamic.lock().expect("principal store");
        for name in machine_spn_aliases(&self.realm, sam_account_name) {
            dynamic.insert(
                lookup_key(&name),
                Principal::with_default_identity(
                    name,
                    PrincipalKey {
                        etype: AES256_CTS_HMAC_SHA1_96,
                        key: key.clone(),
                        salt: salt.clone(),
                    },
                ),
            );
        }
        Ok(key)
    }

    /// Register a machine account from an already-derived AES256 `key` (the DB copy),
    /// under its `sAMAccountName` and `host/`/`cifs/` SPN aliases — how the KDC is
    /// re-seeded for a joined member at startup so its logon works without a re-join.
    pub fn register_machine_key(&self, sam_account_name: &str, key: Vec<u8>) {
        let salt = machine_salt(&self.realm, sam_account_name);
        let aliases = machine_spn_aliases(&self.realm, sam_account_name);
        // Re-registering clears any prior revocation on every alias (machine re-enabled).
        {
            let mut revoked = self.revoked.lock().expect("principal store");
            for name in &aliases {
                revoked.remove(&lookup_key(name));
            }
        }
        let mut dynamic = self.dynamic.lock().expect("principal store");
        for name in aliases {
            dynamic.insert(
                lookup_key(&name),
                Principal::with_default_identity(
                    name,
                    PrincipalKey {
                        etype: AES256_CTS_HMAC_SHA1_96,
                        key: key.clone(),
                        salt: salt.clone(),
                    },
                ),
            );
        }
    }

    /// Register (or refresh) a **user** principal from an already-derived AES256 `key`
    /// via `&self` — the runtime counterpart of the startup seed. Inbound replication
    /// calls this each cycle so a freshly replicated user (or a replicated password
    /// change) can obtain a TGT **without a DC restart** (the static seed only runs at
    /// startup). The dynamic entry shadows any stale static one (`get` checks dynamic
    /// first). Machine accounts (`sAMAccountName` ending `$`) should use
    /// [`register_machine_key`](Self::register_machine_key) instead so their SPN
    /// aliases are registered too.
    pub fn register_user_key(&self, sam_account_name: &str, key: Vec<u8>) {
        self.register_user_identity(
            sam_account_name,
            key,
            0,
            DOMAIN_USERS_RID,
            vec![DOMAIN_USERS_RID],
        );
    }

    /// Register (or refresh) a user principal WITH its PAC identity (RID + groups), so
    /// a runtime-added or -refreshed user's logon ticket carries the real SID and group
    /// SIDs. The identity-aware counterpart of [`add_user_principal`](Self::add_user_principal)
    /// for the live refresh path.
    pub fn register_user_identity(
        &self,
        sam_account_name: &str,
        key: Vec<u8>,
        rid: u32,
        primary_group_rid: u32,
        group_rids: Vec<u32>,
    ) {
        let components = vec![sam_account_name.to_string()];
        let salt = default_salt(&self.realm, &components);
        let lookup = lookup_key(&components);
        // Re-registering clears any prior revocation (an account re-enabled upstream).
        self.revoked
            .lock()
            .expect("principal store")
            .remove(&lookup);
        self.dynamic.lock().expect("principal store").insert(
            lookup,
            Principal {
                name: components,
                key: PrincipalKey {
                    etype: AES256_CTS_HMAC_SHA1_96,
                    key,
                    salt,
                },
                rid,
                primary_group_rid,
                group_rids,
            },
        );
    }

    /// Revoke a principal (a user or machine disabled or deleted upstream) so it can no
    /// longer obtain a TGT or a service ticket at runtime: drop any dynamic entry AND
    /// mark the key revoked so a statically-seeded principal of the same name is shadowed
    /// too (`get` checks the revoked set first). A **machine** account (`sAMAccountName`
    /// ending `$`) revokes ALL its lookup keys — the account name and its `host/`/`cifs/`
    /// SPN aliases — so a decommissioned computer cannot still get a service ticket via an
    /// alias. Cleared by a later re-registration (the account re-enabled upstream).
    pub fn remove_dynamic_principal(&self, sam_account_name: &str) {
        let keys: Vec<String> = if sam_account_name.ends_with('$') {
            machine_spn_aliases(&self.realm, sam_account_name)
                .iter()
                .map(|n| lookup_key(n))
                .collect()
        } else {
            vec![lookup_key(&[sam_account_name.to_string()])]
        };
        {
            let mut dynamic = self.dynamic.lock().expect("principal store");
            for k in &keys {
                dynamic.remove(k);
            }
        }
        let mut revoked = self.revoked.lock().expect("principal store");
        for k in keys {
            revoked.insert(k);
        }
    }
}

/// The machine account's fully-qualified DNS name: `<hostname>.<lowercase realm>`
/// (hostname = the `sAMAccountName` minus a trailing `$`, lower-cased).
fn machine_fqdn(realm: &str, sam_account_name: &str) -> String {
    format!(
        "{}.{}",
        sam_account_name.trim_end_matches('$').to_lowercase(),
        realm.to_lowercase()
    )
}

/// The AD computer-account Kerberos salt: the default AES256 salt of `host/<fqdn>`.
pub fn machine_salt(realm: &str, sam_account_name: &str) -> String {
    default_salt(
        realm,
        &["host".to_string(), machine_fqdn(realm, sam_account_name)],
    )
}

/// The name components a machine account is looked up by: its `sAMAccountName` plus
/// the `host/<fqdn>` and `cifs/<fqdn>` SPNs (all sharing one key).
pub fn machine_spn_aliases(realm: &str, sam_account_name: &str) -> Vec<Vec<String>> {
    let fqdn = machine_fqdn(realm, sam_account_name);
    vec![
        vec![sam_account_name.to_string()],
        vec!["host".to_string(), fqdn.clone()],
        vec!["cifs".to_string(), fqdn],
    ]
}

/// Derive a machine account's AES256 long-term key from its **raw UTF-16LE password**,
/// the way a Windows member derives its own: AES256 s2k over the **WTF-8** password
/// (fidelity for random UTF-16) and the AD computer-account salt (`host/<fqdn>`). The
/// KDC must match this so a `host/`/`cifs/` service ticket decrypts at the workstation.
///
/// # Errors
/// Propagates a key-derivation failure.
pub fn machine_kerberos_key(
    realm: &str,
    sam_account_name: &str,
    pw_utf16le: &[u8],
) -> KdcResult<Vec<u8>> {
    let units: Vec<u16> = pw_utf16le
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    derive_aes256_key_bytes(
        &wtf8(&units),
        machine_salt(realm, sam_account_name).as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_salt_matches_rfc3961_convention() {
        assert_eq!(
            default_salt("EXAMPLE.COM", &["p3".to_string()]),
            "EXAMPLE.COMp3"
        );
        assert_eq!(
            default_salt(
                "EXAMPLE.COM",
                &["krbtgt".to_string(), "EXAMPLE.COM".to_string()]
            ),
            "EXAMPLE.COMkrbtgtEXAMPLE.COM"
        );
    }

    #[test]
    fn revocation_shadows_a_static_principal_until_reregistered() {
        // A statically-seeded user (the startup path) can obtain a ticket…
        let mut store = PrincipalStore::new("EXAMPLE.COM");
        store.add_key_principal(&["dave"], vec![7u8; 32]);
        let store = std::sync::Arc::new(store);
        assert!(store.get(&["dave".to_string()]).is_some());

        // …until revoked (disabled/deleted upstream): a plain dynamic-map removal would
        // let `get` fall back to the static seed, so revocation must shadow it (B4a/B4b).
        store.remove_dynamic_principal("dave");
        assert!(
            store.get(&["dave".to_string()]).is_none(),
            "a revoked static principal must not authenticate"
        );

        // Re-registering (re-enabled upstream) clears the revocation.
        store.register_user_key("dave", vec![9u8; 32]);
        assert!(store.get(&["dave".to_string()]).is_some());
    }

    #[test]
    fn revoking_a_machine_account_revokes_its_spn_aliases() {
        let store = std::sync::Arc::new(PrincipalStore::new("EXAMPLE.COM"));
        store.register_machine_key("WS01$", vec![3u8; 32]);
        let fqdn = machine_fqdn("EXAMPLE.COM", "WS01$");
        // The account and both SPN aliases resolve while enabled.
        assert!(store.get(&["WS01$".to_string()]).is_some());
        assert!(store.get(&["host".to_string(), fqdn.clone()]).is_some());
        assert!(store.get(&["cifs".to_string(), fqdn.clone()]).is_some());

        // Revoking the machine must revoke EVERY alias, not just the account name —
        // else a decommissioned computer could still get a host/cifs service ticket.
        store.remove_dynamic_principal("WS01$");
        assert!(store.get(&["WS01$".to_string()]).is_none());
        assert!(store.get(&["host".to_string(), fqdn.clone()]).is_none());
        assert!(store.get(&["cifs".to_string(), fqdn.clone()]).is_none());

        // Re-registering (re-enabled upstream) restores all aliases.
        store.register_machine_key("WS01$", vec![4u8; 32]);
        assert!(store.get(&["host".to_string(), fqdn]).is_some());
    }

    #[test]
    fn wtf8_encodes_ascii_pairs_and_lone_surrogates() {
        // ASCII → identity.
        assert_eq!(wtf8(&"Ab1".encode_utf16().collect::<Vec<_>>()), b"Ab1");
        // A valid surrogate pair (U+1F600) → its 4-byte UTF-8.
        assert_eq!(wtf8(&[0xD83D, 0xDE00]), vec![0xF0, 0x9F, 0x98, 0x80]);
        // A LONE high surrogate → its 3-byte form (what a String would drop).
        assert_eq!(wtf8(&[0xD83D]), vec![0xED, 0xA0, 0xBD]);
        // BMP (U+00E9 é) → 2-byte UTF-8.
        assert_eq!(wtf8(&[0x00E9]), vec![0xC3, 0xA9]);
    }

    #[test]
    fn register_machine_utf16_resolves_host_spn_with_ad_salt() {
        let store = PrincipalStore::new("YUMEWAKA.LOCAL");
        let pw: Vec<u8> = "S3cret!"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        store
            .register_machine_utf16("DESKTOP-K78L1UQ$", &pw)
            .unwrap();
        // The account and its host/cifs SPNs all resolve to the one key.
        let fqdn = "desktop-k78l1uq.yumewaka.local";
        let sam = store.get(&["DESKTOP-K78L1UQ$".to_string()]).expect("sam");
        let host = store
            .get(&["host".to_string(), fqdn.to_string()])
            .expect("host spn");
        let cifs = store
            .get(&["cifs".to_string(), fqdn.to_string()])
            .expect("cifs spn");
        assert_eq!(sam.key.key, host.key.key);
        assert_eq!(host.key.key, cifs.key.key);
        // The salt is the AD computer-account salt (host/<fqdn>), and the key matches
        // a WTF-8 derivation over it.
        assert_eq!(host.key.salt, format!("YUMEWAKA.LOCALhost{fqdn}"));
        let expect = derive_aes256_key_bytes(
            &wtf8(&"S3cret!".encode_utf16().collect::<Vec<_>>()),
            host.key.salt.as_bytes(),
        )
        .unwrap();
        assert_eq!(host.key.key, expect);
    }

    #[test]
    fn derive_key_is_deterministic_and_32_bytes() {
        let a = derive_aes256_key("password12", "EXAMPLE.COMp3").unwrap();
        let b = derive_aes256_key("password12", "EXAMPLE.COMp3").unwrap();
        assert_eq!(a, b, "s2k must be deterministic");
        assert_eq!(a.len(), 32, "aes256 key is 32 bytes");
        let c = derive_aes256_key("password12", "EXAMPLE.COMother").unwrap();
        assert_ne!(a, c, "different salt ⇒ different key");
    }

    #[test]
    fn store_lookup_is_case_insensitive() {
        let mut store = PrincipalStore::new("EXAMPLE.COM");
        store
            .add_password_principal(&["alice"], "password12")
            .unwrap();
        store
            .add_password_principal(&["krbtgt", "EXAMPLE.COM"], "krbtgt-secret")
            .unwrap();
        assert!(store.get(&["ALICE".to_string()]).is_some());
        assert!(store.krbtgt().is_some());
        assert!(store.get(&["bob".to_string()]).is_none());
    }
}
