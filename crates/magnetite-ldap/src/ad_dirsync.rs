//! Active Directory / Samba AD DC change-tracking consumer via the DirSync
//! control (`LDAP_SERVER_DIRSYNC_OID = 1.2.840.113556.1.4.841`).
//!
//! AD does **not** implement RFC 4533 syncrepl — it tracks changes with DirSync:
//! a search carrying the control returns objects changed since an opaque cookie,
//! and the cookie in the `SearchResultDone` advances it. This consumer imports AD
//! users/groups **read-only, one-way** into the local directory, mapping
//! `objectGUID`→ the entry's source id and `isDeleted=TRUE`→ a deletion. Within
//! one pass it re-issues the search (draining the backlog / all pending changes)
//! until a pass returns no objects.
//!
//! Not handled (a Magnetite provider / OpenLDAP path uses [`crate::consumer`]):
//! write-back to AD, Kerberos, and confidential attributes needing replication
//! rights (set `dirsync_flags = 8192` to fetch public data only).

use crate::ad_map::{normalize_ad_entry, AdMapOpts};
use crate::codec::GuardedLdapCodec;
use anyhow::{bail, Result};
use base64::Engine;
use futures::{SinkExt, StreamExt};
use ldap3_proto::control::LdapControl;
use ldap3_proto::proto::{
    LdapBindCred, LdapBindRequest, LdapDerefAliases, LdapFilter, LdapMsg, LdapOp,
    LdapSearchRequest, LdapSearchResultEntry, LdapSearchScope,
};
use ldap3_proto::LdapResultCode;
use magnetite_core::LdapConsumerConfig;
use magnetite_db::Db;
use tokio_util::codec::Framed;

/// Backstop against a provider whose cookie never advances (avoid an infinite
/// drain loop within a single pass).
const MAX_PASSES: usize = 10_000;
/// DirSync per-page byte budget requested from the server.
const DIRSYNC_MAX_BYTES: i64 = 10 * 1024 * 1024;

/// One DirSync refresh: bind, then repeatedly search with the DirSync control
/// until a pass returns no objects. Returns `(applied, deleted, base64_cookie)`.
pub async fn ad_dirsync_once(
    db: &Db,
    config: &LdapConsumerConfig,
    base_dn: &str,
) -> Result<(u64, u64, String)> {
    let base = config
        .base_dn
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| base_dn.to_string());

    // The DirSync cookie is opaque binary; it is stored base64-encoded in the
    // shared sync-state column. A non-decodable value (e.g. a leftover syncrepl
    // cookie) is treated as empty → a full resync.
    let stored = db.get_ldap_sync_state().await?.cookie;
    let mut cookie: Vec<u8> = base64::engine::general_purpose::STANDARD
        .decode(stored.trim())
        .unwrap_or_default();

    // Connect, upgrading to TLS for an `ldaps://` upstream so the authenticated
    // bind (carrying `bind_password`) and the pulled data never go in the clear.
    let stream = crate::client_tls::connect(config).await?;
    let mut framed = Framed::new(stream, GuardedLdapCodec::default());

    // AD requires an authenticated bind for DirSync.
    let bind = LdapMsg::new(
        1,
        LdapOp::BindRequest(LdapBindRequest {
            dn: config.bind_dn.clone(),
            cred: LdapBindCred::Simple(config.bind_password.clone()),
        }),
    );
    framed.send(bind).await?;
    match framed.next().await {
        Some(Ok(m)) => match m.op {
            LdapOp::BindResponse(r) if r.res.code == LdapResultCode::Success => {}
            LdapOp::BindResponse(r) => bail!("bind rejected: {:?} {}", r.res.code, r.res.message),
            other => bail!("expected bind response, got {other:?}"),
        },
        Some(Err(e)) => return Err(e.into()),
        None => bail!("connection closed before bind response"),
    }

    let opts = AdMapOpts {
        posix: config.posix_mapping(),
        uid_base: config.posix_uid_base(),
        gid_base: config.posix_gid_base(),
    };
    let (mut applied, mut deleted) = (0u64, 0u64);
    let mut msgid = 2;
    for _ in 0..MAX_PASSES {
        let req = LdapSearchRequest {
            base: base.clone(),
            scope: LdapSearchScope::Subtree,
            aliases: LdapDerefAliases::Never,
            sizelimit: 0,
            timelimit: 0,
            typesonly: false,
            filter: LdapFilter::Present("objectClass".into()),
            attrs: vec![], // all attributes
        };
        let ctrl = LdapControl::AdDirsync {
            flags: config.dirsync_flags(),
            max_bytes: DIRSYNC_MAX_BYTES,
            cookie: if cookie.is_empty() {
                None
            } else {
                Some(cookie.clone())
            },
        };
        framed
            .send(LdapMsg::new_with_ctrls(
                msgid,
                LdapOp::SearchRequest(req),
                vec![ctrl],
            ))
            .await?;
        msgid += 1;

        let mut entries = 0u64;
        let mut next_cookie: Option<Vec<u8>> = None;
        let mut completed = false;
        while let Some(item) = framed.next().await {
            let msg = item?;
            match msg.op {
                LdapOp::SearchResultEntry(entry) => {
                    entries += 1;
                    apply_ad_entry(db, &entry, &opts, &mut applied, &mut deleted).await?;
                }
                LdapOp::SearchResultDone(res) => {
                    if res.code != LdapResultCode::Success {
                        bail!("DirSync search rejected: {:?} {}", res.code, res.message);
                    }
                    next_cookie = dirsync_cookie(&msg.ctrl);
                    completed = true;
                    break;
                }
                LdapOp::IntermediateResponse(_) => {}
                _ => {}
            }
        }
        if !completed {
            bail!("provider closed the connection before completing the DirSync search");
        }
        if let Some(c) = next_cookie {
            cookie = c;
        }
        if entries == 0 {
            break; // backlog drained / no more changes
        }
    }

    let _ = framed
        .send(LdapMsg::new(msgid, LdapOp::UnbindRequest))
        .await;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&cookie);
    Ok((applied, deleted, encoded))
}

/// Apply one AD object: delete by `objectGUID` when tombstoned (`isDeleted`),
/// otherwise normalize and upsert it. Objects without an `objectGUID` are skipped.
async fn apply_ad_entry(
    db: &Db,
    entry: &LdapSearchResultEntry,
    opts: &AdMapOpts,
    applied: &mut u64,
    deleted: &mut u64,
) -> Result<()> {
    let n = normalize_ad_entry(entry, opts);
    let Some(guid) = n.guid else {
        return Ok(());
    };
    if n.is_deleted {
        if db.apply_ldap_sync_delete(&guid).await? {
            *deleted += 1;
        }
    } else {
        db.apply_ldap_sync_entry(&entry.dn, &guid, n.object_classes, &n.attributes, n.enabled)
            .await?;
        *applied += 1;
    }
    Ok(())
}

/// The opaque cookie of a DirSync control on a response, if present.
fn dirsync_cookie(ctrls: &[LdapControl]) -> Option<Vec<u8>> {
    ctrls.iter().find_map(|c| match c {
        LdapControl::AdDirsync {
            cookie: Some(bytes),
            ..
        } => Some(bytes.clone()),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ldap3_proto::proto::{LdapBindResponse, LdapPartialAttribute, LdapResult};
    use ldap3_proto::LdapCodec;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    /// An AD object the fake provider returns for the first DirSync search.
    struct AdObj {
        dn: String,
        guid: [u8; 16],
        classes: Vec<&'static str>,
        deleted: bool,
    }

    fn result(code: LdapResultCode, message: &str) -> LdapResult {
        LdapResult {
            code,
            matcheddn: String::new(),
            message: message.to_string(),
            referral: vec![],
        }
    }

    fn dirsync_done(msgid: i32) -> LdapMsg {
        LdapMsg::new_with_ctrls(
            msgid,
            LdapOp::SearchResultDone(result(LdapResultCode::Success, "")),
            vec![LdapControl::AdDirsync {
                flags: 0,
                max_bytes: 0,
                cookie: Some(b"dirsync-cookie-1".to_vec()),
            }],
        )
    }

    /// Fake AD provider: binds, returns `objects` on the first DirSync search
    /// (then a SearchResultDone with a cookie), and an empty result on every
    /// subsequent search (so the consumer's drain loop terminates).
    async fn fake_ad(objects: Vec<AdObj>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let mut framed = Framed::new(stream, LdapCodec::default());
            let Some(Ok(bind)) = framed.next().await else {
                return;
            };
            let _ = framed
                .send(LdapMsg::new(
                    bind.msgid,
                    LdapOp::BindResponse(LdapBindResponse {
                        res: result(LdapResultCode::Success, ""),
                        saslcreds: None,
                    }),
                ))
                .await;
            let mut first = true;
            while let Some(Ok(msg)) = framed.next().await {
                let sid = msg.msgid;
                match msg.op {
                    LdapOp::UnbindRequest => break,
                    LdapOp::SearchRequest(_) => {
                        if first {
                            first = false;
                            for obj in &objects {
                                let mut attrs = vec![
                                    LdapPartialAttribute {
                                        atype: "objectGUID".into(),
                                        vals: vec![obj.guid.to_vec()],
                                    },
                                    LdapPartialAttribute {
                                        atype: "objectClass".into(),
                                        vals: obj
                                            .classes
                                            .iter()
                                            .map(|c| c.as_bytes().to_vec())
                                            .collect(),
                                    },
                                    LdapPartialAttribute {
                                        atype: "sAMAccountName".into(),
                                        vals: vec![b"bob".to_vec()],
                                    },
                                ];
                                if obj.deleted {
                                    attrs.push(LdapPartialAttribute {
                                        atype: "isDeleted".into(),
                                        vals: vec![b"TRUE".to_vec()],
                                    });
                                }
                                let _ = framed
                                    .send(LdapMsg::new(
                                        sid,
                                        LdapOp::SearchResultEntry(LdapSearchResultEntry {
                                            dn: obj.dn.clone(),
                                            attributes: attrs,
                                        }),
                                    ))
                                    .await;
                            }
                        }
                        let _ = framed.send(dirsync_done(sid)).await;
                    }
                    _ => {}
                }
            }
        });
        addr
    }

    async fn test_db() -> (Db, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::connect(dir.path().join("db")).await.unwrap();
        (db, dir)
    }

    fn ad_config(addr: SocketAddr) -> LdapConsumerConfig {
        // The fake provider is loopback plaintext ldap://; the sync binds with a
        // password, which the connect() guard refuses over plaintext unless allowed.
        // A real deployment sets this on a trusted network (or uses ldaps://).
        std::env::set_var("MAGNETITE_LDAP_ALLOW_PLAINTEXT", "1");
        LdapConsumerConfig {
            enabled: true,
            provider_url: format!("ldap://{addr}"),
            bind_dn: "cn=svc,dc=corp,dc=example,dc=com".into(),
            bind_password: "pw".into(),
            base_dn: Some("dc=corp,dc=example,dc=com".into()),
            interval_secs: None,
            mode: Some("ad-dirsync".into()),
            dirsync_flags: None,
            posix_mapping: None,
            posix_uid_base: None,
            posix_gid_base: None,
            reconcile_deletions: None,
            reconcile_every: None,
        }
    }

    #[tokio::test]
    async fn ad_dirsync_imports_then_deletes_by_guid() {
        let (db, _dir) = test_db().await;
        let guid = [7u8; 16];
        let dn = "CN=Bob,CN=Users,DC=corp,DC=example,DC=com".to_string();

        // Import: one user object arrives with an objectGUID.
        let addr = fake_ad(vec![AdObj {
            dn: dn.clone(),
            guid,
            classes: vec!["top", "person", "organizationalPerson", "user"],
            deleted: false,
        }])
        .await;
        let (applied, deleted, cookie) =
            ad_dirsync_once(&db, &ad_config(addr), "dc=example,dc=com")
                .await
                .unwrap();
        assert_eq!(applied, 1);
        assert_eq!(deleted, 0);
        assert!(!cookie.is_empty(), "the DirSync cookie must be persisted");

        // A subsequent pass tombstones the same object (same objectGUID).
        let addr2 = fake_ad(vec![AdObj {
            dn: format!("{dn}\\0ADEL:deadbeef"),
            guid,
            classes: vec!["top"],
            deleted: true,
        }])
        .await;
        let (applied2, deleted2, _) = ad_dirsync_once(&db, &ad_config(addr2), "dc=example,dc=com")
            .await
            .unwrap();
        assert_eq!(applied2, 0);
        assert_eq!(deleted2, 1, "isDeleted object must delete by objectGUID");
    }
}
