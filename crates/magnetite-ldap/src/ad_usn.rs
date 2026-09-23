//! AD/Samba import by **USN polling** — an ordinary paged LDAP search that
//! tracks `uSNChanged`. Unlike DirSync (which Samba only grants to accounts
//! holding the "Replicating Directory Changes" right), this works with a plain
//! read-only account: it enumerates users + groups with SimplePagedResults and
//! records the highest `uSNChanged` seen; the next pass fetches only objects
//! whose `uSNChanged` is greater (an incremental refresh).
//!
//! Scope: additions and modifications, read-only, one-way. Deletions are not
//! seen (a tombstone in `CN=Deleted Objects` needs the Show-Deleted control and
//! access a read-only account usually lacks); use DirSync/USN with a privileged
//! account, or accept that removed AD objects linger locally until re-synced.

use crate::ad_map::{normalize_ad_entry, AdMapOpts};
use crate::codec::GuardedLdapCodec;
use anyhow::{bail, Result};
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

const PAGE_SIZE: i64 = 500;
/// Backstop against a server whose paged cookie never empties.
const MAX_PAGES: usize = 100_000;

/// Attributes fetched for each imported object.
fn wanted_attrs() -> Vec<String> {
    [
        "objectGUID",
        "objectClass",
        "sAMAccountName",
        "cn",
        "name",
        "displayName",
        "mail",
        "userPrincipalName",
        "memberOf",
        "userAccountControl",
        "uSNChanged",
        "objectSid",
        "primaryGroupID",
        "sn",
        "givenName",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// Filter matching AD user accounts and groups; when `since` > 0, only objects
/// changed after it (`uSNChanged >= since+1`).
fn changed_filter(since: u64) -> LdapFilter {
    let objects = LdapFilter::Or(vec![
        LdapFilter::And(vec![
            LdapFilter::Equality("objectClass".into(), "user".into()),
            LdapFilter::Equality("objectCategory".into(), "person".into()),
        ]),
        LdapFilter::Equality("objectCategory".into(), "group".into()),
    ]);
    if since > 0 {
        LdapFilter::And(vec![
            objects,
            LdapFilter::GreaterOrEqual("uSNChanged".into(), (since + 1).to_string()),
        ])
    } else {
        objects
    }
}

/// One USN-polling refresh (incremental): fetch and apply objects changed since
/// the stored cursor. Returns `(applied, 0, new_cookie)`.
pub async fn ad_usn_once(
    db: &Db,
    config: &LdapConsumerConfig,
    base_dn: &str,
) -> Result<(u64, u64, String)> {
    ad_usn_pass(db, config, base_dn, false).await
}

/// A reconciliation refresh: enumerate **all** users/groups, apply them, then
/// delete local AD-sourced entries whose object is no longer present upstream
/// (deletion detection without needing AD tombstone access). Returns
/// `(applied, deleted, new_cookie)`.
pub async fn ad_usn_reconcile(
    db: &Db,
    config: &LdapConsumerConfig,
    base_dn: &str,
) -> Result<(u64, u64, String)> {
    ad_usn_pass(db, config, base_dn, true).await
}

/// The shared USN pass. When `reconcile`, the search is a full enumeration and
/// upstream ids are collected to drive deletion of absent local entries.
async fn ad_usn_pass(
    db: &Db,
    config: &LdapConsumerConfig,
    base_dn: &str,
    reconcile: bool,
) -> Result<(u64, u64, String)> {
    let base = config
        .base_dn
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| base_dn.to_string());
    let last_usn: u64 = db
        .get_ldap_sync_state()
        .await?
        .cookie
        .trim()
        .parse()
        .unwrap_or(0);

    // Connect, upgrading to TLS for an `ldaps://` upstream so the bind (which
    // carries `bind_password`) and the pulled directory data never go in the clear.
    let stream = crate::client_tls::connect(config).await?;
    let mut framed = Framed::new(stream, GuardedLdapCodec::default());

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

    // A reconciliation pass enumerates everything (no uSNChanged filter).
    let filter = if reconcile {
        changed_filter(0)
    } else {
        changed_filter(last_usn)
    };
    let attrs = wanted_attrs();
    let opts = AdMapOpts {
        posix: config.posix_mapping(),
        uid_base: config.posix_uid_base(),
        gid_base: config.posix_gid_base(),
    };
    let mut applied = 0u64;
    let mut max_usn = last_usn;
    let mut page_cookie: Vec<u8> = Vec::new();
    let mut msgid = 2;
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    for _ in 0..MAX_PAGES {
        framed
            .send(LdapMsg::new_with_ctrls(
                msgid,
                LdapOp::SearchRequest(LdapSearchRequest {
                    base: base.clone(),
                    scope: LdapSearchScope::Subtree,
                    aliases: LdapDerefAliases::Never,
                    sizelimit: 0,
                    timelimit: 0,
                    typesonly: false,
                    filter: filter.clone(),
                    attrs: attrs.clone(),
                }),
                vec![LdapControl::SimplePagedResults {
                    size: PAGE_SIZE,
                    cookie: page_cookie.clone(),
                }],
            ))
            .await?;
        msgid += 1;

        let mut next_cookie: Option<Vec<u8>> = None;
        let mut completed = false;
        while let Some(item) = framed.next().await {
            let m = item?;
            match m.op {
                LdapOp::SearchResultEntry(entry) => {
                    if let Some(u) = usn_changed(&entry) {
                        if u > max_usn {
                            max_usn = u;
                        }
                    }
                    let n = normalize_ad_entry(&entry, &opts);
                    if let Some(guid) = n.guid {
                        if reconcile {
                            seen.insert(guid.clone());
                        }
                        db.apply_ldap_sync_entry(
                            &entry.dn,
                            &guid,
                            n.object_classes,
                            &n.attributes,
                            n.enabled,
                        )
                        .await?;
                        applied += 1;
                    }
                }
                LdapOp::SearchResultDone(res) => {
                    if res.code != LdapResultCode::Success {
                        bail!("paged search rejected: {:?} {}", res.code, res.message);
                    }
                    next_cookie = paged_cookie(&m.ctrl);
                    completed = true;
                    break;
                }
                LdapOp::SearchResultReference(_) => {}
                LdapOp::IntermediateResponse(_) => {}
                _ => {}
            }
        }
        if !completed {
            bail!("provider closed the connection before completing the paged search");
        }
        match next_cookie {
            Some(c) if !c.is_empty() => page_cookie = c,
            _ => break, // no more pages
        }
    }

    let _ = framed
        .send(LdapMsg::new(msgid, LdapOp::UnbindRequest))
        .await;

    // Reconcile deletions: any local AD-sourced id not seen upstream has been
    // removed. Guard against wiping everything if the enumeration came back empty
    // (a transient/misconfigured state) — a real directory always has objects.
    let mut deleted = 0u64;
    if reconcile && !seen.is_empty() {
        for uuid in db.ldap_imported_uuids().await? {
            if !seen.contains(&uuid) && db.apply_ldap_sync_delete(&uuid).await? {
                deleted += 1;
            }
        }
    }
    Ok((applied, deleted, max_usn.to_string()))
}

/// The `uSNChanged` of an entry as a `u64`, if present and numeric.
fn usn_changed(entry: &LdapSearchResultEntry) -> Option<u64> {
    entry
        .attributes
        .iter()
        .find(|a| a.atype.eq_ignore_ascii_case("uSNChanged"))
        .and_then(|a| a.vals.first())
        .and_then(|v| std::str::from_utf8(v).ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
}

/// The continuation cookie of a SimplePagedResults control on a response, if any.
fn paged_cookie(ctrls: &[LdapControl]) -> Option<Vec<u8>> {
    ctrls.iter().find_map(|c| match c {
        LdapControl::SimplePagedResults { cookie, .. } => Some(cookie.clone()),
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

    fn result(code: LdapResultCode, message: &str) -> LdapResult {
        LdapResult {
            code,
            matcheddn: String::new(),
            message: message.to_string(),
            referral: vec![],
        }
    }

    fn entry(sid: i32, guid: [u8; 16], sam: &str, usn: u64) -> LdapMsg {
        LdapMsg::new(
            sid,
            LdapOp::SearchResultEntry(LdapSearchResultEntry {
                dn: format!("CN={sam},OU=Users,DC=corp,DC=example,DC=com"),
                attributes: vec![
                    LdapPartialAttribute {
                        atype: "objectGUID".into(),
                        vals: vec![guid.to_vec()],
                    },
                    LdapPartialAttribute {
                        atype: "objectClass".into(),
                        vals: vec![b"top".to_vec(), b"person".to_vec(), b"user".to_vec()],
                    },
                    LdapPartialAttribute {
                        atype: "sAMAccountName".into(),
                        vals: vec![sam.as_bytes().to_vec()],
                    },
                    LdapPartialAttribute {
                        atype: "uSNChanged".into(),
                        vals: vec![usn.to_string().into_bytes()],
                    },
                ],
            }),
        )
    }

    fn paged_done(sid: i32, cookie: &[u8]) -> LdapMsg {
        LdapMsg::new_with_ctrls(
            sid,
            LdapOp::SearchResultDone(result(LdapResultCode::Success, "")),
            vec![LdapControl::SimplePagedResults {
                size: 0,
                cookie: cookie.to_vec(),
            }],
        )
    }

    /// Fake provider serving two pages then an empty continuation cookie.
    async fn fake_ad_usn() -> SocketAddr {
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
            let mut page = 0;
            while let Some(Ok(msg)) = framed.next().await {
                let sid = msg.msgid;
                match msg.op {
                    LdapOp::UnbindRequest => break,
                    LdapOp::SearchRequest(_) => {
                        page += 1;
                        if page == 1 {
                            let _ = framed.send(entry(sid, [1u8; 16], "alice", 10)).await;
                            let _ = framed.send(paged_done(sid, b"page2")).await;
                        } else if page == 2 {
                            let _ = framed.send(entry(sid, [2u8; 16], "bob", 20)).await;
                            let _ = framed.send(paged_done(sid, b"")).await;
                        } else {
                            let _ = framed.send(paged_done(sid, b"")).await;
                        }
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

    fn usn_config(addr: SocketAddr) -> LdapConsumerConfig {
        // The fake provider is loopback plaintext ldap://; the sync binds with a
        // password, which the connect() guard refuses over plaintext unless allowed.
        // A real deployment sets this on a trusted network (or uses ldaps://).
        std::env::set_var("MAGNETITE_LDAP_ALLOW_PLAINTEXT", "1");
        LdapConsumerConfig {
            enabled: true,
            provider_url: format!("ldap://{addr}"),
            bind_dn: "svc@corp.example.com".into(),
            bind_password: "pw".into(),
            base_dn: Some("DC=corp,DC=example,DC=com".into()),
            interval_secs: None,
            mode: Some("ad-usn".into()),
            dirsync_flags: None,
            posix_mapping: None,
            posix_uid_base: None,
            posix_gid_base: None,
            reconcile_deletions: None,
            reconcile_every: None,
        }
    }

    #[tokio::test]
    async fn ad_usn_pages_and_tracks_highest_usn() {
        let (db, _dir) = test_db().await;
        let addr = fake_ad_usn().await;
        let (applied, deleted, cookie) = ad_usn_once(&db, &usn_config(addr), "dc=x").await.unwrap();
        assert_eq!(applied, 2, "both pages' objects are imported");
        assert_eq!(deleted, 0);
        assert_eq!(cookie, "20", "cookie is the highest uSNChanged seen");
    }

    /// Fake provider serving exactly `guid`/`sam` on the first search, then empty.
    async fn fake_ad_single(guid: [u8; 16]) -> SocketAddr {
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
                            let _ = framed.send(entry(sid, guid, "alice", 30)).await;
                        }
                        let _ = framed.send(paged_done(sid, b"")).await;
                    }
                    _ => {}
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn reconcile_deletes_local_entries_absent_upstream() {
        use std::collections::BTreeMap;
        let (db, _dir) = test_db().await;
        // Two locally-imported AD entries; upstream will only still have `a`.
        let guid_a = "01".repeat(16); // hex of [1u8; 16]
        let guid_b = "02".repeat(16);
        let attrs = BTreeMap::new();
        db.apply_ldap_sync_entry(
            "CN=alice,DC=corp,DC=example,DC=com",
            &guid_a,
            vec!["top".into(), "inetOrgPerson".into()],
            &attrs,
            true,
        )
        .await
        .unwrap();
        db.apply_ldap_sync_entry(
            "CN=bob,DC=corp,DC=example,DC=com",
            &guid_b,
            vec!["top".into(), "inetOrgPerson".into()],
            &attrs,
            true,
        )
        .await
        .unwrap();

        let addr = fake_ad_single([1u8; 16]).await;
        let (_applied, deleted, _cookie) = ad_usn_reconcile(&db, &usn_config(addr), "dc=x")
            .await
            .unwrap();
        assert_eq!(deleted, 1, "bob, absent upstream, is reconciled away");

        let remaining = db.ldap_imported_uuids().await.unwrap();
        assert!(remaining.contains(&guid_a), "alice is kept");
        assert!(!remaining.contains(&guid_b), "bob is gone");
    }
}
