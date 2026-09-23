//! RFC 4533 syncrepl **consumer** (refreshOnly). This instance acts as a replica:
//! it connects to an upstream LDAP provider (another Magnetite or OpenLDAP),
//! binds, issues a search carrying a SyncRequest control with the stored cookie,
//! applies the returned add/modify/delete changes to the local directory, and
//! persists the new cookie.
//!
//! Scope: a basic refreshOnly refresh — `SyncState(Add|Modify|Present)` upserts an
//! entry and `SyncState(Delete)` removes it by entryUUID. The present-phase
//! deletion reconciliation and `SyncInfo` intermediate messages that some
//! providers use for large refreshes are not interpreted (ignored); this suffices
//! for a Magnetite provider and incremental OpenLDAP changes.

use crate::codec::GuardedLdapCodec;
use anyhow::{bail, Result};
use futures::{SinkExt, StreamExt};
use ldap3_proto::control::LdapControl;
use ldap3_proto::proto::{
    LdapBindCred, LdapBindRequest, LdapDerefAliases, LdapFilter, LdapMsg, LdapOp,
    LdapPartialAttribute, LdapSearchRequest, LdapSearchResultEntry, LdapSearchScope,
    SyncRequestMode, SyncStateValue,
};
use ldap3_proto::LdapResultCode;
use magnetite_core::LdapConsumerConfig;
use magnetite_db::Db;
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::watch;
use tokio_util::codec::Framed;

/// Spawn the consumer refresh loop: connect to the provider on `config.interval`,
/// apply changes, and persist the cursor + state. Ends on shutdown. `base_dn` is
/// the search base default when the consumer config leaves it unset.
pub fn spawn_consumer(
    db: Db,
    config: LdapConsumerConfig,
    base_dn: String,
    mut shutdown: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let interval = config.interval();
        let mut passno: u32 = 0;
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = tokio::time::sleep(Duration::from_secs(interval)) => {
                    // AD/Samba use DirSync (privileged) or USN polling (read-only);
                    // OpenLDAP uses RFC 4533 syncrepl. For USN, run a full deletion
                    // reconciliation every Nth pass when enabled.
                    let result = if config.is_ad_dirsync() {
                        crate::ad_dirsync::ad_dirsync_once(&db, &config, &base_dn).await
                    } else if config.is_ad_usn() {
                        if config.reconcile_deletions()
                            && passno.is_multiple_of(config.reconcile_every())
                        {
                            crate::ad_usn::ad_usn_reconcile(&db, &config, &base_dn).await
                        } else {
                            crate::ad_usn::ad_usn_once(&db, &config, &base_dn).await
                        }
                    } else {
                        sync_once(&db, &config, &base_dn).await
                    };
                    passno = passno.wrapping_add(1);
                    match result {
                        Ok((applied, deleted, cookie)) => {
                            let _ = db.record_ldap_sync(&cookie, applied, deleted, None).await;
                            if applied > 0 || deleted > 0 {
                                tracing::info!(
                                    "ldap syncrepl from {}: applied={applied} deleted={deleted}",
                                    config.provider_url
                                );
                            }
                        }
                        Err(e) => {
                            tracing::warn!("ldap syncrepl from {} failed: {e}", config.provider_url);
                            let cookie = db
                                .get_ldap_sync_state()
                                .await
                                .map(|s| s.cookie)
                                .unwrap_or_default();
                            let _ = db.record_ldap_sync(&cookie, 0, 0, Some(&e.to_string())).await;
                        }
                    }
                }
            }
        }
    });
}

/// One refresh pass: bind, search with the SyncRequest control, apply changes,
/// and return `(applied, deleted, new_cookie)`.
async fn sync_once(
    db: &Db,
    config: &LdapConsumerConfig,
    base_dn: &str,
) -> Result<(u64, u64, String)> {
    let cookie = db.get_ldap_sync_state().await?.cookie;
    let base = config
        .base_dn
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| base_dn.to_string());

    // Connect, upgrading to TLS for an `ldaps://` upstream so the bind (which
    // carries `bind_password`) and the replicated data never traverse plaintext.
    let stream = crate::client_tls::connect(config).await?;
    let mut framed = Framed::new(stream, GuardedLdapCodec::default());
    sync_dialog(db, config, base, cookie, &mut framed).await
}

/// The post-connect syncrepl dialog over an established (plaintext or TLS) stream:
/// bind, search with the SyncRequest control, apply the returned changes, and
/// return `(applied, deleted, new_cookie)`.
async fn sync_dialog<S>(
    db: &Db,
    config: &LdapConsumerConfig,
    base: String,
    cookie: String,
    framed: &mut Framed<S, GuardedLdapCodec>,
) -> Result<(u64, u64, String)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Bind (simple or anonymous).
    let bind = LdapMsg::new(
        1,
        LdapOp::BindRequest(LdapBindRequest {
            dn: config.bind_dn.clone(),
            cred: LdapBindCred::Simple(config.bind_password.clone()),
        }),
    );
    framed.send(bind).await?;
    match framed.next().await {
        Some(Ok(msg)) => match msg.op {
            LdapOp::BindResponse(r) if r.res.code == LdapResultCode::Success => {}
            LdapOp::BindResponse(r) => bail!("bind rejected: {:?} {}", r.res.code, r.res.message),
            other => bail!("expected bind response, got {other:?}"),
        },
        Some(Err(e)) => return Err(e.into()),
        None => bail!("connection closed before bind response"),
    }

    // Search the base subtree with a SyncRequest control carrying the cookie.
    let req = LdapSearchRequest {
        base,
        scope: LdapSearchScope::Subtree,
        aliases: LdapDerefAliases::Never,
        sizelimit: 0,
        timelimit: 0,
        typesonly: false,
        filter: LdapFilter::Present("objectClass".into()),
        attrs: vec!["*".into()],
    };
    let ctrl = LdapControl::SyncRequest {
        criticality: true,
        mode: SyncRequestMode::RefreshOnly,
        cookie: if cookie.is_empty() {
            None
        } else {
            Some(cookie.clone().into_bytes())
        },
        reload_hint: false,
    };
    framed
        .send(LdapMsg::new_with_ctrls(
            2,
            LdapOp::SearchRequest(req),
            vec![ctrl],
        ))
        .await?;

    let (mut applied, mut deleted) = (0u64, 0u64);
    let mut new_cookie = cookie;
    // The search is only complete on a SearchResultDone with a success code. A
    // provider that closes the connection early (e.g. an anonymous bind that is
    // not authorized to syncrepl, as Samba does) must be reported as a failure,
    // not silently recorded as an empty, successful refresh.
    let mut completed = false;
    while let Some(item) = framed.next().await {
        let msg = item?;
        match msg.op {
            LdapOp::SearchResultEntry(entry) => {
                if let Some((state, uuid)) = sync_state(&msg.ctrl) {
                    let uuid = uuid.to_string();
                    if state == SyncStateValue::Delete {
                        if db.apply_ldap_sync_delete(&uuid).await? {
                            deleted += 1;
                        }
                    } else {
                        let (object_classes, attributes) = split_entry(&entry);
                        db.apply_ldap_sync_entry(
                            &entry.dn,
                            &uuid,
                            object_classes,
                            &attributes,
                            true,
                        )
                        .await?;
                        applied += 1;
                    }
                }
            }
            LdapOp::SearchResultDone(res) => {
                if res.code != LdapResultCode::Success {
                    bail!(
                        "syncrepl search rejected by provider: {:?} {}",
                        res.code,
                        res.message
                    );
                }
                if let Some(c) = sync_done(&msg.ctrl) {
                    new_cookie = c;
                }
                completed = true;
                break;
            }
            // SyncInfo (intermediate) messages are not interpreted in this basic
            // refreshOnly consumer.
            LdapOp::IntermediateResponse(_) => {}
            _ => {}
        }
    }

    let _ = framed.send(LdapMsg::new(3, LdapOp::UnbindRequest)).await;
    if !completed {
        bail!("provider closed the connection before completing the search (no SearchResultDone)");
    }
    Ok((applied, deleted, new_cookie))
}

/// The `(state, entryUUID)` of a SyncState control on a response, if present.
fn sync_state(ctrls: &[LdapControl]) -> Option<(SyncStateValue, uuid::Uuid)> {
    ctrls.iter().find_map(|c| match c {
        LdapControl::SyncState {
            state, entry_uuid, ..
        } => Some((state.clone(), *entry_uuid)),
        _ => None,
    })
}

/// The cookie of a SyncDone control on a response, if present.
fn sync_done(ctrls: &[LdapControl]) -> Option<String> {
    ctrls.iter().find_map(|c| match c {
        LdapControl::SyncDone {
            cookie: Some(bytes),
            ..
        } => Some(String::from_utf8_lossy(bytes).to_string()),
        _ => None,
    })
}

/// Split a search-result entry into its object classes and remaining attributes.
fn split_entry(entry: &LdapSearchResultEntry) -> (Vec<String>, BTreeMap<String, Vec<String>>) {
    let mut object_classes = Vec::new();
    let mut attributes = BTreeMap::new();
    for LdapPartialAttribute { atype, vals } in &entry.attributes {
        let values: Vec<String> = vals
            .iter()
            .map(|v| String::from_utf8_lossy(v).to_string())
            .collect();
        if atype.eq_ignore_ascii_case("objectClass") {
            object_classes = values;
        } else {
            attributes.insert(atype.clone(), values);
        }
    }
    (object_classes, attributes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ldap3_proto::proto::{LdapBindResponse, LdapResult, LdapSearchResultEntry};
    use ldap3_proto::LdapCodec;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;

    /// Behaviour of a fake upstream LDAP provider after a successful bind + search.
    enum Behavior {
        /// Close the connection without a SearchResultDone (the Samba anonymous
        /// case: bind succeeds but the syncrepl search yields nothing and ends).
        CloseAfterBind,
        /// Return a SearchResultDone with a non-success result code.
        DoneFailure,
        /// Return one entry then a successful SearchResultDone.
        EntryThenDone,
    }

    fn result(code: LdapResultCode, message: &str) -> LdapResult {
        LdapResult {
            code,
            matcheddn: String::new(),
            message: message.to_string(),
            referral: vec![],
        }
    }

    /// Spawn a minimal LDAP provider that binds, reads one search, then behaves
    /// per `behavior`. Returns its address.
    async fn fake_provider(behavior: Behavior) -> SocketAddr {
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
            let Some(Ok(search)) = framed.next().await else {
                return;
            };
            let sid = search.msgid;
            match behavior {
                Behavior::CloseAfterBind => { /* drop framed → connection closes */ }
                Behavior::DoneFailure => {
                    let _ = framed
                        .send(LdapMsg::new(
                            sid,
                            LdapOp::SearchResultDone(result(
                                LdapResultCode::InsufficentAccessRights,
                                "not authorized for content sync",
                            )),
                        ))
                        .await;
                }
                Behavior::EntryThenDone => {
                    let entry = LdapMsg::new_with_ctrls(
                        sid,
                        LdapOp::SearchResultEntry(LdapSearchResultEntry {
                            dn: "uid=bob,dc=example,dc=com".into(),
                            attributes: vec![LdapPartialAttribute {
                                atype: "objectClass".into(),
                                vals: vec![b"inetOrgPerson".to_vec()],
                            }],
                        }),
                        vec![LdapControl::SyncState {
                            state: SyncStateValue::Add,
                            entry_uuid: uuid::Uuid::from_u128(1),
                            cookie: None,
                        }],
                    );
                    let _ = framed.send(entry).await;
                    let _ = framed
                        .send(LdapMsg::new(
                            sid,
                            LdapOp::SearchResultDone(result(LdapResultCode::Success, "")),
                        ))
                        .await;
                    let _ = framed.next().await; // absorb the client's unbind
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

    fn config(addr: SocketAddr) -> LdapConsumerConfig {
        LdapConsumerConfig {
            enabled: true,
            provider_url: format!("ldap://{addr}"),
            bind_dn: String::new(),
            bind_password: String::new(),
            base_dn: Some("dc=example,dc=com".into()),
            interval_secs: None,
            mode: None,
            dirsync_flags: None,
            posix_mapping: None,
            posix_uid_base: None,
            posix_gid_base: None,
            reconcile_deletions: None,
            reconcile_every: None,
        }
    }

    #[tokio::test]
    async fn errors_when_provider_closes_without_search_done() {
        let (db, _dir) = test_db().await;
        let addr = fake_provider(Behavior::CloseAfterBind).await;
        let result = sync_once(&db, &config(addr), "dc=example,dc=com").await;
        assert!(
            result.is_err(),
            "a connection closed before SearchResultDone must be an error, not a silent empty sync"
        );
    }

    #[tokio::test]
    async fn errors_on_non_success_search_done() {
        let (db, _dir) = test_db().await;
        let addr = fake_provider(Behavior::DoneFailure).await;
        let result = sync_once(&db, &config(addr), "dc=example,dc=com").await;
        assert!(
            result.is_err(),
            "a SearchResultDone with a failure code must be reported as an error"
        );
    }

    #[tokio::test]
    async fn applies_entries_on_successful_search_done() {
        let (db, _dir) = test_db().await;
        let addr = fake_provider(Behavior::EntryThenDone).await;
        let (applied, deleted, _cookie) = sync_once(&db, &config(addr), "dc=example,dc=com")
            .await
            .unwrap();
        assert_eq!(applied, 1);
        assert_eq!(deleted, 0);
    }
}
