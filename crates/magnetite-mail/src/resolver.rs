//! Recipient resolution for the embedded SMTP server (E4 / 08 mail logic).
//!
//! [`resolve_recipient`] is **pure** over a [`Snapshot`] of the mail config, so
//! the accept/reject policy (local user, alias expansion, relay denial, unknown
//! mailbox) is unit-testable without sockets. The `service` module loads the
//! snapshot and applies the decision during the SMTP dialog.

use magnetite_core::domains::mail::model::{
    Alias, BackupMxDomain, MailDomain, MailUser, MailingList,
};

/// The mail config needed to route an inbound recipient.
#[derive(Clone, Default)]
pub struct Snapshot {
    pub domains: Vec<MailDomain>,
    pub users: Vec<MailUser>,
    pub aliases: Vec<Alias>,
    pub lists: Vec<MailingList>,
    pub backups: Vec<BackupMxDomain>,
}

/// The decision for one `RCPT TO` address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recipient {
    /// Accept and deliver to these local mailbox addresses (alias-expanded).
    Deliver(Vec<String>),
    /// The domain is a backup-MX domain: accept and queue the message for
    /// forwarding to the primary at `host:port`.
    Backup {
        rcpt: String,
        host: String,
        port: u16,
    },
    /// The address's domain is not one we host — relaying is refused.
    RelayDenied,
    /// The domain is local but no such mailbox/alias exists.
    Unknown,
}

fn normalize(addr: &str) -> String {
    addr.trim()
        .trim_start_matches('<')
        .trim_end_matches('>')
        .trim()
        .to_ascii_lowercase()
}

fn domain_of(addr: &str) -> Option<&str> {
    addr.rsplit_once('@').map(|(_, d)| d)
}

impl Snapshot {
    fn hosts_domain(&self, domain: &str) -> bool {
        self.domains
            .iter()
            .any(|d| d.enabled && d.name.eq_ignore_ascii_case(domain))
    }

    fn is_local_user(&self, addr: &str) -> bool {
        self.users
            .iter()
            .any(|u| u.enabled && u.email.eq_ignore_ascii_case(addr))
    }

    /// The enabled backup-MX entry for `domain`, if we are its secondary MX.
    fn backup_for(&self, domain: &str) -> Option<&BackupMxDomain> {
        self.backups
            .iter()
            .find(|b| b.enabled && b.name.eq_ignore_ascii_case(domain))
    }
}

/// Decide how to handle `rcpt`. Alias destinations are expanded one level; only
/// destinations that are local mailboxes are delivered (external forwarding is
/// a relay concern deferred to a later increment).
pub fn resolve_recipient(snapshot: &Snapshot, rcpt: &str) -> Recipient {
    let addr = normalize(rcpt);
    let Some(domain) = domain_of(&addr) else {
        return Recipient::Unknown;
    };
    if !snapshot.hosts_domain(domain) {
        // Not a hosted domain: if we are its backup MX, accept for queueing.
        if let Some(backup) = snapshot.backup_for(domain) {
            return Recipient::Backup {
                rcpt: addr,
                host: backup.primary_host.clone(),
                port: backup.primary_port,
            };
        }
        return Recipient::RelayDenied;
    }
    if snapshot.is_local_user(&addr) {
        return Recipient::Deliver(vec![addr]);
    }
    if let Some(alias) = snapshot
        .aliases
        .iter()
        .find(|a| a.enabled && a.source_address.eq_ignore_ascii_case(&addr))
    {
        let locals: Vec<String> = alias
            .destination_addresses
            .iter()
            .map(|d| normalize(d))
            .filter(|d| snapshot.is_local_user(d))
            .collect();
        return Recipient::Deliver(locals);
    }
    // Mailing list: deliver to local members that opted to receive.
    if let Some(list) = snapshot
        .lists
        .iter()
        .find(|l| l.enabled && l.address.eq_ignore_ascii_case(&addr))
    {
        let locals: Vec<String> = list
            .members
            .iter()
            .filter(|m| m.receive)
            .map(|m| normalize(&m.email))
            .filter(|e| snapshot.is_local_user(e))
            .collect();
        return Recipient::Deliver(locals);
    }
    Recipient::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use magnetite_core::domains::mail::model::MailRole;

    fn domain(name: &str, enabled: bool) -> MailDomain {
        MailDomain {
            id: format!("d:{name}"),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "t".into(),
            name: name.into(),
            enabled,
            max_users: None,
            default_quota_bytes: None,
        }
    }

    fn user(email: &str) -> MailUser {
        let (local, dom) = email.split_once('@').unwrap();
        MailUser {
            id: format!("u:{email}"),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "t".into(),
            local_part: local.into(),
            domain_ref: format!("d:{dom}"),
            email: email.into(),
            display_name: None,
            mail_role: MailRole::User,
            quota_bytes: 0,
            used_bytes: 0,
            enabled: true,
        }
    }

    fn alias(source: &str, dests: &[&str]) -> Alias {
        Alias {
            id: format!("a:{source}"),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "t".into(),
            source_address: source.into(),
            domain_ref: "d".into(),
            destination_addresses: dests.iter().map(|s| s.to_string()).collect(),
            enabled: true,
        }
    }

    fn list(address: &str, members: &[(&str, bool)]) -> MailingList {
        use magnetite_core::domains::mail::model::{MailingListMember, ReplyPolicy};
        MailingList {
            id: format!("l:{address}"),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "t".into(),
            address: address.into(),
            domain_ref: "d".into(),
            name: address.into(),
            description: None,
            owner_ref: "u".into(),
            members: members
                .iter()
                .map(|(email, receive)| MailingListMember {
                    email: email.to_string(),
                    name: None,
                    receive: *receive,
                    can_post: true,
                })
                .collect(),
            reply_policy: ReplyPolicy::List,
            enabled: true,
        }
    }

    fn snapshot() -> Snapshot {
        Snapshot {
            domains: vec![domain("example.com", true)],
            users: vec![user("alice@example.com"), user("bob@example.com")],
            aliases: vec![
                alias(
                    "team@example.com",
                    &["alice@example.com", "bob@example.com"],
                ),
                alias("ext@example.com", &["someone@other.org"]),
            ],
            lists: vec![list(
                "all@example.com",
                &[("alice@example.com", true), ("bob@example.com", false)],
            )],
            backups: vec![backup("backup.example", "mx1.remote.test", 25)],
        }
    }

    fn backup(name: &str, host: &str, port: u16) -> BackupMxDomain {
        BackupMxDomain {
            id: format!("b:{name}"),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            created_by: "t".into(),
            name: name.into(),
            primary_host: host.into(),
            primary_port: port,
            enabled: true,
        }
    }

    #[test]
    fn local_user_delivers() {
        assert_eq!(
            resolve_recipient(&snapshot(), "<Alice@example.com>"),
            Recipient::Deliver(vec!["alice@example.com".into()])
        );
    }

    #[test]
    fn alias_expands_to_local_destinations() {
        assert_eq!(
            resolve_recipient(&snapshot(), "team@example.com"),
            Recipient::Deliver(vec!["alice@example.com".into(), "bob@example.com".into()])
        );
    }

    #[test]
    fn alias_to_external_delivers_nothing_locally() {
        assert_eq!(
            resolve_recipient(&snapshot(), "ext@example.com"),
            Recipient::Deliver(vec![])
        );
    }

    #[test]
    fn mailing_list_delivers_to_receiving_members() {
        // Only members with receive=true and a local mailbox are delivered.
        assert_eq!(
            resolve_recipient(&snapshot(), "all@example.com"),
            Recipient::Deliver(vec!["alice@example.com".into()])
        );
    }

    #[test]
    fn foreign_domain_is_relay_denied() {
        assert_eq!(
            resolve_recipient(&snapshot(), "user@other.org"),
            Recipient::RelayDenied
        );
    }

    #[test]
    fn unknown_local_mailbox() {
        assert_eq!(
            resolve_recipient(&snapshot(), "ghost@example.com"),
            Recipient::Unknown
        );
    }

    #[test]
    fn backup_mx_domain_is_queued_to_primary() {
        assert_eq!(
            resolve_recipient(&snapshot(), "<User@Backup.Example>"),
            Recipient::Backup {
                rcpt: "user@backup.example".into(),
                host: "mx1.remote.test".into(),
                port: 25,
            }
        );
    }
}
