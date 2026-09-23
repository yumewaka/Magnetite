//! Mail management screens (S-MAIL-01..07).

pub mod aliases;
pub mod backup_mx;
pub mod dashboard;
pub mod dkim;
pub mod domains;
pub mod mailing_lists;
pub mod messages;
pub mod nav;
pub mod protocols;
pub mod relay;
pub mod replication;
pub mod settings;
pub mod users;

pub use aliases::AliasesPage;
pub use backup_mx::BackupMxPage;
pub use dashboard::MailDashboard;
pub use dkim::DkimPage;
pub use domains::DomainsPage;
pub use mailing_lists::MailingListsPage;
pub use messages::MessagesPage;
pub use protocols::ProtocolsPage;
pub use relay::MailRelayPage;
pub use replication::MailReplicationPage;
pub use settings::MailSettingsPage;
pub use users::MailUsersPage;
