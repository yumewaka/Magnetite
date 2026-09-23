//! Mail domain: data model (07_data_mail) and write-time validation
//! (screen_mail §5). Pure and shared by the UI and the DB layer.

pub mod model;
pub mod validate;

pub use model::{
    Alias, MailDomain, MailProtocol, MailServerConfig, MailUser, MailingList, MailingListMember,
    ProtocolConfig, ReplyPolicy,
};
