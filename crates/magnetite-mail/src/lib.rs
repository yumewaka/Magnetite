//! `magnetite-mail` — the in-process SMTP receiving server (09b §-1, Phase E4).
//!
//! Ported from the old `service-integration` mail-project onto the shared
//! magnetite-db. A hand-rolled minimal ESMTP dialog (no external SMTP-server
//! library); Magnetite owns the recipient policy. Exposed as a [`MailService`]
//! implementing `magnetite_db::EmbeddedService`.

mod conn;
mod dkim;
mod dsn;
pub mod imap;
mod line;
pub mod pop3;
mod relay;
pub mod resolver;
pub mod service;
mod spf;
mod tls;

pub use dkim::{dkim_txt_from_private_pem, generate_dkim_key, DkimKeyMaterial};
pub use relay::send_mail;
pub use service::MailService;
