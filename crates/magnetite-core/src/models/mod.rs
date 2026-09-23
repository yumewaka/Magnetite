//! Shared data structures for the integrated platform (07 §3).
//!
//! Cross-cutting structures (audit, alert, template, backup, accounts,
//! sessions, status, logs) live here and are referenced by every domain via a
//! `DomainKey` attribute rather than being re-declared per domain.

pub mod account;
pub mod alert;
pub mod audit;
pub mod common;
pub mod ops;
pub mod settings;

pub use account::{
    CurrentUser, LocalAccount, LocalAccountInfo, OidcTokenResponse, Session, SessionInfo,
};
pub use alert::{Alert, NotificationTarget};
pub use audit::{AuditEntry, AuditPage, NewAuditEntry};
pub use common::{
    ActionKind, AlertState, AuthMethod, BackupKind, HealthState, LogKind, LogLevel, NotifyKind,
    OpResult, RecordMeta, Severity,
};
pub use ops::{Backup, DomainStatus, LogEntry, Template};
pub use settings::{DomainToggle, SsoSettings, SystemSettings};
