//! Shared error taxonomy for the Magnetite core.
//!
//! These variants map directly onto the confirmed user-facing messages in the
//! specifications (AC-04 authz, 07 §5 referential integrity, S-00 validation).
//! Presentation layers translate the [`CoreError::message_key`] into localized
//! text; the message strings here are the Japanese source of truth (ja is
//! canonical per 06/10).

use thiserror::Error;

/// Errors produced by core domain logic (validation, authorization,
/// referential integrity). Server/UI layers convert these into localized
/// responses.
#[derive(Debug, Clone, Error)]
pub enum CoreError {
    /// The caller lacks the required role for the requested action (AC-04).
    #[error("この操作を行う権限がありません。")]
    Forbidden,

    /// No valid session — the request must re-authenticate (09 §6.5).
    #[error("認証が必要です。")]
    Unauthenticated,

    /// Input failed validation. Carries the confirmed field message.
    #[error("{0}")]
    Validation(String),

    /// A referenced entity blocks the operation (07 §5 delete guard).
    #[error("他の設定から参照されているため削除できません。")]
    ReferencedByOther,

    /// A uniqueness constraint was violated (S-00 §5).
    #[error("同じ名称が既に存在します。")]
    Duplicate,

    /// The requested entity does not exist.
    #[error("対象が見つかりません。")]
    NotFound,

    /// A persistence/backend failure that is not the caller's fault.
    #[error("{0}")]
    Backend(String),
}

impl CoreError {
    /// Stable i18n key for this error, for callers that want to localize rather
    /// than surface the canonical Japanese `Display` string.
    pub fn message_key(&self) -> &'static str {
        match self {
            CoreError::Forbidden => "error.forbidden",
            CoreError::Unauthenticated => "error.unauthenticated",
            CoreError::Validation(_) => "error.validation",
            CoreError::ReferencedByOther => "error.referenced",
            CoreError::Duplicate => "error.duplicate",
            CoreError::NotFound => "error.not_found",
            CoreError::Backend(_) => "error.backend",
        }
    }
}

/// Convenience alias for core results.
pub type CoreResult<T> = Result<T, CoreError>;
