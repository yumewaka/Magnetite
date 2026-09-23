//! Database layer errors.

use thiserror::Error;

/// Errors from the persistence layer.
#[derive(Debug, Error)]
pub enum DbError {
    #[error("database error: {0}")]
    Surreal(#[from] surrealdb::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("password hashing failed: {0}")]
    PasswordHash(String),

    #[error("constraint violated: {0}")]
    Constraint(String),

    #[error("schema migration failed: {0}")]
    Migration(String),

    #[error("record not found")]
    NotFound,
}

/// Convenience alias for database results.
pub type DbResult<T> = Result<T, DbError>;
