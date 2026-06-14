//! Core error types for the RivetLink platform.

use thiserror::Error;

/// Top-level error type shared across RivetLink crates.
#[derive(Debug, Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("invalid identifier: {0}")]
    InvalidId(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Convenience alias for `Result<T, rivetlink_core::Error>`.
pub type Result<T> = std::result::Result<T, Error>;
