//! Client error types.

use thiserror::Error;

/// Errors emitted by the client.
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("config error: {0}")]
    Config(String),

    #[error("identity error: {0}")]
    Identity(String),

    #[error("http error: {0}")]
    Http(String),

    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("relay error: {0}")]
    Relay(String),

    #[error("websocket error: {0}")]
    WebSocket(String),

    #[error("session rejected by host: {0}")]
    SessionRejected(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("invalid base64: {0}")]
    Base64(String),
}

/// Result alias used throughout the client.
pub type ClientResult<T> = Result<T, ClientError>;
