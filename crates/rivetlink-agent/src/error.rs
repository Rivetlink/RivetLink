//! Agent error types.

use thiserror::Error;

/// Errors emitted by the agent runtime.
#[derive(Debug, Error)]
pub enum AgentError {
    #[error("config error: {0}")]
    Config(String),

    #[error("keystore error: {0}")]
    Keystore(String),

    #[error("relay connection error: {0}")]
    Relay(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("invalid base64: {0}")]
    Base64(String),

    #[error("websocket error: {0}")]
    WebSocket(String),

    #[error("direct-LAN error: {0}")]
    Lan(String),
}

/// Result alias used throughout the agent.
pub type AgentResult<T> = Result<T, AgentError>;
