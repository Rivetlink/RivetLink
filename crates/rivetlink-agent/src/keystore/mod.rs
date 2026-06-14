//! Agent keystore: persists the host's long-term signing and key-exchange keys.
//!
//! Today only a file-backed implementation exists. Platform keychain backends
//! (macOS Keychain, Windows DPAPI, Linux Secret Service) plug in here later.

pub mod file;

use async_trait::async_trait;

use crate::error::AgentResult;

/// Ed25519 signing keypair material as raw bytes.
#[derive(Debug, Clone)]
pub struct SigningKey {
    pub secret: [u8; 32],
    pub public: [u8; 32],
}

/// X25519 ECDH keypair material as raw bytes.
#[derive(Debug, Clone)]
pub struct EncryptionKey {
    pub secret: [u8; 32],
    pub public: [u8; 32],
}

/// Storage abstraction. Implementations must persist keys durably and refuse
/// to overwrite existing keys without an explicit reset.
#[async_trait]
pub trait KeyStore: Send + Sync {
    /// Returns the host's signing key, generating it the first time.
    async fn ensure_signing_key(&self) -> AgentResult<SigningKey>;

    /// Returns the host's X25519 key, generating it the first time.
    async fn ensure_encryption_key(&self) -> AgentResult<EncryptionKey>;

    /// Wipe all stored material. Used for re-enrollment.
    async fn reset(&self) -> AgentResult<()>;
}
