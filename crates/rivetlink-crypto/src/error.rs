//! Cryptographic error types.

use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// A signature verification failed.
    #[error("invalid signature")]
    InvalidSignature,

    /// A nonce or challenge has expired (typically >30 seconds old).
    #[error("nonce expired")]
    NonceExpired,

    /// A nonce has already been used in a prior operation.
    #[error("nonce already used")]
    NonceReused,

    /// A public key is not authorized or recognized.
    #[error("untrusted public key")]
    UntrustedKey,

    /// Key generation failed with the provided error message.
    #[error("key generation failed: {0}")]
    KeyGeneration(String),

    /// Encryption operation failed with the provided error message.
    #[error("encryption failed: {0}")]
    Encryption(String),

    /// Decryption operation failed with the provided error message.
    #[error("decryption failed: {0}")]
    Decryption(String),

    /// The authenticated transport sequence was replayed, skipped, or
    /// reordered. Ordered RivetLink transports deliberately reject this rather
    /// than accepting a potentially stale privileged input event.
    #[error("replayed or out-of-order packet (expected sequence {expected}, received {received})")]
    ReplayOrOutOfOrder { expected: u64, received: u64 },

    /// A directional AEAD sequence reached its hard limit. A fresh handshake
    /// is required rather than ever risking nonce reuse.
    #[error("sealed-channel nonce sequence exhausted")]
    NonceExhausted,

    /// The encrypted wire envelope belongs to an unsupported protocol version.
    #[error("unsupported sealed-channel wire version")]
    UnsupportedWireVersion,

    /// HKDF output derivation unexpectedly failed.
    #[error("session key derivation failed")]
    KeyDerivation,

    /// Post-quantum key encapsulation (ML-KEM) failed.
    #[error("post-quantum key encapsulation failed")]
    PqEncapsulation,

    /// Post-quantum key decapsulation (ML-KEM) failed.
    #[error("post-quantum decapsulation failed")]
    PqDecapsulation,

    /// Hybrid key derivation failed.
    #[error("hybrid key derivation failed")]
    HybridKeyDerivation,

    /// A post-quantum signature (ML-DSA) verification failed.
    #[error("invalid post-quantum signature")]
    InvalidPqSignature,

    /// The requested cryptographic suite is not supported.
    #[error("crypto suite not supported: {0}")]
    UnsupportedSuite(String),

    /// Password-authenticated key agreement (PAKE) failed. Deliberately gives
    /// no detail (wrong password vs malformed message) to avoid an oracle.
    #[error("password authentication failed")]
    PakeFailed,
}

/// Convenience type alias for cryptographic operation results.
pub type CryptoResult<T> = std::result::Result<T, CryptoError>;
