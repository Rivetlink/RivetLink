//! Cryptographic primitives for RivetLink device authentication and key exchange.
//!
//! This crate provides Ed25519 device identities, x25519 ephemeral key exchange,
//! nonce-based challenge-response, and optional post-quantum hybrid signatures
//! and key encapsulation (ML-KEM-768 and ML-DSA-65) when the "post-quantum" feature is enabled.

pub mod challenge;
pub mod error;
pub mod handshake;
pub mod identity;
pub mod sealed;
pub mod session_keys;

#[cfg(feature = "post-quantum")]
pub mod pq_kem;

#[cfg(feature = "post-quantum")]
pub mod pq_identity;

#[cfg(feature = "post-quantum")]
pub mod hybrid;

pub use error::{CryptoError, CryptoResult};
