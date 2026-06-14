//! Nonce-based challenge-response authentication with time-based expiry.
//!
//! [`Nonce`] is a one-off random challenge with a built-in expiry timestamp.
//! [`NonceStore`] is the server-side bookkeeping that prevents replay: every
//! issued nonce is recorded, and `consume()` returns `NonceReused` if the
//! same bytes are presented twice. Expired entries are lazily pruned on the
//! next `consume()`/`cleanup()` call.

use dashmap::DashMap;
use rand_08::rngs::OsRng;
use rand_08::RngCore;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::{CryptoError, CryptoResult};

const NONCE_SIZE: usize = 32;
const NONCE_EXPIRY: Duration = Duration::from_secs(30);

/// A random nonce with 30-second expiry for challenge-response protocols.
pub struct Nonce {
    bytes: [u8; NONCE_SIZE],
    created_at: Instant,
}

impl std::fmt::Debug for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Nonce")
            .field("created_at", &self.created_at)
            .field("expired", &self.is_expired())
            .finish_non_exhaustive()
    }
}

impl Nonce {
    /// Generates a new random 32-byte nonce with current timestamp.
    pub fn generate() -> Self {
        let mut bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut bytes);
        Self {
            bytes,
            created_at: Instant::now(),
        }
    }

    /// Returns a reference to the nonce bytes.
    pub fn as_bytes(&self) -> &[u8; NONCE_SIZE] {
        &self.bytes
    }

    /// Checks if the nonce is still valid (not expired).
    pub fn validate(&self) -> CryptoResult<()> {
        if self.created_at.elapsed() > NONCE_EXPIRY {
            return Err(CryptoError::NonceExpired);
        }
        Ok(())
    }

    /// Returns true if the nonce has expired (older than 30 seconds).
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > NONCE_EXPIRY
    }
}

/// Server-side replay-protection store for challenge nonces.
///
/// `issue()` returns a fresh nonce and records it; `consume()` removes the
/// nonce from the store, refusing the request if the nonce was never issued,
/// has already been consumed, or has expired. The store is internally
/// `Arc<DashMap<_, _>>` so it can be cloned freely across tasks.
#[derive(Debug, Clone)]
pub struct NonceStore {
    issued: Arc<DashMap<[u8; NONCE_SIZE], Instant>>,
    ttl: Duration,
}

impl Default for NonceStore {
    fn default() -> Self {
        Self::new(NONCE_EXPIRY)
    }
}

impl NonceStore {
    /// Build a store with a custom expiry. Use [`NonceStore::default`] for the
    /// 30-second default.
    pub fn new(ttl: Duration) -> Self {
        Self {
            issued: Arc::new(DashMap::new()),
            ttl,
        }
    }

    /// Generate, record, and return a new nonce.
    pub fn issue(&self) -> Nonce {
        let nonce = Nonce::generate();
        self.issued.insert(*nonce.as_bytes(), nonce.created_at);
        nonce
    }

    /// Atomically remove a nonce from the store, validating it was issued
    /// and has not yet expired.
    ///
    /// Returns `CryptoError::NonceReused` if the nonce was never issued or
    /// was already consumed, and `CryptoError::NonceExpired` if it lived too
    /// long.
    pub fn consume(&self, bytes: &[u8; NONCE_SIZE]) -> CryptoResult<()> {
        match self.issued.remove(bytes) {
            None => Err(CryptoError::NonceReused),
            Some((_, created_at)) => {
                if created_at.elapsed() > self.ttl {
                    Err(CryptoError::NonceExpired)
                } else {
                    Ok(())
                }
            },
        }
    }

    /// Drop entries that have aged past the TTL. Safe to call periodically
    /// from a background task; not required for correctness.
    pub fn cleanup_expired(&self) -> usize {
        let now = Instant::now();
        let ttl = self.ttl;
        let stale: Vec<_> = self
            .issued
            .iter()
            .filter(|e| now.duration_since(*e.value()) > ttl)
            .map(|e| *e.key())
            .collect();
        let removed = stale.len();
        for key in stale {
            self.issued.remove(&key);
        }
        removed
    }

    /// Current size for tests / metrics.
    pub fn pending(&self) -> usize {
        self.issued.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_is_random() {
        let a = Nonce::generate();
        let b = Nonce::generate();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn fresh_nonce_is_valid() {
        let nonce = Nonce::generate();
        assert!(nonce.validate().is_ok());
        assert!(!nonce.is_expired());
    }

    #[test]
    fn nonce_has_correct_size() {
        let nonce = Nonce::generate();
        assert_eq!(nonce.as_bytes().len(), 32);
    }

    #[test]
    fn store_issues_and_consumes() {
        let store = NonceStore::default();
        let nonce = store.issue();
        assert_eq!(store.pending(), 1);

        assert!(store.consume(nonce.as_bytes()).is_ok());
        assert_eq!(store.pending(), 0);
    }

    #[test]
    fn store_rejects_unknown_nonce() {
        let store = NonceStore::default();
        let bogus = [0u8; NONCE_SIZE];
        assert!(matches!(
            store.consume(&bogus),
            Err(CryptoError::NonceReused)
        ));
    }

    #[test]
    fn store_rejects_double_consume() {
        let store = NonceStore::default();
        let nonce = store.issue();
        store.consume(nonce.as_bytes()).unwrap();
        assert!(matches!(
            store.consume(nonce.as_bytes()),
            Err(CryptoError::NonceReused)
        ));
    }

    #[test]
    fn store_rejects_expired_nonce() {
        let store = NonceStore::new(Duration::from_millis(10));
        let nonce = store.issue();
        std::thread::sleep(Duration::from_millis(40));
        assert!(matches!(
            store.consume(nonce.as_bytes()),
            Err(CryptoError::NonceExpired)
        ));
        // Expired entry was still removed from the map.
        assert_eq!(store.pending(), 0);
    }

    #[test]
    fn cleanup_removes_only_expired() {
        let store = NonceStore::new(Duration::from_millis(20));
        let old = store.issue();
        std::thread::sleep(Duration::from_millis(50));
        let fresh = store.issue();

        let removed = store.cleanup_expired();
        assert_eq!(removed, 1);
        assert_eq!(store.pending(), 1);

        // The expired nonce is gone, the fresh one still works.
        assert!(matches!(
            store.consume(old.as_bytes()),
            Err(CryptoError::NonceReused)
        ));
        assert!(store.consume(fresh.as_bytes()).is_ok());
    }

    #[test]
    fn store_is_cheap_to_clone() {
        let a = NonceStore::default();
        let b = a.clone();
        let nonce = a.issue();
        // Same underlying Arc<DashMap>.
        assert!(b.consume(nonce.as_bytes()).is_ok());
        assert_eq!(a.pending(), 0);
    }
}
