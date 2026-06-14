//! Ephemeral x25519 key exchange for session establishment.

use rand_08::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroize;

/// An ephemeral x25519 key pair for Diffie-Hellman key exchange.
pub struct SessionKeyPair {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl std::fmt::Debug for SessionKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeyPair")
            .field("public", &self.public.as_bytes())
            .finish_non_exhaustive()
    }
}

impl SessionKeyPair {
    /// Generates a new random ephemeral x25519 key pair.
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Returns a reference to the public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// Performs Diffie-Hellman with the peer's public key to derive a shared secret.
    pub fn derive_shared_secret(self, peer_public: &PublicKey) -> DerivedSessionKey {
        let shared = self.secret.diffie_hellman(peer_public);
        DerivedSessionKey {
            bytes: *shared.as_bytes(),
        }
    }
}

/// A 32-byte shared secret derived from Diffie-Hellman key exchange.
pub struct DerivedSessionKey {
    bytes: [u8; 32],
}

impl std::fmt::Debug for DerivedSessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerivedSessionKey").finish_non_exhaustive()
    }
}

impl DerivedSessionKey {
    /// Returns a reference to the 32-byte shared secret.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl Drop for DerivedSessionKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_exchange_produces_same_shared_secret() {
        let alice = SessionKeyPair::generate();
        let bob = SessionKeyPair::generate();

        let alice_public = *alice.public_key();
        let bob_public = *bob.public_key();

        let alice_shared = alice.derive_shared_secret(&bob_public);
        let bob_shared = bob.derive_shared_secret(&alice_public);

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn different_pairs_produce_different_secrets() {
        let alice = SessionKeyPair::generate();
        let bob = SessionKeyPair::generate();
        let eve = SessionKeyPair::generate();

        let bob_public = *bob.public_key();
        let eve_public = *eve.public_key();

        let shared_ab = alice.derive_shared_secret(&bob_public);
        let shared_be = bob.derive_shared_secret(&eve_public);

        assert_ne!(shared_ab.as_bytes(), shared_be.as_bytes());
    }
}
