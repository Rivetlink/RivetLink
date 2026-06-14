//! ML-DSA-65 post-quantum digital signatures (FIPS 204).

use crate::{CryptoError, CryptoResult};
use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{MlDsa65, Seed, Signature, SigningKey, VerifyingKey};
use rand::RngExt;

/// A post-quantum identity based on ML-DSA-65 signing and verification.
pub struct PqIdentity {
    signing_key: SigningKey<MlDsa65>,
}

impl std::fmt::Debug for PqIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqIdentity").finish_non_exhaustive()
    }
}

impl PqIdentity {
    /// Generates a new random ML-DSA-65 post-quantum identity.
    pub fn generate() -> Self {
        let mut rng = rand::rng();
        let seed_bytes: [u8; 32] = rng.random();
        let seed = Seed::from(seed_bytes);
        let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
        Self { signing_key }
    }

    /// Derives an ML-DSA-65 identity from a fixed 32-byte seed for deterministic key generation.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let seed = Seed::from(*seed);
        let signing_key = SigningKey::<MlDsa65>::from_seed(&seed);
        Self { signing_key }
    }

    /// Returns the verifying key for this post-quantum identity.
    pub fn verifying_key(&self) -> VerifyingKey<MlDsa65> {
        self.signing_key.verifying_key().clone()
    }

    /// Signs a message with this identity's ML-DSA-65 private key.
    pub fn sign(&self, message: &[u8]) -> Signature<MlDsa65> {
        self.signing_key.sign(message)
    }

    /// Verifies a post-quantum signature using the provided verifying key.
    pub fn verify(
        verifying_key: &VerifyingKey<MlDsa65>,
        message: &[u8],
        signature: &Signature<MlDsa65>,
    ) -> CryptoResult<()> {
        verifying_key
            .verify(message, signature)
            .map_err(|_| CryptoError::InvalidPqSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pq_sign_and_verify() {
        let identity = PqIdentity::generate();
        let message = b"test challenge nonce";

        let signature = identity.sign(message);
        let vk = identity.verifying_key();

        assert!(PqIdentity::verify(&vk, message, &signature).is_ok());
    }

    #[test]
    fn pq_reject_invalid_signature() {
        let identity_a = PqIdentity::generate();
        let identity_b = PqIdentity::generate();
        let message = b"test challenge nonce";

        let signature = identity_a.sign(message);
        let wrong_key = identity_b.verifying_key();

        assert!(matches!(
            PqIdentity::verify(&wrong_key, message, &signature),
            Err(CryptoError::InvalidPqSignature)
        ));
    }

    #[test]
    fn pq_reject_tampered_message() {
        let identity = PqIdentity::generate();
        let message = b"original message";
        let tampered = b"tampered message";

        let signature = identity.sign(message);
        let vk = identity.verifying_key();

        assert!(matches!(
            PqIdentity::verify(&vk, tampered, &signature),
            Err(CryptoError::InvalidPqSignature)
        ));
    }

    #[test]
    fn pq_deterministic_from_seed() {
        let seed = [42u8; 32];
        let id_a = PqIdentity::from_seed(&seed);
        let id_b = PqIdentity::from_seed(&seed);

        let msg = b"test";
        let sig_a = id_a.sign(msg);
        let vk_b = id_b.verifying_key();

        assert!(PqIdentity::verify(&vk_b, msg, &sig_a).is_ok());
    }
}
