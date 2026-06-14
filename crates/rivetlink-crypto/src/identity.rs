//! Ed25519-based device identity for classical authentication.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_08::rngs::OsRng;
use rand_08::RngCore;
use zeroize::Zeroize;

use crate::{CryptoError, CryptoResult};

/// A device identity based on Ed25519 signing and verification.
pub struct DeviceIdentity {
    signing_key: SigningKey,
}

impl std::fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("public_key", &self.signing_key.verifying_key())
            .finish_non_exhaustive()
    }
}

impl DeviceIdentity {
    /// Generates a new random Ed25519 device identity.
    pub fn generate() -> Self {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        secret.zeroize();
        Self { signing_key }
    }

    /// Returns the public key for this device identity.
    pub fn public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Signs a message with this device's private key.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Verifies a signature using the provided public key.
    pub fn verify(
        public_key: &VerifyingKey,
        message: &[u8],
        signature: &Signature,
    ) -> CryptoResult<()> {
        public_key
            .verify(message, signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

impl Drop for DeviceIdentity {
    fn drop(&mut self) {
        self.signing_key.to_bytes().zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let identity = DeviceIdentity::generate();
        let message = b"test challenge nonce";

        let signature = identity.sign(message);
        let public_key = identity.public_key();

        assert!(DeviceIdentity::verify(&public_key, message, &signature).is_ok());
    }

    #[test]
    fn reject_invalid_signature() {
        let identity_a = DeviceIdentity::generate();
        let identity_b = DeviceIdentity::generate();
        let message = b"test challenge nonce";

        let signature = identity_a.sign(message);
        let wrong_key = identity_b.public_key();

        assert!(matches!(
            DeviceIdentity::verify(&wrong_key, message, &signature),
            Err(CryptoError::InvalidSignature)
        ));
    }

    #[test]
    fn reject_tampered_message() {
        let identity = DeviceIdentity::generate();
        let message = b"original message";
        let tampered = b"tampered message";

        let signature = identity.sign(message);
        let public_key = identity.public_key();

        assert!(matches!(
            DeviceIdentity::verify(&public_key, tampered, &signature),
            Err(CryptoError::InvalidSignature)
        ));
    }
}
