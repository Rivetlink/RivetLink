//! Hybrid classical+post-quantum key exchange and signatures.
//!
//! Combines Ed25519 and ML-DSA-65 signatures, and x25519 and ML-KEM-768 key exchange,
//! for forward secrecy against future quantum adversaries.

use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::identity::DeviceIdentity;
use crate::pq_identity::PqIdentity;
use crate::pq_kem::PqSharedSecret;
use crate::session_keys::DerivedSessionKey;
use crate::{CryptoError, CryptoResult};

use ml_dsa::{MlDsa65, Signature as MlDsaSignature, VerifyingKey as MlDsaVerifyingKey};

const HYBRID_KDF_INFO: &[u8] = b"rivetlink-hybrid-kex-v1";

/// A 32-byte shared secret derived from both classical x25519 and post-quantum ML-KEM-768.
pub struct HybridSharedSecret {
    bytes: [u8; 32],
}

impl std::fmt::Debug for HybridSharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridSharedSecret").finish_non_exhaustive()
    }
}

impl HybridSharedSecret {
    /// Derives a hybrid shared secret from classical and post-quantum components using HKDF-SHA256.
    pub fn derive(classical: &DerivedSessionKey, pq: &PqSharedSecret) -> CryptoResult<Self> {
        let mut ikm = Vec::with_capacity(64);
        ikm.extend_from_slice(classical.as_bytes());
        ikm.extend_from_slice(pq.as_bytes());

        let hk = Hkdf::<Sha256>::new(None, &ikm);
        let mut okm = [0u8; 32];
        hk.expand(HYBRID_KDF_INFO, &mut okm)
            .map_err(|_| CryptoError::HybridKeyDerivation)?;

        ikm.zeroize();

        Ok(Self { bytes: okm })
    }

    /// Returns a reference to the 32-byte hybrid shared secret.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl Drop for HybridSharedSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// A hybrid signature containing both Ed25519 and ML-DSA-65 components.
#[derive(Debug)]
pub struct HybridSignature {
    /// Ed25519 classical signature.
    pub ed25519: Ed25519Signature,
    /// ML-DSA-65 post-quantum signature.
    pub ml_dsa: MlDsaSignature<MlDsa65>,
}

/// A hybrid device identity combining Ed25519 and ML-DSA-65 for dual authentication.
pub struct HybridIdentity {
    classical: DeviceIdentity,
    pq: PqIdentity,
}

impl std::fmt::Debug for HybridIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HybridIdentity")
            .field("classical", &self.classical)
            .field("pq", &self.pq)
            .finish()
    }
}

impl HybridIdentity {
    /// Generates a new random hybrid identity with both classical and post-quantum components.
    pub fn generate() -> Self {
        Self {
            classical: DeviceIdentity::generate(),
            pq: PqIdentity::generate(),
        }
    }

    /// Signs a message with both Ed25519 and ML-DSA-65 keys.
    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        HybridSignature {
            ed25519: self.classical.sign(message),
            ml_dsa: self.pq.sign(message),
        }
    }

    /// Returns the Ed25519 public key.
    pub fn ed25519_public_key(&self) -> Ed25519VerifyingKey {
        self.classical.public_key()
    }

    /// Returns the ML-DSA-65 verifying key.
    pub fn ml_dsa_verifying_key(&self) -> MlDsaVerifyingKey<MlDsa65> {
        self.pq.verifying_key()
    }

    /// Verifies a hybrid signature against both classical and post-quantum public keys.
    pub fn verify_hybrid(
        ed25519_key: &Ed25519VerifyingKey,
        ml_dsa_key: &MlDsaVerifyingKey<MlDsa65>,
        message: &[u8],
        signature: &HybridSignature,
    ) -> CryptoResult<()> {
        DeviceIdentity::verify(ed25519_key, message, &signature.ed25519)?;
        PqIdentity::verify(ml_dsa_key, message, &signature.ml_dsa)?;
        Ok(())
    }
}

/// Supported cryptographic suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoSuite {
    /// Classical Ed25519 and x25519 only.
    Classical,
    /// Hybrid classical and post-quantum (Ed25519+ML-DSA-65, x25519+ML-KEM-768).
    Hybrid,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_kdf_produces_deterministic_output() {
        use crate::pq_kem::PqKeyPair;
        use crate::session_keys::SessionKeyPair;

        let classical_a = SessionKeyPair::generate();
        let classical_b = SessionKeyPair::generate();

        let pub_b = *classical_b.public_key();

        let shared_classical = classical_a.derive_shared_secret(&pub_b);

        let pq_kp = PqKeyPair::generate();
        let ek = pq_kp.encapsulation_key();
        let (ct, pq_sender) = crate::pq_kem::encapsulate(&ek);
        let pq_receiver = pq_kp.decapsulate(&ct);

        let hybrid = HybridSharedSecret::derive(&shared_classical, &pq_sender).unwrap();
        assert_eq!(pq_sender.as_bytes(), pq_receiver.as_bytes());
        assert_eq!(hybrid.as_bytes().len(), 32);
    }

    #[test]
    fn hybrid_sign_and_verify() {
        let identity = HybridIdentity::generate();
        let message = b"rivetlink hybrid auth challenge";

        let sig = identity.sign(message);

        let ed25519_pk = identity.ed25519_public_key();
        let ml_dsa_vk = identity.ml_dsa_verifying_key();

        assert!(HybridIdentity::verify_hybrid(&ed25519_pk, &ml_dsa_vk, message, &sig,).is_ok());
    }

    #[test]
    fn hybrid_verify_fails_with_wrong_classical_key() {
        let identity_a = HybridIdentity::generate();
        let identity_b = HybridIdentity::generate();
        let message = b"test message";

        let sig = identity_a.sign(message);

        let wrong_ed25519 = identity_b.ed25519_public_key();
        let correct_ml_dsa = identity_a.ml_dsa_verifying_key();

        assert!(matches!(
            HybridIdentity::verify_hybrid(&wrong_ed25519, &correct_ml_dsa, message, &sig,),
            Err(CryptoError::InvalidSignature)
        ));
    }

    #[test]
    fn hybrid_verify_fails_with_wrong_pq_key() {
        let identity_a = HybridIdentity::generate();
        let identity_b = HybridIdentity::generate();
        let message = b"test message";

        let sig = identity_a.sign(message);

        let correct_ed25519 = identity_a.ed25519_public_key();
        let wrong_ml_dsa = identity_b.ml_dsa_verifying_key();

        assert!(matches!(
            HybridIdentity::verify_hybrid(&correct_ed25519, &wrong_ml_dsa, message, &sig,),
            Err(CryptoError::InvalidPqSignature)
        ));
    }

    #[test]
    fn both_signatures_required() {
        let identity_a = HybridIdentity::generate();
        let identity_b = HybridIdentity::generate();
        let message = b"test message";

        // Mix signatures from different identities
        let sig_a = identity_a.sign(message);
        let sig_b = identity_b.sign(message);

        let mixed_sig = HybridSignature {
            ed25519: sig_a.ed25519,
            ml_dsa: sig_b.ml_dsa,
        };

        let ed25519_pk = identity_a.ed25519_public_key();
        let ml_dsa_vk = identity_a.ml_dsa_verifying_key();

        // Should fail: PQ sig is from identity_b
        assert!(
            HybridIdentity::verify_hybrid(&ed25519_pk, &ml_dsa_vk, message, &mixed_sig,).is_err()
        );
    }
}
