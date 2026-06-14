//! ML-KEM-768 post-quantum key encapsulation mechanism (FIPS 203).

use ml_kem::kem::Decapsulate;
use ml_kem::MlKem768;
use ml_kem::{Ciphertext, DecapsulationKey, Encapsulate, EncapsulationKey, Generate};
use zeroize::Zeroize;

/// An ML-KEM-768 key pair for post-quantum key encapsulation.
pub struct PqKeyPair {
    decaps_key: DecapsulationKey<MlKem768>,
}

impl std::fmt::Debug for PqKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqKeyPair").finish_non_exhaustive()
    }
}

impl PqKeyPair {
    /// Generates a new random ML-KEM-768 key pair.
    pub fn generate() -> Self {
        let decaps_key = DecapsulationKey::<MlKem768>::generate();
        Self { decaps_key }
    }

    /// Returns the public encapsulation key for this key pair.
    pub fn encapsulation_key(&self) -> EncapsulationKey<MlKem768> {
        self.decaps_key.encapsulation_key().clone()
    }

    /// Decapsulates a ciphertext to recover the shared secret.
    pub fn decapsulate(&self, ciphertext: &Ciphertext<MlKem768>) -> PqSharedSecret {
        let shared = self.decaps_key.decapsulate(ciphertext);
        PqSharedSecret {
            bytes: *shared.as_ref(),
        }
    }
}

/// Encapsulates a shared secret using the provided public encapsulation key.
pub fn encapsulate(
    encaps_key: &EncapsulationKey<MlKem768>,
) -> (Ciphertext<MlKem768>, PqSharedSecret) {
    let mut rng = rand::rng();
    let (ct, shared) = encaps_key.encapsulate_with_rng(&mut rng);
    let secret = PqSharedSecret {
        bytes: *shared.as_ref(),
    };
    (ct, secret)
}

/// A 32-byte post-quantum shared secret from ML-KEM-768.
pub struct PqSharedSecret {
    bytes: [u8; 32],
}

impl std::fmt::Debug for PqSharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqSharedSecret").finish_non_exhaustive()
    }
}

impl PqSharedSecret {
    /// Returns a reference to the 32-byte shared secret.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }
}

impl Drop for PqSharedSecret {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pq_kem_encapsulate_decapsulate() {
        let kp = PqKeyPair::generate();
        let ek = kp.encapsulation_key();

        let (ct, sender_secret) = encapsulate(&ek);
        let receiver_secret = kp.decapsulate(&ct);

        assert_eq!(sender_secret.as_bytes(), receiver_secret.as_bytes());
    }

    #[test]
    fn different_keypairs_produce_different_secrets() {
        let kp_a = PqKeyPair::generate();
        let kp_b = PqKeyPair::generate();

        let ek_a = kp_a.encapsulation_key();
        let ek_b = kp_b.encapsulation_key();

        let (_ct_a, secret_a) = encapsulate(&ek_a);
        let (_ct_b, secret_b) = encapsulate(&ek_b);

        assert_ne!(secret_a.as_bytes(), secret_b.as_bytes());
    }

    #[test]
    fn shared_secret_is_32_bytes() {
        let kp = PqKeyPair::generate();
        let ek = kp.encapsulation_key();
        let (_ct, secret) = encapsulate(&ek);
        assert_eq!(secret.as_bytes().len(), 32);
    }
}
