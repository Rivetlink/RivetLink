//! ML-KEM-768 post-quantum key encapsulation mechanism (FIPS 203).

use ml_kem::kem::Decapsulate;
use ml_kem::MlKem768;
use ml_kem::{
    Ciphertext, DecapsulationKey, Encapsulate, EncapsulationKey, Generate, Key, KeyExport,
};
use zeroize::Zeroize;

use crate::{CryptoError, CryptoResult};

/// Encoded size of an ML-KEM-768 encapsulation (public) key.
pub const ENCAPSULATION_KEY_LEN: usize = 1184;
/// Encoded size of an ML-KEM-768 ciphertext.
pub const CIPHERTEXT_LEN: usize = 1088;

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

    /// The encoded encapsulation key to send to the peer.
    pub fn encapsulation_key_bytes(&self) -> Vec<u8> {
        self.decaps_key.encapsulation_key().to_bytes().to_vec()
    }

    /// Decapsulate an encoded ciphertext from the peer. A ciphertext of the
    /// right size but tampered with yields an unrelated secret (implicit
    /// rejection), so the handshake's key confirmation then fails.
    pub fn decapsulate_bytes(&self, ciphertext: &[u8]) -> CryptoResult<PqSharedSecret> {
        let ciphertext = Ciphertext::<MlKem768>::try_from(ciphertext)
            .map_err(|_| CryptoError::PqDecapsulation)?;
        Ok(self.decapsulate(&ciphertext))
    }

    /// Decapsulates a ciphertext to recover the shared secret.
    pub fn decapsulate(&self, ciphertext: &Ciphertext<MlKem768>) -> PqSharedSecret {
        let mut shared = self.decaps_key.decapsulate(ciphertext);
        let secret = PqSharedSecret {
            bytes: *shared.as_ref(),
        };
        shared.zeroize();
        secret
    }
}

/// Encapsulates a shared secret using the provided public encapsulation key.
pub fn encapsulate(
    encaps_key: &EncapsulationKey<MlKem768>,
) -> (Ciphertext<MlKem768>, PqSharedSecret) {
    let mut rng = rand::rng();
    let (ct, mut shared) = encaps_key.encapsulate_with_rng(&mut rng);
    let secret = PqSharedSecret {
        bytes: *shared.as_ref(),
    };
    shared.zeroize();
    (ct, secret)
}

/// Encapsulate to the peer's encoded encapsulation key, which is validated
/// (FIPS 203 modulus check). Returns the encoded ciphertext to send back.
pub fn encapsulate_to(encapsulation_key: &[u8]) -> CryptoResult<(Vec<u8>, PqSharedSecret)> {
    let key = Key::<EncapsulationKey<MlKem768>>::try_from(encapsulation_key)
        .map_err(|_| CryptoError::PqEncapsulation)?;
    let key = EncapsulationKey::<MlKem768>::new(&key).map_err(|_| CryptoError::PqEncapsulation)?;
    let (ciphertext, secret) = encapsulate(&key);
    Ok((ciphertext.to_vec(), secret))
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
    fn encoded_keys_and_ciphertexts_roundtrip() {
        let kp = PqKeyPair::generate();
        let ek = kp.encapsulation_key_bytes();
        assert_eq!(ek.len(), ENCAPSULATION_KEY_LEN);
        let (ct, sender) = encapsulate_to(&ek).unwrap();
        assert_eq!(ct.len(), CIPHERTEXT_LEN);
        assert_eq!(
            kp.decapsulate_bytes(&ct).unwrap().as_bytes(),
            sender.as_bytes()
        );

        // Wrong sizes are rejected; a tampered ciphertext gives another secret.
        assert!(encapsulate_to(&ek[1..]).is_err());
        assert!(kp.decapsulate_bytes(&ct[1..]).is_err());
        let mut tampered = ct;
        tampered[0] ^= 1;
        assert_ne!(
            kp.decapsulate_bytes(&tampered).unwrap().as_bytes(),
            sender.as_bytes()
        );
    }

    #[test]
    fn shared_secret_is_32_bytes() {
        let kp = PqKeyPair::generate();
        let ek = kp.encapsulation_key();
        let (_ct, secret) = encapsulate(&ek);
        assert_eq!(secret.as_bytes().len(), 32);
    }
}
