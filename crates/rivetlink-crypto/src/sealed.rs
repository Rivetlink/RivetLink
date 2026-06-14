//! Authenticated encryption channel over a derived session key.
//!
//! Wraps ChaCha20-Poly1305 (AEAD) keyed by a 32-byte secret produced by
//! [`crate::session_keys`] (or the hybrid KEX). Each [`SealedChannel::seal`]
//! call generates a fresh random 96-bit nonce and prepends it to the
//! ciphertext, so callers never manage nonces themselves.
//!
//! The derived ECDH secret is run through HKDF-SHA256 with a domain-separation
//! label before being used as the AEAD key — never use a raw DH output as a
//! cipher key directly.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand_08::rngs::OsRng;
use rand_08::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::{CryptoError, CryptoResult};

const NONCE_LEN: usize = 12;
const SEALED_KDF_INFO: &[u8] = b"rivetlink-sealed-channel-v1";

/// A symmetric AEAD channel keyed by a derived session secret.
pub struct SealedChannel {
    key: [u8; 32],
}

impl std::fmt::Debug for SealedChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedChannel").finish_non_exhaustive()
    }
}

impl SealedChannel {
    /// Derive an AEAD key from a raw 32-byte ECDH shared secret via HKDF-SHA256.
    ///
    /// Both peers must call this with the same shared secret to interoperate.
    pub fn from_shared_secret(shared: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(None, shared);
        let mut key = [0u8; 32];
        // expand never fails for a 32-byte output length.
        let _ = hk.expand(SEALED_KDF_INFO, &mut key);
        Self { key }
    }

    /// Encrypt `plaintext`, returning `nonce || ciphertext`.
    pub fn seal(&self, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));

        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::Encryption(e.to_string()))?;

        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt a `nonce || ciphertext` blob produced by [`SealedChannel::seal`].
    pub fn open(&self, sealed: &[u8]) -> CryptoResult<Vec<u8>> {
        if sealed.len() < NONCE_LEN {
            return Err(CryptoError::Decryption("sealed message too short".to_string()));
        }
        let (nonce_bytes, ciphertext) = sealed.split_at(NONCE_LEN);

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| CryptoError::Decryption(e.to_string()))
    }
}

impl Drop for SealedChannel {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel() -> SealedChannel {
        SealedChannel::from_shared_secret(&[7u8; 32])
    }

    #[test]
    fn seal_then_open_roundtrips() {
        let ch = channel();
        let msg = b"top secret screenshot bytes";
        let sealed = ch.seal(msg).unwrap();
        let opened = ch.open(&sealed).unwrap();
        assert_eq!(opened, msg);
    }

    #[test]
    fn same_shared_secret_interoperates() {
        let shared = [42u8; 32];
        let a = SealedChannel::from_shared_secret(&shared);
        let b = SealedChannel::from_shared_secret(&shared);
        let sealed = a.seal(b"hello").unwrap();
        assert_eq!(b.open(&sealed).unwrap(), b"hello");
    }

    #[test]
    fn different_secrets_cannot_open() {
        let a = SealedChannel::from_shared_secret(&[1u8; 32]);
        let b = SealedChannel::from_shared_secret(&[2u8; 32]);
        let sealed = a.seal(b"hello").unwrap();
        assert!(b.open(&sealed).is_err());
    }

    #[test]
    fn nonce_is_unique_per_seal() {
        let ch = channel();
        let s1 = ch.seal(b"same").unwrap();
        let s2 = ch.seal(b"same").unwrap();
        // First 12 bytes are the nonce; they must differ.
        assert_ne!(s1[..NONCE_LEN], s2[..NONCE_LEN]);
        // And therefore the full ciphertexts differ too.
        assert_ne!(s1, s2);
    }

    #[test]
    fn tampered_ciphertext_fails_auth() {
        let ch = channel();
        let mut sealed = ch.seal(b"integrity matters").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0xff;
        assert!(ch.open(&sealed).is_err());
    }

    #[test]
    fn truncated_message_rejected() {
        let ch = channel();
        assert!(ch.open(&[0u8; 4]).is_err());
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let ch = channel();
        let sealed = ch.seal(b"").unwrap();
        assert_eq!(ch.open(&sealed).unwrap(), b"");
    }
}
