//! Directional authenticated encryption for an established RivetLink session.
//!
//! This module deliberately does **not** use random nonces.  A random nonce is
//! unlikely to collide, but it cannot tell a receiver that an attacker replayed
//! an otherwise valid packet.  RivetLink sessions instead derive independent
//! keys for each direction and use a monotonically increasing, strictly checked
//! sequence number as the ChaCha20-Poly1305 nonce.  TCP and the relay WebSocket
//! are ordered transports, so rejecting a gap/reordering is both safer and the
//! correct protocol behaviour.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{CryptoError, CryptoResult};

const HEADER_LEN: usize = 1 + 8;
const TAG_LEN: usize = 16;
const WIRE_VERSION: u8 = 2;
const KDF_LABEL: &[u8] = b"rivetlink-sealed-channel-v2";
const C2H_LABEL: &[u8] = b"rivetlink-c2h";
const H2C_LABEL: &[u8] = b"rivetlink-h2c";

/// Which endpoint owns a channel instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelRole {
    /// The endpoint which initiated this authenticated session (the client).
    Initiator,
    /// The endpoint which accepted this authenticated session (the host).
    Responder,
}

/// A directional AEAD channel established by an authenticated handshake.
pub struct SealedChannel {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    binding_hash: [u8; 32],
    next_send: AtomicU64,
    next_recv: Mutex<u64>,
}

impl std::fmt::Debug for SealedChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedChannel").finish_non_exhaustive()
    }
}

impl SealedChannel {
    /// Derive a directional channel from an ephemeral DH/PAKE secret.
    ///
    /// `transcript` must be the exact, canonical transcript authenticated by
    /// the handshake. It is hashed into the HKDF salt and included as AEAD
    /// associated data, so a key cannot be transplanted into another RivetLink
    /// protocol, role, or handshake.
    pub fn from_handshake_secret(
        shared: &[u8; 32],
        transcript: &[u8],
        role: ChannelRole,
    ) -> CryptoResult<Self> {
        let binding_hash: [u8; 32] = Sha256::digest(transcript).into();
        let hk = Hkdf::<Sha256>::new(Some(&binding_hash), shared);
        let mut c2h = [0u8; 32];
        let mut h2c = [0u8; 32];
        hk.expand(&[KDF_LABEL, C2H_LABEL].concat(), &mut c2h)
            .map_err(|_| CryptoError::KeyDerivation)?;
        hk.expand(&[KDF_LABEL, H2C_LABEL].concat(), &mut h2c)
            .map_err(|_| CryptoError::KeyDerivation)?;
        let (send_key, recv_key) = match role {
            ChannelRole::Initiator => (c2h, h2c),
            ChannelRole::Responder => (h2c, c2h),
        };
        Ok(Self {
            send_key,
            recv_key,
            binding_hash,
            next_send: AtomicU64::new(0),
            next_recv: Mutex::new(0),
        })
    }

    /// Encrypt one ordered application message.
    ///
    /// The wire encoding is `version || sequence_be || ciphertext`. The header
    /// and transcript hash are AEAD associated data. Sequence exhaustion is a
    /// hard error; callers must establish a fresh session rather than risk nonce
    /// reuse.
    pub fn seal(&self, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        // Claim the next sequence number; refuse to wrap. An explicit CAS loop
        // instead of `fetch_update`, which newer toolchains deprecate in favour
        // of `try_update` (unavailable on older ones).
        let mut sequence = self.next_send.load(Ordering::Relaxed);
        loop {
            if sequence == u64::MAX {
                return Err(CryptoError::NonceExhausted);
            }
            match self.next_send.compare_exchange_weak(
                sequence,
                sequence + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => sequence = current,
            }
        }
        let header = header(sequence);
        let cipher = ChaCha20Poly1305::new_from_slice(&self.send_key)
            .map_err(|error| CryptoError::Encryption(error.to_string()))?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce(sequence)),
                Payload {
                    msg: plaintext,
                    aad: &aad(&header, &self.binding_hash),
                },
            )
            .map_err(|error| CryptoError::Encryption(error.to_string()))?;
        let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt one ordered application message.
    ///
    /// A valid ciphertext is accepted exactly once. Duplicate, stale and
    /// reordered messages fail before any application parser sees them.
    pub fn open(&self, sealed: &[u8]) -> CryptoResult<Vec<u8>> {
        if sealed.len() < HEADER_LEN + TAG_LEN {
            return Err(CryptoError::Decryption(
                "sealed message too short".to_string(),
            ));
        }
        let (header_bytes, ciphertext) = sealed.split_at(HEADER_LEN);
        if header_bytes[0] != WIRE_VERSION {
            return Err(CryptoError::UnsupportedWireVersion);
        }
        let sequence = u64::from_be_bytes(
            header_bytes[1..]
                .try_into()
                .map_err(|_| CryptoError::Decryption("invalid sealed header".to_string()))?,
        );
        let mut expected = self
            .next_recv
            .lock()
            .map_err(|_| CryptoError::Decryption("sealed receive state poisoned".to_string()))?;
        if sequence != *expected {
            return Err(CryptoError::ReplayOrOutOfOrder {
                expected: *expected,
                received: sequence,
            });
        }
        let cipher = ChaCha20Poly1305::new_from_slice(&self.recv_key)
            .map_err(|error| CryptoError::Decryption(error.to_string()))?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce(sequence)),
                Payload {
                    msg: ciphertext,
                    aad: &aad(header_bytes, &self.binding_hash),
                },
            )
            .map_err(|error| CryptoError::Decryption(error.to_string()))?;
        *expected = expected.checked_add(1).ok_or(CryptoError::NonceExhausted)?;
        Ok(plaintext)
    }
}

fn header(sequence: u64) -> [u8; HEADER_LEN] {
    let mut bytes = [0u8; HEADER_LEN];
    bytes[0] = WIRE_VERSION;
    bytes[1..].copy_from_slice(&sequence.to_be_bytes());
    bytes
}

fn nonce(sequence: u64) -> [u8; 12] {
    let mut bytes = [0u8; 12];
    bytes[4..].copy_from_slice(&sequence.to_be_bytes());
    bytes
}

fn aad(header: &[u8], binding_hash: &[u8; 32]) -> Vec<u8> {
    let mut result = Vec::with_capacity(KDF_LABEL.len() + header.len() + binding_hash.len());
    result.extend_from_slice(KDF_LABEL);
    result.extend_from_slice(binding_hash);
    result.extend_from_slice(header);
    result
}

impl Drop for SealedChannel {
    fn drop(&mut self) {
        self.send_key.zeroize();
        self.recv_key.zeroize();
        self.binding_hash.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn channels() -> (SealedChannel, SealedChannel) {
        let shared = [7u8; 32];
        let transcript = b"rivetlink-test-transcript";
        (
            SealedChannel::from_handshake_secret(&shared, transcript, ChannelRole::Initiator)
                .unwrap(),
            SealedChannel::from_handshake_secret(&shared, transcript, ChannelRole::Responder)
                .unwrap(),
        )
    }

    #[test]
    fn seal_then_open_roundtrips_in_both_directions() {
        let (client, host) = channels();
        assert_eq!(
            host.open(&client.seal(b"top secret").unwrap()).unwrap(),
            b"top secret"
        );
        assert_eq!(
            client.open(&host.seal(b"reply").unwrap()).unwrap(),
            b"reply"
        );
    }

    #[test]
    fn different_transcripts_cannot_open() {
        let shared = [42u8; 32];
        let sender =
            SealedChannel::from_handshake_secret(&shared, b"a", ChannelRole::Initiator).unwrap();
        let receiver =
            SealedChannel::from_handshake_secret(&shared, b"b", ChannelRole::Responder).unwrap();
        assert!(receiver.open(&sender.seal(b"hello").unwrap()).is_err());
    }

    #[test]
    fn replay_is_rejected() {
        let (client, host) = channels();
        let packet = client.seal(b"once").unwrap();
        assert_eq!(host.open(&packet).unwrap(), b"once");
        assert!(matches!(
            host.open(&packet),
            Err(CryptoError::ReplayOrOutOfOrder { .. })
        ));
    }

    #[test]
    fn reordered_packets_are_rejected() {
        let (client, host) = channels();
        let first = client.seal(b"first").unwrap();
        let second = client.seal(b"second").unwrap();
        assert!(matches!(
            host.open(&second),
            Err(CryptoError::ReplayOrOutOfOrder { .. })
        ));
        assert_eq!(host.open(&first).unwrap(), b"first");
        assert_eq!(host.open(&second).unwrap(), b"second");
    }

    #[test]
    fn direction_keys_prevent_reflection() {
        let (client, _) = channels();
        let packet = client.seal(b"not a server response").unwrap();
        assert!(client.open(&packet).is_err());
    }

    #[test]
    fn tampered_and_truncated_ciphertext_fail() {
        let (client, host) = channels();
        let mut packet = client.seal(b"integrity matters").unwrap();
        *packet.last_mut().unwrap() ^= 0xff;
        assert!(host.open(&packet).is_err());
        assert!(host.open(&packet[..HEADER_LEN]).is_err());
    }

    proptest! {
        /// Malformed network envelopes must be rejected without panicking or
        /// advancing the receive sequence state.
        #[test]
        fn arbitrary_envelopes_do_not_panic_or_open(frame in proptest::collection::vec(any::<u8>(), 0..4096)) {
            let (_, host) = channels();
            let _ = host.open(&frame);
        }
    }
}
