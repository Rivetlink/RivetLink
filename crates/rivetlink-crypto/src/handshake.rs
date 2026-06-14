//! Authenticated ephemeral key exchange for establishing a [`SealedChannel`].
//!
//! Both peers generate an ephemeral x25519 keypair and sign the public key
//! with their long-term Ed25519 identity. The signature binds the ephemeral
//! key to a known identity, so a relay that merely forwards bytes cannot
//! substitute its own ephemeral key (MITM) without also forging an identity
//! signature.
//!
//! Flow:
//! 1. each side calls [`start`] → gets its ephemeral public key + signature to send
//! 2. on receiving the peer's message, call [`verify_peer`] against the peer's
//!    (already-trusted) identity key
//! 3. call [`LocalKeyExchange::into_channel`] with the peer's ephemeral key to
//!    derive the shared [`SealedChannel`]

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use x25519_dalek::PublicKey as X25519Public;

use crate::sealed::SealedChannel;
use crate::session_keys::SessionKeyPair;
use crate::{CryptoError, CryptoResult};

/// One side's in-progress key exchange state.
pub struct LocalKeyExchange {
    keypair: SessionKeyPair,
    ephemeral_public: [u8; 32],
    signature: [u8; 64],
}

impl std::fmt::Debug for LocalKeyExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalKeyExchange")
            .field("ephemeral_public", &self.ephemeral_public)
            .finish_non_exhaustive()
    }
}

/// Begin a key exchange: generate an ephemeral keypair and sign its public
/// key with the long-term identity.
pub fn start(identity: &SigningKey) -> LocalKeyExchange {
    let keypair = SessionKeyPair::generate();
    let ephemeral_public = *keypair.public_key().as_bytes();
    let signature = identity.sign(&ephemeral_public).to_bytes();
    LocalKeyExchange {
        keypair,
        ephemeral_public,
        signature,
    }
}

impl LocalKeyExchange {
    /// The ephemeral x25519 public key bytes to transmit to the peer.
    pub fn ephemeral_public(&self) -> &[u8; 32] {
        &self.ephemeral_public
    }

    /// The Ed25519 signature over the ephemeral key, to transmit to the peer.
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Consume this exchange and derive the shared [`SealedChannel`] using the
    /// peer's ephemeral public key.
    pub fn into_channel(self, peer_ephemeral: &[u8; 32]) -> SealedChannel {
        let peer_public = X25519Public::from(*peer_ephemeral);
        let shared = self.keypair.derive_shared_secret(&peer_public);
        SealedChannel::from_shared_secret(shared.as_bytes())
    }
}

/// Verify the peer's signature over their ephemeral key against their trusted
/// identity public key.
pub fn verify_peer(
    peer_identity: &VerifyingKey,
    peer_ephemeral: &[u8; 32],
    peer_signature: &[u8; 64],
) -> CryptoResult<()> {
    let sig = Signature::from_bytes(peer_signature);
    peer_identity
        .verify(peer_ephemeral, &sig)
        .map_err(|_| CryptoError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_08::rngs::OsRng;
    use rand_08::RngCore;

    fn identity() -> SigningKey {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        SigningKey::from_bytes(&seed)
    }

    #[test]
    fn both_sides_derive_same_channel() {
        let client_id = identity();
        let host_id = identity();

        let client = start(&client_id);
        let host = start(&host_id);

        // Each verifies the other's signed ephemeral key.
        verify_peer(
            &host_id.verifying_key(),
            host.ephemeral_public(),
            host.signature(),
        )
        .expect("client verifies host");
        verify_peer(
            &client_id.verifying_key(),
            client.ephemeral_public(),
            client.signature(),
        )
        .expect("host verifies client");

        let client_eph = *client.ephemeral_public();
        let host_eph = *host.ephemeral_public();

        let client_ch = client.into_channel(&host_eph);
        let host_ch = host.into_channel(&client_eph);

        let sealed = client_ch.seal(b"frame bytes").unwrap();
        assert_eq!(host_ch.open(&sealed).unwrap(), b"frame bytes");
    }

    #[test]
    fn rejects_forged_ephemeral_key() {
        let real_id = identity();
        let real = start(&real_id);

        // Relay swaps the ephemeral key but cannot re-sign with the identity.
        let mut forged = *real.ephemeral_public();
        forged[0] ^= 0xff;

        assert!(matches!(
            verify_peer(&real_id.verifying_key(), &forged, real.signature()),
            Err(CryptoError::InvalidSignature)
        ));
    }

    #[test]
    fn rejects_wrong_identity() {
        let real_id = identity();
        let attacker_id = identity();
        let exchange = start(&real_id);

        assert!(matches!(
            verify_peer(
                &attacker_id.verifying_key(),
                exchange.ephemeral_public(),
                exchange.signature(),
            ),
            Err(CryptoError::InvalidSignature)
        ));
    }
}
