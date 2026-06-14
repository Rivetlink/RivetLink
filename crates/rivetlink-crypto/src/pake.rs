//! Password-authenticated key agreement (SPAKE2) for direct LAN sessions.
//!
//! When two peers connect directly — no relay, no pre-pinned identity — a
//! shared password/PIN authenticates the channel. SPAKE2 turns the password
//! into a shared secret without ever sending it, and without letting a network
//! attacker brute-force it offline (a passive observer learns nothing; an
//! active attacker gets a single online guess per connection). The resulting
//! secret keys a [`SealedChannel`].
//!
//! ## Key confirmation
//!
//! SPAKE2 on its own derives a key but does not *confirm* it: with the wrong
//! password both sides still finish, they just end up with different keys. The
//! mismatch surfaces on the first [`SealedChannel::open`], which fails to
//! authenticate. Callers must therefore treat the first failed decrypt as
//! "wrong password" and abort — the sealed channel's AEAD tag is the
//! confirmation step.
//!
//! ```
//! use rivetlink_crypto::pake;
//!
//! // Both peers start with the same PIN and exchange their messages.
//! let a = pake::start(b"4821");
//! let b = pake::start(b"4821");
//! let chan_a = a.handshake.finish(&b.message).unwrap();
//! let chan_b = b.handshake.finish(&a.message).unwrap();
//!
//! // Matching PINs -> interoperable channel.
//! let sealed = chan_a.seal(b"hello").unwrap();
//! assert_eq!(chan_b.open(&sealed).unwrap(), b"hello");
//! ```

use spake2::{Ed25519Group, Identity, Password, Spake2};

use crate::error::{CryptoError, CryptoResult};
use crate::sealed::SealedChannel;

/// Domain-separation identity, so a SPAKE2 transcript from this protocol can't
/// be replayed into another that happens to use the same password.
const PAKE_IDENTITY: &[u8] = b"rivetlink-direct-pake-v1";

/// One side's started handshake: the in-progress SPAKE2 state plus the message
/// to hand to the peer.
pub struct Started {
    /// The SPAKE2 message to send to the peer.
    pub message: Vec<u8>,
    /// The state to drive to completion via [`Started::finish`].
    pub handshake: PakeHandshake,
}

/// In-progress password-authenticated handshake.
pub struct PakeHandshake {
    state: Spake2<Ed25519Group>,
}

impl std::fmt::Debug for Started {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Started")
            .field("message_len", &self.message.len())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for PakeHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PakeHandshake").finish_non_exhaustive()
    }
}

/// Begin a password-authenticated handshake. Both peers call this with the same
/// password, swap [`Started::message`], then call [`Started::handshake`]'s
/// [`PakeHandshake::finish`] with the peer's message.
pub fn start(password: &[u8]) -> Started {
    let (state, message) = Spake2::<Ed25519Group>::start_symmetric(
        &Password::new(password),
        &Identity::new(PAKE_IDENTITY),
    );
    Started {
        message,
        handshake: PakeHandshake { state },
    }
}

impl PakeHandshake {
    /// Complete the exchange with the peer's message, deriving a sealed channel.
    ///
    /// Returns [`CryptoError::PakeFailed`] only if the peer's message is
    /// malformed. A *wrong* password does not fail here — it yields a channel
    /// whose first [`SealedChannel::open`] will fail (see the module docs).
    pub fn finish(self, peer_message: &[u8]) -> CryptoResult<SealedChannel> {
        let key = self
            .state
            .finish(peer_message)
            .map_err(|_| CryptoError::PakeFailed)?;

        if key.len() != 32 {
            return Err(CryptoError::PakeFailed);
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&key);
        Ok(SealedChannel::from_shared_secret(&secret))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_password_interoperates() {
        let a = start(b"correct horse");
        let b = start(b"correct horse");
        let chan_a = a.handshake.finish(&b.message).unwrap();
        let chan_b = b.handshake.finish(&a.message).unwrap();

        let sealed = chan_a.seal(b"secret").unwrap();
        assert_eq!(chan_b.open(&sealed).unwrap(), b"secret");
    }

    #[test]
    fn wrong_password_yields_unusable_channel() {
        let a = start(b"1234");
        let b = start(b"9999");
        // Both finish (SPAKE2 derives a key regardless)…
        let chan_a = a.handshake.finish(&b.message).unwrap();
        let chan_b = b.handshake.finish(&a.message).unwrap();
        // …but the keys differ, so the AEAD tag fails to authenticate.
        let sealed = chan_a.seal(b"secret").unwrap();
        assert!(chan_b.open(&sealed).is_err());
    }

    #[test]
    fn malformed_peer_message_is_rejected() {
        let a = start(b"pw");
        assert!(matches!(
            a.handshake.finish(b"not a valid spake message"),
            Err(CryptoError::PakeFailed)
        ));
    }

    #[test]
    fn independent_runs_derive_distinct_channels() {
        // Same password, two independent sessions -> different transcripts ->
        // different keys (forward secrecy across sessions).
        let a1 = start(b"pw");
        let b1 = start(b"pw");
        let chan1 = a1.handshake.finish(&b1.message).unwrap();

        let a2 = start(b"pw");
        let b2 = start(b"pw");
        let chan2 = a2.handshake.finish(&b2.message).unwrap();

        let sealed = chan1.seal(b"x").unwrap();
        assert!(chan2.open(&sealed).is_err());
    }
}
