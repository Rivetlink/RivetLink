//! Client identity: a persistent Ed25519 keypair stored on disk.
//!
//! The client's identity public key is what the host trusts (TOFU). The
//! private key signs the ephemeral session key during the handshake. Stored
//! as base64 in a JSON file under the client's data directory.

use base64::Engine;
use ed25519_dalek::SigningKey;
use rand_08::rngs::OsRng;
use rand_08::RngCore;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::error::{SdkError, SdkResult};

/// A loaded client identity.
pub struct Identity {
    signing_key: SigningKey,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredIdentity {
    secret_b64: String,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("public_key", &self.public_key_b64())
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// Load the identity from `path`, generating and persisting a new one if
    /// the file does not yet exist.
    pub fn load_or_create(path: &Path) -> SdkResult<Self> {
        if path.exists() {
            let body = std::fs::read_to_string(path)?;
            let stored: StoredIdentity = serde_json::from_str(&body)?;
            let raw = base64::engine::general_purpose::STANDARD
                .decode(&stored.secret_b64)
                .map_err(|e| SdkError::Base64(e.to_string()))?;
            if raw.len() != 32 {
                return Err(SdkError::Identity("stored key wrong length".to_string()));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&raw);
            return Ok(Self {
                signing_key: SigningKey::from_bytes(&seed),
            });
        }

        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);

        let stored = StoredIdentity {
            secret_b64: base64::engine::general_purpose::STANDARD.encode(signing_key.to_bytes()),
        };
        // Private key — write owner-only (0o600) so it is not world-readable.
        rivetlink_core::secure_file::write_secret(
            path,
            serde_json::to_string_pretty(&stored)?.as_bytes(),
        )?;

        Ok(Self { signing_key })
    }

    /// Reference to the signing key for the session handshake.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Base64 of the 32-byte Ed25519 public key — what the host trusts.
    pub fn public_key_b64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.signing_key.verifying_key().as_bytes())
    }

    /// Default identity path inside a data directory.
    pub fn default_path(dir: &Path) -> PathBuf {
        dir.join("client_identity.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("rivet-sdk-id-{}-{name}.json", uuid::Uuid::now_v7().simple()));
        p
    }

    #[test]
    fn create_then_load_is_stable() {
        let path = tmp("stable");
        let _ = std::fs::remove_file(&path);

        let a = Identity::load_or_create(&path).unwrap();
        let pk_a = a.public_key_b64();

        let b = Identity::load_or_create(&path).unwrap();
        assert_eq!(pk_a, b.public_key_b64(), "reload must yield same key");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn distinct_paths_distinct_keys() {
        let p1 = tmp("one");
        let p2 = tmp("two");
        let a = Identity::load_or_create(&p1).unwrap();
        let b = Identity::load_or_create(&p2).unwrap();
        assert_ne!(a.public_key_b64(), b.public_key_b64());
        let _ = std::fs::remove_file(&p1);
        let _ = std::fs::remove_file(&p2);
    }

    #[test]
    fn public_key_is_32_bytes() {
        let path = tmp("len");
        let id = Identity::load_or_create(&path).unwrap();
        let raw = base64::engine::general_purpose::STANDARD
            .decode(id.public_key_b64())
            .unwrap();
        assert_eq!(raw.len(), 32);
        let _ = std::fs::remove_file(&path);
    }
}
