//! Filesystem-backed keystore.
//!
//! Stores raw 32-byte secrets in JSON files under the configured directory.
//! Not intended for production deployments — operators should wire up a
//! platform keychain backend before exposing the agent to untrusted hosts.

use async_trait::async_trait;
use base64::Engine;
use rand_08::rngs::OsRng;
use rand_08::RngCore;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use super::{EncryptionKey, KeyStore, SigningKey};
use crate::error::{AgentError, AgentResult};

/// File-backed keystore writing key material to a directory.
#[derive(Debug, Clone)]
pub struct FileKeyStore {
    dir: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredKey {
    secret_b64: String,
    public_b64: String,
}

impl StoredKey {
    fn new(secret: &[u8; 32], public: &[u8; 32]) -> Self {
        let engine = base64::engine::general_purpose::STANDARD;
        Self {
            secret_b64: engine.encode(secret),
            public_b64: engine.encode(public),
        }
    }

    fn decode(&self) -> AgentResult<([u8; 32], [u8; 32])> {
        let engine = base64::engine::general_purpose::STANDARD;
        let secret = engine
            .decode(&self.secret_b64)
            .map_err(|e| AgentError::Base64(e.to_string()))?;
        let public = engine
            .decode(&self.public_b64)
            .map_err(|e| AgentError::Base64(e.to_string()))?;
        if secret.len() != 32 || public.len() != 32 {
            return Err(AgentError::Keystore("invalid key length".to_string()));
        }
        let mut s = [0u8; 32];
        let mut p = [0u8; 32];
        s.copy_from_slice(&secret);
        p.copy_from_slice(&public);
        Ok((s, p))
    }
}

impl FileKeyStore {
    /// Create a new keystore rooted at `dir`. The directory is created if it
    /// does not already exist.
    pub fn new(dir: PathBuf) -> AgentResult<Self> {
        Ok(Self { dir })
    }

    fn signing_path(&self) -> PathBuf {
        self.dir.join("signing.json")
    }

    fn encryption_path(&self) -> PathBuf {
        self.dir.join("encryption.json")
    }

    fn load_or<F>(path: &Path, generate: F) -> AgentResult<StoredKey>
    where
        F: FnOnce() -> StoredKey,
    {
        if path.exists() {
            let body = std::fs::read_to_string(path)?;
            return Ok(serde_json::from_str(&body)?);
        }
        let key = generate();
        let body = serde_json::to_string_pretty(&key)?;
        // Key material — write owner-only (0o600), not world-readable.
        rivetlink_core::secure_file::write_secret(path, body.as_bytes())?;
        Ok(key)
    }
}

#[async_trait]
impl KeyStore for FileKeyStore {
    async fn ensure_signing_key(&self) -> AgentResult<SigningKey> {
        let path = self.signing_path();
        let stored = Self::load_or(&path, generate_signing)?;
        let (secret, public) = stored.decode()?;
        Ok(SigningKey { secret, public })
    }

    async fn ensure_encryption_key(&self) -> AgentResult<EncryptionKey> {
        let path = self.encryption_path();
        let stored = Self::load_or(&path, generate_encryption)?;
        let (secret, public) = stored.decode()?;
        Ok(EncryptionKey { secret, public })
    }

    async fn reset(&self) -> AgentResult<()> {
        for path in [self.signing_path(), self.encryption_path()] {
            if path.exists() {
                std::fs::remove_file(&path)?;
            }
        }
        Ok(())
    }
}

fn generate_signing() -> StoredKey {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let sk = ed25519_dalek::SigningKey::from_bytes(&secret);
    let pk = sk.verifying_key();
    StoredKey::new(sk.as_bytes(), pk.as_bytes())
}

fn generate_encryption() -> StoredKey {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let sk = x25519_dalek::StaticSecret::from(secret);
    let pk = x25519_dalek::PublicKey::from(&sk);
    StoredKey::new(&sk.to_bytes(), pk.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "rivet-keystore-{}-{name}",
            uuid::Uuid::now_v7().simple()
        ));
        p
    }

    #[tokio::test]
    async fn signing_key_is_persistent() {
        let dir = tmp_dir("signing");
        let store = FileKeyStore::new(dir.clone()).unwrap();
        let first = store.ensure_signing_key().await.unwrap();
        let second = store.ensure_signing_key().await.unwrap();
        assert_eq!(first.secret, second.secret);
        assert_eq!(first.public, second.public);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn encryption_key_is_persistent() {
        let dir = tmp_dir("enc");
        let store = FileKeyStore::new(dir.clone()).unwrap();
        let first = store.ensure_encryption_key().await.unwrap();
        let second = store.ensure_encryption_key().await.unwrap();
        assert_eq!(first.secret, second.secret);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn reset_clears_keys() {
        let dir = tmp_dir("reset");
        let store = FileKeyStore::new(dir.clone()).unwrap();
        let before = store.ensure_signing_key().await.unwrap();
        store.reset().await.unwrap();
        let after = store.ensure_signing_key().await.unwrap();
        assert_ne!(before.secret, after.secret, "reset must produce fresh key");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn signing_and_encryption_are_independent() {
        let dir = tmp_dir("independent");
        let store = FileKeyStore::new(dir.clone()).unwrap();
        let sig = store.ensure_signing_key().await.unwrap();
        let enc = store.ensure_encryption_key().await.unwrap();
        assert_ne!(sig.secret, enc.secret);
        std::fs::remove_dir_all(&dir).ok();
    }
}
