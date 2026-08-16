//! Host-side trusted-client store (trust on first use).
//!
//! This is the heart of the zero-trust model: the **host** — not the relay —
//! decides who may connect. Client identity public keys that have been
//! approved are persisted here. On a new connection the host checks this
//! store; a match auto-authorizes, a miss triggers an operator prompt.
//!
//! Stored as JSON in the agent's data directory. The relay never sees it.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::error::{AgentError, AgentResult};

/// A single trusted client entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedEntry {
    /// Human-friendly label shown in logs.
    pub name: String,
    /// May view the screen.
    pub can_view: bool,
    /// May send input (control). Not used by the screenshot MVP.
    pub can_control: bool,
}

/// File-backed map of trusted client identity keys (base64) → entry.
#[derive(Debug, Clone)]
pub struct TrustedClients {
    path: PathBuf,
    entries: BTreeMap<String, TrustedEntry>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoredFile {
    clients: BTreeMap<String, TrustedEntry>,
}

impl TrustedClients {
    /// Load the store from disk, or start empty if the file does not exist.
    pub fn load_or_empty(path: &Path) -> AgentResult<Self> {
        let entries: BTreeMap<String, TrustedEntry> = if path.exists() {
            let body = std::fs::read_to_string(path)?;
            let stored: StoredFile = serde_json::from_str(&body)?;
            stored.clients
        } else {
            BTreeMap::new()
        };
        Ok(Self {
            path: path.to_path_buf(),
            entries,
        })
    }

    /// Look up a client by its base64 identity key.
    pub fn get(&self, public_key_b64: &str) -> Option<&TrustedEntry> {
        self.entries.get(public_key_b64.trim())
    }

    /// True if the client key is already trusted.
    pub fn is_trusted(&self, public_key_b64: &str) -> bool {
        self.entries.contains_key(public_key_b64.trim())
    }

    /// Add (or replace) a trusted client and persist immediately.
    pub fn trust(&mut self, public_key_b64: &str, entry: TrustedEntry) -> AgentResult<()> {
        self.entries
            .insert(public_key_b64.trim().to_string(), entry);
        self.save()
    }

    /// Remove a trusted client and persist.
    pub fn revoke(&mut self, public_key_b64: &str) -> AgentResult<()> {
        self.entries.remove(public_key_b64.trim());
        self.save()
    }

    /// Number of trusted clients.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if no clients are trusted yet.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn save(&self) -> AgentResult<()> {
        let stored = StoredFile {
            clients: self.entries.clone(),
        };
        rivetlink_core::secure_file::write_secret(
            &self.path,
            serde_json::to_string_pretty(&stored)?.as_bytes(),
        )
        .map_err(AgentError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "rivet-trusted-{}-{name}.json",
            uuid::Uuid::now_v7().simple()
        ));
        p
    }

    fn entry() -> TrustedEntry {
        TrustedEntry {
            name: "laptop".to_string(),
            can_view: true,
            can_control: false,
        }
    }

    #[test]
    fn empty_store_trusts_nobody() {
        let path = tmp("empty");
        let store = TrustedClients::load_or_empty(&path).unwrap();
        assert!(store.is_empty());
        assert!(!store.is_trusted("abc"));
    }

    #[test]
    fn trust_then_persist_and_reload() {
        let path = tmp("persist");
        {
            let mut store = TrustedClients::load_or_empty(&path).unwrap();
            store.trust("KEY123", entry()).unwrap();
            assert!(store.is_trusted("KEY123"));
        }
        let reloaded = TrustedClients::load_or_empty(&path).unwrap();
        assert!(reloaded.is_trusted("KEY123"));
        assert_eq!(reloaded.get("KEY123").unwrap().name, "laptop");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn trim_is_applied() {
        let path = tmp("trim");
        let mut store = TrustedClients::load_or_empty(&path).unwrap();
        store.trust("  KEY  ", entry()).unwrap();
        assert!(store.is_trusted("KEY"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn revoke_removes() {
        let path = tmp("revoke");
        let mut store = TrustedClients::load_or_empty(&path).unwrap();
        store.trust("K", entry()).unwrap();
        store.revoke("K").unwrap();
        assert!(!store.is_trusted("K"));
        let _ = std::fs::remove_file(&path);
    }
}
