//! Client configuration: relay endpoints + identity location.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::error::{SdkError, SdkResult};

/// Persisted client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Relay WebSocket URL. Public relay connections require `wss://`.
    pub relay_ws_url: String,
    /// Relay REST base URL. Public relay connections require `https://`.
    pub relay_http_url: String,
    /// Path to the client's Ed25519 identity file.
    pub identity_path: PathBuf,
}

impl ClientConfig {
    /// Load configuration from a JSON file.
    pub fn load(path: &Path) -> SdkResult<Self> {
        let body = std::fs::read_to_string(path)
            .map_err(|e| SdkError::Config(format!("read {}: {e}", path.display())))?;
        let cfg: Self = serde_json::from_str(&body)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Persist configuration as pretty JSON, creating parent dirs.
    pub fn save(&self, path: &Path) -> SdkResult<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    /// Reject malformed URLs early.
    pub fn validate(&self) -> SdkResult<()> {
        if !self.relay_ws_url.starts_with("wss://") {
            return Err(SdkError::Config(
                "relay_ws_url must use wss://; plaintext relay WebSockets are unsafe".to_string(),
            ));
        }
        if !self.relay_http_url.starts_with("https://") {
            return Err(SdkError::Config(
                "relay_http_url must use https://; plaintext relay HTTP is unsafe".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "rivet-sdk-cfg-{}-{name}.json",
            uuid::Uuid::now_v7().simple()
        ));
        p
    }

    fn sample() -> ClientConfig {
        ClientConfig {
            relay_ws_url: "wss://relay.example/ws".into(),
            relay_http_url: "https://relay.example".into(),
            identity_path: PathBuf::from("/tmp/id.json"),
        }
    }

    #[test]
    fn round_trip() {
        let path = tmp("rt");
        let cfg = sample();
        cfg.save(&path).unwrap();
        let loaded = ClientConfig::load(&path).unwrap();
        assert_eq!(loaded.relay_ws_url, cfg.relay_ws_url);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn validate_rejects_bad_ws() {
        let mut cfg = sample();
        cfg.relay_ws_url = "http://x".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_bad_http() {
        let mut cfg = sample();
        cfg.relay_http_url = "ftp://x".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_plaintext_relay_transport() {
        let mut cfg = sample();
        cfg.relay_ws_url = "ws://relay.example/ws".into();
        assert!(cfg.validate().is_err());
        let mut cfg = sample();
        cfg.relay_http_url = "http://relay.example".into();
        assert!(cfg.validate().is_err());
    }
}
