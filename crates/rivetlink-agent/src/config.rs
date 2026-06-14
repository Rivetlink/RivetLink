//! Agent configuration: relay endpoint, device identity, keystore location.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::error::{AgentError, AgentResult};

/// Persisted agent configuration loaded from `config.json` in the agent's
/// data directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Relay server WebSocket URL (e.g. `wss://relay.example.com/ws`).
    pub relay_url: String,

    /// Relay server HTTP base URL (e.g. `https://relay.example.com`).
    /// Used for one-shot REST calls like device registration.
    pub relay_http_url: String,

    /// Display name reported to the relay server when registering.
    pub device_name: String,

    /// Path to the keystore directory holding signing + encryption keys.
    pub keystore_path: PathBuf,

    /// Device ID assigned by the relay after a successful registration.
    /// Required by the `run` subcommand to authenticate via DEVICE_HELLO.
    #[serde(default)]
    pub device_id: Option<uuid::Uuid>,

    /// Heartbeat interval in seconds.
    #[serde(default = "default_heartbeat")]
    pub heartbeat_secs: u64,

    /// Reconnect backoff cap in seconds.
    #[serde(default = "default_reconnect_cap")]
    pub reconnect_cap_secs: u64,
}

fn default_heartbeat() -> u64 {
    10
}

fn default_reconnect_cap() -> u64 {
    60
}

impl AgentConfig {
    /// Load configuration from a JSON file on disk.
    pub fn load(path: &std::path::Path) -> AgentResult<Self> {
        let body = std::fs::read_to_string(path)
            .map_err(|e| AgentError::Config(format!("read {}: {e}", path.display())))?;
        let cfg: Self = serde_json::from_str(&body)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Persist configuration to disk as pretty-printed JSON.
    pub fn save(&self, path: &std::path::Path) -> AgentResult<()> {
        let body = serde_json::to_string_pretty(self)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, body)?;
        Ok(())
    }

    /// Reject obviously broken values before they reach networking code.
    pub fn validate(&self) -> AgentResult<()> {
        if !self.relay_url.starts_with("ws://") && !self.relay_url.starts_with("wss://") {
            return Err(AgentError::Config(
                "relay_url must start with ws:// or wss://".to_string(),
            ));
        }
        if !self.relay_http_url.starts_with("http://")
            && !self.relay_http_url.starts_with("https://")
        {
            return Err(AgentError::Config(
                "relay_http_url must start with http:// or https://".to_string(),
            ));
        }
        if self.device_name.is_empty() {
            return Err(AgentError::Config("device_name is required".to_string()));
        }
        if self.heartbeat_secs == 0 {
            return Err(AgentError::Config(
                "heartbeat_secs must be > 0".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AgentConfig {
        AgentConfig {
            relay_url: "wss://relay.test/ws".into(),
            relay_http_url: "https://relay.test".into(),
            device_name: "host-1".into(),
            keystore_path: PathBuf::from("/tmp/keys"),
            device_id: None,
            heartbeat_secs: 10,
            reconnect_cap_secs: 60,
        }
    }

    #[test]
    fn round_trip_save_load() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "rivet-agent-cfg-{}.json",
            uuid::Uuid::now_v7().simple()
        ));

        let cfg = sample();
        cfg.save(&path).unwrap();

        let loaded = AgentConfig::load(&path).unwrap();
        assert_eq!(loaded.relay_url, cfg.relay_url);
        assert_eq!(loaded.device_name, cfg.device_name);
        assert_eq!(loaded.heartbeat_secs, 10);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn validate_rejects_bad_url_scheme() {
        let mut cfg = sample();
        cfg.relay_url = "http://relay.test".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_device_name() {
        let mut cfg = sample();
        cfg.device_name = String::new();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_heartbeat() {
        let mut cfg = sample();
        cfg.heartbeat_secs = 0;
        assert!(cfg.validate().is_err());
    }
}
