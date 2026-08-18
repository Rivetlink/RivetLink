//! High-level client facade — the main entry point for SDK consumers.
//!
//! Ties together config, identity, the REST API, and the encrypted session
//! handshake so a caller (the CLI, the desktop app, a third-party integrator)
//! drives a support session without touching the wire protocol directly.
//!
//! ```no_run
//! # async fn run() -> rivetlink_sdk::SdkResult<()> {
//! use rivetlink_sdk::{ClientConfig, RivetClient};
//! use std::path::PathBuf;
//!
//! let mut client = RivetClient::new(ClientConfig {
//!     relay_ws_url: "ws://127.0.0.1:8080/ws".into(),
//!     relay_http_url: "http://127.0.0.1:8080".into(),
//!     identity_path: PathBuf::from("client_identity.json"),
//! })?;
//!
//! client.login("operator@example.com", "password").await?;
//! let devices = client.list_devices().await?;
//! if let Some(device) = devices.first() {
//!     let path = client.capture_screenshot(device, PathBuf::from("shot.png")).await?;
//!     println!("saved {}", path.display());
//! }
//! # Ok(())
//! # }
//! ```

use std::path::{Path, PathBuf};

use crate::config::ClientConfig;
use crate::error::{SdkError, SdkResult};
use crate::identity::Identity;
use crate::rest::{self, Device};
use crate::session::{self, CaptureParams};
use rivetlink_protocol::{ConsoleInputPacket, SessionCapability};

/// A support client bound to one identity and one relay.
///
/// Construct it, `login`, then `list_devices` / `capture_screenshot`. The
/// access token is held internally after `login` succeeds.
#[derive(Debug)]
pub struct RivetClient {
    config: ClientConfig,
    identity: Identity,
    token: Option<String>,
}

impl RivetClient {
    /// Build a client from an in-memory config, loading (or creating) the
    /// identity file it points at.
    pub fn new(config: ClientConfig) -> SdkResult<Self> {
        config.validate()?;
        let identity = Identity::load_or_create(&config.identity_path)?;
        Ok(Self {
            config,
            identity,
            token: None,
        })
    }

    /// Build a client from a JSON config file on disk.
    pub fn from_config_file(path: &Path) -> SdkResult<Self> {
        let config = ClientConfig::load(path)?;
        Self::new(config)
    }

    /// This client's identity public key (base64) — what a host trusts (TOFU).
    pub fn public_key(&self) -> String {
        self.identity.public_key_b64()
    }

    /// The relay endpoints / identity path this client is bound to.
    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    /// Whether `login` has succeeded and a token is held.
    pub fn is_authenticated(&self) -> bool {
        self.token.is_some()
    }

    /// Authenticate against the relay; stores the access token internally.
    pub async fn login(&mut self, email: &str, password: &str) -> SdkResult<()> {
        let token = rest::login(&self.config.relay_http_url, email, password).await?;
        self.token = Some(token);
        Ok(())
    }

    /// List the devices visible to the authenticated user.
    pub async fn list_devices(&self) -> SdkResult<Vec<Device>> {
        rest::list_devices(&self.config.relay_http_url, self.token()?).await
    }

    /// Register a host device using this client's already-authenticated relay
    /// session. The access token remains private to the SDK.
    pub async fn register_device(
        &self,
        public_key: &str,
        hostname: &str,
        platform: Option<&str>,
    ) -> SdkResult<String> {
        rest::register_device(
            &self.config.relay_http_url,
            self.token()?,
            public_key,
            hostname,
            platform,
        )
        .await
    }

    /// Find one device by its id (lists and filters server-side results).
    pub async fn find_device(&self, device_id: &str) -> SdkResult<Device> {
        self.list_devices()
            .await?
            .into_iter()
            .find(|d| d.id == device_id)
            .ok_or_else(|| SdkError::Config(format!("device {device_id} not found in your org")))
    }

    /// Connect to `device`, run the encrypted handshake, and write one
    /// screenshot to `output_path`. The host may prompt its operator to
    /// approve the connection (TOFU consent).
    pub async fn capture_screenshot(
        &self,
        device: &Device,
        output_path: PathBuf,
    ) -> SdkResult<PathBuf> {
        let device_id = uuid::Uuid::parse_str(&device.id)
            .map_err(|e| SdkError::Config(format!("invalid device id: {e}")))?;

        session::capture_screenshot(CaptureParams {
            relay_ws_url: &self.config.relay_ws_url,
            token: self.token()?,
            identity: &self.identity,
            device_id,
            host_public_key_b64: &device.public_key,
            output_path,
            requested_capability: SessionCapability::Screenshot,
            console_input: None,
        })
        .await
        .map(|outcome| outcome.path)
    }

    /// As [`Self::capture_screenshot`], retaining the authenticated host
    /// lifecycle state for a remote-console UI.
    pub async fn capture_screenshot_outcome(
        &self,
        device: &Device,
        output_path: PathBuf,
    ) -> SdkResult<session::CaptureOutcome> {
        let device_id = uuid::Uuid::parse_str(&device.id)
            .map_err(|e| SdkError::Config(format!("invalid device id: {e}")))?;
        session::capture_screenshot(CaptureParams {
            relay_ws_url: &self.config.relay_ws_url,
            token: self.token()?,
            identity: &self.identity,
            device_id,
            host_public_key_b64: &device.public_key,
            output_path,
            requested_capability: SessionCapability::Screenshot,
            console_input: None,
        })
        .await
    }

    /// Send one normalized physical-console event through the E2E channel,
    /// then capture the resulting screen. This is intentionally stateless: a
    /// reboot closes the operation and a caller explicitly reconnects.
    pub async fn console_input_and_capture(
        &self,
        device: &Device,
        event: ConsoleInputPacket,
        output_path: PathBuf,
    ) -> SdkResult<PathBuf> {
        let device_id = uuid::Uuid::parse_str(&device.id)
            .map_err(|e| SdkError::Config(format!("invalid device id: {e}")))?;
        session::capture_screenshot(CaptureParams {
            relay_ws_url: &self.config.relay_ws_url,
            token: self.token()?,
            identity: &self.identity,
            device_id,
            host_public_key_b64: &device.public_key,
            output_path,
            requested_capability: SessionCapability::ConsoleControl,
            console_input: Some(event),
        })
        .await
        .map(|outcome| outcome.path)
    }

    /// As [`Self::console_input_and_capture`], but preserves the host's
    /// authenticated physical-console state for UI lifecycle reporting.
    pub async fn console_input_and_capture_outcome(
        &self,
        device: &Device,
        event: ConsoleInputPacket,
        output_path: PathBuf,
    ) -> SdkResult<session::CaptureOutcome> {
        let device_id = uuid::Uuid::parse_str(&device.id)
            .map_err(|e| SdkError::Config(format!("invalid device id: {e}")))?;
        session::capture_screenshot(CaptureParams {
            relay_ws_url: &self.config.relay_ws_url,
            token: self.token()?,
            identity: &self.identity,
            device_id,
            host_public_key_b64: &device.public_key,
            output_path,
            requested_capability: SessionCapability::ConsoleControl,
            console_input: Some(event),
        })
        .await
    }

    /// Internal: the stored token, or a `NotAuthenticated` error.
    fn token(&self) -> SdkResult<&str> {
        self.token.as_deref().ok_or(SdkError::NotAuthenticated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn registration_requires_authenticated_session() {
        let identity_path = std::env::temp_dir().join(format!(
            "rivetlink-sdk-client-test-{}.json",
            uuid::Uuid::now_v7()
        ));
        let client = RivetClient::new(ClientConfig {
            relay_ws_url: "ws://127.0.0.1:8080/ws".into(),
            relay_http_url: "http://127.0.0.1:8080".into(),
            identity_path: identity_path.clone(),
        })
        .unwrap();

        let err = client
            .register_device("test-public-key", "Home Node", Some("linux"))
            .await
            .unwrap_err();
        assert!(matches!(err, SdkError::NotAuthenticated));
        std::fs::remove_file(identity_path).ok();
    }
}
