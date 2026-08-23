//! TLS-authenticated device registration against the relay's
//! `/devices/register` endpoint.
//!
//! Registration carries a user bearer token and the host's long-term identity,
//! so accepting plaintext HTTP here would let a hostile network replace the
//! identity before the end-to-end handshake begins.  Keep this path on the
//! SDK's HTTPS-only REST implementation rather than maintaining a separate
//! ad-hoc HTTP client in the agent.

use base64::Engine;
use uuid::Uuid;

use crate::error::{AgentError, AgentResult};

/// Outcome of a successful registration.
#[derive(Debug, Clone)]
pub struct RegisteredDevice {
    pub device_id: Uuid,
}

/// Register this agent as a device against the relay server over HTTPS.
pub async fn register_device(
    base_url: &str,
    user_token: &str,
    public_key: &[u8; 32],
    device_name: &str,
    platform: Option<&str>,
) -> AgentResult<RegisteredDevice> {
    let public_key = base64::engine::general_purpose::STANDARD.encode(public_key);
    let id = rivetlink_sdk::rest::register_device(
        base_url,
        user_token,
        &public_key,
        device_name,
        platform,
    )
    .await
    .map_err(|error| AgentError::Relay(format!("secure device registration failed: {error}")))?;
    let device_id = Uuid::parse_str(&id)
        .map_err(|error| AgentError::Relay(format!("relay returned invalid device id: {error}")))?;
    Ok(RegisteredDevice { device_id })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn registration_rejects_plaintext_relay_before_connecting() {
        let error = register_device("http://relay.test", "token", &[0; 32], "host", None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("https://"));
    }
}
