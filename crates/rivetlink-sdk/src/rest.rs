//! TLS-authenticated REST client for the relay API.
//!
//! Device identities and bearer tokens are security-critical bootstrap data.
//! They must never travel over plaintext HTTP on a hostile network: otherwise
//! a network attacker can replace a host key before the end-to-end handshake.

use serde::Deserialize;
use serde_json::Value;

use crate::error::{SdkError, SdkResult};

/// A device as returned by `GET /devices`.
#[derive(Debug, Clone, Deserialize)]
pub struct Device {
    pub id: String,
    pub hostname: Option<String>,
    pub platform: Option<String>,
    pub last_seen: Option<String>,
    #[serde(default)]
    pub online: bool,
    /// Base64 Ed25519 identity key, pinned by the E2E relay handshake.
    pub public_key: String,
}

/// Log in and return the access token over TLS.
pub async fn login(base_url: &str, email: &str, password: &str) -> SdkResult<String> {
    let response = client()?
        .post(endpoint(base_url, "/auth/login")?)
        .json(&serde_json::json!({ "email": email, "password": password }))
        .send()
        .await
        .map_err(|error| http_error(&error))?;
    let body = response
        .json::<Value>()
        .await
        .map_err(|error| http_error(&error))?;
    body.get("access_token")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| SdkError::Auth("login response missing access_token".to_string()))
}

/// List devices visible to the authenticated user.
pub async fn list_devices(base_url: &str, token: &str) -> SdkResult<Vec<Device>> {
    let response = client()?
        .get(endpoint(base_url, "/devices")?)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|error| http_error(&error))?;
    response
        .json::<Vec<Device>>()
        .await
        .map_err(|error| http_error(&error))
}

/// Register a host device for the authenticated user's organisation.
pub async fn register_device(
    base_url: &str,
    token: &str,
    public_key: &str,
    hostname: &str,
    platform: Option<&str>,
) -> SdkResult<String> {
    let response = client()?
        .post(endpoint(base_url, "/devices/register")?)
        .bearer_auth(token)
        .json(&serde_json::json!({
            "public_key": public_key,
            "hostname": hostname,
            "platform": platform,
        }))
        .send()
        .await
        .map_err(|error| http_error(&error))?;
    device_id_from_response(
        &response
            .json::<Value>()
            .await
            .map_err(|error| http_error(&error))?,
    )
}

fn client() -> SdkResult<reqwest::Client> {
    reqwest::Client::builder()
        .https_only(true)
        .build()
        .map_err(|error| http_error(&error))
}

fn endpoint(base_url: &str, path: &str) -> SdkResult<reqwest::Url> {
    let mut base = reqwest::Url::parse(base_url)
        .map_err(|error| SdkError::Config(format!("invalid relay HTTP URL: {error}")))?;
    if base.scheme() != "https" {
        return Err(SdkError::Config(
            "relay_http_url must use https://; plaintext relay HTTP is unsafe".to_string(),
        ));
    }
    if base.query().is_some() || base.fragment().is_some() {
        return Err(SdkError::Config(
            "relay_http_url must not contain a query or fragment".to_string(),
        ));
    }
    // Keep base paths such as https://relay.example/api working.
    base.set_path(&format!("{}{}", base.path().trim_end_matches('/'), path));
    Ok(base)
}

fn http_error(error: &reqwest::Error) -> SdkError {
    if let Some(status) = error.status() {
        SdkError::Http(format!("relay request failed: {status}"))
    } else {
        SdkError::Http(format!("relay TLS request failed: {error}"))
    }
}

fn device_id_from_response(resp: &Value) -> SdkResult<String> {
    resp.get("id")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| SdkError::Http("device registration response missing id".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_requires_https() {
        assert!(endpoint("http://relay.example", "/devices").is_err());
        assert!(endpoint("https://relay.example", "/devices").is_ok());
    }

    #[test]
    fn endpoint_preserves_api_prefix() {
        let url = endpoint("https://relay.example/api", "/devices").unwrap();
        assert_eq!(url.as_str(), "https://relay.example/api/devices");
    }

    #[test]
    fn registration_response_requires_device_id() {
        assert_eq!(
            device_id_from_response(&serde_json::json!({ "id": "device-1" })).unwrap(),
            "device-1"
        );
        assert!(device_id_from_response(&serde_json::json!({})).is_err());
    }
}
