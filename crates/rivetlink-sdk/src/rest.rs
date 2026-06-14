//! Minimal HTTP/1.1 client for the relay's REST API (login + device list).
//!
//! Hand-rolled over `tokio::net::TcpStream` to avoid a heavyweight HTTP client
//! dependency. Plain HTTP only — TLS termination is expected at a reverse
//! proxy in production. Good enough for LAN testing and VPS-behind-nginx.

use serde::Deserialize;
use serde_json::Value;
use std::net::ToSocketAddrs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{SdkError, SdkResult};

/// A device as returned by `GET /devices`.
#[derive(Debug, Clone, Deserialize)]
pub struct Device {
    pub id: String,
    pub hostname: Option<String>,
    pub platform: Option<String>,
    pub last_seen: Option<String>,
    /// Base64 Ed25519 identity key — used to pin the host during the handshake.
    pub public_key: String,
}

/// Log in and return the access token.
pub async fn login(base_url: &str, email: &str, password: &str) -> SdkResult<String> {
    let body = serde_json::json!({ "email": email, "password": password });
    let resp = request(base_url, "POST", "/auth/login", None, Some(&body)).await?;
    resp.get("access_token")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| SdkError::Auth("login response missing access_token".to_string()))
}

/// List devices visible to the authenticated user.
pub async fn list_devices(base_url: &str, token: &str) -> SdkResult<Vec<Device>> {
    let resp = request(base_url, "GET", "/devices", Some(token), None).await?;
    let devices: Vec<Device> = serde_json::from_value(resp)?;
    Ok(devices)
}

/// Perform a single HTTP request and parse the JSON body.
async fn request(
    base_url: &str,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<&Value>,
) -> SdkResult<Value> {
    let (host, port, prefix) = parse_base_url(base_url)?;
    let body_bytes = match body {
        Some(v) => serde_json::to_vec(v)?,
        None => Vec::new(),
    };

    let auth_line = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let content_line = if body.is_some() {
        format!("Content-Type: application/json\r\nContent-Length: {}\r\n", body_bytes.len())
    } else {
        String::new()
    };

    let full_path = format!("{prefix}{path}");
    let head = format!(
        "{method} {full_path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         {auth_line}{content_line}Connection: close\r\n\r\n",
    );

    let addr = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| SdkError::Http(format!("resolve {host}: {e}")))?
        .next()
        .ok_or_else(|| SdkError::Http(format!("no addresses for {host}")))?;

    let mut stream = TcpStream::connect(addr).await?;
    stream.write_all(head.as_bytes()).await?;
    if !body_bytes.is_empty() {
        stream.write_all(&body_bytes).await?;
    }

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let text = String::from_utf8_lossy(&buf);

    let status_line = text
        .lines()
        .next()
        .ok_or_else(|| SdkError::Http("empty response".to_string()))?;
    if !status_line.contains(" 200 ") {
        return Err(SdkError::Http(format!("request failed: {status_line}")));
    }

    let body_start = text
        .find("\r\n\r\n")
        .ok_or_else(|| SdkError::Http("malformed response".to_string()))?
        + 4;
    let parsed: Value = serde_json::from_str(text[body_start..].trim())?;
    Ok(parsed)
}

/// Parse `http://host[:port][/prefix]` into `(host, port, prefix)`.
fn parse_base_url(base: &str) -> SdkResult<(String, u16, String)> {
    let rest = base.strip_prefix("http://").ok_or_else(|| {
        SdkError::Config("relay_http_url must start with http:// (TLS via proxy)".to_string())
    })?;

    let (host_port, prefix) = rest
        .split_once('/')
        .map_or((rest, String::new()), |(a, b)| (a, format!("/{b}")));
    let (host, port) = host_port
        .split_once(':')
        .map_or((host_port.to_string(), 80), |(h, p)| {
            (h.to_string(), p.parse::<u16>().unwrap_or(80))
        });

    Ok((host, port, prefix.trim_end_matches('/').to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain() {
        let (h, p, prefix) = parse_base_url("http://127.0.0.1:8080").unwrap();
        assert_eq!(h, "127.0.0.1");
        assert_eq!(p, 8080);
        assert_eq!(prefix, "");
    }

    #[test]
    fn parse_default_port_and_prefix() {
        let (h, p, prefix) = parse_base_url("http://relay.lan/api").unwrap();
        assert_eq!(h, "relay.lan");
        assert_eq!(p, 80);
        assert_eq!(prefix, "/api");
    }

    #[test]
    fn parse_rejects_https() {
        assert!(parse_base_url("https://relay.lan").is_err());
    }
}
