//! REST-based device registration against the relay's `/devices/register`.
//!
//! Uses a hand-rolled HTTP/1.1 client over `tokio::net::TcpStream` to avoid
//! pulling in a full HTTP client crate. This is fine for one-shot enrollment;
//! anything more sophisticated should switch to `reqwest` or `hyper`.

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::net::ToSocketAddrs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use uuid::Uuid;

use crate::error::{AgentError, AgentResult};

/// Inputs for a registration call.
#[derive(Debug, Serialize)]
struct RegisterRequest<'a> {
    public_key: &'a str,
    hostname: Option<&'a str>,
    platform: Option<&'a str>,
}

/// Server response we care about — the rest is ignored.
#[derive(Debug, Deserialize)]
struct RegisterResponse {
    id: String,
}

/// Outcome of a successful registration.
#[derive(Debug, Clone)]
pub struct RegisteredDevice {
    pub device_id: Uuid,
}

/// Register this agent as a device against the relay server.
///
/// Sends `POST {base_url}/devices/register` with the supplied user JWT in the
/// `Authorization` header and the agent's Ed25519 public key (base64) in the
/// body.
pub async fn register_device(
    base_url: &str,
    user_token: &str,
    public_key: &[u8; 32],
    device_name: &str,
    platform: Option<&str>,
) -> AgentResult<RegisteredDevice> {
    let (host, port, path_prefix, _tls) = parse_base_url(base_url)?;
    let pk_b64 = base64::engine::general_purpose::STANDARD.encode(public_key);

    let body = serde_json::to_vec(&RegisterRequest {
        public_key: &pk_b64,
        hostname: Some(device_name),
        platform,
    })?;

    let path = format!("{path_prefix}/devices/register");
    let request = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Authorization: Bearer {user_token}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n",
        len = body.len(),
    );

    let addr = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| AgentError::Relay(format!("resolve {host}: {e}")))?
        .next()
        .ok_or_else(|| AgentError::Relay(format!("no addresses for {host}")))?;

    let mut stream = TcpStream::connect(addr).await?;
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(&body).await?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let text = String::from_utf8_lossy(&buf);

    let status_line = text
        .lines()
        .next()
        .ok_or_else(|| AgentError::Relay("empty response".to_string()))?;
    if !status_line.contains(" 200 ") {
        return Err(AgentError::Relay(format!(
            "registration failed: {status_line}"
        )));
    }

    let body_start = text
        .find("\r\n\r\n")
        .ok_or_else(|| AgentError::Relay("malformed http response".to_string()))?
        + 4;
    let resp: RegisterResponse = serde_json::from_str(&text[body_start..])?;
    let device_id = Uuid::parse_str(&resp.id)
        .map_err(|e| AgentError::Relay(format!("relay returned invalid device id: {e}")))?;
    Ok(RegisteredDevice { device_id })
}

/// Parse `http(s)://host[:port][/prefix]` into `(host, port, prefix, tls?)`.
fn parse_base_url(base: &str) -> AgentResult<(String, u16, String, bool)> {
    let (tls, rest) = if let Some(rest) = base.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = base.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(AgentError::Config(
            "relay_http_url must use http:// or https://".to_string(),
        ));
    };

    let (host_port, prefix) = rest
        .split_once('/')
        .map_or((rest, String::new()), |(a, b)| (a, format!("/{b}")));
    let (host, port) = host_port.split_once(':').map_or_else(
        || (host_port.to_string(), if tls { 443 } else { 80 }),
        |(h, p)| (h.to_string(), p.parse::<u16>().unwrap_or(80)),
    );

    if tls {
        return Err(AgentError::Relay(
            "https:// registration not yet supported by the agent (TLS not wired up)".to_string(),
        ));
    }

    Ok((host, port, prefix.trim_end_matches('/').to_string(), tls))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_base_url() {
        let (host, port, prefix, tls) = parse_base_url("http://127.0.0.1:8080").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 8080);
        assert_eq!(prefix, "");
        assert!(!tls);
    }

    #[test]
    fn parse_http_base_url_with_path() {
        let (host, port, prefix, _) = parse_base_url("http://relay.test:9090/api").unwrap();
        assert_eq!(host, "relay.test");
        assert_eq!(port, 9090);
        assert_eq!(prefix, "/api");
    }

    #[test]
    fn parse_http_default_port() {
        let (_, port, _, _) = parse_base_url("http://relay.test").unwrap();
        assert_eq!(port, 80);
    }

    #[test]
    fn parse_https_rejected_for_now() {
        let result = parse_base_url("https://relay.test");
        assert!(result.is_err(), "https not yet supported");
    }

    #[test]
    fn parse_rejects_other_schemes() {
        assert!(parse_base_url("ftp://relay.test").is_err());
    }
}
