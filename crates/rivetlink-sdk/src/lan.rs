//! Direct-LAN discovery and transport (mDNS + TCP).
//!
//! Hosts advertise themselves on the local network with mDNS under the
//! `_rivetlink._tcp.local.` service type, carrying their friendly name,
//! identity public key, and protocol version in TXT records. Clients
//! [`discover`] those hosts, then open a TCP connection and run the
//! transport-agnostic [`crate::direct`] handshake over it to establish an
//! end-to-end encrypted [`SealedChannel`].
//!
//! On top of the sealed channel sits a tiny request/response protocol
//! ([`LanRequest`] / [`LanResponse`]) — enough to drive the screenshot MVP. The
//! relay is never involved; this is host↔client on the same network.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use rivetlink_crypto::sealed::SealedChannel;

use crate::direct;
use crate::error::{SdkError, SdkResult};
use crate::identity::Identity;

/// mDNS service type RivetLink hosts advertise under.
pub const SERVICE_TYPE: &str = "_rivetlink._tcp.local.";

/// Direct-LAN wire protocol version, advertised in mDNS and used for
/// compatibility checks once version negotiation lands.
pub const PROTOCOL_VERSION: u16 = 1;

const TXT_NAME: &str = "name";
const TXT_PUBKEY: &str = "pk";
const TXT_VERSION: &str = "v";

/// Upper bound on a single sealed application frame (a screenshot PNG, base64).
const MAX_SEALED_FRAME: usize = 32 * 1024 * 1024;

/// A RivetLink host found on the local network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LanDevice {
    /// Friendly instance name the host advertised.
    pub name: String,
    /// A reachable IP address (IPv4 preferred).
    pub address: String,
    /// TCP port the host listens on.
    pub port: u16,
    /// Host identity public key (base64), if advertised — lets the client pin
    /// the host so a later key-mode connection is MITM-proof.
    pub public_key: Option<String>,
    /// Protocol version the host advertised, if any.
    pub protocol_version: Option<u16>,
}

impl LanDevice {
    /// Resolve the advertised address + port into a [`SocketAddr`].
    pub fn socket_addr(&self) -> SdkResult<SocketAddr> {
        let ip: IpAddr = self
            .address
            .parse()
            .map_err(|_| SdkError::Discovery(format!("bad address: {}", self.address)))?;
        Ok(SocketAddr::new(ip, self.port))
    }

    /// The advertised host identity as a verifying key, if present and valid.
    pub fn host_identity(&self) -> Option<VerifyingKey> {
        let b64 = self.public_key.as_ref()?;
        let raw = B64.decode(b64.trim()).ok()?;
        let bytes: [u8; 32] = raw.as_slice().try_into().ok()?;
        VerifyingKey::from_bytes(&bytes).ok()
    }
}

// ---- Discovery (client) ----------------------------------------------------

/// Browse the local network for RivetLink hosts for up to `timeout`.
///
/// mDNS is blocking, so the browse runs on a blocking thread. Returns one entry
/// per resolved host (deduplicated by mDNS fullname).
pub async fn discover(timeout: Duration) -> SdkResult<Vec<LanDevice>> {
    tokio::task::spawn_blocking(move || discover_blocking(timeout))
        .await
        .map_err(|e| SdkError::Discovery(format!("discovery task failed: {e}")))?
}

fn discover_blocking(timeout: Duration) -> SdkResult<Vec<LanDevice>> {
    let daemon = ServiceDaemon::new().map_err(|e| SdkError::Discovery(e.to_string()))?;
    let rx = daemon
        .browse(SERVICE_TYPE)
        .map_err(|e| SdkError::Discovery(e.to_string()))?;

    let deadline = Instant::now() + timeout;
    let mut found: BTreeMap<String, LanDevice> = BTreeMap::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match rx.recv_timeout(remaining) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                if let Some(dev) = device_from_info(&info) {
                    found.insert(info.get_fullname().to_string(), dev);
                }
            },
            Ok(_) => {},
            Err(_) => break, // timed out waiting for the next event
        }
    }
    let _ = daemon.shutdown();
    Ok(found.into_values().collect())
}

fn device_from_info(info: &ServiceInfo) -> Option<LanDevice> {
    let address = info
        .get_addresses()
        .iter()
        .find(|ip| ip.is_ipv4())
        .or_else(|| info.get_addresses().iter().next())
        .map(ToString::to_string)?;
    let name = info
        .get_property_val_str(TXT_NAME)
        .map(str::to_string)
        .unwrap_or_else(|| {
            info.get_fullname()
                .split('.')
                .next()
                .unwrap_or("RivetLink")
                .to_string()
        });
    let public_key = info.get_property_val_str(TXT_PUBKEY).map(str::to_string);
    let protocol_version = info
        .get_property_val_str(TXT_VERSION)
        .and_then(|v| v.parse().ok());
    Some(LanDevice {
        name,
        address,
        port: info.get_port(),
        public_key,
        protocol_version,
    })
}

// ---- Advertising (host) ----------------------------------------------------

/// A live mDNS advertisement. Dropping it unregisters the service.
pub struct Advertiser {
    daemon: ServiceDaemon,
    fullname: String,
}

impl std::fmt::Debug for Advertiser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Advertiser")
            .field("fullname", &self.fullname)
            .finish()
    }
}

impl Advertiser {
    /// Advertise this host on the LAN. `instance` is the friendly device name,
    /// `public_key` the host identity (base64), `port` the TCP listener port,
    /// `version` the protocol version. Local addresses are filled in
    /// automatically.
    pub fn start(instance: &str, port: u16, public_key: &str, version: u16) -> SdkResult<Self> {
        let daemon = ServiceDaemon::new().map_err(|e| SdkError::Discovery(e.to_string()))?;
        let hostname = format!("{}.local.", sanitize_hostname(instance));
        let props: [(&str, String); 3] = [
            (TXT_NAME, instance.to_string()),
            (TXT_PUBKEY, public_key.to_string()),
            (TXT_VERSION, version.to_string()),
        ];
        let info = ServiceInfo::new(SERVICE_TYPE, instance, &hostname, "", port, &props[..])
            .map_err(|e| SdkError::Discovery(e.to_string()))?
            .enable_addr_auto();
        let fullname = info.get_fullname().to_string();
        daemon
            .register(info)
            .map_err(|e| SdkError::Discovery(e.to_string()))?;
        Ok(Self { daemon, fullname })
    }
}

impl Drop for Advertiser {
    fn drop(&mut self) {
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}

/// Reduce a free-form device name to a DNS-label-safe hostname.
fn sanitize_hostname(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let trimmed = cleaned.trim_matches('-');
    if trimmed.is_empty() {
        "rivetlink".to_string()
    } else {
        trimmed.to_ascii_lowercase()
    }
}

// ---- Application protocol over the sealed channel --------------------------

/// A client request over an established sealed LAN channel.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum LanRequest {
    /// Ask the host for a single screenshot.
    Screenshot,
}

/// A host response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "ok")]
pub enum LanResponse {
    /// A screenshot, as base64-encoded PNG bytes.
    Screenshot { png_b64: String },
    /// The host could not satisfy the request.
    Error { message: String },
}

async fn write_sealed<W>(w: &mut W, ch: &SealedChannel, plain: &[u8]) -> SdkResult<()>
where
    W: AsyncWrite + Unpin,
{
    let sealed = ch.seal(plain).map_err(|e| SdkError::Crypto(e.to_string()))?;
    let len = u32::try_from(sealed.len())
        .map_err(|_| SdkError::Crypto("sealed frame too large".to_string()))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&sealed).await?;
    w.flush().await?;
    Ok(())
}

async fn read_sealed<R>(r: &mut R, ch: &SealedChannel) -> SdkResult<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_SEALED_FRAME {
        return Err(SdkError::Crypto("sealed frame too large".to_string()));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    ch.open(&buf)
        .map_err(|_| SdkError::Crypto("decrypt failed".to_string()))
}

/// Send a request over the sealed channel (client side).
pub async fn send_request<W>(w: &mut W, ch: &SealedChannel, req: &LanRequest) -> SdkResult<()>
where
    W: AsyncWrite + Unpin,
{
    write_sealed(w, ch, &serde_json::to_vec(req)?).await
}

/// Receive a request over the sealed channel (host side).
pub async fn recv_request<R>(r: &mut R, ch: &SealedChannel) -> SdkResult<LanRequest>
where
    R: AsyncRead + Unpin,
{
    Ok(serde_json::from_slice(&read_sealed(r, ch).await?)?)
}

/// Send a response over the sealed channel (host side).
pub async fn send_response<W>(w: &mut W, ch: &SealedChannel, resp: &LanResponse) -> SdkResult<()>
where
    W: AsyncWrite + Unpin,
{
    write_sealed(w, ch, &serde_json::to_vec(resp)?).await
}

/// Receive a response over the sealed channel (client side).
pub async fn recv_response<R>(r: &mut R, ch: &SealedChannel) -> SdkResult<LanResponse>
where
    R: AsyncRead + Unpin,
{
    Ok(serde_json::from_slice(&read_sealed(r, ch).await?)?)
}

// ---- High-level client helpers ---------------------------------------------

/// Connect to a host over the LAN with a shared PIN (PAKE) and fetch one
/// screenshot. Returns the raw PNG bytes.
pub async fn screenshot_password(addr: SocketAddr, password: &str) -> SdkResult<Vec<u8>> {
    let mut stream = TcpStream::connect(addr).await?;
    let channel = direct::client_connect_password(&mut stream, password).await?;
    fetch_screenshot(&mut stream, &channel).await
}

/// Connect to a host over the LAN with our Ed25519 identity (TOFU). If
/// `pinned_host` is given (e.g. from the advertised public key), the host must
/// match it — defeating a MITM.
pub async fn screenshot_key(
    addr: SocketAddr,
    identity: &Identity,
    pinned_host: Option<VerifyingKey>,
) -> SdkResult<Vec<u8>> {
    let mut stream = TcpStream::connect(addr).await?;
    let channel = direct::client_connect_key(&mut stream, identity, pinned_host).await?;
    fetch_screenshot(&mut stream, &channel).await
}

async fn fetch_screenshot(stream: &mut TcpStream, channel: &SealedChannel) -> SdkResult<Vec<u8>> {
    send_request(stream, channel, &LanRequest::Screenshot).await?;
    match recv_response(stream, channel).await? {
        LanResponse::Screenshot { png_b64 } => B64
            .decode(png_b64.trim())
            .map_err(|e| SdkError::Base64(e.to_string())),
        LanResponse::Error { message } => Err(SdkError::Relay(message)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_hostname_is_dns_safe() {
        assert_eq!(sanitize_hostname("Jan's Laptop"), "jan-s-laptop");
        assert_eq!(sanitize_hostname("  --  "), "rivetlink");
        assert_eq!(sanitize_hostname("Café 42"), "caf--42");
    }

    #[tokio::test]
    async fn sealed_request_response_roundtrip() {
        let (mut c, mut h) = tokio::io::duplex(64 * 1024);
        let shared = [9u8; 32];
        let ch_c = SealedChannel::from_shared_secret(&shared);
        let ch_h = SealedChannel::from_shared_secret(&shared);

        let host = tokio::spawn(async move {
            let req = recv_request(&mut h, &ch_h).await.unwrap();
            assert!(matches!(req, LanRequest::Screenshot));
            send_response(&mut h, &ch_h, &LanResponse::Screenshot {
                png_b64: B64.encode(b"PNGDATA"),
            })
            .await
            .unwrap();
        });

        send_request(&mut c, &ch_c, &LanRequest::Screenshot).await.unwrap();
        let resp = recv_response(&mut c, &ch_c).await.unwrap();
        host.await.unwrap();
        match resp {
            LanResponse::Screenshot { png_b64 } => {
                assert_eq!(B64.decode(png_b64).unwrap(), b"PNGDATA");
            },
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn lan_device_socket_addr_parses() {
        let dev = LanDevice {
            name: "Host".to_string(),
            address: "192.168.1.5".to_string(),
            port: 7000,
            public_key: None,
            protocol_version: Some(1),
        };
        assert_eq!(dev.socket_addr().unwrap().to_string(), "192.168.1.5:7000");
    }
}
