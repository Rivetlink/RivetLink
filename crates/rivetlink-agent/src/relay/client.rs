//! WebSocket client that connects the agent to the relay server.
//!
//! Responsibilities:
//! - open a TLS/WS connection to the configured relay URL
//! - send the initial `AUTH` message with the agent's JWT
//! - emit periodic heartbeats so the relay knows the agent is alive
//! - hand off incoming signaling frames to a caller-provided handler

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::{tungstenite::Message, MaybeTlsStream, WebSocketStream};
use uuid::Uuid;

use crate::error::{AgentError, AgentResult};

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
const DEVICE_AUTH_PROTOCOL_VERSION: u16 = 2;
const DEVICE_AUTH_DOMAIN: &[u8] = b"rivetlink-relay-device-auth-v2";

/// AUTH message sent as the first frame after connecting (user mode).
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
enum OutgoingAuth<'a> {
    Auth { token: &'a str },
}

/// Server's response to the user AUTH frame.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum AuthAck {
    #[serde(rename = "AUTHENTICATED")]
    Authenticated {
        #[serde(default)]
        user_id: Option<String>,
        #[serde(default)]
        device_id: Option<String>,
    },
    #[serde(other)]
    Other,
}

/// First frame in the device-auth flow.
#[derive(Debug, Serialize)]
#[serde(tag = "type")]
enum OutgoingDeviceHello {
    #[serde(rename = "DEVICE_HELLO")]
    Hello {
        device_id: Uuid,
        protocol_version: u16,
    },
}

/// Server-sent challenge.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum DeviceChallenge {
    #[serde(rename = "DEVICE_CHALLENGE")]
    Challenge {
        nonce: String,
        protocol_version: u16,
    },
}

/// Client-sent challenge response.
#[derive(Debug, Serialize)]
#[serde(tag = "type")]
enum OutgoingDeviceAuth<'a> {
    #[serde(rename = "DEVICE_AUTH")]
    Auth { signature: &'a str },
}

/// Connected relay client. The session token is consumed at construction so
/// the caller can rotate refresh tokens between (re)connects.
#[derive(Debug)]
pub struct RelayClient {
    stream: WsStream,
    heartbeat_interval: Duration,
}

impl RelayClient {
    /// Open a WebSocket connection and complete the AUTH handshake.
    pub async fn connect(
        url: &str,
        token: &str,
        heartbeat_interval: Duration,
    ) -> AgentResult<Self> {
        ensure_secure_relay_url(url)?;
        let (mut stream, _resp) = tokio_tungstenite::connect_async(url)
            .await
            .map_err(|e| AgentError::Relay(format!("connect failed: {e}")))?;

        let auth = serde_json::to_string(&OutgoingAuth::Auth { token })?;
        stream
            .send(Message::Text(auth))
            .await
            .map_err(|e| AgentError::WebSocket(e.to_string()))?;

        let first = stream
            .next()
            .await
            .ok_or_else(|| AgentError::Relay("relay closed before AUTH ack".to_string()))?
            .map_err(|e| AgentError::WebSocket(e.to_string()))?;

        let text = match first {
            Message::Text(t) => t,
            Message::Close(_) => {
                return Err(AgentError::Relay("relay closed during AUTH".to_string()));
            },
            other => {
                return Err(AgentError::Relay(format!(
                    "unexpected message during AUTH: {other:?}"
                )));
            },
        };

        let ack: AuthAck = serde_json::from_str(&text).map_err(AgentError::Serde)?;
        match ack {
            AuthAck::Authenticated { user_id, device_id } => {
                tracing::info!(?user_id, ?device_id, "relay AUTH accepted");
                Ok(Self {
                    stream,
                    heartbeat_interval,
                })
            },
            AuthAck::Other => Err(AgentError::Relay(format!("AUTH rejected: {text}"))),
        }
    }

    /// Open a WebSocket connection as a device and complete the
    /// challenge-response handshake using the agent's Ed25519 signing key.
    pub async fn connect_device(
        url: &str,
        device_id: Uuid,
        signing_key: &SigningKey,
        heartbeat_interval: Duration,
    ) -> AgentResult<Self> {
        ensure_secure_relay_url(url)?;
        let (mut stream, _resp) = tokio_tungstenite::connect_async(url)
            .await
            .map_err(|e| AgentError::Relay(format!("connect failed: {e}")))?;

        let hello = serde_json::to_string(&OutgoingDeviceHello::Hello {
            device_id,
            protocol_version: DEVICE_AUTH_PROTOCOL_VERSION,
        })?;
        stream
            .send(Message::Text(hello))
            .await
            .map_err(|e| AgentError::WebSocket(e.to_string()))?;

        let challenge_frame = stream
            .next()
            .await
            .ok_or_else(|| AgentError::Relay("relay closed before DEVICE_CHALLENGE".to_string()))?
            .map_err(|e| AgentError::WebSocket(e.to_string()))?;

        let challenge_text = match challenge_frame {
            Message::Text(t) => t,
            other => {
                return Err(AgentError::Relay(format!(
                    "unexpected message awaiting challenge: {other:?}"
                )));
            },
        };

        let challenge: DeviceChallenge =
            serde_json::from_str(&challenge_text).map_err(AgentError::Serde)?;
        let DeviceChallenge::Challenge {
            nonce,
            protocol_version,
        } = challenge;
        if protocol_version != DEVICE_AUTH_PROTOCOL_VERSION {
            return Err(AgentError::Relay(
                "relay rejected the secure device-auth protocol version".to_string(),
            ));
        }
        let nonce_bytes = base64::engine::general_purpose::STANDARD
            .decode(&nonce)
            .map_err(|e| AgentError::Base64(e.to_string()))?;
        let nonce: [u8; 32] = nonce_bytes
            .try_into()
            .map_err(|_| AgentError::Relay("invalid relay device challenge".to_string()))?;
        let signature = signing_key.sign(&device_challenge_binding(device_id, &nonce));
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

        let auth = serde_json::to_string(&OutgoingDeviceAuth::Auth {
            signature: &sig_b64,
        })?;
        stream
            .send(Message::Text(auth))
            .await
            .map_err(|e| AgentError::WebSocket(e.to_string()))?;

        let ack_frame = stream
            .next()
            .await
            .ok_or_else(|| AgentError::Relay("relay closed before AUTHENTICATED".to_string()))?
            .map_err(|e| AgentError::WebSocket(e.to_string()))?;

        let ack_text = match ack_frame {
            Message::Text(t) => t,
            other => {
                return Err(AgentError::Relay(format!(
                    "unexpected message awaiting AUTHENTICATED: {other:?}"
                )));
            },
        };

        let ack: AuthAck = serde_json::from_str(&ack_text).map_err(AgentError::Serde)?;
        match ack {
            AuthAck::Authenticated { device_id, .. } => {
                tracing::info!(?device_id, "device auth accepted");
                Ok(Self {
                    stream,
                    heartbeat_interval,
                })
            },
            AuthAck::Other => Err(AgentError::Relay(format!(
                "DEVICE_AUTH rejected: {ack_text}"
            ))),
        }
    }

    /// Pump messages until the connection closes or the handler returns an error.
    ///
    /// The handler receives every text frame from the relay; the client itself
    /// is responsible only for the heartbeat ticker.
    pub async fn run<F, Fut>(mut self, mut on_message: F) -> AgentResult<()>
    where
        F: FnMut(String) -> Fut + Send,
        Fut: std::future::Future<Output = AgentResult<()>> + Send,
    {
        let mut interval = tokio::time::interval(self.heartbeat_interval);
        interval.tick().await; // burn the immediate tick

        loop {
            tokio::select! {
                msg = self.stream.next() => {
                    match msg {
                        Some(Ok(Message::Text(t))) => {
                            on_message(t).await?;
                        },
                        Some(Ok(Message::Close(_))) | None => {
                            tracing::info!("relay closed connection");
                            return Ok(());
                        },
                        Some(Ok(_)) => {},
                        Some(Err(e)) => {
                            return Err(AgentError::WebSocket(e.to_string()));
                        },
                    }
                },
                _ = interval.tick() => {
                    let heartbeat = serde_json::json!({"type":"HEARTBEAT"}).to_string();
                    if let Err(e) = self.stream.send(Message::Text(heartbeat)).await {
                        return Err(AgentError::WebSocket(e.to_string()));
                    }
                },
            }
        }
    }

    /// Send a raw JSON-encoded frame to the relay.
    pub async fn send_raw(&mut self, body: &str) -> AgentResult<()> {
        self.stream
            .send(Message::Text(body.to_string()))
            .await
            .map_err(|e| AgentError::WebSocket(e.to_string()))
    }

    /// Run a host message loop: parse inbound [`SignalPacket`]s, dispatch to a
    /// [`HostHandler`], and send back any frames it produces. Emits periodic
    /// heartbeats so the relay does not time out an idle host.
    pub async fn run_host<H: HostHandler>(mut self, handler: &mut H) -> AgentResult<()> {
        let mut interval = tokio::time::interval(self.heartbeat_interval);
        interval.tick().await; // discard immediate tick

        loop {
            tokio::select! {
                msg = self.stream.next() => {
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            match serde_json::from_str::<rivetlink_protocol::SignalPacket>(&text) {
                                Ok(packet) => {
                                    let outgoing = handler.handle(packet).await?;
                                    for frame in outgoing {
                                        self.stream
                                            .send(Message::Text(frame))
                                            .await
                                            .map_err(|e| AgentError::WebSocket(e.to_string()))?;
                                    }
                                },
                                Err(_) => tracing::trace!("ignored non-signal frame"),
                            }
                        },
                        Some(Ok(Message::Close(_))) | None => {
                            tracing::info!("relay closed connection");
                            return Ok(());
                        },
                        Some(Ok(_)) => {},
                        Some(Err(e)) => return Err(AgentError::WebSocket(e.to_string())),
                    }
                },
                _ = interval.tick() => {
                    let heartbeat = serde_json::json!({"type": "HEARTBEAT"}).to_string();
                    self.stream
                        .send(Message::Text(heartbeat))
                        .await
                        .map_err(|e| AgentError::WebSocket(e.to_string()))?;
                },
            }
        }
    }

    /// Like [`Self::run_host`], but also serves relay tunnels (protocol v3).
    ///
    /// Each accepted tunnel becomes a local byte stream handed to `serve`,
    /// which runs the direct-LAN protocol on it; the relay only carries the
    /// frames. Legacy packets still go to `handler`. Returning (relay gone or
    /// error) drops every running tunnel.
    #[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
    pub async fn run_host_tunnels<H, F, Fut>(
        mut self,
        handler: &mut H,
        max_tunnels: usize,
        serve: F,
    ) -> AgentResult<()>
    where
        H: HostHandler,
        F: Fn(DuplexStream) -> Fut,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        use rivetlink_core::{SessionId, SessionRole};
        use rivetlink_protocol::{SignalPacket, RELAY_TUNNEL_VERSION};

        let mut interval = tokio::time::interval(self.heartbeat_interval);
        interval.tick().await; // discard immediate tick
        let (out_tx, mut out_rx) = mpsc::channel::<Message>(256);
        let mut inbound: BTreeMap<Uuid, mpsc::Sender<Vec<u8>>> = BTreeMap::new();
        let mut tunnels = tokio::task::JoinSet::new();

        loop {
            let reply: Vec<String> = tokio::select! {
                msg = self.stream.next() => match msg {
                    Some(Ok(Message::Binary(frame))) => {
                        let Some((sid, payload)) = split_tunnel_frame(&frame) else { continue };
                        let Some(tx) = inbound.get(&sid) else { continue };
                        // Waiting here slows the whole relay link down to the
                        // slowest tunnel; one that stays stuck is dropped.
                        if tx.send_timeout(payload.to_vec(), TUNNEL_SEND_TIMEOUT).await.is_err() {
                            tracing::warn!(session = %sid, "relay tunnel stuck; closing it");
                            inbound.remove(&sid);
                        }
                        continue;
                    },
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<SignalPacket>(&text) {
                            Ok(SignalPacket::SessionRequest {
                                protocol_version: RELAY_TUNNEL_VERSION,
                                session_id: Some(sid),
                                ..
                            }) => {
                                let packet = if inbound.len() >= max_tunnels {
                                    SignalPacket::SessionRejected { session_id: sid, reason: "host busy".to_string() }
                                } else {
                                    let (host_end, pump_end) = tokio::io::duplex(TUNNEL_BUFFER);
                                    let (tx, rx) = mpsc::channel(64);
                                    inbound.insert(sid.0, tx);
                                    let session = serve(host_end);
                                    let pump = tunnel_pump(pump_end, sid.0, rx, out_tx.clone());
                                    tunnels.spawn(async move {
                                        tokio::join!(session, pump);
                                        sid.0
                                    });
                                    tracing::info!(session = %sid, "relay tunnel accepted");
                                    SignalPacket::SessionAccepted { session_id: sid, role: SessionRole::Controller }
                                };
                                vec![serde_json::to_string(&packet)?]
                            },
                            Ok(SignalPacket::SessionClosed { session_id: SessionId(sid) })
                                if inbound.contains_key(&sid) =>
                            {
                                // Closing the inbound side ends the session task.
                                inbound.remove(&sid);
                                continue;
                            },
                            Ok(packet) => handler.handle(packet).await?,
                            Err(_) => {
                                tracing::trace!("ignored non-signal frame");
                                continue;
                            },
                        }
                    },
                    Some(Ok(Message::Close(_))) | None => {
                        tracing::info!("relay closed connection");
                        return Ok(());
                    },
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => return Err(AgentError::WebSocket(e.to_string())),
                },
                Some(message) = out_rx.recv() => {
                    self.stream
                        .send(message)
                        .await
                        .map_err(|e| AgentError::WebSocket(e.to_string()))?;
                    continue;
                },
                Some(Ok(sid)) = tunnels.join_next(), if !tunnels.is_empty() => {
                    inbound.remove(&sid);
                    tracing::info!(session = %sid, "relay tunnel ended");
                    continue;
                },
                _ = interval.tick() => vec![serde_json::json!({"type": "HEARTBEAT"}).to_string()],
            };
            for frame in reply {
                self.stream
                    .send(Message::Text(frame))
                    .await
                    .map_err(|e| AgentError::WebSocket(e.to_string()))?;
            }
        }
    }
}

fn ensure_secure_relay_url(url: &str) -> AgentResult<()> {
    // Plain ws:// only to this machine (tests, a relay on the same host).
    let loopback = ["ws://127.0.0.1:", "ws://localhost:", "ws://[::1]:"];
    if url.starts_with("wss://") || loopback.iter().any(|prefix| url.starts_with(prefix)) {
        Ok(())
    } else {
        Err(AgentError::Config(
            "relay_url must use wss://; plaintext relay WebSockets are unsafe".to_string(),
        ))
    }
}

fn device_challenge_binding(device_id: Uuid, nonce: &[u8; 32]) -> Vec<u8> {
    let mut binding =
        Vec::with_capacity(DEVICE_AUTH_DOMAIN.len() + 2 + device_id.as_bytes().len() + nonce.len());
    binding.extend_from_slice(DEVICE_AUTH_DOMAIN);
    binding.extend_from_slice(&DEVICE_AUTH_PROTOCOL_VERSION.to_be_bytes());
    binding.extend_from_slice(device_id.as_bytes());
    binding.extend_from_slice(nonce);
    binding
}

/// Bytes buffered between a tunnel's session task and the relay link.
const TUNNEL_BUFFER: usize = 256 * 1024;
/// How long one tunnel may hold up the relay link before it is dropped.
const TUNNEL_SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// `[16-byte session id][payload]` → (session id, payload).
fn split_tunnel_frame(frame: &[u8]) -> Option<(Uuid, &[u8])> {
    if frame.len() <= 16 {
        return None;
    }
    let (sid, payload) = frame.split_at(16);
    Some((Uuid::from_slice(sid).ok()?, payload))
}

/// Move one tunnel's bytes between its local stream and the relay link.
/// When the host side ends the session, the relay is told so.
async fn tunnel_pump(
    stream: DuplexStream,
    session_id: Uuid,
    mut inbound: mpsc::Receiver<Vec<u8>>,
    out: mpsc::Sender<Message>,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let upstream = async {
        let mut buf = vec![0u8; rivetlink_protocol::MAX_TUNNEL_PAYLOAD];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    let frame = [session_id.as_bytes().as_slice(), &buf[..n]].concat();
                    if out.send(Message::Binary(frame)).await.is_err() {
                        return;
                    }
                },
            }
        }
    };
    let downstream = async {
        while let Some(payload) = inbound.recv().await {
            if writer.write_all(&payload).await.is_err() {
                return;
            }
        }
    };
    tokio::select! {
        () = upstream => {
            let closed = rivetlink_protocol::SignalPacket::SessionClosed {
                session_id: rivetlink_core::SessionId(session_id),
            };
            if let Ok(text) = serde_json::to_string(&closed) {
                let _ = out.send(Message::Text(text)).await;
            }
        },
        () = downstream => {},
    }
}

/// Handles inbound signaling packets for a host, producing outbound frames.
#[async_trait::async_trait]
pub trait HostHandler: Send {
    /// Process one packet, returning zero or more JSON frames to transmit.
    async fn handle(
        &mut self,
        packet: rivetlink_protocol::SignalPacket,
    ) -> AgentResult<Vec<String>>;
}
