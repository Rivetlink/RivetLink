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
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_tungstenite::{tungstenite::Message, MaybeTlsStream, WebSocketStream};
use uuid::Uuid;

use crate::error::{AgentError, AgentResult};

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

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
    Hello { device_id: Uuid },
}

/// Server-sent challenge.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum DeviceChallenge {
    #[serde(rename = "DEVICE_CHALLENGE")]
    Challenge { nonce: String },
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
        let (mut stream, _resp) = tokio_tungstenite::connect_async(url)
            .await
            .map_err(|e| AgentError::Relay(format!("connect failed: {e}")))?;

        let hello = serde_json::to_string(&OutgoingDeviceHello::Hello { device_id })?;
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
        let DeviceChallenge::Challenge { nonce } = challenge;
        let nonce_bytes = base64::engine::general_purpose::STANDARD
            .decode(&nonce)
            .map_err(|e| AgentError::Base64(e.to_string()))?;

        let signature = signing_key.sign(&nonce_bytes);
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
            AuthAck::Other => Err(AgentError::Relay(format!("DEVICE_AUTH rejected: {ack_text}"))),
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
