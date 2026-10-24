//! A byte stream to a host through the relay (relay protocol v3).
//!
//! [`open`] asks the relay for a tunnel session to a device and returns a
//! local stream. Everything written to it reaches the host as binary
//! WebSocket frames `[session id][payload]`, and the host's frames come back
//! out. The relay forwards those frames unread; the caller runs the
//! direct-LAN protocol over the stream ([`crate::lan::connect_key_over`]),
//! which authenticates the host by its pinned key and encrypts end to end.

use std::time::Duration;

use futures_util::{SinkExt, Stream, StreamExt};
use rivetlink_core::DeviceId;
use rivetlink_protocol::{
    SessionCapability, SignalPacket, MAX_TUNNEL_PAYLOAD, RELAY_TUNNEL_VERSION,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use crate::error::{SdkError, SdkResult};

/// Bytes buffered between the caller and the WebSocket in each direction.
const TUNNEL_BUFFER: usize = 256 * 1024;
/// How long connecting, authenticating and waiting for the host may take.
const OPEN_TIMEOUT: Duration = Duration::from_secs(15);
/// Keeps the relay's heartbeat alive while a still screen sends nothing.
const PING_INTERVAL: Duration = Duration::from_secs(10);

/// Where and as whom to open a tunnel.
#[derive(Debug, Clone, Copy)]
pub struct TunnelParams<'a> {
    pub relay_ws_url: &'a str,
    pub token: &'a str,
    pub device_id: Uuid,
    /// Our identity key, sent so the host can refuse an unknown client early.
    /// It is a hint only: the handshake inside the tunnel is what counts.
    pub client_public_key: &'a str,
    pub requested_capability: SessionCapability,
}

/// Open a tunnel to `params.device_id`. The returned stream ends (EOF) when
/// the host or the relay closes the session; dropping it closes the session.
pub async fn open(params: TunnelParams<'_>) -> SdkResult<DuplexStream> {
    require_secure_ws(params.relay_ws_url)?;
    let (ws, session_id) = tokio::time::timeout(OPEN_TIMEOUT, start_session(params))
        .await
        .map_err(|_| SdkError::Relay("relay tunnel did not open in time".to_string()))??;
    tracing::info!(session = %session_id, device = %params.device_id, "relay tunnel open");
    let (caller_end, pump_end) = tokio::io::duplex(TUNNEL_BUFFER);
    tokio::spawn(pump(ws, session_id, pump_end));
    Ok(caller_end)
}

/// Only `wss://` crosses a network. Plain `ws://` is allowed to the local
/// machine, for tests and a relay on the same host.
pub fn require_secure_ws(url: &str) -> SdkResult<()> {
    if url.starts_with("wss://") {
        return Ok(());
    }
    if let Some(rest) = url.strip_prefix("ws://") {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let host = authority
            .rsplit_once(':')
            .map_or(authority, |(host, _)| host);
        // No userinfo: `ws://localhost:80@evil.com` connects to evil.com.
        if !authority.contains('@') && ["127.0.0.1", "localhost", "[::1]"].contains(&host) {
            return Ok(());
        }
    }
    Err(SdkError::Config(
        "relay URL must use wss://; plaintext relay WebSockets are unsafe".to_string(),
    ))
}

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Authenticate, request a tunnel and wait until the host accepts it.
async fn start_session(params: TunnelParams<'_>) -> SdkResult<(Ws, Uuid)> {
    let (mut ws, _) = tokio_tungstenite::connect_async(params.relay_ws_url)
        .await
        .map_err(|e| SdkError::Relay(format!("connect failed: {e}")))?;
    let auth = serde_json::json!({"type": "AUTH", "token": params.token});
    ws.send(Message::Text(auth.to_string()))
        .await
        .map_err(|e| SdkError::Relay(e.to_string()))?;
    let ack: serde_json::Value = serde_json::from_str(&next_text(&mut ws).await?)?;
    if ack.get("type").and_then(|v| v.as_str()) != Some("AUTHENTICATED") {
        return Err(SdkError::Auth(format!("unexpected auth response: {ack}")));
    }

    let request = SignalPacket::SessionRequest {
        device_id: DeviceId(params.device_id),
        client_public_key: params.client_public_key.to_string(),
        protocol_version: RELAY_TUNNEL_VERSION,
        requested_capability: params.requested_capability,
        session_id: None,
    };
    ws.send(Message::Text(serde_json::to_string(&request)?))
        .await
        .map_err(|e| SdkError::Relay(e.to_string()))?;
    loop {
        match serde_json::from_str::<SignalPacket>(&next_text(&mut ws).await?) {
            Ok(SignalPacket::SessionAccepted { session_id, .. }) => return Ok((ws, session_id.0)),
            Ok(SignalPacket::SessionRejected { reason, .. }) => {
                return Err(SdkError::SessionRejected(reason))
            },
            _ => {},
        }
    }
}

async fn next_text(ws: &mut Ws) -> SdkResult<String> {
    while let Some(message) = ws.next().await {
        match message.map_err(|e| SdkError::Relay(e.to_string()))? {
            Message::Text(text) => return Ok(text),
            Message::Close(_) => break,
            _ => {},
        }
    }
    Err(SdkError::Relay("relay closed the connection".to_string()))
}

/// Move bytes between the caller's stream and the WebSocket until either
/// side ends, then close the session.
async fn pump(ws: Ws, session_id: Uuid, stream: DuplexStream) {
    let (sink, incoming) = ws.split();
    let (reader, writer) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::channel::<Message>(64);

    let send_all = async move {
        let mut sink = sink;
        while let Some(message) = rx.recv().await {
            if sink.send(message).await.is_err() {
                return;
            }
        }
        let _ = sink.close().await;
    };
    let pumps = async move {
        tokio::select! {
            () = upstream(reader, session_id, tx.clone()) => {},
            () = downstream(incoming, session_id, writer) => {},
            () = ping(tx) => {},
        }
        // Dropping the senders here lets `send_all` flush and close.
    };
    tokio::join!(send_all, pumps);
    tracing::info!(session = %session_id, "relay tunnel closed");
}

/// Caller → host. On EOF the session is closed explicitly.
async fn upstream(mut reader: ReadHalf<DuplexStream>, session_id: Uuid, tx: mpsc::Sender<Message>) {
    let mut buf = vec![0u8; MAX_TUNNEL_PAYLOAD];
    loop {
        let n = match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let frame = [session_id.as_bytes().as_slice(), &buf[..n]].concat();
        if tx.send(Message::Binary(frame)).await.is_err() {
            return;
        }
    }
    let closed = SignalPacket::SessionClosed {
        session_id: rivetlink_core::SessionId(session_id),
    };
    if let Ok(text) = serde_json::to_string(&closed) {
        let _ = tx.send(Message::Text(text)).await;
    }
}

/// Host → caller. Ends when the relay or host closes the session.
async fn downstream(
    mut incoming: impl Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
    session_id: Uuid,
    mut writer: WriteHalf<DuplexStream>,
) {
    while let Some(Ok(message)) = incoming.next().await {
        match message {
            Message::Binary(frame) => {
                // Only frames tagged with our session; the relay never sends
                // others, but a frame is never trusted to say otherwise.
                let Some(payload) = frame.strip_prefix(session_id.as_bytes().as_slice()) else {
                    continue;
                };
                if writer.write_all(payload).await.is_err() {
                    return;
                }
            },
            Message::Text(text) => match serde_json::from_str(&text) {
                Ok(
                    SignalPacket::SessionClosed { session_id: sid }
                    | SignalPacket::SessionRejected {
                        session_id: sid, ..
                    },
                ) if sid.0 == session_id => return,
                _ => {},
            },
            Message::Close(_) => return,
            _ => {},
        }
    }
}

async fn ping(tx: mpsc::Sender<Message>) {
    let mut interval = tokio::time::interval(PING_INTERVAL);
    interval.tick().await;
    loop {
        interval.tick().await;
        if tx.send(Message::Ping(Vec::new())).await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_tls_or_loopback_websockets_are_allowed() {
        assert!(require_secure_ws("wss://relay.example.com/ws").is_ok());
        assert!(require_secure_ws("ws://127.0.0.1:8080/ws").is_ok());
        assert!(require_secure_ws("ws://localhost:8080/ws").is_ok());
        assert!(require_secure_ws("ws://relay.example.com/ws").is_err());
        assert!(require_secure_ws("ws://127.0.0.1.evil.com:80/ws").is_err());
        assert!(require_secure_ws("ws://localhost.evil.com/ws").is_err());
        assert!(require_secure_ws("http://127.0.0.1:8080").is_err());
        assert!(require_secure_ws("ws://[::1]:8080/ws").is_ok());
        assert!(require_secure_ws("ws://localhost:80@evil.com/ws").is_err());
        assert!(require_secure_ws("ws://127.0.0.1:80@evil.com:80/ws").is_err());
        assert!(require_secure_ws("ws://evil.com/127.0.0.1:80").is_err());
    }
}
