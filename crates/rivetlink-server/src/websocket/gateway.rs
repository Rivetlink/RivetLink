//! WebSocket upgrade handler with JWT or device challenge-response authentication.
//!
//! Two authentication paths are supported on the first frame:
//!
//! - **User clients** send `{"type":"AUTH","token":"<jwt>"}` and the server
//!   validates a standard access-token JWT.
//! - **Host agents** (devices) send `{"type":"DEVICE_HELLO","device_id":"..."}`,
//!   the server replies with a random `DEVICE_CHALLENGE { nonce }`, and the
//!   agent must respond with `DEVICE_AUTH { signature }` proving possession of
//!   the device's Ed25519 signing key. The signature covers a fresh challenge
//!   bound to the device id and protocol version — no JWT, no shared secret.

use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    response::IntoResponse,
};
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use futures_util::{stream::SplitSink, SinkExt, StreamExt};
use rand_08::rngs::OsRng;
use rand_08::RngCore;
use serde::Deserialize;
use tokio::sync::mpsc;
use uuid::Uuid;

use rivetlink_core::SessionId;
use rivetlink_protocol::{SignalPacket, MAX_TUNNEL_PAYLOAD};

use crate::auth::jwt;
use crate::db::devices;
use crate::sessions::manager::ActiveSession;
use crate::state::{AppState, SignalingMessage};
use crate::websocket::connection::{ConnectedClient, ConnectionMap, PrincipalKind, OUTGOING_QUEUE};
use crate::websocket::heartbeat::HeartbeatTracker;

/// Largest WebSocket message accepted. Tunnel frames are at most 64 KiB plus
/// the session id; legacy screenshot chunks are ~65 KiB of JSON.
const MAX_WS_MESSAGE: usize = 256 * 1024;
/// How long a tunnel frame may wait for room in the receiver's queue before
/// the session is ended as stuck (matches the agent's LAN frame timeout).
const TUNNEL_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const SESSION_ID_LEN: usize = 16;
const DEVICE_CHALLENGE_SIZE: usize = 32;
const DEVICE_AUTH_PROTOCOL_VERSION: u16 = 2;
const DEVICE_AUTH_DOMAIN: &[u8] = b"rivetlink-relay-device-auth-v2";

/// First-frame handshake messages accepted from the client.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum WsHandshakeMessage {
    #[serde(rename = "AUTH")]
    UserAuth { token: String },
    #[serde(rename = "DEVICE_HELLO")]
    DeviceHello {
        device_id: Uuid,
        protocol_version: u16,
    },
}

/// Second-frame from the device after receiving a `DEVICE_CHALLENGE`.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum WsDeviceFollowup {
    #[serde(rename = "DEVICE_AUTH")]
    DeviceAuth { signature: String },
}

/// Outcome of a successful handshake.
struct AuthOutcome {
    principal_id: Uuid,
    org_id: Uuid,
    kind: PrincipalKind,
}

/// Upgrade HTTP request to WebSocket; returns rejection with auth timeout if no JWT.
pub async fn ws_upgrade(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.max_message_size(MAX_WS_MESSAGE)
        .max_frame_size(MAX_WS_MESSAGE)
        .on_upgrade(move |socket| handle_socket(socket, state))
}

#[allow(clippy::cognitive_complexity)]
async fn handle_socket(socket: WebSocket, state: AppState) {
    let (mut ws_sink, mut ws_stream) = socket.split();

    let auth_result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        wait_for_auth(&mut ws_stream, &mut ws_sink, &state),
    )
    .await;

    let outcome = match auth_result {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => {
            let msg = serde_json::json!({"error": e}).to_string();
            let _ = ws_sink.send(Message::Text(msg)).await;
            return;
        },
        Err(_) => {
            let msg = serde_json::json!({"error": "auth timeout"}).to_string();
            let _ = ws_sink.send(Message::Text(msg)).await;
            return;
        },
    };

    let principal_id = outcome.principal_id;
    let org_id = outcome.org_id;
    let kind = outcome.kind;

    tracing::info!(principal = %principal_id, ?kind, "websocket authenticated");

    let conn_id = Uuid::now_v7();
    let (outgoing_tx, mut outgoing_rx) = mpsc::channel::<Message>(OUTGOING_QUEUE);

    state.connections.insert(
        conn_id,
        ConnectedClient {
            user_id: principal_id,
            org_id,
            kind,
            sender: outgoing_tx,
        },
    );

    let _ = ws_sink
        .send(Message::Text(authenticated_message(kind, principal_id)))
        .await;

    let heartbeat = HeartbeatTracker::new(state.config.disconnect_timeout_secs);

    let write_task = tokio::spawn(async move {
        while let Some(msg) = outgoing_rx.recv().await {
            if ws_sink.send(msg).await.is_err() {
                break;
            }
        }
    });

    let heartbeat_interval_secs = state.config.heartbeat_interval_secs;
    let reader_state = state.clone();
    let read_task = tokio::spawn(async move {
        let state = reader_state;
        let mut heartbeat = heartbeat;
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(heartbeat_interval_secs));

        loop {
            tokio::select! {
                msg = ws_stream.next() => {
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            heartbeat.touch();
                            let message = SignalingMessage {
                                conn_id,
                                principal_id,
                                org_id,
                                kind,
                                text,
                            };
                            if let Err(e) = state.signaling_tx.send(message) {
                                tracing::error!(error = %e, "signaling channel closed");
                                break;
                            }
                        },
                        Some(Ok(Message::Binary(frame))) => {
                            heartbeat.touch();
                            forward_tunnel_frame(&state, conn_id, frame).await;
                        },
                        Some(Ok(Message::Ping(_))) => {
                            heartbeat.touch();
                        },
                        Some(Ok(Message::Close(_))) | None => break,
                        _ => {},
                    }
                },
                _ = interval.tick() => {
                    if heartbeat.is_expired() {
                        tracing::info!(principal = %principal_id, "heartbeat timeout");
                        break;
                    }
                },
            }
        }
    });

    tokio::select! {
        _ = write_task => {},
        _ = read_task => {},
    }

    forget_connection(&state, conn_id);
    tracing::info!(principal = %principal_id, "websocket disconnected");
}

/// The `AUTHENTICATED` frame telling a principal who it is.
fn authenticated_message(kind: PrincipalKind, principal_id: Uuid) -> String {
    let payload = match kind {
        PrincipalKind::User => serde_json::json!({
            "type": "AUTHENTICATED",
            "user_id": principal_id.to_string(),
        }),
        PrincipalKind::Device => serde_json::json!({
            "type": "AUTHENTICATED",
            "device_id": principal_id.to_string(),
        }),
    };
    payload.to_string()
}

/// Forward one tunnel frame `[session id][payload]` to the session's other
/// connection, unread. Waits while that connection's queue is full, so a slow
/// viewer slows the host down (like TCP on the LAN path) instead of growing
/// memory; a peer that stays stuck ends the session.
async fn forward_tunnel_frame(state: &AppState, conn_id: Uuid, frame: Vec<u8>) {
    if frame.len() <= SESSION_ID_LEN || frame.len() > SESSION_ID_LEN + MAX_TUNNEL_PAYLOAD {
        tracing::warn!(len = frame.len(), "dropping malformed tunnel frame");
        return;
    }
    let Ok(session_id) = Uuid::from_slice(&frame[..SESSION_ID_LEN]) else {
        return;
    };
    let Some(peer) = state.sessions.tunnel_peer_conn(&session_id, &conn_id) else {
        tracing::debug!(session = %session_id, "dropping tunnel frame for a session this connection is not in");
        return;
    };
    let Some(sender) = state.connections.get_sender(&peer) else {
        return;
    };
    if sender
        .send_timeout(Message::Binary(frame), TUNNEL_SEND_TIMEOUT)
        .await
        .is_err()
    {
        tracing::warn!(session = %session_id, "tunnel peer stuck or gone, ending session");
        if let Some(session) = state.sessions.remove_session(&session_id) {
            notify_closed(&state.connections, &session);
        }
    }
}

/// Drop a closed connection and end every session it took part in.
fn forget_connection(state: &AppState, conn_id: Uuid) {
    state.connections.remove(&conn_id);
    for session in state.sessions.remove_for_conn(&conn_id) {
        notify_closed(&state.connections, &session);
    }
}

/// Tell both ends that the relay ended the session.
fn notify_closed(connections: &ConnectionMap, session: &ActiveSession) {
    let Ok(text) = serde_json::to_string(&SignalPacket::SessionClosed {
        session_id: SessionId(session.id),
    }) else {
        return;
    };
    for conn in [session.initiator_conn, session.device_conn] {
        connections.send_to(&conn, &text);
    }
}

/// Read the first frame and dispatch on its `type` discriminator.
async fn wait_for_auth(
    stream: &mut (impl StreamExt<Item = Result<Message, axum::Error>> + Unpin),
    sink: &mut SplitSink<WebSocket, Message>,
    state: &AppState,
) -> Result<AuthOutcome, String> {
    let text = read_text(stream).await?;

    let msg: WsHandshakeMessage =
        serde_json::from_str(&text).map_err(|e| format!("invalid auth message: {e}"))?;

    match msg {
        WsHandshakeMessage::UserAuth { token } => authenticate_user(&token, state),
        WsHandshakeMessage::DeviceHello {
            device_id,
            protocol_version,
        } => {
            if protocol_version != DEVICE_AUTH_PROTOCOL_VERSION {
                return Err("unsupported secure device-auth protocol".to_string());
            }
            authenticate_device(device_id, stream, sink, state).await
        },
    }
}

/// Validate a user JWT and return the resulting principal record.
fn authenticate_user(token: &str, state: &AppState) -> Result<AuthOutcome, String> {
    let claims = jwt::decode_access_token(token, &state.config.jwt_secret)
        .map_err(|e| format!("auth failed: {e}"))?;
    Ok(AuthOutcome {
        principal_id: claims.sub,
        org_id: claims.org,
        kind: PrincipalKind::User,
    })
}

/// Run the device challenge-response: look up the device, send a random
/// nonce, await the signature, verify it against the stored Ed25519 key.
async fn authenticate_device(
    device_id: Uuid,
    stream: &mut (impl StreamExt<Item = Result<Message, axum::Error>> + Unpin),
    sink: &mut SplitSink<WebSocket, Message>,
    state: &AppState,
) -> Result<AuthOutcome, String> {
    let device = devices::get_device(&state.db, device_id)
        .await
        .map_err(|_| "unknown device".to_string())?;

    let verifying_key = parse_public_key(&device.public_key)?;

    let mut nonce = [0u8; DEVICE_CHALLENGE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(nonce);

    let challenge = serde_json::json!({
        "type": "DEVICE_CHALLENGE",
        "protocol_version": DEVICE_AUTH_PROTOCOL_VERSION,
        "nonce": nonce_b64,
    })
    .to_string();
    sink.send(Message::Text(challenge))
        .await
        .map_err(|e| format!("send DEVICE_CHALLENGE failed: {e}"))?;

    let text = read_text(stream).await?;
    let followup: WsDeviceFollowup =
        serde_json::from_str(&text).map_err(|e| format!("invalid DEVICE_AUTH frame: {e}"))?;
    let WsDeviceFollowup::DeviceAuth { signature } = followup;

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&signature)
        .map_err(|e| format!("invalid base64 signature: {e}"))?;
    if sig_bytes.len() != 64 {
        return Err(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes.len()
        ));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);

    use ed25519_dalek::Verifier;
    verifying_key
        .verify(&device_challenge_binding(device_id, &nonce), &sig)
        .map_err(|_| "invalid signature".to_string())?;

    // Note: we do not persist nonces because each challenge is consumed
    // within a single handshake (one-shot). A future global NonceStore would
    // be needed only if challenges were issued outside the handshake.

    Ok(AuthOutcome {
        principal_id: device.id,
        org_id: device.organization_id,
        kind: PrincipalKind::Device,
    })
}

fn device_challenge_binding(device_id: Uuid, nonce: &[u8; DEVICE_CHALLENGE_SIZE]) -> Vec<u8> {
    let mut binding =
        Vec::with_capacity(DEVICE_AUTH_DOMAIN.len() + 2 + device_id.as_bytes().len() + nonce.len());
    binding.extend_from_slice(DEVICE_AUTH_DOMAIN);
    binding.extend_from_slice(&DEVICE_AUTH_PROTOCOL_VERSION.to_be_bytes());
    binding.extend_from_slice(device_id.as_bytes());
    binding.extend_from_slice(nonce);
    binding
}

/// Read frames until we get a text payload, propagating errors and closure.
async fn read_text(
    stream: &mut (impl StreamExt<Item = Result<Message, axum::Error>> + Unpin),
) -> Result<String, String> {
    while let Some(msg) = stream.next().await {
        match msg {
            Ok(Message::Text(t)) => return Ok(t),
            Ok(Message::Close(_)) => return Err("connection closed".to_string()),
            Err(e) => return Err(format!("ws error: {e}")),
            _ => continue,
        }
    }
    Err("connection closed before handshake completed".to_string())
}

/// Decode a stored device public key (base64) into an Ed25519 `VerifyingKey`.
fn parse_public_key(encoded: &str) -> Result<VerifyingKey, String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|e| format!("invalid stored public_key: {e}"))?;
    if raw.len() != 32 {
        return Err(format!(
            "stored public_key must be 32 bytes, got {}",
            raw.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&raw);
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("invalid public_key: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_public_key_round_trip() {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let sk = ed25519_dalek::SigningKey::from_bytes(&bytes);
        let pk_b64 =
            base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().as_bytes());
        let decoded = parse_public_key(&pk_b64).expect("must parse");
        assert_eq!(decoded.as_bytes(), sk.verifying_key().as_bytes());
    }

    #[test]
    fn parse_public_key_rejects_invalid_base64() {
        assert!(parse_public_key("not-base64-!@#").is_err());
    }

    #[test]
    fn parse_public_key_rejects_wrong_length() {
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
        assert!(parse_public_key(&short).is_err());
    }

    #[test]
    fn device_challenge_is_bound_to_the_device_and_protocol() {
        let nonce = [7u8; DEVICE_CHALLENGE_SIZE];
        let first = Uuid::now_v7();
        let second = Uuid::now_v7();
        assert_ne!(
            device_challenge_binding(first, &nonce),
            device_challenge_binding(second, &nonce)
        );
    }
}
