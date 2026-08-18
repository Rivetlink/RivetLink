//! WebSocket upgrade handler with JWT or device challenge-response authentication.
//!
//! Two authentication paths are supported on the first frame:
//!
//! - **User clients** send `{"type":"AUTH","token":"<jwt>"}` and the server
//!   validates a standard access-token JWT.
//! - **Host agents** (devices) send `{"type":"DEVICE_HELLO","device_id":"..."}`,
//!   the server replies with a random `DEVICE_CHALLENGE { nonce }`, and the
//!   agent must respond with `DEVICE_AUTH { signature }` proving possession of
//!   the device's Ed25519 signing key. The signature covers the raw nonce
//!   bytes — no JWT, no shared bearer secret.

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

use crate::auth::jwt;
use crate::db::devices;
use crate::state::AppState;
use crate::websocket::connection::{ConnectedClient, PrincipalKind};
use crate::websocket::heartbeat::HeartbeatTracker;

const DEVICE_CHALLENGE_SIZE: usize = 32;

/// First-frame handshake messages accepted from the client.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum WsHandshakeMessage {
    #[serde(rename = "AUTH")]
    UserAuth { token: String },
    #[serde(rename = "DEVICE_HELLO")]
    DeviceHello { device_id: Uuid },
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
    ws.on_upgrade(move |socket| handle_socket(socket, state))
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

    let (outgoing_tx, mut outgoing_rx) = mpsc::unbounded_channel::<String>();

    state.connections.insert(
        principal_id,
        ConnectedClient {
            user_id: principal_id,
            org_id,
            kind,
            sender: outgoing_tx,
        },
    );

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
    let _ = ws_sink.send(Message::Text(payload.to_string())).await;

    let heartbeat = HeartbeatTracker::new(state.config.disconnect_timeout_secs);

    let connections_for_cleanup = state.connections.clone();
    let signaling_tx = state.signaling_tx.clone();

    let write_task = tokio::spawn(async move {
        while let Some(msg) = outgoing_rx.recv().await {
            if ws_sink.send(Message::Text(msg)).await.is_err() {
                break;
            }
        }
    });

    let heartbeat_interval_secs = state.config.heartbeat_interval_secs;
    let read_task = tokio::spawn(async move {
        let mut heartbeat = heartbeat;
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(heartbeat_interval_secs));

        loop {
            tokio::select! {
                msg = ws_stream.next() => {
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            heartbeat.touch();
                            if let Err(e) = signaling_tx.send((principal_id, org_id, text)) {
                                tracing::error!(error = %e, "signaling channel closed");
                                break;
                            }
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

    connections_for_cleanup.remove(&principal_id);
    tracing::info!(principal = %principal_id, "websocket disconnected");
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
        WsHandshakeMessage::DeviceHello { device_id } => {
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

    let challenge = serde_json::json!({"type": "DEVICE_CHALLENGE", "nonce": nonce_b64}).to_string();
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
        .verify(&nonce, &sig)
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
}
