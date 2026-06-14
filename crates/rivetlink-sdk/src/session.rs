//! Client-side session flow: connect, request, handshake, receive screenshot.
//!
//! State machine over the relay WebSocket:
//! 1. authenticate as a user (JWT)
//! 2. send `SessionRequest` carrying our identity public key (host trusts it)
//! 3. on `SessionAccepted`: send our signed ephemeral key, await the host's
//! 4. verify the host's ephemeral key against its pinned identity, derive the
//!    sealed channel
//! 5. send `ScreenshotRequest`, reassemble the base64 chunks, decrypt, save
//!
//! `SessionRejected` at any point aborts with the host's reason.

use base64::Engine;
use ed25519_dalek::VerifyingKey;
use rivetlink_core::{DeviceId, SessionId};
use rivetlink_crypto::handshake::{self, LocalKeyExchange};
use rivetlink_crypto::sealed::SealedChannel;
use rivetlink_protocol::SignalPacket;
use futures_util::{SinkExt, StreamExt};
use std::path::PathBuf;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use crate::error::{SdkError, SdkResult};
use crate::identity::Identity;

/// Inputs for a single screenshot session.
#[derive(Debug)]
pub struct CaptureParams<'a> {
    pub relay_ws_url: &'a str,
    pub token: &'a str,
    pub identity: &'a Identity,
    pub device_id: Uuid,
    /// Base64 Ed25519 identity key of the host, from the authenticated REST API.
    pub host_public_key_b64: &'a str,
    pub output_path: PathBuf,
}

/// Run a single screenshot session end to end. Returns the path written.
pub async fn capture_screenshot(req: CaptureParams<'_>) -> SdkResult<PathBuf> {
    let host_identity = parse_identity(req.host_public_key_b64)?;

    let (mut ws, _resp) = tokio_tungstenite::connect_async(req.relay_ws_url)
        .await
        .map_err(|e| SdkError::Relay(format!("connect failed: {e}")))?;

    // 1. User auth.
    send(&mut ws, &serde_json::json!({"type": "AUTH", "token": req.token})).await?;
    let ack = recv_text(&mut ws).await?;
    let ack_json: serde_json::Value = serde_json::from_str(&ack)?;
    if ack_json.get("type").and_then(|v| v.as_str()) != Some("AUTHENTICATED") {
        return Err(SdkError::Auth(format!("unexpected auth response: {ack}")));
    }

    // 2. Session request with our identity key.
    let session_request = SignalPacket::SessionRequest {
        device_id: DeviceId(req.device_id),
        client_public_key: req.identity.public_key_b64(),
        session_id: None,
    };
    send_packet(&mut ws, &session_request).await?;

    // 3-5. Drive the rest of the handshake.
    let mut local_kex: Option<LocalKeyExchange> = None;
    let mut channel: Option<SealedChannel> = None;
    let mut session_id: Option<SessionId> = None;
    let mut chunks: Vec<(u32, String)> = Vec::new();

    loop {
        let text = recv_text(&mut ws).await?;
        let packet: SignalPacket = match serde_json::from_str(&text) {
            Ok(p) => p,
            Err(_) => continue, // ignore non-signal frames
        };

        match packet {
            SignalPacket::SessionAccepted { session_id: sid, role } => {
                tracing::info!(session = %sid, ?role, "host accepted session");
                session_id = Some(sid);
                let kex = handshake::start(req.identity.signing_key());
                send_packet(&mut ws, &key_exchange_packet(sid, req.identity, &kex)).await?;
                local_kex = Some(kex);
            },
            SignalPacket::SessionRejected { reason, .. } => {
                return Err(SdkError::SessionRejected(reason));
            },
            SignalPacket::SessionKeyExchange {
                session_id: sid,
                ephemeral_public_key,
                identity_public_key,
                signature,
            } => {
                // Pin host identity: the asserted identity must equal the key
                // we fetched over the authenticated REST channel.
                if identity_public_key.trim() != req.host_public_key_b64.trim() {
                    return Err(SdkError::Crypto(
                        "host identity key mismatch — possible MITM".to_string(),
                    ));
                }
                let peer_eph = decode_32(&ephemeral_public_key)?;
                let peer_sig = decode_64(&signature)?;
                handshake::verify_peer(&host_identity, &peer_eph, &peer_sig)
                    .map_err(|e| SdkError::Crypto(format!("host key exchange invalid: {e}")))?;

                let kex = local_kex
                    .take()
                    .ok_or_else(|| SdkError::Crypto("host key exchange arrived before accept".to_string()))?;
                channel = Some(kex.into_channel(&peer_eph));
                session_id = Some(sid);

                // 5. Ask for the screenshot.
                send_packet(&mut ws, &SignalPacket::ScreenshotRequest { session_id: sid }).await?;
                tracing::info!("secure channel established, requested screenshot");
            },
            SignalPacket::ScreenshotData {
                sequence,
                total,
                last,
                payload,
                ..
            } => {
                chunks.push((sequence, payload));
                if last || chunks.len() >= total as usize {
                    let channel = channel
                        .as_ref()
                        .ok_or_else(|| SdkError::Crypto("data before key exchange".to_string()))?;
                    let path = finalize(&mut chunks, Some(total), channel, &req.output_path)?;
                    // Politely close the session.
                    if let Some(sid) = session_id {
                        let _ = send_packet(&mut ws, &SignalPacket::SessionClosed { session_id: sid }).await;
                    }
                    let _ = ws.close(None).await;
                    return Ok(path);
                }
            },
            SignalPacket::SessionClosed { .. } => {
                return Err(SdkError::Relay("host closed the session".to_string()));
            },
            _ => {},
        }
    }
}

/// Reassemble, decrypt, and write the captured image.
fn finalize(
    chunks: &mut [(u32, String)],
    total: Option<u32>,
    channel: &SealedChannel,
    output_path: &PathBuf,
) -> SdkResult<PathBuf> {
    if let Some(total) = total {
        if chunks.len() != total as usize {
            return Err(SdkError::Relay(format!(
                "incomplete capture: {} of {total} chunks",
                chunks.len()
            )));
        }
    }
    chunks.sort_by_key(|(seq, _)| *seq);

    let mut b64 = String::new();
    for (_, part) in chunks.iter() {
        b64.push_str(part);
    }

    let sealed = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| SdkError::Base64(e.to_string()))?;
    let image = channel
        .open(&sealed)
        .map_err(|e| SdkError::Crypto(format!("decrypt failed: {e}")))?;

    std::fs::write(output_path, &image)?;
    Ok(output_path.clone())
}

/// Build a `SessionKeyExchange` packet from our local exchange state.
fn key_exchange_packet(
    session_id: SessionId,
    identity: &Identity,
    kex: &LocalKeyExchange,
) -> SignalPacket {
    let std = base64::engine::general_purpose::STANDARD;
    SignalPacket::SessionKeyExchange {
        session_id,
        ephemeral_public_key: std.encode(kex.ephemeral_public()),
        identity_public_key: identity.public_key_b64(),
        signature: std.encode(kex.signature()),
    }
}

fn parse_identity(b64: &str) -> SdkResult<VerifyingKey> {
    let raw = decode_32(b64)?;
    VerifyingKey::from_bytes(&raw).map_err(|e| SdkError::Crypto(format!("bad host key: {e}")))
}

fn decode_32(b64: &str) -> SdkResult<[u8; 32]> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| SdkError::Base64(e.to_string()))?;
    if raw.len() != 32 {
        return Err(SdkError::Crypto(format!("expected 32 bytes, got {}", raw.len())));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn decode_64(b64: &str) -> SdkResult<[u8; 64]> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| SdkError::Base64(e.to_string()))?;
    if raw.len() != 64 {
        return Err(SdkError::Crypto(format!("expected 64 bytes, got {}", raw.len())));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&raw);
    Ok(out)
}

async fn send(
    ws: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    value: &serde_json::Value,
) -> SdkResult<()> {
    ws.send(Message::Text(value.to_string()))
        .await
        .map_err(|e| SdkError::WebSocket(e.to_string()))
}

async fn send_packet(
    ws: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    packet: &SignalPacket,
) -> SdkResult<()> {
    let json = serde_json::to_string(packet)?;
    ws.send(Message::Text(json))
        .await
        .map_err(|e| SdkError::WebSocket(e.to_string()))
}

async fn recv_text(
    ws: &mut (impl StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin),
) -> SdkResult<String> {
    while let Some(msg) = ws.next().await {
        match msg.map_err(|e| SdkError::WebSocket(e.to_string()))? {
            Message::Text(t) => return Ok(t),
            Message::Close(_) => return Err(SdkError::Relay("connection closed".to_string())),
            _ => continue,
        }
    }
    Err(SdkError::Relay("stream ended".to_string()))
}
