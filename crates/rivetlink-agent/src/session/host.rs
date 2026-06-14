//! The host's screenshot-session state machine.
//!
//! Implements [`HostHandler`] for the relay loop. Per session it:
//! 1. receives `SessionRequest`, runs the consent check (trusted-store match
//!    auto-accepts; otherwise prompt the operator — trust on first use)
//! 2. replies `SessionAccepted` + its own signed ephemeral key
//! 3. verifies the client's ephemeral key against the client's identity and
//!    derives the sealed channel
//! 4. on `ScreenshotRequest`, captures the screen, seals it, and streams it
//!    back as ordered `ScreenshotData` chunks
//!
//! The host — never the relay — makes the trust decision.

use async_trait::async_trait;
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rivetlink_core::{SessionId, SessionRole};
use rivetlink_crypto::handshake::{self, LocalKeyExchange};
use rivetlink_crypto::sealed::SealedChannel;
use rivetlink_protocol::SignalPacket;

use crate::capture::screenshot;
use crate::error::{AgentError, AgentResult};
use crate::relay::client::HostHandler;
use crate::trusted::{TrustedClients, TrustedEntry};

/// Base64 characters per `ScreenshotData` chunk (~48 KiB).
const CHUNK_CHARS: usize = 48 * 1024;

/// How the host decides whether to admit an unknown client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentPolicy {
    /// Prompt the operator on stdin for unknown clients (TOFU).
    Prompt,
    /// Auto-accept and trust any client (unattended / testing only).
    AutoAccept,
}

/// Per-connection host session state.
pub struct ScreenshotHost {
    signing_key: SigningKey,
    identity_b64: String,
    trusted: TrustedClients,
    policy: ConsentPolicy,

    // Active session state (single session at a time for the MVP).
    session_id: Option<SessionId>,
    client_identity: Option<VerifyingKey>,
    local_kex: Option<LocalKeyExchange>,
    channel: Option<SealedChannel>,
}

impl std::fmt::Debug for ScreenshotHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScreenshotHost")
            .field("identity_b64", &self.identity_b64)
            .field("policy", &self.policy)
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

impl ScreenshotHost {
    /// Create a host handler from the device signing key + trusted store.
    pub fn new(signing_key: SigningKey, trusted: TrustedClients, policy: ConsentPolicy) -> Self {
        let identity_b64 =
            base64::engine::general_purpose::STANDARD.encode(signing_key.verifying_key().as_bytes());
        Self {
            signing_key,
            identity_b64,
            trusted,
            policy,
            session_id: None,
            client_identity: None,
            local_kex: None,
            channel: None,
        }
    }

    /// Reset all per-session state (after close or rejection).
    fn reset(&mut self) {
        self.session_id = None;
        self.client_identity = None;
        self.local_kex = None;
        self.channel = None;
    }

    /// Decide whether to admit a client, prompting the operator if unknown.
    async fn consent(&mut self, client_key_b64: &str) -> AgentResult<bool> {
        if self.trusted.is_trusted(client_key_b64) {
            tracing::info!("client already trusted, auto-accepting");
            return Ok(true);
        }
        if self.policy == ConsentPolicy::AutoAccept {
            self.trusted.trust(
                client_key_b64,
                TrustedEntry {
                    name: "auto-accepted".to_string(),
                    can_view: true,
                    can_control: false,
                },
            )?;
            return Ok(true);
        }

        // Prompt the operator on stdin (blocking → off the async runtime).
        let key_owned = client_key_b64.to_string();
        let approved = tokio::task::spawn_blocking(move || prompt_operator(&key_owned))
            .await
            .map_err(|e| AgentError::Config(format!("consent prompt join error: {e}")))?;

        if approved {
            self.trusted.trust(
                client_key_b64,
                TrustedEntry {
                    name: "approved-on-connect".to_string(),
                    can_view: true,
                    can_control: false,
                },
            )?;
        }
        Ok(approved)
    }

    /// Handle an inbound `SessionRequest`.
    #[allow(clippy::cognitive_complexity)] // linear consent + handshake setup, clearer inline
    async fn on_session_request(
        &mut self,
        client_public_key: String,
        session_id: Option<SessionId>,
    ) -> AgentResult<Vec<String>> {
        let Some(sid) = session_id else {
            tracing::warn!("session request without session_id (relay should stamp it)");
            return Ok(Vec::new());
        };

        let client_identity = match parse_identity(&client_public_key) {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(error = %e, "rejecting: bad client identity key");
                return Ok(vec![reject(sid, "invalid client identity key")?]);
            },
        };

        if !self.consent(&client_public_key).await? {
            tracing::info!("operator denied the connection");
            return Ok(vec![reject(sid, "host operator denied the connection")?]);
        }

        // Accepted: set up state and our half of the key exchange.
        self.reset();
        self.session_id = Some(sid);
        self.client_identity = Some(client_identity);
        let kex = handshake::start(&self.signing_key);
        let kex_frame = self.key_exchange_frame(sid, &kex)?;
        self.local_kex = Some(kex);

        let accept = serde_json::to_string(&SignalPacket::SessionAccepted {
            session_id: sid,
            role: SessionRole::Controller,
        })?;

        tracing::info!(session = %sid, "session accepted");
        Ok(vec![accept, kex_frame])
    }

    /// Handle the client's `SessionKeyExchange`.
    fn on_key_exchange(
        &mut self,
        ephemeral_public_key: &str,
        identity_public_key: &str,
        signature: &str,
    ) -> AgentResult<Vec<String>> {
        let client_identity = self
            .client_identity
            .ok_or_else(|| AgentError::Relay("key exchange before session request".to_string()))?;

        // The asserted identity must match the one from the session request.
        let asserted = parse_identity(identity_public_key)?;
        if asserted.as_bytes() != client_identity.as_bytes() {
            return Err(AgentError::Relay(
                "client identity changed mid-handshake".to_string(),
            ));
        }

        let peer_eph = decode_32(ephemeral_public_key)?;
        let peer_sig = decode_64(signature)?;
        handshake::verify_peer(&client_identity, &peer_eph, &peer_sig)
            .map_err(|e| AgentError::Relay(format!("client key exchange invalid: {e}")))?;

        let kex = self
            .local_kex
            .take()
            .ok_or_else(|| AgentError::Relay("missing local key exchange".to_string()))?;
        self.channel = Some(kex.into_channel(&peer_eph));
        tracing::info!("secure channel established with client");
        Ok(Vec::new())
    }

    /// Handle a `ScreenshotRequest`: capture, seal, chunk.
    async fn on_screenshot_request(&mut self, session_id: SessionId) -> AgentResult<Vec<String>> {
        let channel = self
            .channel
            .as_ref()
            .ok_or_else(|| AgentError::Relay("screenshot requested before key exchange".to_string()))?;

        let image = screenshot::capture_png().await?;
        tracing::info!(bytes = image.len(), "captured screen");

        let sealed = channel
            .seal(&image)
            .map_err(|e| AgentError::Relay(format!("seal failed: {e}")))?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&sealed);

        let frames = chunk_payload(session_id, &b64)?;
        tracing::info!(chunks = frames.len(), "sending encrypted screenshot");
        Ok(frames)
    }

    fn key_exchange_frame(
        &self,
        session_id: SessionId,
        kex: &LocalKeyExchange,
    ) -> AgentResult<String> {
        let std = base64::engine::general_purpose::STANDARD;
        let packet = SignalPacket::SessionKeyExchange {
            session_id,
            ephemeral_public_key: std.encode(kex.ephemeral_public()),
            identity_public_key: self.identity_b64.clone(),
            signature: std.encode(kex.signature()),
        };
        Ok(serde_json::to_string(&packet)?)
    }
}

#[async_trait]
impl HostHandler for ScreenshotHost {
    async fn handle(&mut self, packet: SignalPacket) -> AgentResult<Vec<String>> {
        match packet {
            SignalPacket::SessionRequest {
                client_public_key,
                session_id,
                ..
            } => self.on_session_request(client_public_key, session_id).await,
            SignalPacket::SessionKeyExchange {
                ephemeral_public_key,
                identity_public_key,
                signature,
                ..
            } => self.on_key_exchange(&ephemeral_public_key, &identity_public_key, &signature),
            SignalPacket::ScreenshotRequest { session_id } => {
                self.on_screenshot_request(session_id).await
            },
            SignalPacket::SessionClosed { .. } => {
                tracing::info!("session closed by client");
                self.reset();
                Ok(Vec::new())
            },
            _ => Ok(Vec::new()),
        }
    }
}

/// Split a base64 string into ordered `ScreenshotData` frames.
fn chunk_payload(session_id: SessionId, b64: &str) -> AgentResult<Vec<String>> {
    let bytes = b64.as_bytes();
    let chunk_count = bytes.len().div_ceil(CHUNK_CHARS).max(1);
    let total = u32::try_from(chunk_count)
        .map_err(|_| AgentError::Relay("screenshot too large to chunk".to_string()))?;
    let mut frames = Vec::with_capacity(chunk_count);

    for (idx, chunk) in bytes.chunks(CHUNK_CHARS).enumerate() {
        // idx < chunk_count which fit in u32, so this conversion is safe.
        let sequence = u32::try_from(idx).unwrap_or(u32::MAX);
        let packet = SignalPacket::ScreenshotData {
            session_id,
            sequence,
            total,
            last: sequence + 1 == total,
            payload: String::from_utf8_lossy(chunk).into_owned(),
        };
        frames.push(serde_json::to_string(&packet)?);
    }
    Ok(frames)
}

/// Build a `SessionRejected` frame.
fn reject(session_id: SessionId, reason: &str) -> AgentResult<String> {
    Ok(serde_json::to_string(&SignalPacket::SessionRejected {
        session_id,
        reason: reason.to_string(),
    })?)
}

/// Blocking operator consent prompt on stdin.
fn prompt_operator(client_key_b64: &str) -> bool {
    use std::io::Write;
    println!("\n┌─ RivetLink: incoming connection request ─────────────");
    println!("│ Client identity key:");
    println!("│   {client_key_b64}");
    println!("│ Allow this client to view this host's screen? [y/N]");
    print!("└─> ");
    let _ = std::io::stdout().flush();

    let mut line = String::new();
    if std::io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_lowercase().as_str(), "y" | "yes")
}

fn parse_identity(b64: &str) -> AgentResult<VerifyingKey> {
    let raw = decode_32(b64)?;
    VerifyingKey::from_bytes(&raw).map_err(|e| AgentError::Relay(format!("bad identity key: {e}")))
}

fn decode_32(b64: &str) -> AgentResult<[u8; 32]> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| AgentError::Base64(e.to_string()))?;
    if raw.len() != 32 {
        return Err(AgentError::Relay(format!("expected 32 bytes, got {}", raw.len())));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn decode_64(b64: &str) -> AgentResult<[u8; 64]> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| AgentError::Base64(e.to_string()))?;
    if raw.len() != 64 {
        return Err(AgentError::Relay(format!("expected 64 bytes, got {}", raw.len())));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&raw);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(policy: ConsentPolicy) -> ScreenshotHost {
        let mut seed = [9u8; 32];
        seed[0] = 1;
        let key = SigningKey::from_bytes(&seed);
        let path = std::env::temp_dir().join(format!(
            "rivet-host-test-{}.json",
            uuid::Uuid::now_v7().simple()
        ));
        let trusted = TrustedClients::load_or_empty(&path).unwrap();
        ScreenshotHost::new(key, trusted, policy)
    }

    #[test]
    fn chunking_marks_last_and_total() {
        let sid = SessionId::new();
        let frames = chunk_payload(sid, &"a".repeat(CHUNK_CHARS * 2 + 5)).unwrap();
        assert_eq!(frames.len(), 3);
        // Parse the last frame and confirm `last`/`total`.
        let last: SignalPacket = serde_json::from_str(frames.last().unwrap()).unwrap();
        match last {
            SignalPacket::ScreenshotData { total, last, sequence, .. } => {
                assert_eq!(total, 3);
                assert_eq!(sequence, 2);
                assert!(last);
            },
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn single_chunk_for_small_payload() {
        let frames = chunk_payload(SessionId::new(), "tiny").unwrap();
        assert_eq!(frames.len(), 1);
    }

    #[tokio::test]
    async fn auto_accept_admits_unknown_client() {
        let mut h = host(ConsentPolicy::AutoAccept);
        let approved = h.consent("UNKNOWNKEY").await.unwrap();
        assert!(approved);
        assert!(h.trusted.is_trusted("UNKNOWNKEY"));
    }

    #[tokio::test]
    async fn rejects_bad_identity_key() {
        let mut h = host(ConsentPolicy::AutoAccept);
        let out = h
            .on_session_request("not-base64-!!".to_string(), Some(SessionId::new()))
            .await
            .unwrap();
        assert_eq!(out.len(), 1);
        let pkt: SignalPacket = serde_json::from_str(&out[0]).unwrap();
        assert!(matches!(pkt, SignalPacket::SessionRejected { .. }));
    }

    #[tokio::test]
    async fn accept_emits_accept_and_key_exchange() {
        let mut h = host(ConsentPolicy::AutoAccept);
        // A valid client identity key.
        let client = SigningKey::from_bytes(&[5u8; 32]);
        let client_b64 = base64::engine::general_purpose::STANDARD
            .encode(client.verifying_key().as_bytes());

        let out = h
            .on_session_request(client_b64, Some(SessionId::new()))
            .await
            .unwrap();
        assert_eq!(out.len(), 2);
        let accept: SignalPacket = serde_json::from_str(&out[0]).unwrap();
        let kex: SignalPacket = serde_json::from_str(&out[1]).unwrap();
        assert!(matches!(accept, SignalPacket::SessionAccepted { .. }));
        assert!(matches!(kex, SignalPacket::SessionKeyExchange { .. }));
    }
}
