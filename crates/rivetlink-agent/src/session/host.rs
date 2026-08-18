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
use rivetlink_protocol::{ConsoleInputPacket, HostConsoleState, SessionCapability, SignalPacket};
use std::time::{Duration, Instant};

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
    /// Screenshot-only unattended mode. This mode is intentionally narrower
    /// than a generic auto-accept: only a locally pre-trusted key with
    /// `can_view` is admitted and requests are bounded.
    HeadlessTrustedOnly {
        min_capture_interval: Duration,
        capture_timeout: Duration,
        max_capture_bytes: usize,
    },
    /// Capture from the physical GDM/GNOME console via a locally authenticated
    /// session worker. This requires the additional `can_unattended_console`
    /// owner opt-in; ordinary screenshot trust is not enough.
    UnattendedConsole {
        min_capture_interval: Duration,
        capture_timeout: Duration,
        max_capture_bytes: usize,
    },
}

/// Source of a single capture for an authenticated screenshot session.
///
/// The normal host captures from its own desktop. A boot-time broker instead
/// supplies a narrowly scoped IPC source backed by the active GDM/GNOME
/// worker. In both cases the host seals bytes before they leave the machine.
#[async_trait]
pub trait ScreenshotCapturer: Send {
    /// Capture one PNG while applying the requested unattended timeout.
    async fn capture(&mut self, policy: ConsentPolicy) -> AgentResult<Vec<u8>>;
}

/// Narrow companion to a capture source. An ordinary screenshot host has no
/// such sink, so it can never acquire remote-input capability by accident.
#[async_trait]
pub trait ConsoleInputSink: Send {
    /// Replay one previously authenticated, decrypted normalized event.
    async fn inject(&mut self, event: ConsoleInputPacket) -> AgentResult<()>;
}

#[async_trait]
pub trait ConsoleStateProvider: Send + Sync {
    /// Returns only lifecycle state and a capture generation, never a session
    /// identifier, account name, display address, or screen content.
    async fn console_state(&self) -> Option<(HostConsoleState, u64)>;
}

#[derive(Debug, Default)]
pub(crate) struct LocalScreenshotCapturer;

#[async_trait]
impl ScreenshotCapturer for LocalScreenshotCapturer {
    async fn capture(&mut self, policy: ConsentPolicy) -> AgentResult<Vec<u8>> {
        match policy {
            ConsentPolicy::HeadlessTrustedOnly {
                capture_timeout, ..
            }
            | ConsentPolicy::UnattendedConsole {
                capture_timeout, ..
            } => screenshot::capture_headless_png(capture_timeout).await,
            ConsentPolicy::Prompt => screenshot::capture_png().await,
        }
    }
}

/// Per-connection host session state.
pub struct ScreenshotHost {
    signing_key: SigningKey,
    identity_b64: String,
    trusted: TrustedClients,
    policy: ConsentPolicy,
    capturer: Box<dyn ScreenshotCapturer>,
    input_sink: Option<Box<dyn ConsoleInputSink>>,
    console_state_provider: Option<Box<dyn ConsoleStateProvider>>,

    // Active session state (single session at a time for the MVP).
    session_id: Option<SessionId>,
    capability: Option<SessionCapability>,
    client_identity: Option<VerifyingKey>,
    local_kex: Option<LocalKeyExchange>,
    channel: Option<SealedChannel>,
    last_capture: Option<Instant>,
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
        let identity_b64 = base64::engine::general_purpose::STANDARD
            .encode(signing_key.verifying_key().as_bytes());
        Self {
            signing_key,
            identity_b64,
            trusted,
            policy,
            capturer: Box::<LocalScreenshotCapturer>::default(),
            input_sink: None,
            console_state_provider: None,
            session_id: None,
            capability: None,
            client_identity: None,
            local_kex: None,
            channel: None,
            last_capture: None,
        }
    }

    /// Replace the capture source. Used by the non-root console broker after a
    /// GDM/GNOME worker authenticated itself on the local Unix socket.
    #[must_use]
    pub fn with_capturer(mut self, capturer: Box<dyn ScreenshotCapturer>) -> Self {
        self.capturer = capturer;
        self
    }

    /// Attach a physical-console input sink. This is used only by the local
    /// GDM/GNOME broker after peer-credential validation.
    #[must_use]
    pub fn with_console_input_sink(mut self, sink: Box<dyn ConsoleInputSink>) -> Self {
        self.input_sink = Some(sink);
        self
    }

    #[must_use]
    pub fn with_console_state_provider(mut self, provider: Box<dyn ConsoleStateProvider>) -> Self {
        self.console_state_provider = Some(provider);
        self
    }

    /// Reset all per-session state (after close or rejection).
    fn reset(&mut self) {
        self.session_id = None;
        self.capability = None;
        self.client_identity = None;
        self.local_kex = None;
        self.channel = None;
        self.last_capture = None;
    }

    /// Decide whether to admit a client, prompting the operator if unknown.
    async fn consent(&mut self, client_key_b64: &str) -> AgentResult<bool> {
        if let Some(entry) = self.trusted.get(client_key_b64) {
            if matches!(self.policy, ConsentPolicy::UnattendedConsole { .. }) {
                if self.trusted.may_view_unattended_console(client_key_b64) {
                    tracing::info!(client = %entry.name, "trusted client accepted for unattended console viewing");
                    return Ok(true);
                }
                tracing::warn!(client = %entry.name, "trusted client denied: unattended console opt-in is disabled");
                return Ok(false);
            }
            if entry.can_view {
                tracing::info!(client = %entry.name, "trusted client accepted for screenshot access");
                return Ok(true);
            }
            tracing::warn!(client = %entry.name, "trusted client denied: view permission is disabled");
            return Ok(false);
        }
        if matches!(
            self.policy,
            ConsentPolicy::HeadlessTrustedOnly { .. } | ConsentPolicy::UnattendedConsole { .. }
        ) {
            // A background systemd service cannot safely prompt; it also must
            // not create trust through a connection attempt.
            tracing::warn!("unknown client rejected in headless mode");
            return Ok(false);
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
                    can_unattended_console: false,
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
        requested_capability: SessionCapability,
        session_id: Option<SessionId>,
    ) -> AgentResult<Vec<String>> {
        let Some(sid) = session_id else {
            tracing::warn!("session request without session_id (relay should stamp it)");
            return Ok(Vec::new());
        };
        tracing::info!(session = %sid, "session request received");

        if requested_capability == SessionCapability::ConsoleControl
            && !matches!(self.policy, ConsentPolicy::UnattendedConsole { .. })
        {
            tracing::warn!(session = %sid, ?requested_capability, "unsupported session capability rejected");
            return Ok(vec![reject(
                sid,
                "this host only permits screenshot sessions",
            )?]);
        }

        let client_identity = match parse_identity(&client_public_key) {
            Ok(k) => k,
            Err(e) => {
                tracing::warn!(error = %e, "rejecting: bad client identity key");
                return Ok(vec![reject(sid, "invalid client identity key")?]);
            },
        };

        if requested_capability == SessionCapability::ConsoleControl
            && !self
                .trusted
                .may_control_unattended_console(&client_public_key)
        {
            tracing::warn!(session = %sid, "console control denied by local trust policy");
            return Ok(vec![reject(
                sid,
                "local console-control permission is required",
            )?]);
        }

        if !self.consent(&client_public_key).await? {
            tracing::info!(session = %sid, "session request denied by local host policy");
            return Ok(vec![reject(sid, "host operator denied the connection")?]);
        }

        // Accepted: set up state and our half of the key exchange.
        self.reset();
        self.session_id = Some(sid);
        self.capability = Some(requested_capability);
        self.client_identity = Some(client_identity);
        let kex = handshake::start(&self.signing_key);
        let kex_frame = self.key_exchange_frame(sid, &kex)?;
        self.local_kex = Some(kex);

        let accept = serde_json::to_string(&SignalPacket::SessionAccepted {
            session_id: sid,
            role: SessionRole::Controller,
        })?;

        tracing::info!(session = %sid, "session accepted");
        let mut outgoing = vec![accept, kex_frame];
        if let Some(provider) = &self.console_state_provider {
            if let Some((state, generation)) = provider.console_state().await {
                outgoing.push(serde_json::to_string(&SignalPacket::HostConsoleState {
                    session_id: sid,
                    state,
                    generation,
                })?);
            }
        }
        Ok(outgoing)
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
        if self.session_id != Some(session_id) {
            tracing::warn!(session = %session_id, "rejecting screenshot request for inactive session");
            return Err(AgentError::Relay(
                "screenshot request does not match active session".to_string(),
            ));
        }
        let channel = self.channel.as_ref().ok_or_else(|| {
            AgentError::Relay("screenshot requested before key exchange".to_string())
        })?;

        let image = if let Some((min_capture_interval, max_capture_bytes)) =
            capture_limits(self.policy)
        {
            if self
                .last_capture
                .is_some_and(|last| last.elapsed() < min_capture_interval)
            {
                tracing::warn!("unattended screenshot rejected: request rate limit");
                return Err(AgentError::Relay(
                    "screenshot rate limited; wait before requesting another capture".to_string(),
                ));
            }
            let image = self.capturer.capture(self.policy).await?;
            if image.len() > max_capture_bytes {
                tracing::warn!(
                    bytes = image.len(),
                    max_capture_bytes,
                    "unattended screenshot rejected: size limit"
                );
                return Err(AgentError::Relay(
                    "captured screenshot exceeds configured size limit".to_string(),
                ));
            }
            self.last_capture = Some(Instant::now());
            image
        } else {
            self.capturer.capture(self.policy).await?
        };
        tracing::info!(
            bytes = image.len(),
            "captured screen (encrypted before relay forwarding)"
        );

        let sealed = channel
            .seal(&image)
            .map_err(|e| AgentError::Relay(format!("seal failed: {e}")))?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&sealed);

        let frames = chunk_payload(session_id, &b64)?;
        tracing::info!(chunks = frames.len(), "sending encrypted screenshot");
        Ok(frames)
    }

    async fn on_console_input(
        &mut self,
        session_id: SessionId,
        payload: String,
    ) -> AgentResult<()> {
        if self.session_id != Some(session_id)
            || self.capability != Some(SessionCapability::ConsoleControl)
        {
            return Err(AgentError::Relay(
                "console input does not match an active control session".to_string(),
            ));
        }
        if !matches!(self.policy, ConsentPolicy::UnattendedConsole { .. }) {
            return Err(AgentError::Relay(
                "console input is unavailable for this host".to_string(),
            ));
        }
        // The relay may supply arbitrary ciphertext. Bound it before decoding;
        // do not log either ciphertext or the decrypted input event.
        if payload.len() > 8 * 1024 {
            return Err(AgentError::Relay(
                "console input exceeds size limit".to_string(),
            ));
        }
        let channel = self.channel.as_ref().ok_or_else(|| {
            AgentError::Relay("console input arrived before key exchange".to_string())
        })?;
        let sealed = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .map_err(|error| AgentError::Base64(error.to_string()))?;
        let plaintext = channel
            .open(&sealed)
            .map_err(|error| AgentError::Relay(format!("console input decrypt failed: {error}")))?;
        let event: ConsoleInputPacket = serde_json::from_slice(&plaintext)?;
        validate_console_input(&event)?;
        let sink = self
            .input_sink
            .as_mut()
            .ok_or_else(|| AgentError::Relay("console input sink is unavailable".to_string()))?;
        sink.inject(event).await
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

fn validate_console_input(event: &ConsoleInputPacket) -> AgentResult<()> {
    if let ConsoleInputPacket::Key { code, .. } = event {
        if code.is_empty()
            || code.len() > 64
            || !code
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(AgentError::Relay("invalid console key code".to_string()));
        }
    }
    Ok(())
}

fn capture_limits(policy: ConsentPolicy) -> Option<(Duration, usize)> {
    match policy {
        ConsentPolicy::HeadlessTrustedOnly {
            min_capture_interval,
            max_capture_bytes,
            ..
        }
        | ConsentPolicy::UnattendedConsole {
            min_capture_interval,
            max_capture_bytes,
            ..
        } => Some((min_capture_interval, max_capture_bytes)),
        ConsentPolicy::Prompt => None,
    }
}

#[async_trait]
impl HostHandler for ScreenshotHost {
    async fn handle(&mut self, packet: SignalPacket) -> AgentResult<Vec<String>> {
        match packet {
            SignalPacket::SessionRequest {
                client_public_key,
                requested_capability,
                session_id,
                ..
            } => {
                self.on_session_request(client_public_key, requested_capability, session_id)
                    .await
            },
            SignalPacket::SessionKeyExchange {
                ephemeral_public_key,
                identity_public_key,
                signature,
                ..
            } => self.on_key_exchange(&ephemeral_public_key, &identity_public_key, &signature),
            SignalPacket::ScreenshotRequest { session_id } => {
                match self.on_screenshot_request(session_id).await {
                    Ok(frames) => Ok(frames),
                    Err(error) => {
                        // Capture failures (missing virtual monitor, timeout, size
                        // limit, etc.) are session failures, not agent failures.
                        // Inform the already authenticated client and keep the
                        // systemd service connected for the next request.
                        tracing::warn!(session = %session_id, error = %error, "screenshot request failed safely");
                        self.reset();
                        Ok(vec![reject(
                            session_id,
                            &format!("screenshot unavailable: {error}"),
                        )?])
                    },
                }
            },
            SignalPacket::ConsoleInput {
                session_id,
                payload,
            } => {
                if let Err(error) = self.on_console_input(session_id, payload).await {
                    // Keystrokes may be an Ubuntu password. Never log their
                    // ciphertext, plaintext, key code, or pointer coordinates.
                    tracing::warn!(session = %session_id, error = %error, "console input rejected safely");
                }
                Ok(Vec::new())
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
        return Err(AgentError::Relay(format!(
            "expected 32 bytes, got {}",
            raw.len()
        )));
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
        return Err(AgentError::Relay(format!(
            "expected 64 bytes, got {}",
            raw.len()
        )));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&raw);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct RecordingInputSink(Arc<Mutex<Vec<ConsoleInputPacket>>>);

    #[async_trait]
    impl ConsoleInputSink for RecordingInputSink {
        async fn inject(&mut self, event: ConsoleInputPacket) -> AgentResult<()> {
            self.0.lock().unwrap().push(event);
            Ok(())
        }
    }

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

    fn trust_viewer(host: &mut ScreenshotHost, public_key_b64: &str) {
        host.trusted
            .trust(
                public_key_b64,
                TrustedEntry {
                    name: "test viewer".to_string(),
                    can_view: true,
                    can_control: false,
                    can_unattended_console: false,
                },
            )
            .unwrap();
    }

    #[test]
    fn chunking_marks_last_and_total() {
        let sid = SessionId::new();
        let frames = chunk_payload(sid, &"a".repeat(CHUNK_CHARS * 2 + 5)).unwrap();
        assert_eq!(frames.len(), 3);
        // Parse the last frame and confirm `last`/`total`.
        let last: SignalPacket = serde_json::from_str(frames.last().unwrap()).unwrap();
        match last {
            SignalPacket::ScreenshotData {
                total,
                last,
                sequence,
                ..
            } => {
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
    async fn headless_rejects_unknown_client_without_creating_trust() {
        let mut h = host(ConsentPolicy::HeadlessTrustedOnly {
            min_capture_interval: Duration::from_secs(1),
            capture_timeout: Duration::from_secs(1),
            max_capture_bytes: 1024,
        });
        assert!(!h.consent("UNKNOWNKEY").await.unwrap());
        assert!(!h.trusted.is_trusted("UNKNOWNKEY"));
    }

    #[tokio::test]
    async fn headless_rejects_trusted_client_without_view_permission() {
        let mut h = host(ConsentPolicy::HeadlessTrustedOnly {
            min_capture_interval: Duration::from_secs(1),
            capture_timeout: Duration::from_secs(1),
            max_capture_bytes: 1024,
        });
        h.trusted
            .trust(
                "KNOWN",
                TrustedEntry {
                    name: "restricted".to_string(),
                    can_view: false,
                    can_control: false,
                    can_unattended_console: false,
                },
            )
            .unwrap();
        assert!(!h.consent("KNOWN").await.unwrap());
    }

    #[tokio::test]
    async fn physical_console_requires_its_own_owner_opt_in() {
        let mut h = host(ConsentPolicy::UnattendedConsole {
            min_capture_interval: Duration::from_secs(1),
            capture_timeout: Duration::from_secs(1),
            max_capture_bytes: 1024,
        });
        h.trusted
            .trust(
                "KNOWN",
                TrustedEntry {
                    name: "ordinary viewer".to_string(),
                    can_view: true,
                    can_control: true,
                    can_unattended_console: false,
                },
            )
            .unwrap();
        assert!(!h.consent("KNOWN").await.unwrap());

        h.trusted
            .trust(
                "KNOWN",
                TrustedEntry {
                    name: "owner laptop".to_string(),
                    can_view: true,
                    can_control: true,
                    can_unattended_console: true,
                },
            )
            .unwrap();
        assert!(h.consent("KNOWN").await.unwrap());
    }

    #[test]
    fn console_input_validation_rejects_non_keycode_data() {
        assert!(validate_console_input(&ConsoleInputPacket::Key {
            code: "Enter".to_string(),
            down: true,
        })
        .is_ok());
        assert!(validate_console_input(&ConsoleInputPacket::Key {
            code: "password with spaces".to_string(),
            down: true,
        })
        .is_err());
        assert!(validate_console_input(&ConsoleInputPacket::Key {
            code: "x".repeat(65),
            down: true,
        })
        .is_err());
    }

    #[tokio::test]
    async fn rejects_bad_identity_key() {
        let mut h = host(ConsentPolicy::HeadlessTrustedOnly {
            min_capture_interval: Duration::from_secs(1),
            capture_timeout: Duration::from_secs(1),
            max_capture_bytes: 1024,
        });
        let out = h
            .on_session_request(
                "not-base64-!!".to_string(),
                SessionCapability::Screenshot,
                Some(SessionId::new()),
            )
            .await
            .unwrap();
        assert_eq!(out.len(), 1);
        let pkt: SignalPacket = serde_json::from_str(&out[0]).unwrap();
        assert!(matches!(pkt, SignalPacket::SessionRejected { .. }));
    }

    #[tokio::test]
    async fn accept_emits_accept_and_key_exchange() {
        let mut h = host(ConsentPolicy::HeadlessTrustedOnly {
            min_capture_interval: Duration::from_secs(1),
            capture_timeout: Duration::from_secs(1),
            max_capture_bytes: 1024,
        });
        // A valid client identity key.
        let client = SigningKey::from_bytes(&[5u8; 32]);
        let client_b64 =
            base64::engine::general_purpose::STANDARD.encode(client.verifying_key().as_bytes());
        trust_viewer(&mut h, &client_b64);

        let out = h
            .on_session_request(
                client_b64,
                SessionCapability::Screenshot,
                Some(SessionId::new()),
            )
            .await
            .unwrap();
        assert_eq!(out.len(), 2);
        let accept: SignalPacket = serde_json::from_str(&out[0]).unwrap();
        let kex: SignalPacket = serde_json::from_str(&out[1]).unwrap();
        assert!(matches!(accept, SignalPacket::SessionAccepted { .. }));
        assert!(matches!(kex, SignalPacket::SessionKeyExchange { .. }));
    }

    #[tokio::test]
    async fn screenshot_host_rejects_console_control_even_for_a_trusted_client() {
        let mut h = host(ConsentPolicy::HeadlessTrustedOnly {
            min_capture_interval: Duration::from_secs(1),
            capture_timeout: Duration::from_secs(1),
            max_capture_bytes: 1024,
        });
        let client = SigningKey::from_bytes(&[6u8; 32]);
        let client_b64 =
            base64::engine::general_purpose::STANDARD.encode(client.verifying_key().as_bytes());
        trust_viewer(&mut h, &client_b64);

        let out = h
            .on_session_request(
                client_b64,
                SessionCapability::ConsoleControl,
                Some(SessionId::new()),
            )
            .await
            .unwrap();
        let packet: SignalPacket = serde_json::from_str(&out[0]).unwrap();
        assert!(matches!(packet, SignalPacket::SessionRejected { .. }));
        assert!(h.session_id.is_none());
    }

    #[tokio::test]
    async fn encrypted_console_input_reaches_only_an_authorized_physical_sink() {
        let client = SigningKey::from_bytes(&[8u8; 32]);
        let client_b64 =
            base64::engine::general_purpose::STANDARD.encode(client.verifying_key().as_bytes());
        let received = Arc::new(Mutex::new(Vec::new()));
        let mut h = host(ConsentPolicy::UnattendedConsole {
            min_capture_interval: Duration::ZERO,
            capture_timeout: Duration::from_secs(1),
            max_capture_bytes: 1024,
        })
        .with_console_input_sink(Box::new(RecordingInputSink(received.clone())));
        h.trusted
            .trust(
                &client_b64,
                TrustedEntry {
                    name: "owner".to_string(),
                    can_view: true,
                    can_control: true,
                    can_unattended_console: true,
                },
            )
            .unwrap();
        let session_id = SessionId::new();
        let frames = h
            .on_session_request(
                client_b64.clone(),
                SessionCapability::ConsoleControl,
                Some(session_id),
            )
            .await
            .unwrap();
        let SignalPacket::SessionKeyExchange {
            ephemeral_public_key,
            ..
        } = serde_json::from_str(&frames[1]).unwrap()
        else {
            panic!("host did not send a key exchange");
        };
        let client_kex = handshake::start(&client);
        h.on_key_exchange(
            &base64::engine::general_purpose::STANDARD.encode(client_kex.ephemeral_public()),
            &client_b64,
            &base64::engine::general_purpose::STANDARD.encode(client_kex.signature()),
        )
        .unwrap();
        let channel = client_kex.into_channel(&decode_32(&ephemeral_public_key).unwrap());
        let encoded_event = serde_json::to_vec(&ConsoleInputPacket::Key {
            code: "Enter".to_string(),
            down: true,
        })
        .unwrap();
        let ciphertext =
            base64::engine::general_purpose::STANDARD.encode(channel.seal(&encoded_event).unwrap());
        h.on_console_input(session_id, ciphertext).await.unwrap();
        let received = received.lock().unwrap();
        assert_eq!(received.len(), 1);
        assert!(matches!(
            &received[0],
            ConsoleInputPacket::Key { code, down: true } if code == "Enter"
        ));
    }

    #[tokio::test]
    async fn headless_screenshot_is_sealed_before_it_is_chunked() {
        let client = SigningKey::from_bytes(&[7u8; 32]);
        let client_b64 =
            base64::engine::general_purpose::STANDARD.encode(client.verifying_key().as_bytes());
        let mut h = host(ConsentPolicy::HeadlessTrustedOnly {
            min_capture_interval: Duration::ZERO,
            capture_timeout: Duration::from_secs(1),
            max_capture_bytes: 1024,
        });
        trust_viewer(&mut h, &client_b64);
        let sid = SessionId::new();
        let host_frames = h
            .on_session_request(client_b64.clone(), SessionCapability::Screenshot, Some(sid))
            .await
            .unwrap();
        let host_kex: SignalPacket = serde_json::from_str(&host_frames[1]).unwrap();
        let SignalPacket::SessionKeyExchange {
            ephemeral_public_key,
            ..
        } = host_kex
        else {
            panic!("host did not send its key exchange");
        };

        let client_kex = handshake::start(&client);
        h.on_key_exchange(
            &base64::engine::general_purpose::STANDARD.encode(client_kex.ephemeral_public()),
            &client_b64,
            &base64::engine::general_purpose::STANDARD.encode(client_kex.signature()),
        )
        .unwrap();
        let host_ephemeral = decode_32(&ephemeral_public_key).unwrap();
        let client_channel = client_kex.into_channel(&host_ephemeral);

        std::env::set_var("RIVET_FAKE_CAPTURE", "128");
        let frames = h.on_screenshot_request(sid).await.unwrap();
        std::env::remove_var("RIVET_FAKE_CAPTURE");
        let encoded = frames
            .iter()
            .map(
                |frame| match serde_json::from_str::<SignalPacket>(frame).unwrap() {
                    SignalPacket::ScreenshotData { payload, .. } => payload,
                    _ => panic!("expected encrypted screenshot data"),
                },
            )
            .collect::<String>();
        let sealed = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        let plaintext = client_channel.open(&sealed).unwrap();
        assert_eq!(plaintext.len(), 128);
        assert_ne!(
            sealed, plaintext,
            "relay frames must not contain plaintext capture bytes"
        );
    }

    #[tokio::test]
    async fn capture_failure_returns_a_session_error_without_failing_the_agent() {
        let mut h = host(ConsentPolicy::HeadlessTrustedOnly {
            min_capture_interval: Duration::from_secs(1),
            capture_timeout: Duration::from_secs(1),
            max_capture_bytes: 1024,
        });
        let sid = SessionId::new();
        let out = h
            .handle(SignalPacket::ScreenshotRequest { session_id: sid })
            .await
            .unwrap();
        assert_eq!(out.len(), 1);
        let packet: SignalPacket = serde_json::from_str(&out[0]).unwrap();
        assert!(matches!(packet, SignalPacket::SessionRejected { .. }));
    }
}
