//! Packet definitions for signaling and input communication in RivetLink.

use rivetlink_core::{DeviceId, SessionId, SessionRole};
use serde::{Deserialize, Serialize};

/// The graphical-console state a Linux host reports to an authenticated
/// RivetLink client. These states describe the *physical* console on seat0;
/// they never imply that RivetLink knows an Ubuntu account password.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostConsoleState {
    /// The boot-time broker is up but the display manager is not ready yet.
    Booting,
    /// GDM owns the physical console and can be controlled by a trusted client.
    GdmLogin,
    /// GDM accepted credentials and is replacing the greeter with a desktop.
    SessionStarting,
    /// A normal graphical user session owns the physical console.
    DesktopReady,
    /// The graphical user session owns the console but is locked.
    SessionLocked,
    /// The console owner is changing (logout, user switch, or display restart).
    SessionSwitching,
    /// The host is intentionally not able to serve the physical console.
    Offline,
}

/// Privileged capability requested when opening a session.
///
/// The default deliberately remains screenshot-only so clients built before
/// console support can never acquire pre-login input merely by upgrading the
/// host or relay. A host must make a second, local authorization decision for
/// [`ConsoleControl`](Self::ConsoleControl).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionCapability {
    /// One or more encrypted on-demand captures, without remote input.
    #[default]
    Screenshot,
    /// View and input for the physical Linux console, including GDM.
    ConsoleControl,
}

/// Session signaling packet for establishing and maintaining connections.
///
/// Handles session lifecycle, authentication, and peer discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SignalPacket {
    /// Initial request to establish a session with a device ID and client public key.
    ///
    /// The client sends this with `session_id = None`. The relay allocates a
    /// session, stamps `session_id` with the assigned ID, and forwards the
    /// enriched packet to the host so the host can reference the session in
    /// its accept/reject reply.
    SessionRequest {
        device_id: DeviceId,
        client_public_key: String,
        /// Kept optional on the wire for compatibility with screenshot-only
        /// clients. Missing means `Screenshot`, never `ConsoleControl`.
        #[serde(default)]
        requested_capability: SessionCapability,
        #[serde(default)]
        session_id: Option<SessionId>,
    },
    /// Authentication challenge issued by the server with a nonce.
    AuthChallenge {
        session_id: SessionId,
        nonce: String,
    },
    /// Authentication response from client with signature proof.
    AuthResponse {
        session_id: SessionId,
        signature: String,
    },
    /// Confirmation that session is accepted with assigned role.
    SessionAccepted {
        session_id: SessionId,
        role: SessionRole,
    },
    /// Rejection of session request with reason.
    SessionRejected {
        session_id: SessionId,
        reason: String,
    },
    /// ICE candidate for peer-to-peer connection negotiation.
    IceCandidate {
        session_id: SessionId,
        candidate: String,
    },
    /// Ephemeral x25519 public key for deriving the E2E session secret.
    ///
    /// Both peers send one. `identity_public_key` is the sender's long-term
    /// Ed25519 key (base64) and `signature` is that key's signature over the
    /// raw ephemeral key bytes — this binds the ephemeral key to the trusted
    /// identity so a malicious relay cannot man-in-the-middle the exchange.
    SessionKeyExchange {
        session_id: SessionId,
        /// Base64 of the 32-byte x25519 ephemeral public key.
        ephemeral_public_key: String,
        /// Base64 of the sender's 32-byte Ed25519 identity public key.
        identity_public_key: String,
        /// Base64 of the 64-byte Ed25519 signature over the ephemeral key bytes.
        signature: String,
    },
    /// Client → host: request a single screen capture over the sealed channel.
    ScreenshotRequest { session_id: SessionId },
    /// Host → client: one chunk of an encrypted screen capture.
    ///
    /// Large images are split across multiple chunks ordered by `sequence`;
    /// the final chunk sets `last = true`. The payload is base64 of a
    /// `SealedChannel`-sealed (`nonce || ciphertext`) blob.
    ScreenshotData {
        session_id: SessionId,
        /// Zero-based chunk index.
        sequence: u32,
        /// Total number of chunks in this capture.
        total: u32,
        /// True when this is the final chunk.
        last: bool,
        /// Base64 of the sealed chunk bytes.
        payload: String,
    },
    /// Host → client: non-sensitive physical-console lifecycle state. It is
    /// session-bound so the relay forwards it only to the already authenticated
    /// controller; it contains no display pixels, credentials, or key material.
    HostConsoleState {
        session_id: SessionId,
        state: HostConsoleState,
        /// Increments whenever console ownership changes (for example GDM →
        /// GNOME). A client discards frames from an earlier generation.
        generation: u64,
    },
    /// Controller → host: a sealed, session-bound physical-console input event.
    /// `payload` is a `SealedChannel` ciphertext; the relay cannot inspect
    /// keystrokes or infer an Ubuntu password from it.
    ConsoleInput {
        session_id: SessionId,
        payload: String,
    },
    /// Keepalive signal to maintain connection.
    Heartbeat,
    /// Notification that session has been closed.
    SessionClosed { session_id: SessionId },
}

/// User input packet for remote mouse, keyboard, and clipboard events.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InputPacket {
    /// Mouse cursor movement with absolute coordinates.
    MouseMove { x: i32, y: i32 },
    /// Mouse button press or release event.
    MouseButton {
        button: MouseButton,
        state: ButtonState,
    },
    /// Keyboard key press or release event.
    KeyboardInput { scan_code: u32, state: ButtonState },
    /// Clipboard content synchronization.
    ClipboardSync { content: String },
}

/// The deliberately small input vocabulary accepted for the physical console.
/// Clipboard and text-paste are excluded so the broker never becomes a generic
/// data-transfer channel; password entry remains ordinary key events in GDM.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConsoleInputPacket {
    PointerMove { x: u16, y: u16 },
    PointerButton { button: MouseButton, down: bool },
    Scroll { dx: i16, dy: i16 },
    Key { code: String, down: bool },
}

/// Mouse button identifier.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MouseButton {
    /// Left mouse button.
    Left,
    /// Right mouse button.
    Right,
    /// Middle mouse button.
    Middle,
}

/// Button or key state for mouse and keyboard input.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ButtonState {
    /// Button or key pressed down.
    Down,
    /// Button or key released.
    Up,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_packet_roundtrip() {
        let packet = SignalPacket::Heartbeat;
        let json = serde_json::to_string(&packet).unwrap();
        let parsed: SignalPacket = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, SignalPacket::Heartbeat));
    }

    #[test]
    fn session_request_serialization() {
        let packet = SignalPacket::SessionRequest {
            device_id: DeviceId::new(),
            client_public_key: "test_key".to_string(),
            requested_capability: SessionCapability::Screenshot,
            session_id: None,
        };
        let json = serde_json::to_string(&packet).unwrap();
        assert!(json.contains("SESSION_REQUEST"));
        assert!(json.contains("test_key"));
    }

    #[test]
    fn input_packet_roundtrip() {
        let packet = InputPacket::MouseMove { x: 100, y: 200 };
        let json = serde_json::to_string(&packet).unwrap();
        let parsed: InputPacket = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, InputPacket::MouseMove { x: 100, y: 200 }));
    }

    #[test]
    fn key_exchange_roundtrip() {
        let packet = SignalPacket::SessionKeyExchange {
            session_id: SessionId::new(),
            ephemeral_public_key: "eph".to_string(),
            identity_public_key: "id".to_string(),
            signature: "sig".to_string(),
        };
        let json = serde_json::to_string(&packet).unwrap();
        assert!(json.contains("SESSION_KEY_EXCHANGE"));
        let parsed: SignalPacket = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, SignalPacket::SessionKeyExchange { .. }));
    }

    #[test]
    fn screenshot_request_roundtrip() {
        let packet = SignalPacket::ScreenshotRequest {
            session_id: SessionId::new(),
        };
        let json = serde_json::to_string(&packet).unwrap();
        assert!(json.contains("SCREENSHOT_REQUEST"));
        let parsed: SignalPacket = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, SignalPacket::ScreenshotRequest { .. }));
    }

    #[test]
    fn screenshot_data_roundtrip() {
        let packet = SignalPacket::ScreenshotData {
            session_id: SessionId::new(),
            sequence: 2,
            total: 5,
            last: false,
            payload: "base64chunk".to_string(),
        };
        let json = serde_json::to_string(&packet).unwrap();
        assert!(json.contains("SCREENSHOT_DATA"));
        let parsed: SignalPacket = serde_json::from_str(&json).unwrap();
        match parsed {
            SignalPacket::ScreenshotData {
                sequence,
                total,
                last,
                ..
            } => {
                assert_eq!(sequence, 2);
                assert_eq!(total, 5);
                assert!(!last);
            },
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn console_state_roundtrip() {
        let packet = SignalPacket::HostConsoleState {
            session_id: SessionId::new(),
            state: HostConsoleState::GdmLogin,
            generation: 7,
        };
        let json = serde_json::to_string(&packet).unwrap();
        assert!(json.contains("HOST_CONSOLE_STATE"));
        assert!(json.contains("gdm_login"));
        let parsed: SignalPacket = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            parsed,
            SignalPacket::HostConsoleState {
                state: HostConsoleState::GdmLogin,
                generation: 7,
                ..
            }
        ));
    }

    #[test]
    fn old_session_request_defaults_to_screenshot_capability() {
        let parsed: SignalPacket = serde_json::from_str(
            r#"{"type":"SESSION_REQUEST","device_id":"00000000-0000-0000-0000-000000000001","client_public_key":"test"}"#,
        )
        .unwrap();
        assert!(matches!(
            parsed,
            SignalPacket::SessionRequest {
                requested_capability: SessionCapability::Screenshot,
                ..
            }
        ));
    }

    #[test]
    fn console_input_is_a_separate_sealed_signal() {
        let packet = SignalPacket::ConsoleInput {
            session_id: SessionId::new(),
            payload: "ciphertext-only".to_string(),
        };
        let json = serde_json::to_string(&packet).unwrap();
        assert!(json.contains("CONSOLE_INPUT"));
        assert!(!json.contains("KeyA"));
    }
}
