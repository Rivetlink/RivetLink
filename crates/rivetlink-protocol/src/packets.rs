//! Packet definitions for signaling and input communication in RivetLink.

use rivetlink_core::{DeviceId, SessionId, SessionRole};
use serde::{Deserialize, Serialize};

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
        assert!(matches!(
            parsed,
            SignalPacket::SessionKeyExchange { .. }
        ));
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
}
