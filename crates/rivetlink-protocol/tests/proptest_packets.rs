//! Property-based tests for packet serialization and deserialization.
//!
//! Uses proptest to generate random valid packets and verify they
//! serialize to JSON and deserialize back identically.

#![allow(clippy::unwrap_used)] // proptest strategies are helper code, unwrap is fine

use proptest::prelude::*;
use rivetlink_core::{DeviceId, SessionId, SessionRole};
use rivetlink_protocol::packets::{ButtonState, InputPacket, MouseButton, SignalPacket};

// ─── Strategies ──────────────────────────────────────────

fn any_device_id() -> impl Strategy<Value = DeviceId> {
    prop::string::string_regex("[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}")
        .unwrap()
        .prop_map(|s| {
            let uuid = uuid::Uuid::parse_str(&s).unwrap();
            DeviceId(uuid)
        })
}

fn any_session_id() -> impl Strategy<Value = SessionId> {
    prop::string::string_regex("[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}")
        .unwrap()
        .prop_map(|s| {
            let uuid = uuid::Uuid::parse_str(&s).unwrap();
            SessionId(uuid)
        })
}

fn any_session_role() -> impl Strategy<Value = SessionRole> {
    prop_oneof![
        Just(SessionRole::Viewer),
        Just(SessionRole::Controller),
        Just(SessionRole::Admin),
    ]
}

fn any_mouse_button() -> impl Strategy<Value = MouseButton> {
    prop_oneof![
        Just(MouseButton::Left),
        Just(MouseButton::Right),
        Just(MouseButton::Middle),
    ]
}

fn any_button_state() -> impl Strategy<Value = ButtonState> {
    prop_oneof![Just(ButtonState::Down), Just(ButtonState::Up)]
}

fn any_string() -> impl Strategy<Value = String> {
    ".*"
}

fn any_i32() -> impl Strategy<Value = i32> {
    -10000i32..10000i32
}

fn any_u32() -> impl Strategy<Value = u32> {
    0u32..65536u32
}

// ─── SignalPacket Strategy ──────────────────────────────

fn any_signal_packet() -> impl Strategy<Value = SignalPacket> {
    prop_oneof![
        (any_device_id(), any_string()).prop_map(|(device_id, client_public_key)| {
            SignalPacket::SessionRequest {
                device_id,
                client_public_key,
                requested_capability: SessionCapability::Screenshot,
                session_id: None,
            }
        }),
        (any_session_id(), any_string())
            .prop_map(|(session_id, nonce)| { SignalPacket::AuthChallenge { session_id, nonce } }),
        (any_session_id(), any_string()).prop_map(|(session_id, signature)| {
            SignalPacket::AuthResponse {
                session_id,
                signature,
            }
        }),
        (any_session_id(), any_session_role())
            .prop_map(|(session_id, role)| { SignalPacket::SessionAccepted { session_id, role } }),
        (any_session_id(), any_string()).prop_map(|(session_id, reason)| {
            SignalPacket::SessionRejected { session_id, reason }
        }),
        (any_session_id(), any_string()).prop_map(|(session_id, candidate)| {
            SignalPacket::IceCandidate {
                session_id,
                candidate,
            }
        }),
        Just(SignalPacket::Heartbeat),
        any_session_id().prop_map(|session_id| SignalPacket::SessionClosed { session_id }),
    ]
}

// ─── InputPacket Strategy ───────────────────────────────

fn any_input_packet() -> impl Strategy<Value = InputPacket> {
    prop_oneof![
        (any_i32(), any_i32()).prop_map(|(x, y)| InputPacket::MouseMove { x, y }),
        (any_mouse_button(), any_button_state())
            .prop_map(|(button, state)| InputPacket::MouseButton { button, state }),
        (any_u32(), any_button_state())
            .prop_map(|(scan_code, state)| InputPacket::KeyboardInput { scan_code, state }),
        any_string().prop_map(|content| InputPacket::ClipboardSync { content }),
    ]
}

// ─── Property Tests ─────────────────────────────────────

proptest! {
    #[test]
    fn signal_packet_roundtrip(packet in any_signal_packet()) {
        // Serialize to JSON
        let json_str = serde_json::to_string(&packet)
            .expect("failed to serialize SignalPacket to JSON");

        // Deserialize back from JSON
        let deserialized: SignalPacket = serde_json::from_str(&json_str)
            .expect("failed to deserialize SignalPacket from JSON");

        // Verify they are identical
        assert_eq!(format!("{:?}", packet), format!("{:?}", deserialized));
    }

    #[test]
    fn input_packet_roundtrip(packet in any_input_packet()) {
        // Serialize to JSON
        let json_str = serde_json::to_string(&packet)
            .expect("failed to serialize InputPacket to JSON");

        // Deserialize back from JSON
        let deserialized: InputPacket = serde_json::from_str(&json_str)
            .expect("failed to deserialize InputPacket from JSON");

        // Verify they are identical
        assert_eq!(format!("{:?}", packet), format!("{:?}", deserialized));
    }
}
