//! Signal packet routing between connected WebSocket clients.
//!
//! Receives raw JSON messages from the WebSocket gateway, parses them as [`SignalPacket`],
//! and forwards to the appropriate peer via the connection map and session manager.
//!
//! Authorization is enforced: cross-tenant requests are rejected, and session-bound
//! packets are only forwarded if the sender is a member of that session.

use rivetlink_protocol::SignalPacket;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::sessions::manager::SessionManager;
use crate::state::SignalingMessage;
use crate::websocket::connection::ConnectionMap;

/// Run the signaling router loop, reading from the signaling channel
/// and forwarding packets to the correct peer.
pub async fn run_signaling_router(
    mut rx: mpsc::UnboundedReceiver<SignalingMessage>,
    connections: ConnectionMap,
    sessions: SessionManager,
) {
    tracing::info!("signaling router started");

    while let Some((sender_id, sender_org_id, raw_message)) = rx.recv().await {
        let Ok(packet) = serde_json::from_str::<SignalPacket>(&raw_message) else {
            tracing::warn!(sender = %sender_id, "invalid signal packet, ignoring");
            continue;
        };

        route_packet(
            &connections,
            &sessions,
            &sender_id,
            &sender_org_id,
            &raw_message,
            &packet,
        );
    }

    tracing::info!("signaling router stopped");
}

#[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
fn route_packet(
    connections: &ConnectionMap,
    sessions: &SessionManager,
    sender_id: &Uuid,
    sender_org_id: &Uuid,
    raw_message: &str,
    packet: &SignalPacket,
) {
    match packet {
        SignalPacket::SessionRequest {
            device_id,
            client_public_key,
            requested_capability,
            ..
        } => {
            // Verify target device is in same org (cross-tenant check)
            if let Some(target_client) = connections.get_client(&device_id.0) {
                if target_client.org_id != *sender_org_id {
                    tracing::warn!(
                        sender = %sender_id,
                        target_device = %device_id,
                        "cross-tenant session request rejected"
                    );
                    return;
                }
            }

            let session_id = Uuid::now_v7();
            if sessions
                .create_session(session_id, *sender_org_id, device_id.0, *sender_id)
                .is_none()
            {
                tracing::warn!(
                    sender = %sender_id,
                    "session creation refused: party already in active session"
                );
                return;
            }

            tracing::info!(from = %sender_id, target_device = %device_id, "session request");

            // Enrich the request with the allocated session_id so the host can
            // reference the session when it accepts or rejects.
            let enriched = SignalPacket::SessionRequest {
                device_id: *device_id,
                client_public_key: client_public_key.clone(),
                requested_capability: *requested_capability,
                session_id: Some(rivetlink_core::SessionId(session_id)),
            };
            match serde_json::to_string(&enriched) {
                Ok(msg) => forward_to_device(connections, &device_id.0, &msg),
                Err(e) => {
                    tracing::error!(error = %e, "failed to serialize enriched session request");
                },
            }
        },
        SignalPacket::AuthChallenge { session_id, .. } => {
            if !verify_session_member(sessions, sender_id, &session_id.0) {
                return;
            }
            tracing::debug!(session = %session_id, "forwarding auth challenge");
            forward_to_peer(connections, sessions, sender_id, raw_message);
        },
        SignalPacket::AuthResponse { session_id, .. } => {
            if !verify_session_member(sessions, sender_id, &session_id.0) {
                return;
            }
            tracing::debug!(session = %session_id, "forwarding auth response");
            forward_to_peer(connections, sessions, sender_id, raw_message);
        },
        SignalPacket::SessionAccepted { session_id, .. } => {
            if !verify_session_member(sessions, sender_id, &session_id.0) {
                return;
            }
            tracing::info!(session = %session_id, "session accepted");
            forward_to_peer(connections, sessions, sender_id, raw_message);
        },
        SignalPacket::SessionRejected { session_id, .. } => {
            if !verify_session_member(sessions, sender_id, &session_id.0) {
                return;
            }
            tracing::info!(session = %session_id, "session rejected");
            forward_to_peer(connections, sessions, sender_id, raw_message);
            sessions.remove_session(&session_id.0);
        },
        SignalPacket::IceCandidate { session_id, .. } => {
            if !verify_session_member(sessions, sender_id, &session_id.0) {
                return;
            }
            tracing::trace!(session = %session_id, "forwarding ICE candidate");
            forward_to_peer(connections, sessions, sender_id, raw_message);
        },
        SignalPacket::SessionKeyExchange { session_id, .. } => {
            if !verify_session_member(sessions, sender_id, &session_id.0) {
                return;
            }
            tracing::debug!(session = %session_id, "forwarding session key exchange");
            forward_to_peer(connections, sessions, sender_id, raw_message);
        },
        SignalPacket::ScreenshotRequest { session_id } => {
            if !verify_session_member(sessions, sender_id, &session_id.0) {
                return;
            }
            tracing::debug!(session = %session_id, "forwarding screenshot request");
            forward_to_peer(connections, sessions, sender_id, raw_message);
        },
        SignalPacket::ScreenshotData { session_id, .. } => {
            if !verify_session_member(sessions, sender_id, &session_id.0) {
                return;
            }
            tracing::trace!(session = %session_id, "forwarding screenshot data chunk");
            forward_to_peer(connections, sessions, sender_id, raw_message);
        },
        SignalPacket::HostConsoleState {
            session_id,
            state,
            generation,
        } => {
            if !verify_session_member(sessions, sender_id, &session_id.0) {
                return;
            }
            tracing::info!(session = %session_id, ?state, generation, "forwarding host console state");
            forward_to_peer(connections, sessions, sender_id, raw_message);
        },
        SignalPacket::ConsoleInput { session_id, .. } => {
            if !verify_session_member(sessions, sender_id, &session_id.0) {
                return;
            }
            // Payload is end-to-end sealed and may contain password keystrokes;
            // never inspect or log it at the relay.
            tracing::trace!(session = %session_id, "forwarding sealed console input");
            forward_to_peer(connections, sessions, sender_id, raw_message);
        },
        SignalPacket::Heartbeat => {},
        SignalPacket::SessionClosed { session_id } => {
            if !verify_session_member(sessions, sender_id, &session_id.0) {
                return;
            }
            tracing::info!(session = %session_id, "session closed");
            forward_to_peer(connections, sessions, sender_id, raw_message);
            sessions.remove_session(&session_id.0);
        },
    }
}

/// Verify sender is a participant in the referenced session.
fn verify_session_member(sessions: &SessionManager, sender_id: &Uuid, session_id: &Uuid) -> bool {
    if !sessions.is_session_member(sender_id, session_id) {
        tracing::warn!(
            sender = %sender_id,
            session = %session_id,
            "unauthorized: sender is not a session member"
        );
        return false;
    }
    true
}

/// Forward a message directly to a device by its user_id.
fn forward_to_device(connections: &ConnectionMap, device_user_id: &Uuid, message: &str) {
    if !connections.send_to(device_user_id, message) {
        tracing::warn!(target_device = %device_user_id, "target device not connected");
    }
}

/// Forward a message to the peer in the sender's active session.
fn forward_to_peer(
    connections: &ConnectionMap,
    sessions: &SessionManager,
    sender_id: &Uuid,
    message: &str,
) {
    match sessions.find_peer(sender_id) {
        Some(peer_id) => {
            if !connections.send_to(&peer_id, message) {
                tracing::warn!(peer = %peer_id, "peer not connected");
            }
        },
        None => {
            tracing::warn!(sender = %sender_id, "no active session found for sender");
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::websocket::connection::{ConnectedClient, ConnectionMap, PrincipalKind};
    use rivetlink_core::DeviceId;
    use tokio::sync::mpsc;

    fn setup() -> (ConnectionMap, SessionManager) {
        (ConnectionMap::new(), SessionManager::new())
    }

    fn org_id() -> Uuid {
        // Shared org for same-tenant tests
        Uuid::from_u128(0x1234_5678_9abc_def0_1234_5678_9abc_def0)
    }

    #[tokio::test]
    async fn session_request_forwarded_to_same_org_device() {
        let (connections, sessions) = setup();
        let (sig_tx, sig_rx) = mpsc::unbounded_channel::<SignalingMessage>();
        let shared_org = org_id();

        let device_user_id = Uuid::now_v7();
        let (ws_tx, mut ws_rx) = mpsc::unbounded_channel();

        connections.insert(
            device_user_id,
            ConnectedClient {
                user_id: device_user_id,
                org_id: shared_org,
                kind: PrincipalKind::User,
                sender: ws_tx,
            },
        );

        let conn_clone = connections.clone();
        let sess_clone = sessions.clone();
        let router_handle = tokio::spawn(run_signaling_router(sig_rx, conn_clone, sess_clone));

        let sender_id = Uuid::now_v7();
        let packet = SignalPacket::SessionRequest {
            device_id: DeviceId(device_user_id),
            client_public_key: "test_key".to_string(),
            requested_capability: rivetlink_protocol::SessionCapability::Screenshot,
            session_id: None,
        };
        let message = serde_json::to_string(&packet).unwrap();

        sig_tx.send((sender_id, shared_org, message)).unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_millis(100), ws_rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert!(received.contains("SESSION_REQUEST"));
        assert!(received.contains("test_key"));

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(sessions.active_count(), 1);

        drop(sig_tx);
        let _ = router_handle.await;
    }

    #[tokio::test]
    async fn relay_preserves_requested_capability_for_host_authorization() {
        let (connections, sessions) = setup();
        let (sig_tx, sig_rx) = mpsc::unbounded_channel::<SignalingMessage>();
        let shared_org = org_id();
        let device_id = Uuid::now_v7();
        let (host_tx, mut host_rx) = mpsc::unbounded_channel();
        connections.insert(
            device_id,
            ConnectedClient {
                user_id: device_id,
                org_id: shared_org,
                kind: PrincipalKind::Device,
                sender: host_tx,
            },
        );
        let router_handle = tokio::spawn(run_signaling_router(
            sig_rx,
            connections.clone(),
            sessions.clone(),
        ));

        let request = SignalPacket::SessionRequest {
            device_id: DeviceId(device_id),
            client_public_key: "controller-key".to_string(),
            requested_capability: rivetlink_protocol::SessionCapability::ConsoleControl,
            session_id: None,
        };
        sig_tx
            .send((
                Uuid::now_v7(),
                shared_org,
                serde_json::to_string(&request).unwrap(),
            ))
            .unwrap();
        let raw = tokio::time::timeout(std::time::Duration::from_millis(100), host_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let forwarded: SignalPacket = serde_json::from_str(&raw).unwrap();
        assert!(matches!(
            forwarded,
            SignalPacket::SessionRequest {
                requested_capability: rivetlink_protocol::SessionCapability::ConsoleControl,
                session_id: Some(_),
                ..
            }
        ));

        drop(sig_tx);
        let _ = router_handle.await;
    }

    #[tokio::test]
    async fn cross_tenant_session_request_rejected() {
        let (connections, sessions) = setup();
        let (sig_tx, sig_rx) = mpsc::unbounded_channel::<SignalingMessage>();

        let device_org = Uuid::now_v7();
        let attacker_org = Uuid::now_v7();

        let device_user_id = Uuid::now_v7();
        let (ws_tx, mut ws_rx) = mpsc::unbounded_channel();

        connections.insert(
            device_user_id,
            ConnectedClient {
                user_id: device_user_id,
                org_id: device_org,
                kind: PrincipalKind::User,
                sender: ws_tx,
            },
        );

        let conn_clone = connections.clone();
        let sess_clone = sessions.clone();
        let router_handle = tokio::spawn(run_signaling_router(sig_rx, conn_clone, sess_clone));

        let attacker_id = Uuid::now_v7();
        let packet = SignalPacket::SessionRequest {
            device_id: DeviceId(device_user_id),
            client_public_key: "attacker_key".to_string(),
            requested_capability: rivetlink_protocol::SessionCapability::Screenshot,
            session_id: None,
        };
        let message = serde_json::to_string(&packet).unwrap();

        // Attacker sends from different org
        sig_tx.send((attacker_id, attacker_org, message)).unwrap();

        let result =
            tokio::time::timeout(std::time::Duration::from_millis(100), ws_rx.recv()).await;
        assert!(
            result.is_err(),
            "cross-tenant request should not be forwarded"
        );
        assert_eq!(sessions.active_count(), 0);

        drop(sig_tx);
        let _ = router_handle.await;
    }

    #[tokio::test]
    async fn session_close_requires_membership() {
        let (connections, sessions) = setup();
        let (sig_tx, sig_rx) = mpsc::unbounded_channel::<SignalingMessage>();
        let shared_org = org_id();

        // Create a session between client and device
        let client_id = Uuid::now_v7();
        let device_id = Uuid::now_v7();
        let session_id = Uuid::now_v7();
        sessions.create_session(session_id, shared_org, device_id, client_id);

        let (dev_tx, _dev_rx) = mpsc::unbounded_channel();
        connections.insert(
            device_id,
            ConnectedClient {
                user_id: device_id,
                org_id: shared_org,
                kind: PrincipalKind::User,
                sender: dev_tx,
            },
        );

        let conn_clone = connections.clone();
        let sess_clone = sessions.clone();
        let router_handle = tokio::spawn(run_signaling_router(sig_rx, conn_clone, sess_clone));

        // Attacker (not in session) tries to close it
        let attacker_id = Uuid::now_v7();
        let close_packet = SignalPacket::SessionClosed {
            session_id: rivetlink_core::SessionId(session_id),
        };
        let message = serde_json::to_string(&close_packet).unwrap();

        sig_tx.send((attacker_id, shared_org, message)).unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Session should still be active — attacker wasn't a member
        assert_eq!(sessions.active_count(), 1);

        drop(sig_tx);
        let _ = router_handle.await;
    }

    #[tokio::test]
    async fn session_close_by_member_succeeds() {
        let (connections, sessions) = setup();
        let (sig_tx, sig_rx) = mpsc::unbounded_channel::<SignalingMessage>();
        let shared_org = org_id();

        let client_id = Uuid::now_v7();
        let device_id = Uuid::now_v7();
        let session_id = Uuid::now_v7();
        sessions.create_session(session_id, shared_org, device_id, client_id);

        let (dev_tx, _dev_rx) = mpsc::unbounded_channel();
        connections.insert(
            device_id,
            ConnectedClient {
                user_id: device_id,
                org_id: shared_org,
                kind: PrincipalKind::User,
                sender: dev_tx,
            },
        );

        let conn_clone = connections.clone();
        let sess_clone = sessions.clone();
        let router_handle = tokio::spawn(run_signaling_router(sig_rx, conn_clone, sess_clone));

        // Client (session member) closes session
        let close_packet = SignalPacket::SessionClosed {
            session_id: rivetlink_core::SessionId(session_id),
        };
        let message = serde_json::to_string(&close_packet).unwrap();

        sig_tx.send((client_id, shared_org, message)).unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Session should be removed
        assert_eq!(sessions.active_count(), 0);

        drop(sig_tx);
        let _ = router_handle.await;
    }

    #[tokio::test]
    async fn console_state_is_forwarded_only_to_the_authenticated_session_peer() {
        let (connections, sessions) = setup();
        let (sig_tx, sig_rx) = mpsc::unbounded_channel::<SignalingMessage>();
        let shared_org = org_id();
        let client_id = Uuid::now_v7();
        let device_id = Uuid::now_v7();
        let session_id = Uuid::now_v7();
        sessions.create_session(session_id, shared_org, device_id, client_id);

        let (client_tx, mut client_rx) = mpsc::unbounded_channel();
        connections.insert(
            client_id,
            ConnectedClient {
                user_id: client_id,
                org_id: shared_org,
                kind: PrincipalKind::User,
                sender: client_tx,
            },
        );

        let router_handle = tokio::spawn(run_signaling_router(
            sig_rx,
            connections.clone(),
            sessions.clone(),
        ));
        let packet = SignalPacket::HostConsoleState {
            session_id: rivetlink_core::SessionId(session_id),
            state: rivetlink_protocol::HostConsoleState::GdmLogin,
            generation: 1,
        };
        sig_tx
            .send((
                device_id,
                shared_org,
                serde_json::to_string(&packet).unwrap(),
            ))
            .unwrap();

        let forwarded =
            tokio::time::timeout(std::time::Duration::from_millis(100), client_rx.recv())
                .await
                .unwrap()
                .unwrap();
        assert!(forwarded.contains("HOST_CONSOLE_STATE"));
        assert!(forwarded.contains("gdm_login"));

        // An arbitrary tenant peer cannot inject visible console state.
        let outsider = Uuid::now_v7();
        sig_tx
            .send((
                outsider,
                shared_org,
                serde_json::to_string(&packet).unwrap(),
            ))
            .unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), client_rx.recv())
                .await
                .is_err()
        );

        drop(sig_tx);
        let _ = router_handle.await;
    }

    #[tokio::test]
    async fn invalid_packet_ignored() {
        let (connections, sessions) = setup();
        let (sig_tx, sig_rx) = mpsc::unbounded_channel::<SignalingMessage>();

        let conn_clone = connections.clone();
        let sess_clone = sessions.clone();
        let router_handle = tokio::spawn(run_signaling_router(sig_rx, conn_clone, sess_clone));

        sig_tx
            .send((
                Uuid::now_v7(),
                Uuid::now_v7(),
                "not valid json!!!".to_string(),
            ))
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        drop(sig_tx);
        let _ = router_handle.await;
    }

    #[tokio::test]
    async fn heartbeat_packet_not_forwarded() {
        let (connections, sessions) = setup();
        let (sig_tx, sig_rx) = mpsc::unbounded_channel::<SignalingMessage>();
        let shared_org = org_id();

        let device_id = Uuid::now_v7();
        let (ws_tx, mut ws_rx) = mpsc::unbounded_channel();
        connections.insert(
            device_id,
            ConnectedClient {
                user_id: device_id,
                org_id: shared_org,
                kind: PrincipalKind::User,
                sender: ws_tx,
            },
        );

        let conn_clone = connections.clone();
        let sess_clone = sessions.clone();
        let router_handle = tokio::spawn(run_signaling_router(sig_rx, conn_clone, sess_clone));

        let heartbeat = serde_json::to_string(&SignalPacket::Heartbeat).unwrap();
        sig_tx.send((device_id, shared_org, heartbeat)).unwrap();

        let result = tokio::time::timeout(std::time::Duration::from_millis(50), ws_rx.recv()).await;
        assert!(result.is_err(), "heartbeat should not be forwarded");

        drop(sig_tx);
        let _ = router_handle.await;
    }
}
