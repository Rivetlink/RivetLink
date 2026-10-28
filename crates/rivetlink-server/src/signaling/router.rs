//! Signal packet routing between connected WebSocket clients.
//!
//! Receives text frames from the WebSocket gateway, parses them as [`SignalPacket`],
//! and forwards them to the other connection of the referenced session.
//!
//! Authorization is enforced: a session request must target an online device of
//! the sender's own organisation, and session-bound packets are only forwarded
//! from one of the session's two connections to the other.

use std::time::Instant;

use rivetlink_core::SessionId;
use rivetlink_protocol::{SignalPacket, RELAY_TUNNEL_VERSION};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::sessions::manager::{ActiveSession, SessionManager};
use crate::state::SignalingMessage;
use crate::websocket::connection::{ConnectionMap, PrincipalKind};

/// Run the signaling router loop, reading from the signaling channel
/// and forwarding packets to the correct peer.
pub async fn run_signaling_router(
    mut rx: mpsc::Receiver<SignalingMessage>,
    connections: ConnectionMap,
    sessions: SessionManager,
) {
    tracing::info!("signaling router started");

    while let Some(message) = rx.recv().await {
        let Ok(packet) = serde_json::from_str::<SignalPacket>(&message.text) else {
            tracing::debug!(sender = %message.principal_id, "invalid signal packet, ignoring");
            continue;
        };
        route_packet(&connections, &sessions, &message, &packet);
    }

    tracing::info!("signaling router stopped");
}

fn route_packet(
    connections: &ConnectionMap,
    sessions: &SessionManager,
    message: &SignalingMessage,
    packet: &SignalPacket,
) {
    match packet {
        SignalPacket::SessionRequest {
            device_id,
            client_public_key,
            protocol_version,
            requested_capability,
            ..
        } => {
            let session_id = Uuid::now_v7();
            let reject = |reason: &str| {
                tracing::warn!(sender = %message.principal_id, target_device = %device_id, reason, "session request refused");
                let rejected = SignalPacket::SessionRejected {
                    session_id: SessionId(session_id),
                    reason: reason.to_string(),
                };
                if let Ok(text) = serde_json::to_string(&rejected) {
                    connections.send_to(&message.conn_id, &text);
                }
            };
            if message.kind != PrincipalKind::User {
                return reject("only users can open sessions");
            }
            // Offline and foreign devices get the same answer, so a request
            // does not reveal whether a device id exists in another tenant.
            let Some(device_conn) = connections.device_conn(&device_id.0).filter(|conn| {
                connections
                    .get_client(conn)
                    .is_some_and(|device| device.org_id == message.org_id)
            }) else {
                return reject("device is offline or unknown");
            };
            if let Err(reason) = sessions.create_session(ActiveSession {
                id: session_id,
                org_id: message.org_id,
                device_id: device_id.0,
                device_conn,
                initiator_id: message.principal_id,
                initiator_conn: message.conn_id,
                tunnel: *protocol_version == RELAY_TUNNEL_VERSION,
                started_at: Instant::now(),
            }) {
                return reject(reason);
            }

            tracing::info!(from = %message.principal_id, target_device = %device_id, session = %session_id, protocol_version, "session request");

            // Enrich the request with the allocated session_id so the host can
            // reference the session when it accepts or rejects.
            let enriched = SignalPacket::SessionRequest {
                device_id: *device_id,
                client_public_key: client_public_key.clone(),
                protocol_version: *protocol_version,
                requested_capability: *requested_capability,
                session_id: Some(SessionId(session_id)),
            };
            let delivered = serde_json::to_string(&enriched)
                .is_ok_and(|text| connections.send_to(&device_conn, &text));
            // Either connection may have closed while this request waited in
            // the router queue. Its cleanup already ran, so a session bound to
            // it would never be removed and would hold a slot for good.
            if !delivered || connections.get_sender(&message.conn_id).is_none() {
                sessions.remove_session(&session_id);
                reject("device is offline or unknown");
            }
        },
        SignalPacket::SessionRejected { session_id, .. }
        | SignalPacket::SessionClosed { session_id } => {
            if forward(connections, sessions, message, session_id) {
                tracing::info!(session = %session_id, "session ended");
                sessions.remove_session(&session_id.0);
            }
        },
        // Payloads are end-to-end sealed (console input may contain password
        // keystrokes); never inspect or log them at the relay.
        SignalPacket::AuthChallenge { session_id, .. }
        | SignalPacket::AuthResponse { session_id, .. }
        | SignalPacket::SessionAccepted { session_id, .. }
        | SignalPacket::IceCandidate { session_id, .. }
        | SignalPacket::SessionKeyExchange { session_id, .. }
        | SignalPacket::ScreenshotRequest { session_id }
        | SignalPacket::ScreenshotData { session_id, .. }
        | SignalPacket::HostConsoleState { session_id, .. }
        | SignalPacket::ConsoleInput { session_id, .. } => {
            forward(connections, sessions, message, session_id);
        },
        SignalPacket::Heartbeat => {},
    }
}

/// Forward the raw frame to the session's other connection. Returns false
/// (and drops it) when the sender is not one of the session's connections.
fn forward(
    connections: &ConnectionMap,
    sessions: &SessionManager,
    message: &SignalingMessage,
    session_id: &SessionId,
) -> bool {
    let Some(peer) = sessions.peer_conn(&session_id.0, &message.conn_id) else {
        if sessions.get_session_org(&session_id.0).is_some() {
            tracing::warn!(
                sender = %message.principal_id,
                session = %session_id,
                "unauthorized: sender is not a session member"
            );
        } else {
            // Routine: an end echoing the close of a session already gone.
            tracing::debug!(session = %session_id, "packet for an ended session dropped");
        }
        return false;
    };
    if !connections.send_to(&peer, &message.text) {
        tracing::warn!(session = %session_id, "peer not reachable");
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::websocket::connection::{ConnectedClient, OUTGOING_QUEUE};
    use axum::extract::ws::Message;
    use rivetlink_core::DeviceId;
    use rivetlink_protocol::{SessionCapability, RELAY_PROTOCOL_VERSION};

    fn org_id() -> Uuid {
        Uuid::from_u128(0x1234_5678_9abc_def0_1234_5678_9abc_def0)
    }

    struct Conn {
        conn_id: Uuid,
        principal_id: Uuid,
        org_id: Uuid,
        kind: PrincipalKind,
        rx: mpsc::Receiver<Message>,
    }

    impl Conn {
        fn say(&self, packet: &SignalPacket) -> SignalingMessage {
            SignalingMessage {
                conn_id: self.conn_id,
                principal_id: self.principal_id,
                org_id: self.org_id,
                kind: self.kind,
                text: serde_json::to_string(packet).unwrap(),
            }
        }

        fn next(&mut self) -> Option<SignalPacket> {
            match self.rx.try_recv().ok()? {
                Message::Text(text) => Some(serde_json::from_str(&text).unwrap()),
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    fn connect(connections: &ConnectionMap, kind: PrincipalKind, org_id: Uuid) -> Conn {
        let (tx, rx) = mpsc::channel(OUTGOING_QUEUE);
        let (conn_id, principal_id) = (Uuid::now_v7(), Uuid::now_v7());
        connections.insert(
            conn_id,
            ConnectedClient {
                user_id: principal_id,
                org_id,
                kind,
                sender: tx,
            },
        );
        Conn {
            conn_id,
            principal_id,
            org_id,
            kind,
            rx,
        }
    }

    fn request(device: &Conn, protocol_version: u16) -> SignalPacket {
        SignalPacket::SessionRequest {
            device_id: DeviceId(device.principal_id),
            client_public_key: "client-key".to_string(),
            protocol_version,
            requested_capability: SessionCapability::ConsoleControl,
            session_id: None,
        }
    }

    fn route(connections: &ConnectionMap, sessions: &SessionManager, message: &SignalingMessage) {
        let packet = serde_json::from_str(&message.text).unwrap();
        route_packet(connections, sessions, message, &packet);
    }

    #[test]
    fn a_request_from_a_connection_that_already_closed_leaves_no_session() {
        let (connections, sessions) = (ConnectionMap::new(), SessionManager::new());
        let device = connect(&connections, PrincipalKind::Device, org_id());
        let user = connect(&connections, PrincipalKind::User, org_id());
        // The socket closed (and was cleaned up) while its request was queued.
        let queued = user.say(&request(&device, RELAY_TUNNEL_VERSION));
        connections.remove(&user.conn_id);

        route(&connections, &sessions, &queued);
        assert_eq!(sessions.active_count(), 0);
    }

    #[test]
    fn session_request_reaches_the_device_with_a_session_id() {
        let (connections, sessions) = (ConnectionMap::new(), SessionManager::new());
        let mut device = connect(&connections, PrincipalKind::Device, org_id());
        let user = connect(&connections, PrincipalKind::User, org_id());

        route(
            &connections,
            &sessions,
            &user.say(&request(&device, RELAY_TUNNEL_VERSION)),
        );

        let Some(SignalPacket::SessionRequest {
            session_id: Some(sid),
            requested_capability: SessionCapability::ConsoleControl,
            ..
        }) = device.next()
        else {
            panic!("expected an enriched session request");
        };
        assert_eq!(sessions.active_count(), 1);
        assert_eq!(
            sessions.tunnel_peer_conn(&sid.0, &user.conn_id),
            Some(device.conn_id)
        );
    }

    #[test]
    fn requests_for_offline_or_foreign_devices_are_rejected_alike() {
        let (connections, sessions) = (ConnectionMap::new(), SessionManager::new());
        let mut foreign = connect(&connections, PrincipalKind::Device, Uuid::now_v7());
        let mut user = connect(&connections, PrincipalKind::User, org_id());
        let offline = Conn {
            conn_id: Uuid::now_v7(),
            principal_id: Uuid::now_v7(),
            org_id: org_id(),
            kind: PrincipalKind::Device,
            rx: mpsc::channel(1).1,
        };

        for target in [&foreign, &offline] {
            route(
                &connections,
                &sessions,
                &user.say(&request(target, RELAY_PROTOCOL_VERSION)),
            );
            let Some(SignalPacket::SessionRejected { reason, .. }) = user.next() else {
                panic!("expected a rejection");
            };
            assert_eq!(reason, "device is offline or unknown");
        }
        assert!(foreign.next().is_none());
        assert_eq!(sessions.active_count(), 0);
    }

    #[test]
    fn a_device_cannot_open_a_session() {
        let (connections, sessions) = (ConnectionMap::new(), SessionManager::new());
        let target = connect(&connections, PrincipalKind::Device, org_id());
        let mut other_device = connect(&connections, PrincipalKind::Device, org_id());
        route(
            &connections,
            &sessions,
            &other_device.say(&request(&target, RELAY_TUNNEL_VERSION)),
        );
        assert!(matches!(
            other_device.next(),
            Some(SignalPacket::SessionRejected { .. })
        ));
        assert_eq!(sessions.active_count(), 0);
    }

    #[test]
    fn packets_go_to_the_requesting_connection_only() {
        let (connections, sessions) = (ConnectionMap::new(), SessionManager::new());
        let mut device = connect(&connections, PrincipalKind::Device, org_id());
        let mut user = connect(&connections, PrincipalKind::User, org_id());
        // A second socket of the same user (e.g. the app's signaling socket).
        let (tx, mut sibling_rx) = mpsc::channel(OUTGOING_QUEUE);
        connections.insert(
            Uuid::now_v7(),
            ConnectedClient {
                user_id: user.principal_id,
                org_id: org_id(),
                kind: PrincipalKind::User,
                sender: tx,
            },
        );

        route(
            &connections,
            &sessions,
            &user.say(&request(&device, RELAY_TUNNEL_VERSION)),
        );
        let Some(SignalPacket::SessionRequest {
            session_id: Some(sid),
            ..
        }) = device.next()
        else {
            panic!("expected request");
        };
        let accepted = SignalPacket::SessionAccepted {
            session_id: sid,
            role: rivetlink_core::SessionRole::Controller,
        };
        route(&connections, &sessions, &device.say(&accepted));
        assert!(matches!(
            user.next(),
            Some(SignalPacket::SessionAccepted { .. })
        ));
        assert!(sibling_rx.try_recv().is_err());
    }

    #[test]
    fn outsiders_cannot_inject_or_close() {
        let (connections, sessions) = (ConnectionMap::new(), SessionManager::new());
        let mut device = connect(&connections, PrincipalKind::Device, org_id());
        let mut user = connect(&connections, PrincipalKind::User, org_id());
        let outsider = connect(&connections, PrincipalKind::User, org_id());
        route(
            &connections,
            &sessions,
            &user.say(&request(&device, RELAY_TUNNEL_VERSION)),
        );
        let Some(SignalPacket::SessionRequest {
            session_id: Some(sid),
            ..
        }) = device.next()
        else {
            panic!("expected request");
        };

        let state = SignalPacket::HostConsoleState {
            session_id: sid,
            state: rivetlink_protocol::HostConsoleState::GdmLogin,
            generation: 1,
        };
        route(&connections, &sessions, &outsider.say(&state));
        route(
            &connections,
            &sessions,
            &outsider.say(&SignalPacket::SessionClosed { session_id: sid }),
        );
        assert!(user.next().is_none());
        assert_eq!(sessions.active_count(), 1);

        route(&connections, &sessions, &device.say(&state));
        assert!(matches!(
            user.next(),
            Some(SignalPacket::HostConsoleState { .. })
        ));
        route(
            &connections,
            &sessions,
            &user.say(&SignalPacket::SessionClosed { session_id: sid }),
        );
        assert!(matches!(
            device.next(),
            Some(SignalPacket::SessionClosed { .. })
        ));
        assert_eq!(sessions.active_count(), 0);
    }

    #[tokio::test]
    async fn invalid_and_heartbeat_packets_are_dropped() {
        let (connections, sessions) = (ConnectionMap::new(), SessionManager::new());
        let mut device = connect(&connections, PrincipalKind::Device, org_id());
        let (tx, rx) = mpsc::channel(8);
        let router = tokio::spawn(run_signaling_router(rx, connections.clone(), sessions));
        let mut garbage = device.say(&SignalPacket::Heartbeat);
        tx.send(garbage.clone()).await.unwrap();
        garbage.text = "not valid json!!!".to_string();
        tx.send(garbage).await.unwrap();
        drop(tx);
        router.await.unwrap();
        assert!(device.next().is_none());
    }
}
