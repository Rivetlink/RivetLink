//! Thread-safe map of connected WebSocket clients.
//!
//! Every WebSocket gets its own connection id. A user may hold several at once
//! (the app's signaling socket plus one per relay tunnel), so routing always
//! targets a connection, never just a user. A device has one live connection;
//! a reconnect replaces it.

use axum::extract::ws::Message;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use uuid::Uuid;

/// Outgoing messages queued per connection. With messages capped at
/// `MAX_WS_MESSAGE` (gateway) one queue holds at most about 5 MiB, and one
/// slow reader holds up only the senders writing to it. 64 tunnel frames are
/// still 4 MiB of video in flight, plenty to keep a stream moving.
/// ponytail: the bound is per connection, not per account; add a
/// per-principal connection cap if an account opening many slow sockets
/// ever becomes a problem.
pub const OUTGOING_QUEUE: usize = 64;

/// Channel feeding a connection's WebSocket writer.
pub type WsSender = mpsc::Sender<Message>;

/// Whether a connected principal is a user (control client) or a device
/// (host agent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalKind {
    User,
    Device,
}

/// Connected principal with user/org context and outgoing message channel.
///
/// The `user_id` field actually stores the principal ID — for user
/// connections it's the `users.id`, for devices it's the `devices.id`.
/// The two namespaces are both UUIDv7 and globally unique.
#[derive(Debug, Clone)]
pub struct ConnectedClient {
    pub user_id: Uuid,
    pub org_id: Uuid,
    pub kind: PrincipalKind,
    pub sender: WsSender,
}

/// Concurrent map of connected clients keyed by connection id.
#[derive(Debug, Clone, Default)]
pub struct ConnectionMap {
    inner: Arc<DashMap<Uuid, ConnectedClient>>,
    /// device id → its current connection id.
    devices: Arc<DashMap<Uuid, Uuid>>,
}

impl ConnectionMap {
    /// Create a new empty connection map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a connection. A device's newest connection becomes the one
    /// session requests are routed to.
    pub fn insert(&self, conn_id: Uuid, client: ConnectedClient) {
        if client.kind == PrincipalKind::Device {
            self.devices.insert(client.user_id, conn_id);
        }
        self.inner.insert(conn_id, client);
    }

    /// Remove a closed connection. A device stays online if it already
    /// reconnected on a newer connection.
    pub fn remove(&self, conn_id: &Uuid) {
        if let Some((_, client)) = self.inner.remove(conn_id) {
            if client.kind == PrincipalKind::Device {
                self.devices
                    .remove_if(&client.user_id, |_, current| current == conn_id);
            }
        }
    }

    /// The live connection of a device, if it is online.
    pub fn device_conn(&self, device_id: &Uuid) -> Option<Uuid> {
        self.devices.get(device_id).map(|conn| *conn)
    }

    /// Whether this exact principal currently has an authenticated device
    /// websocket. A connected user with the same organisation is not evidence
    /// that a Home Node is online.
    #[must_use]
    pub fn device_is_connected(&self, device_id: &Uuid) -> bool {
        self.devices.contains_key(device_id)
    }

    /// Get message sender for a connection; None if it is gone.
    pub fn get_sender(&self, conn_id: &Uuid) -> Option<WsSender> {
        self.inner.get(conn_id).map(|c| c.sender.clone())
    }

    /// Get total number of connections.
    pub fn connected_count(&self) -> usize {
        self.inner.len()
    }

    /// Get a clone of the connection's client info (for authorization checks).
    pub fn get_client(&self, conn_id: &Uuid) -> Option<ConnectedClient> {
        self.inner.get(conn_id).map(|c| c.clone())
    }

    /// Queue a text message without waiting; false if the connection is gone
    /// or its queue is full.
    pub fn send_to(&self, conn_id: &Uuid, message: &str) -> bool {
        self.inner.get(conn_id).is_some_and(|client| {
            client
                .sender
                .try_send(Message::Text(message.to_string()))
                .is_ok()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(kind: PrincipalKind, user_id: Uuid) -> (ConnectedClient, mpsc::Receiver<Message>) {
        let (tx, rx) = mpsc::channel(OUTGOING_QUEUE);
        (
            ConnectedClient {
                user_id,
                org_id: Uuid::now_v7(),
                kind,
                sender: tx,
            },
            rx,
        )
    }

    #[test]
    fn send_reaches_the_connection_until_it_is_removed() {
        let map = ConnectionMap::new();
        let conn = Uuid::now_v7();
        let (c, mut rx) = client(PrincipalKind::User, Uuid::now_v7());
        map.insert(conn, c);
        assert_eq!(map.connected_count(), 1);

        assert!(map.send_to(&conn, "hello"));
        assert_eq!(rx.try_recv().unwrap(), Message::Text("hello".into()));

        map.remove(&conn);
        assert!(!map.send_to(&conn, "hello"));
        assert_eq!(map.connected_count(), 0);
    }

    #[test]
    fn send_to_a_dropped_receiver_fails() {
        let map = ConnectionMap::new();
        let conn = Uuid::now_v7();
        let (c, rx) = client(PrincipalKind::User, Uuid::now_v7());
        map.insert(conn, c);
        drop(rx);
        assert!(!map.send_to(&conn, "hello"));
    }

    #[test]
    fn one_user_can_hold_several_connections() {
        let map = ConnectionMap::new();
        let user = Uuid::now_v7();
        let (first, mut first_rx) = client(PrincipalKind::User, user);
        let (second, mut second_rx) = client(PrincipalKind::User, user);
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        map.insert(a, first);
        map.insert(b, second);
        assert!(map.send_to(&a, "to-a"));
        assert!(map.send_to(&b, "to-b"));
        assert_eq!(first_rx.try_recv().unwrap(), Message::Text("to-a".into()));
        assert_eq!(second_rx.try_recv().unwrap(), Message::Text("to-b".into()));
    }

    #[test]
    fn a_device_reconnect_survives_the_old_connection_closing() {
        let map = ConnectionMap::new();
        let device = Uuid::now_v7();
        let (old, _old_rx) = client(PrincipalKind::Device, device);
        let (new, _new_rx) = client(PrincipalKind::Device, device);
        let (old_conn, new_conn) = (Uuid::now_v7(), Uuid::now_v7());
        map.insert(old_conn, old);
        map.insert(new_conn, new);
        map.remove(&old_conn);
        assert_eq!(map.device_conn(&device), Some(new_conn));
        assert!(map.device_is_connected(&device));
        map.remove(&new_conn);
        assert!(!map.device_is_connected(&device));
    }

    #[test]
    fn device_presence_does_not_confuse_a_user_with_a_device() {
        let map = ConnectionMap::new();
        let id = Uuid::now_v7();
        let (user, _rx) = client(PrincipalKind::User, id);
        map.insert(Uuid::now_v7(), user);
        assert!(!map.device_is_connected(&id));
    }
}
