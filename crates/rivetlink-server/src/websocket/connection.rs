//! Thread-safe map of connected WebSocket clients indexed by user or device ID.

use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use uuid::Uuid;

/// Unbounded channel for sending WebSocket messages.
pub type WsSender = mpsc::UnboundedSender<String>;

/// Whether a connected principal is a user (control client) or a device
/// (host agent). The signaling router does not care about the distinction —
/// it's recorded for tracing and audit purposes.
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

/// Concurrent map of connected clients keyed by user ID; safe across threads.
#[derive(Debug, Clone, Default)]
pub struct ConnectionMap {
    inner: Arc<DashMap<Uuid, ConnectedClient>>,
}

impl ConnectionMap {
    /// Create a new empty connection map.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }

    /// Register a connected client.
    pub fn insert(&self, user_id: Uuid, client: ConnectedClient) {
        self.inner.insert(user_id, client);
    }

    /// Remove a disconnected client.
    pub fn remove(&self, user_id: &Uuid) {
        self.inner.remove(user_id);
    }

    /// Get message sender for a connected client; None if not connected.
    pub fn get_sender(&self, user_id: &Uuid) -> Option<WsSender> {
        self.inner.get(user_id).map(|c| c.sender.clone())
    }

    /// Check if user has an active connection.
    pub fn contains(&self, user_id: &Uuid) -> bool {
        self.inner.contains_key(user_id)
    }

    /// Get total number of connected clients.
    pub fn connected_count(&self) -> usize {
        self.inner.len()
    }

    /// Get a clone of the connected client info (for authorization checks).
    pub fn get_client(&self, user_id: &Uuid) -> Option<ConnectedClient> {
        self.inner.get(user_id).map(|c| c.clone())
    }

    /// Send message to connected client; returns false if send fails or client disconnected.
    pub fn send_to(&self, user_id: &Uuid, message: &str) -> bool {
        if let Some(client) = self.inner.get(user_id) {
            client.sender.send(message.to_string()).is_ok()
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_client(sender: WsSender) -> ConnectedClient {
        ConnectedClient {
            user_id: Uuid::now_v7(),
            org_id: Uuid::now_v7(),
            kind: PrincipalKind::User,
            sender,
        }
    }

    #[test]
    fn connection_map_insert_and_get() {
        let map = ConnectionMap::new();
        let user_id = Uuid::now_v7();
        let (tx, _rx) = mpsc::unbounded_channel();

        let mut client = user_client(tx);
        client.user_id = user_id;
        map.insert(user_id, client);

        assert!(map.contains(&user_id));
        assert_eq!(map.connected_count(), 1);
        assert!(map.get_sender(&user_id).is_some());
    }

    #[test]
    fn connection_map_remove() {
        let map = ConnectionMap::new();
        let user_id = Uuid::now_v7();
        let (tx, _rx) = mpsc::unbounded_channel();

        let mut client = user_client(tx);
        client.user_id = user_id;
        map.insert(user_id, client);

        map.remove(&user_id);
        assert!(!map.contains(&user_id));
        assert_eq!(map.connected_count(), 0);
    }

    #[test]
    fn connection_map_send_to_connected() {
        let map = ConnectionMap::new();
        let user_id = Uuid::now_v7();
        let (tx, mut rx) = mpsc::unbounded_channel();

        let mut client = user_client(tx);
        client.user_id = user_id;
        map.insert(user_id, client);

        assert!(map.send_to(&user_id, "hello"));
        assert_eq!(rx.try_recv().unwrap(), "hello");
    }

    #[test]
    fn connection_map_send_to_disconnected() {
        let map = ConnectionMap::new();
        let user_id = Uuid::now_v7();
        assert!(!map.send_to(&user_id, "hello"));
    }

    #[test]
    fn connection_map_send_to_dropped_receiver() {
        let map = ConnectionMap::new();
        let user_id = Uuid::now_v7();
        let (tx, rx) = mpsc::unbounded_channel();

        let mut client = user_client(tx);
        client.user_id = user_id;
        map.insert(user_id, client);

        drop(rx);
        assert!(!map.send_to(&user_id, "hello"));
    }

    #[test]
    fn principal_kind_distinguishes_user_and_device() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let user = user_client(tx.clone());
        let device = ConnectedClient {
            user_id: Uuid::now_v7(),
            org_id: Uuid::now_v7(),
            kind: PrincipalKind::Device,
            sender: tx,
        };
        assert_eq!(user.kind, PrincipalKind::User);
        assert_eq!(device.kind, PrincipalKind::Device);
        assert_ne!(user.kind, device.kind);
    }
}
