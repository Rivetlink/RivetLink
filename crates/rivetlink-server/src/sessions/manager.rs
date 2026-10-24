//! Real-time session state: which two connections a relay session joins.
//!
//! This is in-memory state (not DB) — used by the signaling router and the
//! tunnel forwarder to know where a session's packets go. A session is bound
//! to the two WebSocket connections that set it up, so it ends with either.

use dashmap::DashMap;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

/// Sessions one user may have open at once (all their connections together).
pub const MAX_SESSIONS_PER_USER: usize = 4;
/// Sessions one device may serve at once.
pub const MAX_SESSIONS_PER_DEVICE: usize = 16;

/// Tracks all active sessions in memory.
#[derive(Debug, Clone, Default)]
pub struct SessionManager {
    sessions: Arc<DashMap<Uuid, ActiveSession>>,
}

/// An active remote session between a client connection and a device connection.
#[derive(Debug, Clone)]
pub struct ActiveSession {
    pub id: Uuid,
    pub org_id: Uuid,
    pub device_id: Uuid,
    pub device_conn: Uuid,
    pub initiator_id: Uuid,
    pub initiator_conn: Uuid,
    /// Carries opaque binary tunnel frames (relay protocol v3).
    pub tunnel: bool,
    pub started_at: Instant,
}

impl SessionManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a session unless the user or device is at its limit.
    ///
    /// ponytail: counts by scanning all sessions; fine for a self-hosted relay,
    /// keep per-principal counters if this ever serves thousands.
    pub fn create_session(&self, session: ActiveSession) -> Result<(), &'static str> {
        let (mut by_user, mut by_device) = (0, 0);
        for s in self.sessions.iter() {
            by_user += usize::from(s.initiator_id == session.initiator_id);
            by_device += usize::from(s.device_id == session.device_id);
        }
        if by_user >= MAX_SESSIONS_PER_USER {
            return Err("too many open sessions for this account");
        }
        if by_device >= MAX_SESSIONS_PER_DEVICE {
            return Err("device is busy");
        }
        self.sessions.insert(session.id, session);
        Ok(())
    }

    /// The other connection of a session, if `sender_conn` is one of its two.
    /// This is the membership check for everything routed by session id.
    pub fn peer_conn(&self, session_id: &Uuid, sender_conn: &Uuid) -> Option<Uuid> {
        let s = self.sessions.get(session_id)?;
        if s.initiator_conn == *sender_conn {
            Some(s.device_conn)
        } else if s.device_conn == *sender_conn {
            Some(s.initiator_conn)
        } else {
            None
        }
    }

    /// Like [`Self::peer_conn`], but only for tunnel sessions.
    pub fn tunnel_peer_conn(&self, session_id: &Uuid, sender_conn: &Uuid) -> Option<Uuid> {
        if !self.sessions.get(session_id)?.tunnel {
            return None;
        }
        self.peer_conn(session_id, sender_conn)
    }

    /// Get the org_id for a session (for cross-tenant checks).
    pub fn get_session_org(&self, session_id: &Uuid) -> Option<Uuid> {
        self.sessions.get(session_id).map(|s| s.org_id)
    }

    /// Remove a session.
    pub fn remove_session(&self, session_id: &Uuid) -> Option<ActiveSession> {
        self.sessions.remove(session_id).map(|(_, s)| s)
    }

    /// Remove every session the closed connection took part in.
    pub fn remove_for_conn(&self, conn_id: &Uuid) -> Vec<ActiveSession> {
        let ids: Vec<Uuid> = self
            .sessions
            .iter()
            .filter(|s| s.initiator_conn == *conn_id || s.device_conn == *conn_id)
            .map(|s| s.id)
            .collect();
        ids.iter()
            .filter_map(|id| self.remove_session(id))
            .collect()
    }

    /// Count of currently active sessions.
    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn session(device_id: Uuid, initiator_id: Uuid) -> ActiveSession {
        ActiveSession {
            id: Uuid::now_v7(),
            org_id: Uuid::from_u128(1),
            device_id,
            device_conn: Uuid::now_v7(),
            initiator_id,
            initiator_conn: Uuid::now_v7(),
            tunnel: true,
            started_at: Instant::now(),
        }
    }

    #[test]
    fn peers_are_the_two_connections_and_nobody_else() {
        let mgr = SessionManager::new();
        let s = session(Uuid::now_v7(), Uuid::now_v7());
        mgr.create_session(s.clone()).unwrap();
        assert_eq!(mgr.peer_conn(&s.id, &s.initiator_conn), Some(s.device_conn));
        assert_eq!(mgr.peer_conn(&s.id, &s.device_conn), Some(s.initiator_conn));
        assert_eq!(mgr.peer_conn(&s.id, &Uuid::now_v7()), None);
        assert_eq!(mgr.peer_conn(&Uuid::now_v7(), &s.initiator_conn), None);
    }

    #[test]
    fn only_tunnel_sessions_carry_binary_frames() {
        let mgr = SessionManager::new();
        let mut s = session(Uuid::now_v7(), Uuid::now_v7());
        s.tunnel = false;
        mgr.create_session(s.clone()).unwrap();
        assert_eq!(mgr.tunnel_peer_conn(&s.id, &s.initiator_conn), None);
    }

    #[test]
    fn a_closed_connection_ends_its_sessions_only() {
        let mgr = SessionManager::new();
        let device = Uuid::now_v7();
        let a = session(device, Uuid::now_v7());
        let mut b = session(device, Uuid::now_v7());
        b.device_conn = a.device_conn;
        let other = session(Uuid::now_v7(), Uuid::now_v7());
        for s in [&a, &b, &other] {
            mgr.create_session(s.clone()).unwrap();
        }

        let ended = mgr.remove_for_conn(&a.initiator_conn);
        assert_eq!(ended.len(), 1);
        assert_eq!(mgr.active_count(), 2);

        let ended = mgr.remove_for_conn(&a.device_conn);
        assert_eq!(ended.len(), 1);
        assert_eq!(mgr.active_count(), 1);
    }

    #[test]
    fn limits_per_user_and_per_device() {
        let mgr = SessionManager::new();
        let user = Uuid::now_v7();
        for _ in 0..MAX_SESSIONS_PER_USER {
            mgr.create_session(session(Uuid::now_v7(), user)).unwrap();
        }
        assert!(mgr.create_session(session(Uuid::now_v7(), user)).is_err());

        let device = Uuid::now_v7();
        for _ in 0..MAX_SESSIONS_PER_DEVICE {
            mgr.create_session(session(device, Uuid::now_v7())).unwrap();
        }
        assert!(mgr.create_session(session(device, Uuid::now_v7())).is_err());
    }
}
