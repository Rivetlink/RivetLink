//! Real-time session state manager tracking active sessions, participants, and ownership.
//!
//! This is in-memory state (not DB) — used by the signaling router to know
//! which users are in which session so packets can be forwarded to the right peer.

use dashmap::DashMap;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

/// Tracks all active sessions and their participants in memory.
#[derive(Debug, Clone, Default)]
pub struct SessionManager {
    sessions: Arc<DashMap<Uuid, ActiveSession>>,
    /// Maps user_id → session_id for fast reverse lookup.
    user_sessions: Arc<DashMap<Uuid, Uuid>>,
}

/// An active remote session between a support client and a host device.
#[derive(Debug, Clone)]
pub struct ActiveSession {
    pub id: Uuid,
    pub org_id: Uuid,
    pub device_id: Uuid,
    pub initiator_id: Uuid,
    pub controller: Option<Uuid>,
    pub viewers: Vec<Uuid>,
    pub started_at: Instant,
}

impl SessionManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new active session. Returns `None` if either party already has an active session.
    pub fn create_session(
        &self,
        session_id: Uuid,
        org_id: Uuid,
        device_id: Uuid,
        initiator_id: Uuid,
    ) -> Option<Uuid> {
        // Refuse to overwrite existing in-flight sessions
        if self.user_sessions.contains_key(&initiator_id)
            || self.user_sessions.contains_key(&device_id)
        {
            return None;
        }

        let session = ActiveSession {
            id: session_id,
            org_id,
            device_id,
            initiator_id,
            controller: Some(initiator_id),
            viewers: Vec::new(),
            started_at: Instant::now(),
        };

        self.sessions.insert(session_id, session);
        self.user_sessions.insert(initiator_id, session_id);
        self.user_sessions.insert(device_id, session_id);

        Some(session_id)
    }

    /// Check if a user is a member of the given session.
    pub fn is_session_member(&self, sender_id: &Uuid, session_id: &Uuid) -> bool {
        self.user_sessions
            .get(sender_id)
            .map(|sid| *sid == *session_id)
            .unwrap_or(false)
    }

    /// Check if a user is a member of ANY session (for session-bound packets without explicit ID).
    pub fn is_in_session(&self, sender_id: &Uuid) -> bool {
        self.user_sessions.contains_key(sender_id)
    }

    /// Get the org_id for a session (for cross-tenant checks).
    pub fn get_session_org(&self, session_id: &Uuid) -> Option<Uuid> {
        self.sessions.get(session_id).map(|s| s.org_id)
    }

    /// Find the peer user in a session (the other side of a 1:1 signaling exchange).
    /// Given sender_id, returns the other participant's user_id.
    pub fn find_peer(&self, sender_id: &Uuid) -> Option<Uuid> {
        let session_id = self.user_sessions.get(sender_id)?;
        let session = self.sessions.get(&session_id)?;

        if session.initiator_id == *sender_id {
            // Sender is the support client → peer is the device
            Some(session.device_id)
        } else if session.device_id == *sender_id {
            // Sender is the device → peer is the initiator
            Some(session.initiator_id)
        } else {
            // Sender is a viewer → peer is the device (for ICE etc)
            Some(session.device_id)
        }
    }

    /// Look up which session a user belongs to.
    pub fn get_session_for_user(&self, user_id: &Uuid) -> Option<Uuid> {
        self.user_sessions.get(user_id).map(|r| *r)
    }

    /// Add a viewer to an existing session.
    pub fn add_viewer(&self, session_id: &Uuid, viewer_id: Uuid) {
        if let Some(mut session) = self.sessions.get_mut(session_id) {
            session.viewers.push(viewer_id);
            self.user_sessions.insert(viewer_id, *session_id);
        }
    }

    /// Remove a session and clean up all participant mappings.
    pub fn remove_session(&self, session_id: &Uuid) {
        if let Some((_, session)) = self.sessions.remove(session_id) {
            self.user_sessions.remove(&session.initiator_id);
            self.user_sessions.remove(&session.device_id);
            for viewer in &session.viewers {
                self.user_sessions.remove(viewer);
            }
        }
    }

    /// Count of currently active sessions.
    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn org() -> Uuid {
        Uuid::from_u128(1)
    }

    #[test]
    fn create_and_find_peer() {
        let mgr = SessionManager::new();
        let sid = Uuid::now_v7();
        let dev = Uuid::now_v7();
        let user = Uuid::now_v7();

        assert!(mgr.create_session(sid, org(), dev, user).is_some());
        assert_eq!(mgr.find_peer(&user), Some(dev));
        assert_eq!(mgr.find_peer(&dev), Some(user));
    }

    #[test]
    fn unknown_user_has_no_peer() {
        let mgr = SessionManager::new();
        assert_eq!(mgr.find_peer(&Uuid::now_v7()), None);
    }

    #[test]
    fn remove_session_cleans_up() {
        let mgr = SessionManager::new();
        let sid = Uuid::now_v7();
        let dev = Uuid::now_v7();
        let user = Uuid::now_v7();

        mgr.create_session(sid, org(), dev, user);
        assert_eq!(mgr.active_count(), 1);

        mgr.remove_session(&sid);
        assert_eq!(mgr.active_count(), 0);
        assert_eq!(mgr.find_peer(&user), None);
        assert_eq!(mgr.find_peer(&dev), None);
    }

    #[test]
    fn add_viewer_to_session() {
        let mgr = SessionManager::new();
        let sid = Uuid::now_v7();
        let dev = Uuid::now_v7();
        let user = Uuid::now_v7();
        let viewer = Uuid::now_v7();

        mgr.create_session(sid, org(), dev, user);
        mgr.add_viewer(&sid, viewer);

        assert_eq!(mgr.find_peer(&viewer), Some(dev));
        assert_eq!(mgr.get_session_for_user(&viewer), Some(sid));
    }

    #[test]
    fn remove_session_cleans_viewers() {
        let mgr = SessionManager::new();
        let sid = Uuid::now_v7();
        let dev = Uuid::now_v7();
        let user = Uuid::now_v7();
        let viewer = Uuid::now_v7();

        mgr.create_session(sid, org(), dev, user);
        mgr.add_viewer(&sid, viewer);

        mgr.remove_session(&sid);
        assert_eq!(mgr.find_peer(&viewer), None);
    }

    #[test]
    fn multiple_sessions_isolated() {
        let mgr = SessionManager::new();

        let s1 = Uuid::now_v7();
        let d1 = Uuid::now_v7();
        let u1 = Uuid::now_v7();

        let s2 = Uuid::now_v7();
        let d2 = Uuid::now_v7();
        let u2 = Uuid::now_v7();

        mgr.create_session(s1, org(), d1, u1);
        mgr.create_session(s2, org(), d2, u2);

        assert_eq!(mgr.active_count(), 2);
        assert_eq!(mgr.find_peer(&u1), Some(d1));
        assert_eq!(mgr.find_peer(&u2), Some(d2));

        mgr.remove_session(&s1);
        assert_eq!(mgr.active_count(), 1);
        assert_eq!(mgr.find_peer(&u1), None);
        assert_eq!(mgr.find_peer(&u2), Some(d2));
    }

    #[test]
    fn refuse_overwrite_existing_session() {
        let mgr = SessionManager::new();
        let dev = Uuid::now_v7();
        let user = Uuid::now_v7();

        assert!(mgr
            .create_session(Uuid::now_v7(), org(), dev, user)
            .is_some());
        // Same user tries second session
        assert!(mgr
            .create_session(Uuid::now_v7(), org(), Uuid::now_v7(), user)
            .is_none());
        // Same device tries second session
        assert!(mgr
            .create_session(Uuid::now_v7(), org(), dev, Uuid::now_v7())
            .is_none());
    }

    #[test]
    fn session_membership_check() {
        let mgr = SessionManager::new();
        let sid = Uuid::now_v7();
        let dev = Uuid::now_v7();
        let user = Uuid::now_v7();
        let outsider = Uuid::now_v7();

        mgr.create_session(sid, org(), dev, user);

        assert!(mgr.is_session_member(&user, &sid));
        assert!(mgr.is_session_member(&dev, &sid));
        assert!(!mgr.is_session_member(&outsider, &sid));
    }
}
