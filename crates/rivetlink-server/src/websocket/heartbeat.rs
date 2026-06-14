//! Configurable heartbeat timeout tracking for WebSocket connections.

use std::time::{Duration, Instant};

/// Tracks activity with configurable inactivity timeout; disconnects on expiry.
#[derive(Debug)]
pub struct HeartbeatTracker {
    last_activity: Instant,
    timeout: Duration,
}

impl HeartbeatTracker {
    /// Create heartbeat tracker with inactivity timeout.
    pub fn new(timeout_secs: u64) -> Self {
        Self {
            last_activity: Instant::now(),
            timeout: Duration::from_secs(timeout_secs),
        }
    }

    /// Reset activity timer to now.
    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Check if inactivity timeout has been exceeded.
    pub fn is_expired(&self) -> bool {
        self.last_activity.elapsed() > self.timeout
    }

    /// Get time elapsed since last activity.
    pub fn elapsed(&self) -> Duration {
        self.last_activity.elapsed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_heartbeat_not_expired() {
        let hb = HeartbeatTracker::new(30);
        assert!(!hb.is_expired());
    }

    #[test]
    fn heartbeat_with_zero_timeout_expires_immediately() {
        let hb = HeartbeatTracker::new(0);
        std::thread::sleep(Duration::from_millis(10));
        assert!(hb.is_expired());
    }

    #[test]
    fn touch_resets_timer() {
        let mut hb = HeartbeatTracker::new(30);
        std::thread::sleep(Duration::from_millis(50));
        let before = hb.elapsed();
        hb.touch();
        let after = hb.elapsed();
        assert!(after < before);
    }
}
