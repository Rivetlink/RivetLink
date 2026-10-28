//! Per-IP sliding-window rate limiter.
//!
//! Tracks the timestamps of recent requests for each client IP in a `DashMap`
//! and rejects new requests once the per-window quota is exceeded. Intended
//! to be applied as a `route_layer` on sensitive endpoints (auth, register)
//! to slow down credential stuffing and registration spam.
//!
//! IP resolution uses the left-most `X-Forwarded-For` entry when it parses as
//! an IP address and falls back to the TCP peer address. The deployment's
//! reverse proxy (Caddy) overwrites that header with the address it saw, so
//! the header is authoritative there; for direct exposure operators must
//! strip it at the edge. The `Forwarded` header is never read: Caddy passes a
//! client-supplied one through untouched.
//!
//! IPv6 clients are keyed by their /64 prefix, which one host usually owns
//! whole, so rotating addresses inside it does not reset the quota.

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// Most client keys tracked at once. At a few hundred bytes per key this
/// caps the limiter at tens of MiB, however many addresses send requests.
const MAX_TRACKED_KEYS: usize = 100_000;
/// Least time between two sweeps of idle keys, so a full map cannot turn
/// every request into a full scan.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Sliding-window rate limiter keyed by client IP.
#[derive(Clone, Debug)]
pub struct RateLimiter {
    buckets: Arc<DashMap<String, Vec<Instant>>>,
    last_sweep: Arc<Mutex<Instant>>,
    max_requests: u32,
    window: Duration,
    max_keys: usize,
}

impl RateLimiter {
    /// Build a new limiter allowing `max_requests` per `window`.
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
            last_sweep: Arc::new(Mutex::new(Instant::now())),
            max_requests,
            window,
            max_keys: MAX_TRACKED_KEYS,
        }
    }

    /// Record an attempt for `key` and report whether the request is allowed.
    ///
    /// Returns `Ok(())` if under the quota, or `Err(retry_after_secs)` when
    /// the caller should wait before retrying. When the map is full of keys
    /// that are still inside their window, new keys are refused (fail
    /// closed) instead of growing the map.
    pub fn check(&self, key: &str) -> Result<(), u64> {
        let now = Instant::now();
        if self.buckets.len() >= self.max_keys && !self.buckets.contains_key(key) {
            self.sweep(now);
            if self.buckets.len() >= self.max_keys {
                return Err(self.window.as_secs().max(1));
            }
        }
        let mut entry = self.buckets.entry(key.to_string()).or_default();

        // Drop timestamps that have aged out of the window.
        entry.retain(|t| now.duration_since(*t) < self.window);

        if entry.len() >= self.max_requests as usize {
            // Retry-after = time until the oldest entry leaves the window.
            let oldest = entry.first().copied().unwrap_or(now);
            let elapsed = now.duration_since(oldest);
            let remaining = self.window.saturating_sub(elapsed);
            return Err(remaining.as_secs().max(1));
        }

        entry.push(now);
        Ok(())
    }

    /// Number of distinct keys currently tracked (for tests / metrics).
    pub fn tracked_keys(&self) -> usize {
        self.buckets.len()
    }

    /// Drop keys with no request inside the window. Runs at most once per
    /// `SWEEP_INTERVAL`; must not be called while holding a map entry.
    fn sweep(&self, now: Instant) {
        {
            let mut last = self
                .last_sweep
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if now.duration_since(*last) < SWEEP_INTERVAL {
                return;
            }
            *last = now;
        }
        self.buckets.retain(|_, hits| {
            hits.last()
                .is_some_and(|t| now.duration_since(*t) < self.window)
        });
    }
}

/// Extract a stable client identifier from request headers / peer address.
///
/// `peer` is optional because tower's `oneshot` and other in-process test
/// transports do not populate `ConnectInfo`. In that case we fall back to a
/// shared `"local"` bucket, which keeps the middleware functional during
/// integration tests without breaking production behaviour.
fn client_key(headers: &axum::http::HeaderMap, peer: Option<SocketAddr>) -> String {
    // Only a well-formed address is used, so a client cannot pick the key's
    // size or shape.
    let forwarded = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|first| first.trim().parse::<IpAddr>().ok());
    forwarded
        .or_else(|| peer.map(|p| p.ip()))
        .map_or_else(|| "local".to_string(), ip_key)
}

/// Rate-limit key for an address: IPv4 as is, IPv6 by its /64 prefix.
fn ip_key(ip: IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        },
    }
}

/// Axum middleware wired up via `from_fn_with_state(limiter, layer)`.
pub async fn layer(
    State(limiter): State<RateLimiter>,
    peer: Option<ConnectInfo<SocketAddr>>,
    req: Request,
    next: Next,
) -> Response {
    let key = client_key(req.headers(), peer.map(|ConnectInfo(a)| a));
    match limiter.check(&key) {
        Ok(()) => next.run(req).await,
        Err(retry_after) => {
            let mut resp = (
                StatusCode::TOO_MANY_REQUESTS,
                axum::Json(serde_json::json!({"error": "rate limited"})),
            )
                .into_response();
            if let Ok(v) = HeaderValue::from_str(&retry_after.to_string()) {
                resp.headers_mut().insert(header::RETRY_AFTER, v);
            }
            resp
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_requests_under_limit() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));
        assert!(limiter.check("1.1.1.1").is_ok());
        assert!(limiter.check("1.1.1.1").is_ok());
        assert!(limiter.check("1.1.1.1").is_ok());
    }

    #[test]
    fn rejects_request_over_limit() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        assert!(limiter.check("2.2.2.2").is_ok());
        assert!(limiter.check("2.2.2.2").is_ok());

        let err = limiter.check("2.2.2.2").expect_err("should reject");
        assert!(err >= 1, "retry-after must be at least 1 second");
    }

    #[test]
    fn separate_keys_have_separate_quotas() {
        let limiter = RateLimiter::new(1, Duration::from_secs(60));
        assert!(limiter.check("a").is_ok());
        assert!(limiter.check("a").is_err());
        assert!(limiter.check("b").is_ok(), "different IP shares no quota");
    }

    #[test]
    fn old_entries_are_purged() {
        let limiter = RateLimiter::new(1, Duration::from_millis(50));
        assert!(limiter.check("ttl").is_ok());
        assert!(limiter.check("ttl").is_err());

        std::thread::sleep(Duration::from_millis(80));
        assert!(
            limiter.check("ttl").is_ok(),
            "after window passes, quota refills"
        );
    }

    #[test]
    fn tracked_keys_grows_per_unique_ip() {
        let limiter = RateLimiter::new(5, Duration::from_secs(60));
        limiter.check("a").unwrap();
        limiter.check("b").unwrap();
        limiter.check("c").unwrap();
        assert_eq!(limiter.tracked_keys(), 3);
    }

    #[test]
    fn client_key_prefers_forwarded_header() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.7, 10.0.0.1"),
        );
        let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        assert_eq!(client_key(&headers, Some(peer)), "203.0.113.7");
    }

    #[test]
    fn client_key_falls_back_to_peer() {
        let headers = axum::http::HeaderMap::new();
        let peer: SocketAddr = "198.51.100.4:5555".parse().unwrap();
        assert_eq!(client_key(&headers, Some(peer)), "198.51.100.4");
    }

    #[test]
    fn client_key_ignores_empty_forwarded() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static(""));
        let peer: SocketAddr = "192.0.2.9:80".parse().unwrap();
        assert_eq!(client_key(&headers, Some(peer)), "192.0.2.9");
    }

    #[test]
    fn client_key_falls_back_to_local_when_no_peer() {
        let headers = axum::http::HeaderMap::new();
        assert_eq!(client_key(&headers, None), "local");
    }

    #[test]
    fn client_key_ignores_the_forwarded_header() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            header::FORWARDED,
            HeaderValue::from_static("for=203.0.113.9"),
        );
        headers.insert("x-forwarded-for", HeaderValue::from_static("198.51.100.1"));
        assert_eq!(client_key(&headers, None), "198.51.100.1");

        headers.remove("x-forwarded-for");
        let peer: SocketAddr = "192.0.2.9:80".parse().unwrap();
        assert_eq!(client_key(&headers, Some(peer)), "192.0.2.9");
    }

    #[test]
    fn client_key_ignores_a_forwarded_for_that_is_not_an_address() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("random-junk-1234"),
        );
        let peer: SocketAddr = "192.0.2.9:80".parse().unwrap();
        assert_eq!(client_key(&headers, Some(peer)), "192.0.2.9");
    }

    #[test]
    fn ipv6_clients_share_a_key_per_slash_64() {
        let a = client_key(
            &axum::http::HeaderMap::new(),
            Some("[2001:db8:1:2::1]:1".parse().unwrap()),
        );
        let b = client_key(
            &axum::http::HeaderMap::new(),
            Some("[2001:db8:1:2:ffff::9]:1".parse().unwrap()),
        );
        let other = client_key(
            &axum::http::HeaderMap::new(),
            Some("[2001:db8:1:3::1]:1".parse().unwrap()),
        );
        assert_eq!(a, "2001:db8:1:2::/64");
        assert_eq!(a, b);
        assert_ne!(a, other);
        let mapped = client_key(
            &axum::http::HeaderMap::new(),
            Some("[::ffff:192.0.2.1]:1".parse().unwrap()),
        );
        assert_eq!(mapped, "192.0.2.1");
    }

    #[test]
    fn a_full_map_drops_idle_keys_and_refuses_new_ones_while_all_are_fresh() {
        let mut limiter = RateLimiter::new(5, Duration::from_millis(50));
        limiter.max_keys = 2;
        limiter.check("a").unwrap();
        limiter.check("b").unwrap();
        assert!(
            limiter.check("c").is_err(),
            "full of fresh keys: fail closed"
        );
        assert!(limiter.check("a").is_ok(), "known keys keep working");

        std::thread::sleep(Duration::from_millis(80));
        *limiter.last_sweep.lock().unwrap() -= SWEEP_INTERVAL;
        assert!(limiter.check("c").is_ok(), "idle keys were swept");
        assert_eq!(limiter.tracked_keys(), 1);
    }
}
