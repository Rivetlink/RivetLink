//! Per-IP sliding-window rate limiter.
//!
//! Tracks the timestamps of recent requests for each client IP in a `DashMap`
//! and rejects new requests once the per-window quota is exceeded. Intended
//! to be applied as a `route_layer` on sensitive endpoints (auth, register)
//! to slow down credential stuffing and registration spam.
//!
//! IP resolution prefers the `X-Forwarded-For` header (left-most entry) and
//! falls back to the TCP peer address. Behind a trusted reverse proxy the
//! header is authoritative; for direct exposure operators should strip the
//! header at the edge.

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Sliding-window rate limiter keyed by client IP.
#[derive(Clone, Debug)]
pub struct RateLimiter {
    buckets: Arc<DashMap<String, Vec<Instant>>>,
    max_requests: u32,
    window: Duration,
}

impl RateLimiter {
    /// Build a new limiter allowing `max_requests` per `window`.
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
            max_requests,
            window,
        }
    }

    /// Record an attempt for `key` and report whether the request is allowed.
    ///
    /// Returns `Ok(())` if under the quota, or `Err(retry_after_secs)` when
    /// the caller should wait before retrying.
    pub fn check(&self, key: &str) -> Result<(), u64> {
        let now = Instant::now();
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
}

/// Extract a stable client identifier from request headers / peer address.
///
/// `peer` is optional because tower's `oneshot` and other in-process test
/// transports do not populate `ConnectInfo`. In that case we fall back to a
/// shared `"local"` bucket, which keeps the middleware functional during
/// integration tests without breaking production behaviour.
fn client_key(headers: &axum::http::HeaderMap, peer: Option<SocketAddr>) -> String {
    // Prefer X-Forwarded-For when present (operators must strip it at the edge
    // for untrusted clients).
    if let Some(xff) = headers
        .get(header::FORWARDED)
        .or_else(|| headers.get("x-forwarded-for"))
    {
        if let Ok(s) = xff.to_str() {
            if let Some(first) = s.split(',').next() {
                let trimmed = first.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
    }
    peer.map_or_else(|| "local".to_string(), |p| p.ip().to_string())
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
}
