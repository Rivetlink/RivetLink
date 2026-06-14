//! HTTP router definition with all public endpoints.

use std::time::Duration;

use axum::{
    middleware,
    routing::{get, post},
    Router,
};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::handlers;
use crate::middleware::{rate_limit, RateLimiter, RequestIdLayer};
use crate::state::AppState;
use crate::websocket::gateway;

/// Default rate limits for credential-handling endpoints.
///
/// 10 attempts per minute per IP gives legitimate users headroom for typos
/// while throttling credential-stuffing and registration spam.
const AUTH_RATE_LIMIT_MAX: u32 = 10;
const AUTH_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Create the main Axum router with health, auth, device, session, audit, and WebSocket routes.
pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::permissive()
        .allow_origin(Any)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
        ])
        .max_age(Duration::from_secs(3600));

    let auth_limiter = RateLimiter::new(AUTH_RATE_LIMIT_MAX, AUTH_RATE_LIMIT_WINDOW);

    let auth_routes = Router::new()
        .route("/auth/register", post(handlers::auth::register))
        .route("/auth/login", post(handlers::auth::login))
        .route("/auth/refresh", post(handlers::auth::refresh))
        .route_layer(middleware::from_fn_with_state(
            auth_limiter,
            rate_limit::layer,
        ));

    Router::new()
        .route("/health", get(handlers::health::health))
        .merge(auth_routes)
        .route("/devices", get(handlers::devices::list_devices))
        .route(
            "/devices/register",
            post(handlers::devices::register_device),
        )
        .route("/sessions", get(handlers::sessions::list_sessions))
        .route("/audit-logs", get(handlers::audit::list_audit_logs))
        .route("/ws", get(gateway::ws_upgrade))
        .layer(RequestIdLayer)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
