//! Integration tests for HTTP endpoints, auth flow, device/session/audit operations.

#![allow(clippy::unwrap_used)] // integration test helpers — unwrap is appropriate
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]

use axum::http::StatusCode;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use tokio::sync::mpsc;

use rivetlink_server::config::ServerConfig;
use rivetlink_server::router::create_router;
use rivetlink_server::sessions::manager::SessionManager;
use rivetlink_server::state::AppState;
use rivetlink_server::websocket::connection::ConnectionMap;

fn test_config() -> ServerConfig {
    ServerConfig {
        database_url: "postgres://rivet:rivet_dev@localhost/rivet".to_string(),
        redis_url: "redis://127.0.0.1:6379".to_string(),
        jwt_secret: "integration-test-secret-key-32chars!".to_string(),
        bind_addr: "127.0.0.1:0".to_string(),
        access_token_expiry_secs: 900,
        refresh_token_expiry_secs: 604800,
        max_failed_logins: 5,
        lockout_duration_secs: 900,
        heartbeat_interval_secs: 10,
        disconnect_timeout_secs: 30,
        reconnect_grace_secs: 15,
    }
}

async fn setup() -> Option<AppState> {
    let config = test_config();
    let db = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await
        .ok()?;

    sqlx::migrate!("../../migrations")
        .run(&db)
        .await
        .expect("migrations must apply cleanly");

    let connections = ConnectionMap::new();
    let sessions = SessionManager::new();
    let (signaling_tx, _signaling_rx) = mpsc::unbounded_channel();

    Some(AppState {
        db,
        config,
        connections,
        sessions,
        signaling_tx,
    })
}

async fn cleanup_test_data(state: &AppState, email: &str) {
    // Clean up in reverse FK order
    let _ = sqlx::query(
        "DELETE FROM audit_logs WHERE actor_user_id IN (SELECT id FROM users WHERE email = $1)",
    )
    .bind(email)
    .execute(&state.db)
    .await;

    let user = sqlx::query_scalar::<_, uuid::Uuid>("SELECT id FROM users WHERE email = $1")
        .bind(email)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

    if let Some(user_id) = user {
        let _ = sqlx::query("DELETE FROM session_participants WHERE user_id = $1")
            .bind(user_id)
            .execute(&state.db)
            .await;
    }

    let org_id =
        sqlx::query_scalar::<_, uuid::Uuid>("SELECT organization_id FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();

    let _ = sqlx::query("DELETE FROM users WHERE email = $1")
        .bind(email)
        .execute(&state.db)
        .await;

    if let Some(oid) = org_id {
        let _ = sqlx::query("DELETE FROM devices WHERE organization_id = $1")
            .bind(oid)
            .execute(&state.db)
            .await;
        let _ = sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(oid)
            .execute(&state.db)
            .await;
    }
}

fn unique_email(prefix: &str) -> String {
    format!("{prefix}-{}@test.rivetlink.dev", uuid::Uuid::now_v7())
}

// ─── Health ──────────────────────────────────────────────

#[tokio::test]
async fn health_endpoint() {
    let Some(state) = setup().await else {
        eprintln!("skipping: database not available");
        return;
    };

    let app = create_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .uri("/health")
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

// ─── Auth: Register ──────────────────────────────────────

#[tokio::test]
async fn register_creates_user_and_returns_tokens() {
    let Some(state) = setup().await else {
        eprintln!("skipping: database not available");
        return;
    };

    let email = unique_email("register");
    let app = create_router(state.clone());

    let response = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .method("POST")
            .uri("/auth/register")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                json!({
                    "email": email,
                    "password": "test-password-123",
                    "display_name": "Test User",
                    "organization_name": "Test Org"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json["access_token"].is_string());
    assert!(json["refresh_token"].is_string());
    assert!(json["user_id"].is_string());
    assert!(json["organization_id"].is_string());

    cleanup_test_data(&state, &email).await;
}

#[tokio::test]
async fn register_rejects_invalid_email() {
    let Some(state) = setup().await else {
        eprintln!("skipping: database not available");
        return;
    };

    let app = create_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .method("POST")
            .uri("/auth/register")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                json!({
                    "email": "not-an-email",
                    "password": "test-password-123",
                    "display_name": "Test",
                    "organization_name": "Org"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn register_rejects_short_password() {
    let Some(state) = setup().await else {
        eprintln!("skipping: database not available");
        return;
    };

    let app = create_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .method("POST")
            .uri("/auth/register")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                json!({
                    "email": "test@test.com",
                    "password": "short",
                    "display_name": "Test",
                    "organization_name": "Org"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn register_rejects_duplicate_email() {
    let Some(state) = setup().await else {
        eprintln!("skipping: database not available");
        return;
    };

    let email = unique_email("dup");
    let body = json!({
        "email": email,
        "password": "test-password-123",
        "display_name": "Test",
        "organization_name": "Org"
    })
    .to_string();

    // First register
    let app = create_router(state.clone());
    let r1 = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .method("POST")
            .uri("/auth/register")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.clone()))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(r1.status(), StatusCode::OK);

    // Second register with same email
    let app = create_router(state.clone());
    let r2 = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .method("POST")
            .uri("/auth/register")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body))
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(r2.status(), StatusCode::CONFLICT);

    cleanup_test_data(&state, &email).await;
}

// ─── Auth: Login ─────────────────────────────────────────

#[tokio::test]
async fn login_with_valid_credentials() {
    let Some(state) = setup().await else {
        eprintln!("skipping: database not available");
        return;
    };

    let email = unique_email("login");

    // Register first
    let app = create_router(state.clone());
    let _ = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .method("POST")
            .uri("/auth/register")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                json!({
                    "email": email,
                    "password": "correct-password",
                    "display_name": "Login Test",
                    "organization_name": "Login Org"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    // Login
    let app = create_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .method("POST")
            .uri("/auth/login")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                json!({
                    "email": email,
                    "password": "correct-password"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["access_token"].is_string());

    cleanup_test_data(&state, &email).await;
}

#[tokio::test]
async fn login_with_wrong_password() {
    let Some(state) = setup().await else {
        eprintln!("skipping: database not available");
        return;
    };

    let email = unique_email("wrongpw");

    // Register
    let app = create_router(state.clone());
    let _ = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .method("POST")
            .uri("/auth/register")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                json!({
                    "email": email,
                    "password": "correct-password",
                    "display_name": "Test",
                    "organization_name": "Org"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    // Login with wrong password
    let app = create_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .method("POST")
            .uri("/auth/login")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                json!({
                    "email": email,
                    "password": "wrong-password"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    cleanup_test_data(&state, &email).await;
}

// ─── Protected endpoints ─────────────────────────────────

#[tokio::test]
async fn devices_requires_auth() {
    let Some(state) = setup().await else {
        eprintln!("skipping: database not available");
        return;
    };

    let app = create_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .uri("/devices")
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn devices_accessible_with_token() {
    let Some(state) = setup().await else {
        eprintln!("skipping: database not available");
        return;
    };

    let email = unique_email("devices");

    // Register to get token
    let app = create_router(state.clone());
    let reg_response = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .method("POST")
            .uri("/auth/register")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                json!({
                    "email": email,
                    "password": "test-password-123",
                    "display_name": "Device Test",
                    "organization_name": "Device Org"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    let body = axum::body::to_bytes(reg_response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let auth: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let token = auth["access_token"].as_str().unwrap();

    // List devices with token
    let app = create_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .uri("/devices")
            .header("authorization", format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let devices: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(devices.is_array());
    assert_eq!(devices.as_array().unwrap().len(), 0);

    cleanup_test_data(&state, &email).await;
}

// ─── Device Registration ─────────────────────────────────

#[tokio::test]
async fn register_and_list_device() {
    let Some(state) = setup().await else {
        eprintln!("skipping: database not available");
        return;
    };

    let email = unique_email("devreg");

    // Register user
    let app = create_router(state.clone());
    let reg = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .method("POST")
            .uri("/auth/register")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                json!({
                    "email": email,
                    "password": "test-password-123",
                    "display_name": "Dev Reg Test",
                    "organization_name": "Dev Reg Org"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    let body = axum::body::to_bytes(reg.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let auth: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let token = auth["access_token"].as_str().unwrap();

    // Register device
    let app = create_router(state.clone());
    let dev_response = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .method("POST")
            .uri("/devices/register")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(axum::body::Body::from(
                json!({
                    "public_key": "ed25519:test-public-key-base64",
                    "hostname": "test-machine",
                    "platform": "linux"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(dev_response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(dev_response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let device: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(device["hostname"].as_str().unwrap(), "test-machine");
    assert_eq!(device["platform"].as_str().unwrap(), "linux");

    // List devices — should have 1
    let app = create_router(state.clone());
    let list = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .uri("/devices")
            .header("authorization", format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    let body = axum::body::to_bytes(list.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let devices: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0]["hostname"].as_str().unwrap(), "test-machine");

    cleanup_test_data(&state, &email).await;
}

// ─── Token Refresh ───────────────────────────────────────

#[tokio::test]
async fn refresh_token_returns_new_pair() {
    let Some(state) = setup().await else {
        eprintln!("skipping: database not available");
        return;
    };

    let email = unique_email("refresh");

    // Register
    let app = create_router(state.clone());
    let reg = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .method("POST")
            .uri("/auth/register")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                json!({
                    "email": email,
                    "password": "test-password-123",
                    "display_name": "Refresh Test",
                    "organization_name": "Refresh Org"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    let body = axum::body::to_bytes(reg.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let auth: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let refresh_token = auth["refresh_token"].as_str().unwrap();

    // Refresh
    let app = create_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .method("POST")
            .uri("/auth/refresh")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                json!({ "refresh_token": refresh_token }).to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let new_auth: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(new_auth["access_token"].is_string());
    assert!(new_auth["refresh_token"].is_string());

    // Verify new access token works on a protected endpoint
    let new_token = new_auth["access_token"].as_str().unwrap();
    let app = create_router(state.clone());
    let protected = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .uri("/devices")
            .header("authorization", format!("Bearer {new_token}"))
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(protected.status(), StatusCode::OK);

    cleanup_test_data(&state, &email).await;
}

// ─── Audit Logs ──────────────────────────────────────────

#[tokio::test]
async fn audit_logs_created_on_register_and_login() {
    let Some(state) = setup().await else {
        eprintln!("skipping: database not available");
        return;
    };

    let email = unique_email("audit");

    // Register and capture the owner token — only owners can read the audit log.
    let app = create_router(state.clone());
    let register_response = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .method("POST")
            .uri("/auth/register")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                json!({
                    "email": email,
                    "password": "test-password-123",
                    "display_name": "Audit Test",
                    "organization_name": "Audit Org"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();
    let register_body = axum::body::to_bytes(register_response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let register_json: serde_json::Value = serde_json::from_slice(&register_body).unwrap();
    let owner_token = register_json["access_token"].as_str().unwrap().to_string();

    // Login to ensure the auth.login audit row exists (token is discarded —
    // login currently issues the "operator" role which lacks audit:read).
    let app = create_router(state.clone());
    let _ = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .method("POST")
            .uri("/auth/login")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                json!({
                    "email": email,
                    "password": "test-password-123"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();
    let token = owner_token.as_str();

    // Check audit logs
    let app = create_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .uri("/audit-logs")
            .header("authorization", format!("Bearer {token}"))
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let logs: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();

    let actions: Vec<&str> = logs.iter().filter_map(|l| l["action"].as_str()).collect();
    assert!(actions.contains(&"user.registered"));
    assert!(actions.contains(&"auth.login"));

    cleanup_test_data(&state, &email).await;
}

// ─── Account Lockout ─────────────────────────────────────

#[tokio::test]
async fn account_lockout_after_max_failed_attempts() {
    let Some(state) = setup().await else {
        eprintln!("skipping: database not available");
        return;
    };

    let email = unique_email("lockout");

    // Register user
    let app = create_router(state.clone());
    let _ = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .method("POST")
            .uri("/auth/register")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                json!({
                    "email": email,
                    "password": "correct-password",
                    "display_name": "Lockout Test",
                    "organization_name": "Lockout Org"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    // Send 5 wrong password attempts
    for i in 0..5 {
        let app = create_router(state.clone());
        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method("POST")
                .uri("/auth/login")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    json!({
                        "email": email,
                        "password": format!("wrong-password-{}", i)
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

        // Each wrong attempt should return 401
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    // 6th attempt with correct password should be 429 (rate limited)
    let app = create_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .method("POST")
            .uri("/auth/login")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                json!({
                    "email": email,
                    "password": "correct-password"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    cleanup_test_data(&state, &email).await;
}

// ─── Login Errors ───────────────────────────────────────

#[tokio::test]
async fn login_with_nonexistent_email() {
    let Some(state) = setup().await else {
        eprintln!("skipping: database not available");
        return;
    };

    let app = create_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .method("POST")
            .uri("/auth/login")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                json!({
                    "email": "nonexistent@test.rivetlink.dev",
                    "password": "some-password"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ─── Token Usage ────────────────────────────────────────

#[tokio::test]
async fn access_token_cannot_be_used_as_refresh() {
    let Some(state) = setup().await else {
        eprintln!("skipping: database not available");
        return;
    };

    let email = unique_email("token-reuse");

    // Register to get tokens
    let app = create_router(state.clone());
    let reg = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .method("POST")
            .uri("/auth/register")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                json!({
                    "email": email,
                    "password": "test-password-123",
                    "display_name": "Token Reuse Test",
                    "organization_name": "Token Reuse Org"
                })
                .to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    let body = axum::body::to_bytes(reg.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let auth: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let access_token = auth["access_token"].as_str().unwrap();

    // Try to use access_token as refresh_token
    let app = create_router(state.clone());
    let response = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .method("POST")
            .uri("/auth/refresh")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                json!({ "refresh_token": access_token }).to_string(),
            ))
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    cleanup_test_data(&state, &email).await;
}

// ─── Sessions Endpoint Auth ──────────────────────────────

#[tokio::test]
async fn sessions_endpoint_requires_auth() {
    let Some(state) = setup().await else {
        eprintln!("skipping: database not available");
        return;
    };

    let app = create_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .uri("/sessions")
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ─── Audit Logs Endpoint Auth ───────────────────────────

#[tokio::test]
async fn audit_logs_endpoint_requires_auth() {
    let Some(state) = setup().await else {
        eprintln!("skipping: database not available");
        return;
    };

    let app = create_router(state);

    let response = tower::ServiceExt::oneshot(
        app,
        axum::http::Request::builder()
            .uri("/audit-logs")
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// WebSocket gateway integration tests
// ---------------------------------------------------------------------------

mod ws {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use serde_json::Value;
    use std::net::SocketAddr;
    use tokio_tungstenite::tungstenite::Message;

    /// Bind on a random local port and spawn the relay server. Returns the
    /// resolved address and a shutdown handle.
    async fn spawn_test_server(state: AppState) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = create_router(state);

        let handle = tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        });

        // Give the server a moment to start accepting connections.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        (addr, handle)
    }

    /// Register a user via REST and return the access token + email used.
    async fn register_user(addr: SocketAddr) -> (String, String) {
        let email = format!("ws-test-{}@test.com", uuid::Uuid::now_v7().simple());
        let client = reqwest_like_post(
            addr,
            "/auth/register",
            json!({
                "email": email,
                "password": "password123",
                "display_name": "WS Test",
                "organization_name": "WS Org",
            }),
        )
        .await;

        let token = client
            .get("access_token")
            .and_then(Value::as_str)
            .expect("register must return access_token")
            .to_string();
        (email, token)
    }

    /// Minimal HTTP POST helper using a fresh tokio TcpStream + manual HTTP/1.1 request
    /// to avoid pulling in a full HTTP client crate. Body is JSON.
    async fn reqwest_like_post(addr: SocketAddr, path: &str, body: Value) -> Value {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let req = format!(
            "POST {path} HTTP/1.1\r\n\
             Host: {addr}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {len}\r\n\
             Connection: close\r\n\
             \r\n",
            len = body_bytes.len(),
        );

        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.write_all(&body_bytes).await.unwrap();

        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();

        let text = String::from_utf8_lossy(&buf);
        let body_start = text.find("\r\n\r\n").unwrap() + 4;
        serde_json::from_str(&text[body_start..]).unwrap()
    }

    #[tokio::test]
    async fn ws_authenticates_and_receives_authenticated_message() {
        let Some(state) = setup().await else {
            eprintln!("skipping: postgres unavailable");
            return;
        };

        let (addr, handle) = spawn_test_server(state.clone()).await;
        let (email, token) = register_user(addr).await;

        let url = format!("ws://{addr}/ws");
        let (mut ws, _resp) = tokio_tungstenite::connect_async(&url).await.unwrap();

        let auth = json!({"type": "AUTH", "token": token}).to_string();
        ws.send(Message::Text(auth)).await.unwrap();

        let msg = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next())
            .await
            .expect("auth response timeout")
            .expect("ws stream closed")
            .expect("ws error");

        let text = match msg {
            Message::Text(t) => t,
            other => panic!("expected text message, got {other:?}"),
        };
        let parsed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            parsed.get("type").and_then(Value::as_str),
            Some("AUTHENTICATED")
        );
        assert!(parsed.get("user_id").and_then(Value::as_str).is_some());

        ws.close(None).await.ok();
        handle.abort();
        cleanup_test_data(&state, &email).await;
    }

    #[tokio::test]
    async fn ws_rejects_invalid_token() {
        let Some(state) = setup().await else {
            eprintln!("skipping: postgres unavailable");
            return;
        };
        let (addr, handle) = spawn_test_server(state).await;

        let url = format!("ws://{addr}/ws");
        let (mut ws, _resp) = tokio_tungstenite::connect_async(&url).await.unwrap();

        let auth = json!({"type": "AUTH", "token": "not.a.real.jwt"}).to_string();
        ws.send(Message::Text(auth)).await.unwrap();

        let msg = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next())
            .await
            .expect("response timeout")
            .expect("ws stream closed")
            .expect("ws error");

        if let Message::Text(t) = msg {
            let parsed: Value = serde_json::from_str(&t).unwrap();
            assert!(
                parsed.get("error").is_some(),
                "expected error response, got {parsed:?}"
            );
        }

        handle.abort();
    }

    #[tokio::test]
    async fn ws_auth_timeout_when_no_message_sent() {
        let Some(state) = setup().await else {
            eprintln!("skipping: postgres unavailable");
            return;
        };
        let (addr, handle) = spawn_test_server(state).await;

        let url = format!("ws://{addr}/ws");
        let (mut ws, _resp) = tokio_tungstenite::connect_async(&url).await.unwrap();

        // Don't send anything — server should send an error and close after 5s.
        let result = tokio::time::timeout(std::time::Duration::from_secs(7), ws.next()).await;
        // Either we received a timeout error message or the connection closed.
        match result {
            Ok(Some(Ok(Message::Text(t)))) => {
                let parsed: Value = serde_json::from_str(&t).unwrap();
                assert!(parsed.get("error").is_some());
            },
            Ok(Some(Ok(Message::Close(_)) | Err(_)) | None) => {
                // also acceptable — server hung up
            },
            Ok(_) => {},
            Err(_) => panic!("server did not enforce auth timeout"),
        }

        handle.abort();
    }
}

// ---------------------------------------------------------------------------
// RBAC enforcement tests
// ---------------------------------------------------------------------------

mod rbac {
    use super::*;
    use serde_json::Value;

    async fn register_owner(state: &AppState, email: &str) -> String {
        let app = create_router(state.clone());
        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method("POST")
                .uri("/auth/register")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    json!({
                        "email": email,
                        "password": "rbac-password-99",
                        "display_name": "RBAC Owner",
                        "organization_name": "RBAC Org",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        json["access_token"].as_str().unwrap().to_string()
    }

    async fn login_operator(state: &AppState, email: &str) -> String {
        let app = create_router(state.clone());
        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method("POST")
                .uri("/auth/login")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    json!({"email": email, "password": "rbac-password-99"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        json["access_token"].as_str().unwrap().to_string()
    }

    async fn call(state: &AppState, method: &str, uri: &str, token: &str) -> StatusCode {
        let app = create_router(state.clone());
        let response = tower::ServiceExt::oneshot(
            app,
            axum::http::Request::builder()
                .method(method)
                .uri(uri)
                .header("authorization", format!("Bearer {token}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        response.status()
    }

    #[tokio::test]
    async fn owner_can_read_audit_log() {
        let Some(state) = setup().await else {
            eprintln!("skipping: postgres unavailable");
            return;
        };
        let email = unique_email("rbac-owner");
        let token = register_owner(&state, &email).await;

        assert_eq!(
            call(&state, "GET", "/audit-logs", &token).await,
            StatusCode::OK
        );
        assert_eq!(
            call(&state, "GET", "/devices", &token).await,
            StatusCode::OK
        );
        assert_eq!(
            call(&state, "GET", "/sessions", &token).await,
            StatusCode::OK
        );

        cleanup_test_data(&state, &email).await;
    }

    #[tokio::test]
    async fn operator_blocked_from_audit_log() {
        let Some(state) = setup().await else {
            eprintln!("skipping: postgres unavailable");
            return;
        };
        let email = unique_email("rbac-op");
        let _ = register_owner(&state, &email).await;
        let op_token = login_operator(&state, &email).await;

        // Operators can list but not read audit
        assert_eq!(
            call(&state, "GET", "/devices", &op_token).await,
            StatusCode::OK
        );
        assert_eq!(
            call(&state, "GET", "/sessions", &op_token).await,
            StatusCode::OK
        );
        assert_eq!(
            call(&state, "GET", "/audit-logs", &op_token).await,
            StatusCode::FORBIDDEN,
            "operator must not read audit log",
        );

        cleanup_test_data(&state, &email).await;
    }
}

// ---------------------------------------------------------------------------
// Device authentication (challenge-response)
// ---------------------------------------------------------------------------

mod device_auth {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};
    use futures_util::{SinkExt, StreamExt};
    use rand_08::rngs::OsRng;
    use rand_08::RngCore;
    use serde_json::Value;
    use std::net::SocketAddr;
    use tokio_tungstenite::tungstenite::Message;

    async fn spawn_test_server(state: AppState) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = create_router(state);
        let handle = tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        (addr, handle)
    }

    async fn http_post(addr: SocketAddr, path: &str, token: Option<&str>, body: Value) -> Value {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let auth = token
            .map(|t| format!("Authorization: Bearer {t}\r\n"))
            .unwrap_or_default();
        let req = format!(
            "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n{auth}Content-Length: {len}\r\nConnection: close\r\n\r\n",
            len = body_bytes.len(),
        );
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream.write_all(req.as_bytes()).await.unwrap();
        stream.write_all(&body_bytes).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);
        let body_start = text.find("\r\n\r\n").unwrap() + 4;
        serde_json::from_str(&text[body_start..]).unwrap()
    }

    fn fresh_signing_key() -> SigningKey {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        SigningKey::from_bytes(&seed)
    }

    #[tokio::test]
    async fn device_can_authenticate_with_challenge_response() {
        let Some(state) = setup().await else {
            eprintln!("skipping: postgres unavailable");
            return;
        };
        let (addr, handle) = spawn_test_server(state.clone()).await;

        // Register a user → owner JWT
        let email = unique_email("device-auth");
        let reg = http_post(
            addr,
            "/auth/register",
            None,
            json!({
                "email": email,
                "password": "secret-password",
                "display_name": "Device Auth Test",
                "organization_name": "Device Auth Org",
            }),
        )
        .await;
        let token = reg["access_token"].as_str().unwrap().to_string();

        // Generate a fresh device keypair and register it
        let device_signing = fresh_signing_key();
        let device_public = device_signing.verifying_key();
        let pk_b64 = base64::engine::general_purpose::STANDARD.encode(device_public.as_bytes());

        let dev_resp = http_post(
            addr,
            "/devices/register",
            Some(&token),
            json!({"public_key": pk_b64, "hostname": "test-host", "platform": "linux"}),
        )
        .await;
        let device_id = dev_resp["id"].as_str().unwrap().to_string();

        // Connect via WS and run the DEVICE_HELLO handshake by hand
        let url = format!("ws://{addr}/ws");
        let (mut ws, _resp) = tokio_tungstenite::connect_async(&url).await.unwrap();

        ws.send(Message::Text(
            json!({"type": "DEVICE_HELLO", "device_id": device_id}).to_string(),
        ))
        .await
        .unwrap();

        // Receive DEVICE_CHALLENGE
        let challenge_frame = ws.next().await.unwrap().unwrap();
        let challenge_text = match challenge_frame {
            Message::Text(t) => t,
            other => panic!("expected text, got {other:?}"),
        };
        let challenge: Value = serde_json::from_str(&challenge_text).unwrap();
        assert_eq!(
            challenge.get("type").and_then(Value::as_str),
            Some("DEVICE_CHALLENGE"),
            "expected DEVICE_CHALLENGE, got {challenge_text}",
        );
        let nonce_b64 = challenge["nonce"].as_str().unwrap();
        let nonce = base64::engine::general_purpose::STANDARD
            .decode(nonce_b64)
            .unwrap();

        // Sign it
        let sig = device_signing.sign(&nonce);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        ws.send(Message::Text(
            json!({"type": "DEVICE_AUTH", "signature": sig_b64}).to_string(),
        ))
        .await
        .unwrap();

        // Expect AUTHENTICATED
        let ack_frame = ws.next().await.unwrap().unwrap();
        let ack_text = match ack_frame {
            Message::Text(t) => t,
            other => panic!("expected text, got {other:?}"),
        };
        let ack: Value = serde_json::from_str(&ack_text).unwrap();
        assert_eq!(ack["type"].as_str(), Some("AUTHENTICATED"));
        assert_eq!(ack["device_id"].as_str(), Some(device_id.as_str()));

        ws.close(None).await.ok();
        handle.abort();
        cleanup_test_data(&state, &email).await;
    }

    #[tokio::test]
    async fn device_auth_rejects_wrong_signature() {
        let Some(state) = setup().await else {
            eprintln!("skipping: postgres unavailable");
            return;
        };
        let (addr, handle) = spawn_test_server(state.clone()).await;

        let email = unique_email("device-bad-sig");
        let reg = http_post(
            addr,
            "/auth/register",
            None,
            json!({
                "email": email,
                "password": "secret-password",
                "display_name": "Bad Sig Test",
                "organization_name": "Bad Sig Org",
            }),
        )
        .await;
        let token = reg["access_token"].as_str().unwrap().to_string();

        // Register device with key A, but sign with key B
        let real_key = fresh_signing_key();
        let attacker_key = fresh_signing_key();
        let pk_b64 =
            base64::engine::general_purpose::STANDARD.encode(real_key.verifying_key().as_bytes());

        let dev_resp = http_post(
            addr,
            "/devices/register",
            Some(&token),
            json!({"public_key": pk_b64}),
        )
        .await;
        let device_id = dev_resp["id"].as_str().unwrap().to_string();

        let url = format!("ws://{addr}/ws");
        let (mut ws, _resp) = tokio_tungstenite::connect_async(&url).await.unwrap();

        ws.send(Message::Text(
            json!({"type": "DEVICE_HELLO", "device_id": device_id}).to_string(),
        ))
        .await
        .unwrap();

        let challenge_frame = ws.next().await.unwrap().unwrap();
        let Message::Text(challenge_text) = challenge_frame else {
            panic!("expected text frame for DEVICE_CHALLENGE");
        };
        let challenge: Value = serde_json::from_str(&challenge_text).unwrap();
        let nonce_b64 = challenge["nonce"].as_str().unwrap();
        let nonce = base64::engine::general_purpose::STANDARD
            .decode(nonce_b64)
            .unwrap();

        // Sign with the wrong key
        let sig = attacker_key.sign(&nonce);
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        ws.send(Message::Text(
            json!({"type": "DEVICE_AUTH", "signature": sig_b64}).to_string(),
        ))
        .await
        .unwrap();

        // Server should respond with error, not AUTHENTICATED
        let resp_frame = ws.next().await.unwrap().unwrap();
        let resp_text = match resp_frame {
            Message::Text(t) => t,
            other => panic!("expected text, got {other:?}"),
        };
        let resp: Value = serde_json::from_str(&resp_text).unwrap();
        assert!(
            resp.get("error").is_some(),
            "expected error, got {resp_text}",
        );

        handle.abort();
        cleanup_test_data(&state, &email).await;
    }

    #[tokio::test]
    async fn device_auth_rejects_unknown_device() {
        let Some(state) = setup().await else {
            eprintln!("skipping: postgres unavailable");
            return;
        };
        let (addr, handle) = spawn_test_server(state).await;

        let url = format!("ws://{addr}/ws");
        let (mut ws, _resp) = tokio_tungstenite::connect_async(&url).await.unwrap();

        // Random device_id that was never registered
        let bogus = uuid::Uuid::now_v7();
        ws.send(Message::Text(
            json!({"type": "DEVICE_HELLO", "device_id": bogus}).to_string(),
        ))
        .await
        .unwrap();

        let frame = ws.next().await.unwrap().unwrap();
        if let Message::Text(t) = frame {
            let v: Value = serde_json::from_str(&t).unwrap();
            assert!(
                v.get("error").is_some(),
                "expected error for unknown device"
            );
        }

        handle.abort();
    }
}
