//! End to end through the real relay: SDK tunnel → relay → agent tunnel host,
//! with the hybrid direct-LAN handshake and a sealed request inside.
//!
//! Needs Postgres (CI's integration job); skips when it is not reachable.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::time::Duration;

use base64::Engine;
use ed25519_dalek::SigningKey;
use rivetlink_agent::relay::client::HostHandler;
use rivetlink_agent::relay::RelayClient;
use rivetlink_protocol::{SessionCapability, SignalPacket};
use rivetlink_sdk::direct;
use rivetlink_sdk::lan::{self, LanRequest, LanResponse};
use rivetlink_sdk::relay_tunnel::{self, TunnelParams};
use rivetlink_sdk::{Identity, Transport};
use rivetlink_server::config::ServerConfig;
use rivetlink_server::sessions::manager::SessionManager;
use rivetlink_server::state::AppState;
use rivetlink_server::websocket::connection::ConnectionMap;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn start_relay(stun_server: Option<String>) -> Option<SocketAddr> {
    let config = ServerConfig {
        // Same database as the server integration tests (CI service).
        database_url: "postgres://rivet:rivet_dev@localhost/rivet".to_string(),
        redis_url: "redis://127.0.0.1:6379".to_string(),
        jwt_secret: "relay-tunnel-test-secret-key-32chars!".to_string(),
        bind_addr: "127.0.0.1:0".to_string(),
        access_token_expiry_secs: 900,
        refresh_token_expiry_secs: 604_800,
        max_failed_logins: 5,
        lockout_duration_secs: 900,
        heartbeat_interval_secs: 10,
        disconnect_timeout_secs: 30,
        reconnect_grace_secs: 15,
        stun_server,
        audit_retention_days: 90,
    };
    let db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(3))
        .connect(&config.database_url)
        .await
        .ok()?;
    sqlx::migrate!("../../migrations").run(&db).await.unwrap();

    let (signaling_tx, signaling_rx) =
        tokio::sync::mpsc::channel(rivetlink_server::websocket::gateway::SIGNALING_QUEUE);
    let state = AppState {
        db,
        config,
        connections: ConnectionMap::new(),
        sessions: SessionManager::new(),
        signaling_tx,
    };
    tokio::spawn(rivetlink_server::signaling::router::run_signaling_router(
        signaling_rx,
        state.connections.clone(),
        state.sessions.clone(),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = rivetlink_server::router::create_router(state);
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    Some(addr)
}

async fn post(addr: SocketAddr, path: &str, token: Option<&str>, body: Value) -> Value {
    let body = serde_json::to_vec(&body).unwrap();
    let auth = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n{auth}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let text = String::from_utf8_lossy(&response);
    serde_json::from_str(&text[text.find("\r\n\r\n").unwrap() + 4..]).unwrap()
}

/// The tunnel test needs no legacy relay behaviour.
struct NoLegacy;

#[async_trait::async_trait]
impl HostHandler for NoLegacy {
    async fn handle(
        &mut self,
        _packet: SignalPacket,
    ) -> rivetlink_agent::error::AgentResult<Vec<String>> {
        Ok(Vec::new())
    }
}

/// A relay with a registered device whose agent relay loop serves up to
/// `max_tunnels` tunnels with a tiny LAN host. Returns (ws url, user token,
/// device id, host public key).
async fn start_host(
    stun_server: Option<String>,
    max_tunnels: usize,
) -> Option<(String, String, uuid::Uuid, String)> {
    let addr = start_relay(stun_server).await?;
    let email = format!("tunnel-{}@test.com", uuid::Uuid::now_v7().simple());
    let registered = post(
        addr,
        "/auth/register",
        None,
        json!({
            "email": email,
            "password": "secret-password",
            "display_name": "Tunnel",
            "organization_name": "Tunnel Org",
        }),
    )
    .await;
    let token = registered["access_token"].as_str().unwrap().to_string();

    let host_key = SigningKey::from_bytes(&rand_seed());
    let host_public =
        base64::engine::general_purpose::STANDARD.encode(host_key.verifying_key().as_bytes());
    let device = post(
        addr,
        "/devices/register",
        Some(&token),
        json!({"public_key": host_public, "hostname": "tunnel-host", "platform": "linux"}),
    )
    .await;
    let device_id = uuid::Uuid::parse_str(device["id"].as_str().unwrap()).unwrap();

    // Host: the agent's relay loop serving each tunnel with a tiny LAN host.
    let ws_url = format!("ws://{addr}/ws");
    let host = RelayClient::connect_device(&ws_url, device_id, &host_key, Duration::from_secs(5))
        .await
        .unwrap();
    let serve_key = host_key.clone();
    tokio::spawn(async move {
        let serve = |mut stream: tokio::io::DuplexStream| {
            let identity = Identity::from_signing_key(serve_key.clone());
            async move {
                let (channel, _client) = direct::host_accept_key(&mut stream, &identity, |_| true)
                    .await
                    .unwrap();
                while let Ok(LanRequest::ListDisplays) =
                    lan::recv_request(&mut stream, &channel).await
                {
                    let reply = LanResponse::Displays {
                        displays: Vec::new(),
                        features: vec!["via-relay".to_string()],
                    };
                    lan::send_response(&mut stream, &channel, &reply)
                        .await
                        .unwrap();
                }
            }
        };
        let _ = host
            .run_host_tunnels(&mut NoLegacy, max_tunnels, serve)
            .await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    Some((ws_url, token, device_id, host_public))
}

#[tokio::test]
async fn a_relay_tunnel_carries_an_authenticated_lan_session() {
    let Some((ws_url, token, device_id, host_public)) = start_host(None, 4).await else {
        eprintln!("skipping: postgres unavailable");
        return;
    };

    // Client: two tunnels at once from the same account, like the app's
    // console view plus a desktop stream.
    let client = Identity::from_signing_key(SigningKey::from_bytes(&rand_seed()));
    let client_key = client.public_key_b64();
    let params = TunnelParams {
        relay_ws_url: &ws_url,
        token: &token,
        device_id,
        client_public_key: &client_key,
        requested_capability: SessionCapability::ConsoleControl,
    };
    let mut first = relay_tunnel::open(params).await.unwrap();
    let mut second = relay_tunnel::open(params).await.unwrap();
    for stream in [&mut first, &mut second] {
        let channel = lan::connect_key_over(stream, &client, &host_public)
            .await
            .unwrap();
        let (_, features) = lan::list_displays_and_features(stream, &channel)
            .await
            .unwrap();
        assert_eq!(features, vec!["via-relay".to_string()]);
    }

    // A wrong pin is refused inside the tunnel; the relay cannot substitute a host.
    let mut third = relay_tunnel::open(params).await.unwrap();
    let wrong = base64::engine::general_purpose::STANDARD.encode(
        SigningKey::from_bytes(&rand_seed())
            .verifying_key()
            .as_bytes(),
    );
    assert!(lan::connect_key_over(&mut third, &client, &wrong)
        .await
        .is_err());
}

#[tokio::test]
async fn a_direct_path_replaces_the_relay_when_stun_is_configured() {
    let stun = stun_server().await.to_string();
    let Some((ws_url, token, device_id, host_public)) = start_host(Some(stun), 4).await else {
        eprintln!("skipping: postgres unavailable");
        return;
    };
    let client = Identity::from_signing_key(SigningKey::from_bytes(&rand_seed()));
    let client_key = client.public_key_b64();
    let (mut stream, channel, transport) = relay_tunnel::connect_best(
        TunnelParams {
            relay_ws_url: &ws_url,
            token: &token,
            device_id,
            client_public_key: &client_key,
            requested_capability: SessionCapability::ConsoleControl,
        },
        &client,
        &host_public,
    )
    .await
    .unwrap();
    assert_eq!(transport, Transport::P2p);
    let (_, features) = lan::list_displays_and_features(&mut stream, &channel)
        .await
        .unwrap();
    assert_eq!(features, vec!["via-relay".to_string()]);
}

#[tokio::test]
async fn the_relay_tunnel_stays_usable_when_no_direct_path_opens() {
    let stun = stun_server().await.to_string();
    // One slot: the relay tunnel takes it, so the host ignores the offer,
    // like a host without direct-path support.
    let Some((ws_url, token, device_id, host_public)) = start_host(Some(stun), 1).await else {
        eprintln!("skipping: postgres unavailable");
        return;
    };
    let client = Identity::from_signing_key(SigningKey::from_bytes(&rand_seed()));
    let client_key = client.public_key_b64();
    let (mut stream, channel, transport) = relay_tunnel::connect_best(
        TunnelParams {
            relay_ws_url: &ws_url,
            token: &token,
            device_id,
            client_public_key: &client_key,
            requested_capability: SessionCapability::ConsoleControl,
        },
        &client,
        &host_public,
    )
    .await
    .unwrap();
    assert_eq!(transport, Transport::Relay);
    // Still alive well after every direct-path timeout has passed.
    tokio::time::sleep(Duration::from_secs(6)).await;
    let (_, features) = lan::list_displays_and_features(&mut stream, &channel)
        .await
        .unwrap();
    assert_eq!(features, vec!["via-relay".to_string()]);
}

/// Answers every STUN Binding request with the sender's own address.
async fn stun_server() -> SocketAddr {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let (SocketAddr::V4(from), true) = (from, n >= 20) else {
                continue;
            };
            let mut reply = vec![0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42];
            reply.extend_from_slice(&buf[8..20]);
            reply.extend_from_slice(&[0x00, 0x20, 0x00, 0x08, 0x00, 0x01]);
            reply.extend_from_slice(&(from.port() ^ 0x2112).to_be_bytes());
            reply.extend_from_slice(&(u32::from(*from.ip()) ^ 0x2112_a442).to_be_bytes());
            let _ = socket.send_to(&reply, from).await;
        }
    });
    addr
}

/// Distinct per call; test keys need not be secret.
fn rand_seed() -> [u8; 32] {
    let bytes = [
        *uuid::Uuid::now_v7().as_bytes(),
        *uuid::Uuid::now_v7().as_bytes(),
    ]
    .concat();
    bytes.try_into().unwrap()
}
