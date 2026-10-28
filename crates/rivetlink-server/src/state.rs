//! Shared application state passed to all request handlers.

use sqlx::PgPool;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::config::ServerConfig;
use crate::sessions::manager::SessionManager;
use crate::websocket::connection::{ConnectionMap, PrincipalKind};

/// A text frame from an authenticated connection, queued for the router.
#[derive(Debug, Clone)]
pub struct SignalingMessage {
    pub conn_id: Uuid,
    pub principal_id: Uuid,
    /// Included for cross-tenant authorization checks.
    pub org_id: Uuid,
    pub kind: PrincipalKind,
    pub text: String,
}

/// Shared state containing database, config, connections, and signaling channel.
#[derive(Debug, Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: ServerConfig,
    pub connections: ConnectionMap,
    pub sessions: SessionManager,
    /// Bounded: see `websocket::gateway::SIGNALING_QUEUE`.
    pub signaling_tx: mpsc::Sender<SignalingMessage>,
}
