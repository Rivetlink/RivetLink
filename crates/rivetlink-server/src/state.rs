//! Shared application state passed to all request handlers.

use sqlx::PgPool;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::config::ServerConfig;
use crate::sessions::manager::SessionManager;
use crate::websocket::connection::ConnectionMap;

/// (user_id, org_id, raw_message_json) — org_id included for cross-tenant authorization checks.
pub type SignalingMessage = (Uuid, Uuid, String);

/// Shared state containing database, config, connections, and signaling channel.
#[derive(Debug, Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: ServerConfig,
    pub connections: ConnectionMap,
    pub sessions: SessionManager,
    pub signaling_tx: mpsc::UnboundedSender<SignalingMessage>,
}
