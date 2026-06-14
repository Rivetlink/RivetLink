//! SQLx row structs for database models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Organization entity containing name and lifecycle timestamps.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// User account with password hash, failed login tracking, and account lock status.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub email: String,
    pub display_name: String,
    pub password_hash: String,
    pub failed_login_count: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// Device registered in the network with public key and optional platform metadata.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Device {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub hostname: Option<String>,
    pub platform: Option<String>,
    pub public_key: String,
    pub created_at: DateTime<Utc>,
    pub last_seen: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
}

/// P2P session instance between devices, tracking relay usage and lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Session {
    pub id: Uuid,
    pub device_id: Uuid,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub relay_used: bool,
}

/// User joining/leaving a session with assigned role and timestamps.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct SessionParticipant {
    pub id: Uuid,
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub role: String,
    pub joined_at: DateTime<Utc>,
    pub left_at: Option<DateTime<Utc>>,
}

/// Immutable audit log entry recording user actions and device events.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AuditLog {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub actor_user_id: Option<Uuid>,
    pub target_device_id: Option<Uuid>,
    pub action: String,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}
