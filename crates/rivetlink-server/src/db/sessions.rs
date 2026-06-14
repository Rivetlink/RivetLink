//! Session database queries for P2P connections and participant tracking.

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use super::models::{Session, SessionParticipant};
use crate::error::ServerResult;

/// Create a new P2P session for a device.
pub async fn create_session(
    pool: &PgPool,
    device_id: Uuid,
    relay_used: bool,
) -> ServerResult<Session> {
    let id = Uuid::now_v7();
    let session = sqlx::query_as::<_, Session>(
        "INSERT INTO sessions (id, device_id, relay_used) VALUES ($1, $2, $3) RETURNING *",
    )
    .bind(id)
    .bind(device_id)
    .bind(relay_used)
    .fetch_one(pool)
    .await?;

    Ok(session)
}

/// Mark session as ended (set ended_at timestamp).
pub async fn end_session(pool: &PgPool, session_id: Uuid) -> ServerResult<()> {
    sqlx::query("UPDATE sessions SET ended_at = $1 WHERE id = $2")
        .bind(Utc::now())
        .bind(session_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Add a user as participant to a session with assigned role.
pub async fn add_participant(
    pool: &PgPool,
    session_id: Uuid,
    user_id: Uuid,
    role: &str,
) -> ServerResult<SessionParticipant> {
    let id = Uuid::now_v7();
    let participant = sqlx::query_as::<_, SessionParticipant>(
        "INSERT INTO session_participants (id, session_id, user_id, role) \
         VALUES ($1, $2, $3, $4) RETURNING *",
    )
    .bind(id)
    .bind(session_id)
    .bind(user_id)
    .bind(role)
    .fetch_one(pool)
    .await?;

    Ok(participant)
}

/// List recent sessions for an organization with limit.
pub async fn list_sessions_by_org(
    pool: &PgPool,
    organization_id: Uuid,
    limit: i64,
) -> ServerResult<Vec<Session>> {
    let sessions = sqlx::query_as::<_, Session>(
        "SELECT s.* FROM sessions s \
         JOIN devices d ON s.device_id = d.id \
         WHERE d.organization_id = $1 \
         ORDER BY s.started_at DESC \
         LIMIT $2",
    )
    .bind(organization_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(sessions)
}
