//! Device database queries and lifecycle management.

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use super::models::Device;
use crate::error::{ServerError, ServerResult};

/// Register new device with public key and optional platform metadata.
pub async fn register_device(
    pool: &PgPool,
    organization_id: Uuid,
    public_key: &str,
    hostname: Option<&str>,
    platform: Option<&str>,
) -> ServerResult<Device> {
    let id = Uuid::now_v7();
    let device = sqlx::query_as::<_, Device>(
        "INSERT INTO devices (id, organization_id, public_key, hostname, platform) \
         VALUES ($1, $2, $3, $4, $5) RETURNING *",
    )
    .bind(id)
    .bind(organization_id)
    .bind(public_key)
    .bind(hostname)
    .bind(platform)
    .fetch_one(pool)
    .await?;

    Ok(device)
}

/// List all active devices for an organization, newest first.
pub async fn list_devices_by_org(
    pool: &PgPool,
    organization_id: Uuid,
) -> ServerResult<Vec<Device>> {
    let devices = sqlx::query_as::<_, Device>(
        "SELECT * FROM devices WHERE organization_id = $1 AND deleted_at IS NULL \
         ORDER BY created_at DESC",
    )
    .bind(organization_id)
    .fetch_all(pool)
    .await?;

    Ok(devices)
}

/// Retrieve device by ID; returns NotFound if missing.
pub async fn get_device(pool: &PgPool, id: Uuid) -> ServerResult<Device> {
    sqlx::query_as::<_, Device>("SELECT * FROM devices WHERE id = $1 AND deleted_at IS NULL")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| ServerError::NotFound("device not found".to_string()))
}

/// Update device last_seen timestamp to current time.
pub async fn update_last_seen(pool: &PgPool, id: Uuid) -> ServerResult<()> {
    sqlx::query("UPDATE devices SET last_seen = $1 WHERE id = $2")
        .bind(Utc::now())
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}
