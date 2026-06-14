//! Audit log database queries for compliance and debugging.

use sqlx::PgPool;
use uuid::Uuid;

use super::models::AuditLog;
use crate::error::ServerResult;

/// Create an audit log entry recording an action with optional metadata.
pub async fn create_audit_log(
    pool: &PgPool,
    organization_id: Uuid,
    actor_user_id: Option<Uuid>,
    target_device_id: Option<Uuid>,
    action: &str,
    metadata: Option<serde_json::Value>,
) -> ServerResult<AuditLog> {
    let id = Uuid::now_v7();
    let log = sqlx::query_as::<_, AuditLog>(
        "INSERT INTO audit_logs (id, organization_id, actor_user_id, target_device_id, action, metadata) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
    )
    .bind(id)
    .bind(organization_id)
    .bind(actor_user_id)
    .bind(target_device_id)
    .bind(action)
    .bind(metadata)
    .fetch_one(pool)
    .await?;

    Ok(log)
}

/// List recent audit logs for an organization with limit.
pub async fn list_audit_logs(
    pool: &PgPool,
    organization_id: Uuid,
    limit: i64,
) -> ServerResult<Vec<AuditLog>> {
    let logs = sqlx::query_as::<_, AuditLog>(
        "SELECT * FROM audit_logs WHERE organization_id = $1 \
         ORDER BY created_at DESC LIMIT $2",
    )
    .bind(organization_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(logs)
}
