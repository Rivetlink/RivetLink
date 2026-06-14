//! Organization database queries.

use sqlx::PgPool;
use uuid::Uuid;

use super::models::Organization;
use crate::error::{ServerError, ServerResult};

/// Create a new organization with the given name.
pub async fn create_organization(pool: &PgPool, name: &str) -> ServerResult<Organization> {
    let id = Uuid::now_v7();
    let org = sqlx::query_as::<_, Organization>(
        "INSERT INTO organizations (id, name) VALUES ($1, $2) RETURNING *",
    )
    .bind(id)
    .bind(name)
    .fetch_one(pool)
    .await?;

    Ok(org)
}

/// Retrieve organization by ID (excludes soft-deleted rows).
pub async fn get_organization(pool: &PgPool, id: Uuid) -> ServerResult<Organization> {
    sqlx::query_as::<_, Organization>(
        "SELECT * FROM organizations WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| ServerError::NotFound("organization not found".to_string()))
}
