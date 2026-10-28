//! User database queries with password and lockout management.

use chrono::{Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use super::models::User;
use crate::error::{ServerError, ServerResult};

/// Create a new user with email and hashed password; rejects duplicate emails.
pub async fn create_user(
    pool: &PgPool,
    organization_id: Uuid,
    email: &str,
    display_name: &str,
    password_hash: &str,
) -> ServerResult<User> {
    let id = Uuid::now_v7();
    let user = sqlx::query_as::<_, User>(
        "INSERT INTO users (id, organization_id, email, display_name, password_hash) \
         VALUES ($1, $2, $3, $4, $5) RETURNING *",
    )
    .bind(id)
    .bind(organization_id)
    .bind(email)
    .bind(display_name)
    .bind(password_hash)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(ref db_err) if db_err.constraint() == Some("users_email_key") => {
            ServerError::Conflict("email already exists".to_string())
        },
        other => ServerError::Database(other),
    })?;

    Ok(user)
}

/// Retrieve user by email; returns InvalidCredentials if not found.
pub async fn get_user_by_email(pool: &PgPool, email: &str) -> ServerResult<User> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1 AND deleted_at IS NULL")
        .bind(email)
        .fetch_optional(pool)
        .await?
        .ok_or(ServerError::InvalidCredentials)
}

/// Retrieve user by ID; returns NotFound if missing.
pub async fn get_user_by_id(pool: &PgPool, id: Uuid) -> ServerResult<User> {
    sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| ServerError::NotFound("user not found".to_string()))
}

/// Count a login attempt before its password is checked, in one statement.
///
/// Returns the attempt's number, or `None` when the account is locked. The
/// attempt that reaches `max_attempts` locks the account at once, so
/// concurrent requests cannot all slip past the check: at most
/// `max_attempts` passwords are tried before the first lock, and one per
/// lockout period after it (the count stays above the limit). A successful
/// login clears the count and the lock with [`reset_failed_logins`].
pub async fn reserve_login_attempt(
    pool: &PgPool,
    user_id: Uuid,
    max_attempts: i32,
    lockout_secs: i64,
) -> ServerResult<Option<i32>> {
    let locked_until = Utc::now() + Duration::seconds(lockout_secs);
    let count = sqlx::query_scalar::<_, i32>(
        "UPDATE users SET failed_login_count = failed_login_count + 1, \
             locked_until = CASE WHEN failed_login_count + 1 >= $2 THEN $3 ELSE locked_until END \
         WHERE id = $1 AND (locked_until IS NULL OR locked_until <= now()) \
         RETURNING failed_login_count",
    )
    .bind(user_id)
    .bind(max_attempts)
    .bind(locked_until)
    .fetch_optional(pool)
    .await?;

    Ok(count)
}

/// Clear failed login counter and lock status after successful authentication.
pub async fn reset_failed_logins(pool: &PgPool, user_id: Uuid) -> ServerResult<()> {
    sqlx::query("UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}
