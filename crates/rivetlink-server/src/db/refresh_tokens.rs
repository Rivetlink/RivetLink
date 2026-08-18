//! Refresh token store: rotation chain + theft detection.
//!
//! Each refresh token is identified by a `jti` and grouped into a `family_id`.
//! On rotation the old row is marked revoked and points to its successor; if a
//! revoked token is ever presented again it's treated as theft and the whole
//! family is invalidated.

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{ServerError, ServerResult};

/// A refresh token row in the database.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RefreshTokenRow {
    pub jti: Uuid,
    pub user_id: Uuid,
    pub family_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub replaced_by_jti: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

impl RefreshTokenRow {
    /// True if the row has been marked revoked.
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// True if the row is past its expiry.
    pub fn is_expired(&self) -> bool {
        self.expires_at <= Utc::now()
    }
}

/// Insert a freshly issued refresh token.
pub async fn insert(
    pool: &PgPool,
    jti: Uuid,
    user_id: Uuid,
    family_id: Uuid,
    expires_in_secs: i64,
) -> ServerResult<()> {
    let expires_at = Utc::now() + Duration::seconds(expires_in_secs);
    sqlx::query(
        "INSERT INTO refresh_tokens (jti, user_id, family_id, expires_at) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(jti)
    .bind(user_id)
    .bind(family_id)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Look up a refresh token by its `jti`. Returns `None` if no row exists.
pub async fn get_by_jti(pool: &PgPool, jti: Uuid) -> ServerResult<Option<RefreshTokenRow>> {
    let row = sqlx::query_as::<_, RefreshTokenRow>("SELECT * FROM refresh_tokens WHERE jti = $1")
        .bind(jti)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

/// Mark a single token as revoked and (optionally) record its successor.
pub async fn mark_revoked(pool: &PgPool, jti: Uuid, replaced_by: Option<Uuid>) -> ServerResult<()> {
    sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = now(), replaced_by_jti = $2 \
         WHERE jti = $1 AND revoked_at IS NULL",
    )
    .bind(jti)
    .bind(replaced_by)
    .execute(pool)
    .await?;
    Ok(())
}

/// Revoke every token in a family. Used when token theft is detected.
pub async fn revoke_family(pool: &PgPool, family_id: Uuid) -> ServerResult<u64> {
    let result = sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = now() \
         WHERE family_id = $1 AND revoked_at IS NULL",
    )
    .bind(family_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Revoke every refresh token owned by a user (e.g. on logout-everywhere or
/// password change).
pub async fn revoke_all_for_user(pool: &PgPool, user_id: Uuid) -> ServerResult<u64> {
    let result = sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = now() \
         WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Rotation outcome describing why a refresh attempt was rejected, if any.
#[derive(Debug)]
pub enum RotationError {
    /// No row exists for the presented jti.
    Unknown,
    /// Row exists but `expires_at` has passed.
    Expired,
    /// Row was already marked revoked. The caller should revoke the family.
    Reused { family_id: Uuid },
}

/// Validate a presented refresh token jti and return its row for rotation.
///
/// Returns `Err(RotationError::Reused)` if the token was already used — the
/// caller must then revoke the whole family.
pub async fn validate_for_rotation(
    pool: &PgPool,
    jti: Uuid,
) -> Result<RefreshTokenRow, RotationError> {
    let row = sqlx::query_as::<_, RefreshTokenRow>("SELECT * FROM refresh_tokens WHERE jti = $1")
        .bind(jti)
        .fetch_optional(pool)
        .await
        .map_err(|_| RotationError::Unknown)?;

    let Some(row) = row else {
        return Err(RotationError::Unknown);
    };

    if row.is_revoked() {
        return Err(RotationError::Reused {
            family_id: row.family_id,
        });
    }

    if row.is_expired() {
        return Err(RotationError::Expired);
    }

    Ok(row)
}

impl From<RotationError> for ServerError {
    fn from(err: RotationError) -> Self {
        match err {
            RotationError::Unknown => Self::InvalidToken("unknown refresh token".to_string()),
            RotationError::Expired => Self::TokenExpired,
            RotationError::Reused { .. } => {
                Self::InvalidToken("refresh token reused — family revoked".to_string())
            },
        }
    }
}
