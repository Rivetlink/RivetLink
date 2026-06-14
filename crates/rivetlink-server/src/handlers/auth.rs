//! User registration, login, and token refresh endpoints.

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{jwt, password};
use crate::db::{audit, organizations, refresh_tokens, users};
use crate::error::{ServerError, ServerResult};
use crate::state::AppState;

/// Registration request with email, password, display name, and organization name.
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub display_name: String,
    pub organization_name: String,
}

/// Authentication response with access token, refresh token, and IDs.
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub user_id: String,
    pub organization_id: String,
}

/// Register new user and organization; returns access and refresh tokens.
pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> ServerResult<Json<AuthResponse>> {
    validate_register_request(&req)?;

    let password_hash = password::hash_password(&req.password)?;

    let org = organizations::create_organization(&state.db, &req.organization_name).await?;
    let user = users::create_user(
        &state.db,
        org.id,
        &req.email,
        &req.display_name,
        &password_hash,
    )
    .await?;

    let resp = issue_new_family(&state, user.id, org.id, vec!["owner".to_string()]).await?;

    audit::create_audit_log(
        &state.db,
        org.id,
        Some(user.id),
        None,
        "user.registered",
        None,
    )
    .await?;

    Ok(Json(resp))
}

/// Login request with email and password.
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// Login with email/password; enforces failed login lockout; audits result.
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> ServerResult<Json<AuthResponse>> {
    let user = users::get_user_by_email(&state.db, &req.email).await?;

    if users::is_locked(&user).await {
        let locked_until = user.locked_until.ok_or(ServerError::Internal(
            "locked user without locked_until".to_string(),
        ))?;
        return Err(ServerError::AccountLocked(locked_until));
    }

    let valid = password::verify_password(&req.password, &user.password_hash)?;
    if !valid {
        let count = users::increment_failed_logins(&state.db, user.id).await?;
        if count >= state.config.max_failed_logins {
            users::lock_user(&state.db, user.id, state.config.lockout_duration_secs).await?;

            audit::create_audit_log(
                &state.db,
                user.organization_id,
                Some(user.id),
                None,
                "auth.account_locked",
                Some(serde_json::json!({"failed_attempts": count})),
            )
            .await?;
        }

        audit::create_audit_log(
            &state.db,
            user.organization_id,
            Some(user.id),
            None,
            "auth.failed",
            None,
        )
        .await?;

        return Err(ServerError::InvalidCredentials);
    }

    users::reset_failed_logins(&state.db, user.id).await?;

    let resp = issue_new_family(
        &state,
        user.id,
        user.organization_id,
        vec!["operator".to_string()],
    )
    .await?;

    audit::create_audit_log(
        &state.db,
        user.organization_id,
        Some(user.id),
        None,
        "auth.login",
        None,
    )
    .await?;

    Ok(Json(resp))
}

/// Token refresh request with refresh_token.
#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

/// Issue new token pair from a valid refresh token.
///
/// Performs theft detection: if the presented token has already been rotated
/// (revoked_at set), the entire family is revoked and the request rejected.
pub async fn refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> ServerResult<Json<AuthResponse>> {
    let claims = jwt::decode_refresh_token(&req.refresh_token, &state.config.jwt_secret)?;

    let row = match refresh_tokens::validate_for_rotation(&state.db, claims.jti).await {
        Ok(row) => row,
        Err(refresh_tokens::RotationError::Reused { family_id }) => {
            // Theft detected: revoke the entire family and audit.
            let count = refresh_tokens::revoke_family(&state.db, family_id).await?;
            audit::create_audit_log(
                &state.db,
                claims.org,
                Some(claims.sub),
                None,
                "auth.refresh_token_theft_detected",
                Some(serde_json::json!({"family_id": family_id, "revoked_count": count})),
            )
            .await?;
            return Err(ServerError::InvalidToken(
                "refresh token reused — family revoked".to_string(),
            ));
        },
        Err(other) => return Err(other.into()),
    };

    let user = users::get_user_by_id(&state.db, row.user_id).await?;

    let pair = jwt::create_token_pair(
        user.id,
        user.organization_id,
        claims.roles,
        row.family_id,
        &state.config.jwt_secret,
        state.config.access_token_expiry_secs,
        state.config.refresh_token_expiry_secs,
    )?;

    refresh_tokens::insert(
        &state.db,
        pair.refresh_jti,
        user.id,
        row.family_id,
        state.config.refresh_token_expiry_secs,
    )
    .await?;

    refresh_tokens::mark_revoked(&state.db, row.jti, Some(pair.refresh_jti)).await?;

    Ok(Json(AuthResponse {
        access_token: pair.access_token,
        refresh_token: pair.refresh_token,
        user_id: user.id.to_string(),
        organization_id: user.organization_id.to_string(),
    }))
}

/// Helper: issue a fresh token family (new login / registration) and persist
/// the refresh token's `jti` for later rotation tracking.
async fn issue_new_family(
    state: &AppState,
    user_id: Uuid,
    org_id: Uuid,
    roles: Vec<String>,
) -> ServerResult<AuthResponse> {
    let family = Uuid::now_v7();
    let pair = jwt::create_token_pair(
        user_id,
        org_id,
        roles,
        family,
        &state.config.jwt_secret,
        state.config.access_token_expiry_secs,
        state.config.refresh_token_expiry_secs,
    )?;

    refresh_tokens::insert(
        &state.db,
        pair.refresh_jti,
        user_id,
        family,
        state.config.refresh_token_expiry_secs,
    )
    .await?;

    Ok(AuthResponse {
        access_token: pair.access_token,
        refresh_token: pair.refresh_token,
        user_id: user_id.to_string(),
        organization_id: org_id.to_string(),
    })
}

/// Validate registration request fields (email, password strength, required fields).
fn validate_register_request(req: &RegisterRequest) -> ServerResult<()> {
    if req.email.is_empty() || !req.email.contains('@') || req.email.len() > 254 {
        return Err(ServerError::Validation("invalid email".to_string()));
    }
    if req.password.len() < 8 || req.password.len() > 128 {
        return Err(ServerError::Validation(
            "password must be 8-128 characters".to_string(),
        ));
    }
    if req.display_name.is_empty() {
        return Err(ServerError::Validation(
            "display_name is required".to_string(),
        ));
    }
    if req.organization_name.is_empty() {
        return Err(ServerError::Validation(
            "organization_name is required".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_empty_email() {
        let req = RegisterRequest {
            email: String::new(),
            password: "password123".to_string(),
            display_name: "Test".to_string(),
            organization_name: "Org".to_string(),
        };
        assert!(validate_register_request(&req).is_err());
    }

    #[test]
    fn validate_rejects_email_without_at() {
        let req = RegisterRequest {
            email: "not-an-email".to_string(),
            password: "password123".to_string(),
            display_name: "Test".to_string(),
            organization_name: "Org".to_string(),
        };
        assert!(validate_register_request(&req).is_err());
    }

    #[test]
    fn validate_rejects_short_password() {
        let req = RegisterRequest {
            email: "test@test.com".to_string(),
            password: "short".to_string(),
            display_name: "Test".to_string(),
            organization_name: "Org".to_string(),
        };
        assert!(validate_register_request(&req).is_err());
    }

    #[test]
    fn validate_accepts_valid_request() {
        let req = RegisterRequest {
            email: "test@test.com".to_string(),
            password: "password123".to_string(),
            display_name: "Test User".to_string(),
            organization_name: "Test Org".to_string(),
        };
        assert!(validate_register_request(&req).is_ok());
    }

    #[test]
    fn validate_rejects_empty_display_name() {
        let req = RegisterRequest {
            email: "test@test.com".to_string(),
            password: "password123".to_string(),
            display_name: String::new(),
            organization_name: "Org".to_string(),
        };
        assert!(validate_register_request(&req).is_err());
    }

    #[test]
    fn validate_rejects_empty_org_name() {
        let req = RegisterRequest {
            email: "test@test.com".to_string(),
            password: "password123".to_string(),
            display_name: "Test".to_string(),
            organization_name: String::new(),
        };
        assert!(validate_register_request(&req).is_err());
    }
}
