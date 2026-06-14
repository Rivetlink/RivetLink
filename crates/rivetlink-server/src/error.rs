//! Server error types and HTTP response mapping.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use thiserror::Error;

/// Unified error type for authentication, validation, database, and runtime failures.
#[derive(Debug, Error)]
pub enum ServerError {
    #[error("authentication failed: {0}")]
    Auth(String),

    #[error("invalid credentials")]
    InvalidCredentials,

    #[error("account locked until {0}")]
    AccountLocked(chrono::DateTime<chrono::Utc>),

    #[error("token expired")]
    TokenExpired,

    #[error("invalid token: {0}")]
    InvalidToken(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("rate limited")]
    RateLimited,

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("redis error: {0}")]
    Redis(#[from] redis::RedisError),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

impl ServerError {
    /// Map error variant to appropriate HTTP status code.
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Auth(_)
            | Self::InvalidCredentials
            | Self::TokenExpired
            | Self::InvalidToken(_) => StatusCode::UNAUTHORIZED,
            Self::AccountLocked(_) | Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Validation(_) => StatusCode::BAD_REQUEST,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Database(_) | Self::Redis(_) | Self::Config(_) | Self::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            },
        }
    }

    /// Extract client-safe error message (hides internal details).
    fn client_message(&self) -> String {
        match self {
            Self::Auth(msg)
            | Self::InvalidToken(msg)
            | Self::NotFound(msg)
            | Self::Validation(msg)
            | Self::Forbidden(msg)
            | Self::Conflict(msg) => msg.clone(),
            Self::InvalidCredentials => "invalid credentials".to_string(),
            Self::AccountLocked(_) => "account locked".to_string(),
            Self::TokenExpired => "token expired".to_string(),
            Self::RateLimited => "rate limited".to_string(),
            Self::Database(_) | Self::Redis(_) | Self::Config(_) | Self::Internal(_) => {
                "internal error".to_string()
            },
        }
    }
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        match &self {
            ServerError::Database(e) => tracing::error!(error = %e, "database error"),
            ServerError::Redis(e) => tracing::error!(error = %e, "redis error"),
            ServerError::Config(e) | ServerError::Internal(e) => {
                tracing::error!(error = %e, "server error");
            },
            _ => {},
        }

        let status = self.status_code();
        let body = ErrorResponse {
            error: self.client_message(),
        };
        (status, axum::Json(body)).into_response()
    }
}

/// Result type alias for server operations.
pub type ServerResult<T> = Result<T, ServerError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_messages() {
        let err = ServerError::Auth("bad token".to_string());
        assert_eq!(err.to_string(), "authentication failed: bad token");

        let err = ServerError::InvalidCredentials;
        assert_eq!(err.to_string(), "invalid credentials");

        let err = ServerError::NotFound("device".to_string());
        assert_eq!(err.to_string(), "not found: device");

        let err = ServerError::Validation("email required".to_string());
        assert_eq!(err.to_string(), "validation error: email required");
    }

    #[test]
    fn error_into_response_status_codes() {
        use axum::http::StatusCode;

        let cases: Vec<(ServerError, StatusCode)> = vec![
            (ServerError::InvalidCredentials, StatusCode::UNAUTHORIZED),
            (ServerError::NotFound("x".into()), StatusCode::NOT_FOUND),
            (ServerError::Validation("x".into()), StatusCode::BAD_REQUEST),
            (ServerError::Forbidden("x".into()), StatusCode::FORBIDDEN),
            (ServerError::RateLimited, StatusCode::TOO_MANY_REQUESTS),
            (ServerError::Conflict("x".into()), StatusCode::CONFLICT),
            (
                ServerError::Internal("x".into()),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ];

        for (error, expected_status) in cases {
            let response = error.into_response();
            assert_eq!(response.status(), expected_status);
        }
    }
}
