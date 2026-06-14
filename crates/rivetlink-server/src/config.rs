//! Server configuration loaded from environment variables.

use crate::error::{ServerError, ServerResult};

/// Server runtime configuration for database, Redis, JWT, networking, and timeouts.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub database_url: String,
    pub redis_url: String,
    pub jwt_secret: String,
    pub bind_addr: String,
    pub access_token_expiry_secs: i64,
    pub refresh_token_expiry_secs: i64,
    pub max_failed_logins: i32,
    pub lockout_duration_secs: i64,
    pub heartbeat_interval_secs: u64,
    pub disconnect_timeout_secs: u64,
    pub reconnect_grace_secs: u64,
}

impl ServerConfig {
    /// Load server configuration from environment variables, with sensible defaults.
    pub fn from_env() -> ServerResult<Self> {
        Ok(Self {
            database_url: required("DATABASE_URL")?,
            redis_url: optional("REDIS_URL", "redis://127.0.0.1:6379"),
            jwt_secret: {
                let secret = required("JWT_SECRET")?;
                if secret.len() < 32 {
                    return Err(ServerError::Config(
                        "JWT_SECRET must be at least 32 characters".to_string(),
                    ));
                }
                secret
            },
            bind_addr: optional("BIND_ADDR", "0.0.0.0:8080"),
            access_token_expiry_secs: parse_or("ACCESS_TOKEN_EXPIRY_SECS", 900),
            refresh_token_expiry_secs: parse_or("REFRESH_TOKEN_EXPIRY_SECS", 604800),
            max_failed_logins: parse_or("MAX_FAILED_LOGINS", 5),
            lockout_duration_secs: parse_or("LOCKOUT_DURATION_SECS", 900),
            heartbeat_interval_secs: parse_or("HEARTBEAT_INTERVAL_SECS", 10),
            disconnect_timeout_secs: parse_or("DISCONNECT_TIMEOUT_SECS", 30),
            reconnect_grace_secs: parse_or("RECONNECT_GRACE_SECS", 15),
        })
    }
}

#[allow(clippy::disallowed_methods)]
fn required(key: &str) -> ServerResult<String> {
    std::env::var(key).map_err(|_| ServerError::Config(format!("{key} is required")))
}

#[allow(clippy::disallowed_methods)]
fn optional(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[allow(clippy::disallowed_methods)]
fn parse_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    #[test]
    fn missing_required_env_returns_error() {
        std::env::remove_var("DATABASE_URL");
        std::env::remove_var("JWT_SECRET");

        let result = ServerConfig::from_env();
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.to_string().contains("DATABASE_URL"));
    }

    #[test]
    fn valid_config_from_env() {
        std::env::set_var("DATABASE_URL", "postgres://test");
        std::env::set_var("JWT_SECRET", "test-secret-key-minimum-length-32");

        let config = ServerConfig::from_env();
        assert!(config.is_ok());

        let config = config.unwrap();
        assert_eq!(config.database_url, "postgres://test");
        assert_eq!(config.bind_addr, "0.0.0.0:8080");
        assert_eq!(config.access_token_expiry_secs, 900);
        assert_eq!(config.max_failed_logins, 5);
        assert_eq!(config.heartbeat_interval_secs, 10);

        std::env::remove_var("DATABASE_URL");
        std::env::remove_var("JWT_SECRET");
    }

    #[test]
    fn custom_values_override_defaults() {
        std::env::set_var("DATABASE_URL", "postgres://custom");
        std::env::set_var("JWT_SECRET", "custom-secret-that-is-at-least-32c");
        std::env::set_var("BIND_ADDR", "127.0.0.1:9090");
        std::env::set_var("ACCESS_TOKEN_EXPIRY_SECS", "300");
        std::env::set_var("MAX_FAILED_LOGINS", "3");

        let config = ServerConfig::from_env().unwrap();
        assert_eq!(config.bind_addr, "127.0.0.1:9090");
        assert_eq!(config.access_token_expiry_secs, 300);
        assert_eq!(config.max_failed_logins, 3);

        std::env::remove_var("DATABASE_URL");
        std::env::remove_var("JWT_SECRET");
        std::env::remove_var("BIND_ADDR");
        std::env::remove_var("ACCESS_TOKEN_EXPIRY_SECS");
        std::env::remove_var("MAX_FAILED_LOGINS");
    }

    #[test]
    fn invalid_parse_uses_default() {
        std::env::set_var("ACCESS_TOKEN_EXPIRY_SECS", "not-a-number");
        let val: i64 = parse_or("ACCESS_TOKEN_EXPIRY_SECS", 900);
        assert_eq!(val, 900);
        std::env::remove_var("ACCESS_TOKEN_EXPIRY_SECS");
    }
}
