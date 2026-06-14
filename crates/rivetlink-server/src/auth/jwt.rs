//! JWT token encoding and decoding for authentication.
//!
//! Refresh tokens carry a `jti` (unique token ID) and `family` (rotation chain
//! ID) so the server can detect token theft when an already-rotated token is
//! presented a second time.

use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{ServerError, ServerResult};

/// JWT claims containing user/org identity, roles, and rotation metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: Uuid,
    pub org: Uuid,
    pub roles: Vec<String>,
    pub token_type: TokenType,
    /// Unique token identifier. Always populated; only persisted for refresh tokens.
    pub jti: Uuid,
    /// Refresh rotation chain. Always populated; only persisted for refresh tokens.
    pub family: Uuid,
    pub exp: i64,
    pub iat: i64,
}

/// Distinguishes access tokens (short-lived) from refresh tokens (long-lived).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    Access,
    Refresh,
}

/// Pair of access and refresh tokens returned on login/register.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    /// The `jti` of the issued refresh token — caller stores this in the DB.
    pub refresh_jti: Uuid,
    /// Family ID of the issued refresh token — caller stores this in the DB.
    pub refresh_family: Uuid,
}

/// Create access and refresh JWT tokens for a user.
///
/// `family` should be a fresh UUID for a new login, or the existing family ID
/// when rotating a refresh token.
#[allow(clippy::too_many_arguments)] // token issuance naturally fans out into many parameters
pub fn create_token_pair(
    user_id: Uuid,
    org_id: Uuid,
    roles: Vec<String>,
    family: Uuid,
    secret: &str,
    access_expiry_secs: i64,
    refresh_expiry_secs: i64,
) -> ServerResult<TokenPair> {
    let access_jti = Uuid::now_v7();
    let refresh_jti = Uuid::now_v7();

    let access_token = encode_token(
        user_id,
        org_id,
        roles.clone(),
        TokenType::Access,
        access_jti,
        family,
        secret,
        access_expiry_secs,
    )?;

    let refresh_token = encode_token(
        user_id,
        org_id,
        roles,
        TokenType::Refresh,
        refresh_jti,
        family,
        secret,
        refresh_expiry_secs,
    )?;

    Ok(TokenPair {
        access_token,
        refresh_token,
        refresh_jti,
        refresh_family: family,
    })
}

#[allow(clippy::too_many_arguments)]
fn encode_token(
    user_id: Uuid,
    org_id: Uuid,
    roles: Vec<String>,
    token_type: TokenType,
    jti: Uuid,
    family: Uuid,
    secret: &str,
    expiry_secs: i64,
) -> ServerResult<String> {
    let now = Utc::now().timestamp();
    let claims = Claims {
        sub: user_id,
        org: org_id,
        roles,
        token_type,
        jti,
        family,
        exp: now + expiry_secs,
        iat: now,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| ServerError::Internal(format!("jwt encoding failed: {e}")))
}

/// Decode and validate an access token.
pub fn decode_access_token(token: &str, secret: &str) -> ServerResult<Claims> {
    let claims = decode_token(token, secret)?;
    if claims.token_type != TokenType::Access {
        return Err(ServerError::InvalidToken(
            "expected access token".to_string(),
        ));
    }
    Ok(claims)
}

/// Decode and validate a refresh token.
pub fn decode_refresh_token(token: &str, secret: &str) -> ServerResult<Claims> {
    let claims = decode_token(token, secret)?;
    if claims.token_type != TokenType::Refresh {
        return Err(ServerError::InvalidToken(
            "expected refresh token".to_string(),
        ));
    }
    Ok(claims)
}

fn decode_token(token: &str, secret: &str) -> ServerResult<Claims> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => ServerError::TokenExpired,
        _ => ServerError::InvalidToken(format!("jwt decode failed: {e}")),
    })?;

    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &str = "test-secret-key-for-jwt-testing";

    fn test_token_pair() -> TokenPair {
        let user_id = Uuid::now_v7();
        let org_id = Uuid::now_v7();
        let family = Uuid::now_v7();
        create_token_pair(
            user_id,
            org_id,
            vec!["operator".to_string()],
            family,
            TEST_SECRET,
            900,
            604800,
        )
        .unwrap()
    }

    #[test]
    fn create_and_decode_access_token() {
        let user_id = Uuid::now_v7();
        let org_id = Uuid::now_v7();
        let family = Uuid::now_v7();
        let pair = create_token_pair(
            user_id,
            org_id,
            vec!["admin".to_string()],
            family,
            TEST_SECRET,
            900,
            604800,
        )
        .unwrap();

        let claims = decode_access_token(&pair.access_token, TEST_SECRET).unwrap();
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.org, org_id);
        assert_eq!(claims.roles, vec!["admin"]);
        assert_eq!(claims.token_type, TokenType::Access);
        assert_eq!(claims.family, family);
    }

    #[test]
    fn create_and_decode_refresh_token() {
        let user_id = Uuid::now_v7();
        let org_id = Uuid::now_v7();
        let family = Uuid::now_v7();
        let pair = create_token_pair(
            user_id,
            org_id,
            vec!["operator".to_string()],
            family,
            TEST_SECRET,
            900,
            604800,
        )
        .unwrap();

        let claims = decode_refresh_token(&pair.refresh_token, TEST_SECRET).unwrap();
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.token_type, TokenType::Refresh);
        assert_eq!(claims.jti, pair.refresh_jti);
        assert_eq!(claims.family, family);
    }

    #[test]
    fn access_and_refresh_have_different_jtis() {
        let pair = test_token_pair();
        let access = decode_access_token(&pair.access_token, TEST_SECRET).unwrap();
        let refresh = decode_refresh_token(&pair.refresh_token, TEST_SECRET).unwrap();
        assert_ne!(access.jti, refresh.jti);
        assert_eq!(access.family, refresh.family);
    }

    #[test]
    fn access_token_rejected_as_refresh() {
        let pair = test_token_pair();
        let result = decode_refresh_token(&pair.access_token, TEST_SECRET);
        assert!(result.is_err());
    }

    #[test]
    fn refresh_token_rejected_as_access() {
        let pair = test_token_pair();
        let result = decode_access_token(&pair.refresh_token, TEST_SECRET);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_secret_fails_decode() {
        let pair = test_token_pair();
        let result = decode_access_token(&pair.access_token, "wrong-secret");
        assert!(result.is_err());
    }

    #[test]
    fn expired_token_returns_expired_error() {
        let user_id = Uuid::now_v7();
        let org_id = Uuid::now_v7();
        let family = Uuid::now_v7();
        let pair = create_token_pair(
            user_id,
            org_id,
            vec![],
            family,
            TEST_SECRET,
            -300,
            -300,
        )
        .unwrap();

        let result = decode_access_token(&pair.access_token, TEST_SECRET);
        assert!(matches!(result, Err(ServerError::TokenExpired)));
    }

    #[test]
    fn invalid_token_string_fails() {
        let result = decode_access_token("not.a.valid.jwt", TEST_SECRET);
        assert!(result.is_err());
    }

    #[test]
    fn token_contains_all_claims() {
        let user_id = Uuid::now_v7();
        let org_id = Uuid::now_v7();
        let family = Uuid::now_v7();
        let roles = vec!["admin".to_string(), "operator".to_string()];
        let pair = create_token_pair(
            user_id,
            org_id,
            roles.clone(),
            family,
            TEST_SECRET,
            900,
            604800,
        )
        .unwrap();

        let claims = decode_access_token(&pair.access_token, TEST_SECRET).unwrap();
        assert_eq!(claims.roles.len(), 2);
        assert!(claims.exp > claims.iat);
        assert_eq!(claims.exp - claims.iat, 900);
    }
}
