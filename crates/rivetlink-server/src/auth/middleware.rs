//! Request extractor for Bearer token authentication.

use async_trait::async_trait;
use axum::{extract::FromRequestParts, http::request::Parts};
use uuid::Uuid;

use crate::auth::jwt;
use crate::auth::rbac::{permissions_for_roles, Permission};
use crate::error::ServerError;
use crate::state::AppState;

/// Authenticated user extracted from Authorization header Bearer token.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub org_id: Uuid,
    pub roles: Vec<String>,
}

impl AuthUser {
    /// True if any of the user's roles grant the given permission.
    pub fn has_permission(&self, perm: Permission) -> bool {
        permissions_for_roles(&self.roles).contains(&perm)
    }

    /// Return `Ok(())` when the user has the permission, otherwise a
    /// `Forbidden` error suitable for direct propagation from a handler.
    pub fn require(&self, perm: Permission) -> Result<(), ServerError> {
        if self.has_permission(perm) {
            Ok(())
        } else {
            Err(ServerError::Forbidden(format!(
                "missing permission: {}",
                perm.as_str()
            )))
        }
    }
}

#[async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ServerError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| ServerError::Auth("missing authorization header".to_string()))?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| ServerError::Auth("invalid authorization format".to_string()))?;

        let claims = jwt::decode_access_token(token, &state.config.jwt_secret)?;

        Ok(AuthUser {
            user_id: claims.sub,
            org_id: claims.org,
            roles: claims.roles,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(roles: &[&str]) -> AuthUser {
        AuthUser {
            user_id: Uuid::now_v7(),
            org_id: Uuid::now_v7(),
            roles: roles.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    #[test]
    fn owner_passes_org_admin() {
        assert!(user(&["owner"]).has_permission(Permission::OrgAdmin));
    }

    #[test]
    fn operator_fails_audit_read() {
        let u = user(&["operator"]);
        assert!(!u.has_permission(Permission::AuditRead));
        assert!(matches!(
            u.require(Permission::AuditRead),
            Err(ServerError::Forbidden(_))
        ));
    }

    #[test]
    fn viewer_passes_list_only() {
        let u = user(&["viewer"]);
        assert!(u.has_permission(Permission::DevicesList));
        assert!(!u.has_permission(Permission::DevicesRegister));
    }

    #[test]
    fn empty_roles_fail_all() {
        let u = user(&[]);
        assert!(!u.has_permission(Permission::DevicesList));
        assert!(matches!(
            u.require(Permission::DevicesList),
            Err(ServerError::Forbidden(_))
        ));
    }
}
