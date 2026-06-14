//! Audit log listing endpoint for authenticated users.

use axum::{extract::State, Json};
use serde::Serialize;

use crate::auth::middleware::AuthUser;
use crate::auth::rbac::Permission;
use crate::db::audit;
use crate::error::ServerResult;
use crate::state::AppState;

/// Audit log entry with action, actor, target, and metadata.
#[derive(Debug, Serialize)]
pub struct AuditLogResponse {
    pub id: String,
    pub action: String,
    pub actor_user_id: Option<String>,
    pub target_device_id: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: String,
}

impl From<crate::db::models::AuditLog> for AuditLogResponse {
    fn from(a: crate::db::models::AuditLog) -> Self {
        Self {
            id: a.id.to_string(),
            action: a.action,
            actor_user_id: a.actor_user_id.map(|u| u.to_string()),
            target_device_id: a.target_device_id.map(|d| d.to_string()),
            metadata: a.metadata,
            created_at: a.created_at.to_rfc3339(),
        }
    }
}

/// List recent audit logs for the authenticated user's organization.
pub async fn list_audit_logs(
    State(state): State<AppState>,
    auth: AuthUser,
) -> ServerResult<Json<Vec<AuditLogResponse>>> {
    auth.require(Permission::AuditRead)?;
    let logs = audit::list_audit_logs(&state.db, auth.org_id, 100).await?;
    let response: Vec<AuditLogResponse> = logs.into_iter().map(AuditLogResponse::from).collect();
    Ok(Json(response))
}
