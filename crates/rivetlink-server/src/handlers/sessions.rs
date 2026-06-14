//! Session listing endpoint for authenticated users.

use axum::{extract::State, Json};
use serde::Serialize;

use crate::auth::middleware::AuthUser;
use crate::auth::rbac::Permission;
use crate::db::sessions;
use crate::error::ServerResult;
use crate::state::AppState;

/// P2P session details with device, timeline, and relay info.
#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub id: String,
    pub device_id: String,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub relay_used: bool,
}

impl From<crate::db::models::Session> for SessionResponse {
    fn from(s: crate::db::models::Session) -> Self {
        Self {
            id: s.id.to_string(),
            device_id: s.device_id.to_string(),
            started_at: s.started_at.to_rfc3339(),
            ended_at: s.ended_at.map(|t| t.to_rfc3339()),
            relay_used: s.relay_used,
        }
    }
}

/// List recent sessions for the authenticated user's organization.
pub async fn list_sessions(
    State(state): State<AppState>,
    auth: AuthUser,
) -> ServerResult<Json<Vec<SessionResponse>>> {
    auth.require(Permission::SessionsList)?;
    let session_list = sessions::list_sessions_by_org(&state.db, auth.org_id, 100).await?;
    let response: Vec<SessionResponse> = session_list
        .into_iter()
        .map(SessionResponse::from)
        .collect();
    Ok(Json(response))
}
