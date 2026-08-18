//! Device registration and listing endpoints.

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use crate::auth::middleware::AuthUser;
use crate::auth::rbac::Permission;
use crate::db::{audit, devices};
use crate::error::{ServerError, ServerResult};
use crate::state::AppState;

/// Device registration request with public key and optional platform info.
#[derive(Debug, Deserialize)]
pub struct RegisterDeviceRequest {
    pub public_key: String,
    pub hostname: Option<String>,
    pub platform: Option<String>,
}

/// Device details response with ID, keys, and timestamps.
#[derive(Debug, Serialize)]
pub struct DeviceResponse {
    pub id: String,
    pub organization_id: String,
    pub hostname: Option<String>,
    pub platform: Option<String>,
    pub public_key: String,
    pub created_at: String,
    pub last_seen: Option<String>,
    /// True only while this exact device has an authenticated relay websocket.
    /// It is deliberately live state, not an inference from `last_seen`.
    pub online: bool,
}

impl DeviceResponse {
    fn from_device(d: crate::db::models::Device, online: bool) -> Self {
        Self {
            id: d.id.to_string(),
            organization_id: d.organization_id.to_string(),
            hostname: d.hostname,
            platform: d.platform,
            public_key: d.public_key,
            created_at: d.created_at.to_rfc3339(),
            last_seen: d.last_seen.map(|t| t.to_rfc3339()),
            online,
        }
    }
}

/// Register a new device for the authenticated user; audits the action.
pub async fn register_device(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<RegisterDeviceRequest>,
) -> ServerResult<Json<DeviceResponse>> {
    auth.require(Permission::DevicesRegister)?;
    validate_device_request(&req)?;

    let device = devices::register_device(
        &state.db,
        auth.org_id,
        &req.public_key,
        req.hostname.as_deref(),
        req.platform.as_deref(),
    )
    .await?;

    audit::create_audit_log(
        &state.db,
        auth.org_id,
        Some(auth.user_id),
        Some(device.id),
        "device.registered",
        None,
    )
    .await?;

    Ok(Json(DeviceResponse::from_device(device, false)))
}

fn validate_device_request(req: &RegisterDeviceRequest) -> ServerResult<()> {
    if req.public_key.is_empty() {
        return Err(ServerError::Validation(
            "public_key is required".to_string(),
        ));
    }
    if req.public_key.len() > 4096 {
        return Err(ServerError::Validation("public_key too long".to_string()));
    }
    if let Some(ref hostname) = req.hostname {
        if hostname.len() > 255 {
            return Err(ServerError::Validation("hostname too long".to_string()));
        }
    }
    Ok(())
}

/// List all devices for the authenticated user's organization.
pub async fn list_devices(
    State(state): State<AppState>,
    auth: AuthUser,
) -> ServerResult<Json<Vec<DeviceResponse>>> {
    auth.require(Permission::DevicesList)?;
    let device_list = devices::list_devices_by_org(&state.db, auth.org_id).await?;
    let response: Vec<DeviceResponse> = device_list
        .into_iter()
        .map(|device| {
            let online = state.connections.device_is_connected(&device.id);
            DeviceResponse::from_device(device, online)
        })
        .collect();
    Ok(Json(response))
}
