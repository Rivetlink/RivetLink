//! Health check endpoint returning server status and version.

use axum::Json;
use serde::Serialize;

/// Server health status with version information.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
}

/// Health check endpoint; returns 200 OK with version.
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn health_returns_ok() {
        let Json(response) = health().await;
        assert_eq!(response.status, "ok");
        assert_eq!(response.version, "0.1.0");
    }
}
