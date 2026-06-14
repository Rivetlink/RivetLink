//! Native screen capture via the XDG Desktop Portal (Wayland + X11).
//!
//! Uses the desktop portal over D-Bus (through `ashpd`) instead of shelling out
//! to a screenshot binary — so it works on GNOME / KDE / wlroots Wayland with
//! nothing extra installed. On first use the compositor shows a consent dialog,
//! which fits the zero-trust model: the host operator explicitly allows the
//! capture.
//!
//! This is the `Screenshot` portal, which grabs the full desktop. Single-screen
//! selection uses the `ScreenCast` portal (PipeWire) — see `screencast.rs`.

use ashpd::desktop::screenshot::Screenshot;

use crate::error::{AgentError, AgentResult};

/// Capture the screen through the desktop portal and return PNG bytes.
pub async fn capture_png() -> AgentResult<Vec<u8>> {
    let response = Screenshot::request()
        .interactive(false)
        .modal(false)
        .send()
        .await
        .map_err(|e| AgentError::Config(format!("screenshot portal: {e}")))?
        .response()
        .map_err(|e| AgentError::Config(format!("screenshot portal: {e}")))?;

    let url = response.uri();
    let path = url
        .to_file_path()
        .map_err(|()| AgentError::Config(format!("portal returned a non-file uri: {url}")))?;

    let bytes = std::fs::read(&path)?;
    // The portal writes into a temp location it owns; clean it up.
    let _ = std::fs::remove_file(&path);

    if bytes.is_empty() {
        return Err(AgentError::Config("portal capture produced no data".to_string()));
    }
    Ok(bytes)
}
