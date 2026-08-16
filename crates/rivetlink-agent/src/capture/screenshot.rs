//! One-shot screen capture to PNG bytes via platform CLI tools.
//!
//! This is the pragmatic MVP capture path — it shells out to the OS's
//! built-in screenshot utility rather than using a streaming API. Good enough
//! to prove the end-to-end secure pipeline; live video uses the streaming
//! [`super::ScreenCapture`] trait later.
//!
//! Backends:
//! - macOS:   `screencapture -x -t png <file>`
//! - Linux:   `grim` (Wayland) → `scrot` → `import -window root` (X11)
//! - Windows: PowerShell `System.Windows.Forms` capture
//!
//! Set `RIVET_FAKE_CAPTURE=<bytes>` to return synthetic data instead — used
//! for headless CI / e2e tests where no display is available.

use crate::error::{AgentError, AgentResult};
use std::time::Duration;

/// Capture the primary screen and return PNG (or fake) bytes.
pub async fn capture_png() -> AgentResult<Vec<u8>> {
    if let Some(size) = fake_capture_size() {
        return Ok(synthetic_blob(size));
    }

    // Native capture, no external tools:
    //  1. Screenshot portal — whole desktop (preferred; works on GNOME/Wayland).
    //  2. CLI tools — last resort (headless X11 / minimal wlroots).
    // (Live streaming uses Mutter ScreenCast + GStreamer; the one-shot
    // screenshot stays on the portal, which needs no PipeWire negotiation.)
    #[cfg(target_os = "linux")]
    {
        match super::portal::capture_png().await {
            Ok(bytes) => return Ok(bytes),
            Err(e) => {
                tracing::debug!(error = %e, "portal screenshot unavailable, trying CLI tools");
            },
        }
    }

    tokio::task::spawn_blocking(capture_blocking)
        .await
        .map_err(|e| AgentError::Config(format!("capture task join error: {e}")))?
}

/// Capture the dedicated virtual GNOME monitor used by the headless service.
/// This deliberately does not fall back to X11 command-line tools: a headless
/// host must either capture its configured Mutter virtual monitor or fail
/// closed with a useful error.
pub async fn capture_headless_png(timeout: Duration) -> AgentResult<Vec<u8>> {
    if let Some(size) = fake_capture_size() {
        return Ok(synthetic_blob(size));
    }

    #[cfg(target_os = "linux")]
    {
        tokio::task::spawn_blocking(move || super::mutter::capture_png(timeout))
            .await
            .map_err(|e| AgentError::Config(format!("headless capture task join error: {e}")))?
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = timeout;
        Err(AgentError::Config(
            "headless capture is currently supported on Ubuntu GNOME only".to_string(),
        ))
    }
}

/// Read `RIVET_FAKE_CAPTURE` — if set, returns the requested blob size
/// (defaulting to 600 KiB when the value is not a number, exercising chunking).
#[allow(clippy::disallowed_methods)]
fn fake_capture_size() -> Option<usize> {
    std::env::var("RIVET_FAKE_CAPTURE")
        .ok()
        .map(|v| v.parse::<usize>().unwrap_or(600 * 1024))
}

/// Deterministic pseudo-image bytes for testing the transport.
fn synthetic_blob(size: usize) -> Vec<u8> {
    let pattern = b"RIVETLINK-FAKE-SCREENSHOT-";
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        let remaining = size - out.len();
        let take = remaining.min(pattern.len());
        out.extend_from_slice(&pattern[..take]);
    }
    out
}

#[cfg(target_os = "macos")]
fn capture_blocking() -> AgentResult<Vec<u8>> {
    let tmp = temp_png_path();
    run(
        "screencapture",
        &["-x", "-t", "png", tmp.to_str().unwrap_or("/tmp/rivet.png")],
    )?;
    read_and_cleanup(&tmp)
}

#[cfg(target_os = "windows")]
fn capture_blocking() -> AgentResult<Vec<u8>> {
    let tmp = temp_png_path();
    let path = tmp.to_string_lossy().replace('\'', "");
    let script = format!(
        "Add-Type -AssemblyName System.Windows.Forms,System.Drawing; \
         $b=[System.Windows.Forms.SystemInformation]::VirtualScreen; \
         $bmp=New-Object System.Drawing.Bitmap $b.Width,$b.Height; \
         $g=[System.Drawing.Graphics]::FromImage($bmp); \
         $g.CopyFromScreen($b.Location,[System.Drawing.Point]::Empty,$b.Size); \
         $bmp.Save('{path}',[System.Drawing.Imaging.ImageFormat]::Png)"
    );
    run("powershell", &["-NoProfile", "-Command", &script])?;
    read_and_cleanup(&tmp)
}

#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
fn capture_blocking() -> AgentResult<Vec<u8>> {
    let tmp = temp_png_path();
    let path = tmp.to_str().unwrap_or("/tmp/rivet.png");

    // CLI fallbacks for sessions without a desktop portal (headless X11,
    // minimal wlroots). The native path is the XDG portal in `portal.rs`.
    // grim: wlroots Wayland · scrot / import: X11.
    if run("grim", &[path]).is_ok() {
        return read_and_cleanup(&tmp);
    }
    if run("scrot", &["-z", path]).is_ok() {
        return read_and_cleanup(&tmp);
    }
    if run("import", &["-window", "root", path]).is_ok() {
        return read_and_cleanup(&tmp);
    }
    Err(AgentError::Config(
        "no screen capture available (no desktop portal, and none of grim, \
         scrot, or imagemagick found), or set RIVET_FAKE_CAPTURE for headless \
         testing"
            .to_string(),
    ))
}

/// Build a unique temp PNG path.
fn temp_png_path() -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!(
        "rivet-capture-{}.png",
        uuid::Uuid::now_v7().simple()
    ));
    p
}

/// Run a command, mapping non-zero exit / spawn failure to an error.
fn run(cmd: &str, args: &[&str]) -> AgentResult<()> {
    let status = std::process::Command::new(cmd)
        .args(args)
        .status()
        .map_err(|e| AgentError::Config(format!("{cmd}: {e}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(AgentError::Config(format!("{cmd} exited with {status}")))
    }
}

/// Read the captured file and delete it.
fn read_and_cleanup(path: &std::path::Path) -> AgentResult<Vec<u8>> {
    let bytes = std::fs::read(path)?;
    let _ = std::fs::remove_file(path);
    if bytes.is_empty() {
        return Err(AgentError::Config("capture produced no data".to_string()));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_blob_has_exact_size() {
        let blob = synthetic_blob(1000);
        assert_eq!(blob.len(), 1000);
    }

    #[test]
    fn synthetic_blob_is_nonempty_pattern() {
        let blob = synthetic_blob(10);
        assert_eq!(&blob, b"RIVETLINK-");
    }

    #[tokio::test]
    async fn fake_capture_returns_blob() {
        // Use the public path with the env var set in-process.
        // (single-threaded test avoids races on the process-global env)
        std::env::set_var("RIVET_FAKE_CAPTURE", "2048");
        let bytes = capture_png().await.unwrap();
        assert_eq!(bytes.len(), 2048);
        std::env::remove_var("RIVET_FAKE_CAPTURE");
    }
}
