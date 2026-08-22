//! Screen capture abstraction.
//!
//! Platform-specific backends (DXGI on Windows, PipeWire on Linux,
//! ScreenCaptureKit on macOS) plug in by implementing [`ScreenCapture`].
//! No backends are wired up yet — the trait exists to pin down the contract
//! before the heavy platform work lands.

use async_trait::async_trait;

use crate::error::AgentResult;

pub mod screenshot;

// Native desktop-portal capture (Wayland + X11), Linux only.
#[cfg(target_os = "linux")]
pub mod portal;

// Dialog-free live capture via GNOME Mutter ScreenCast + GStreamer, Linux only.
// Backs the Linux streaming path in `screencast` (scap can't talk to modern
// PipeWire daemons).
#[cfg(target_os = "linux")]
pub mod mutter;

// Native local X11 capture for an authenticated GDM/desktop session that is
// actually running under Xorg.  It deliberately uses the session cookie and
// has no disk-backed screenshot path.
#[cfg(target_os = "linux")]
pub mod x11;

// Native single-screen live capture via `scap`: ScreenCast portal + PipeWire on
// Linux, ScreenCaptureKit on macOS. Windows stays client-only for now (scap's
// Windows capture backend doesn't build), matching the app's host support.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod screencast;

/// A single captured frame as raw, owned pixel data plus its dimensions.
#[derive(Debug, Clone)]
pub struct CapturedFrame {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    /// Pixel data, format depends on the backend (BGRA on Windows etc.).
    pub data: Vec<u8>,
}

/// Backend that produces a continuous stream of frames.
#[async_trait]
pub trait ScreenCapture: Send + Sync {
    /// Start capturing. Subsequent calls to [`next_frame`] return frames.
    async fn start(&mut self) -> AgentResult<()>;

    /// Block until the next frame is available.
    async fn next_frame(&mut self) -> AgentResult<CapturedFrame>;

    /// Stop capturing and release any platform resources.
    async fn stop(&mut self) -> AgentResult<()>;
}
