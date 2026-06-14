//! Screen capture abstraction.
//!
//! Platform-specific backends (DXGI on Windows, PipeWire on Linux,
//! ScreenCaptureKit on macOS) plug in by implementing [`ScreenCapture`].
//! No backends are wired up yet — the trait exists to pin down the contract
//! before the heavy platform work lands.

use async_trait::async_trait;

use crate::error::AgentResult;

pub mod screenshot;

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
