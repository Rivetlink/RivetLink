//! Input injection abstraction.
//!
//! Platform backends (`SendInput` on Windows, `uinput` on Linux, `CGEvent`
//! on macOS) implement [`InputInjector`]. No backends wired up yet — only
//! the trait exists so the rest of the agent can be built against a stable
//! API.

use async_trait::async_trait;
use rivetlink_protocol::packets::InputPacket;

use crate::error::AgentResult;

/// Replays an [`InputPacket`] received from a remote controller onto the
/// local OS.
#[async_trait]
pub trait InputInjector: Send + Sync {
    /// Inject a single input event.
    async fn inject(&self, packet: InputPacket) -> AgentResult<()>;
}
