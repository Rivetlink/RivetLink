//! Input injection: replay a remote controller's pointer/keyboard events onto
//! the local OS.
//!
//! Linux uses GNOME Mutter's RemoteDesktop D-Bus API — no kernel device, no
//! `/dev/uinput`, no setup (the compositor injects the events, the same
//! dialog-free path family as our ScreenCast capture). macOS (`CGEvent`) and
//! Windows (`SendInput`) backends are not implemented yet; on those platforms
//! remote control is unavailable.

#[cfg(target_os = "linux")]
pub(crate) mod mutter;

#[cfg(target_os = "linux")]
pub(crate) mod x11;

#[cfg(target_os = "linux")]
pub use mutter::{injected_click_age_ms, InputAction, InputHandle};
