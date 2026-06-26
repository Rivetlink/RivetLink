//! Input injection: replay a remote controller's pointer/keyboard events onto
//! the local OS.
//!
//! Linux uses a uinput virtual device (kernel evdev layer — works under both
//! X11 and Wayland/GNOME). macOS (`CGEvent`) and Windows (`SendInput`) backends
//! are not implemented yet; on those platforms remote control is unavailable.

#[cfg(target_os = "linux")]
mod uinput;

#[cfg(target_os = "linux")]
pub use uinput::UinputInjector;
