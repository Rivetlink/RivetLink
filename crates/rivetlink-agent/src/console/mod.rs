//! Physical-console lifecycle support for unattended Ubuntu hosts.
//!
//! The broker and per-session workers use this small, platform-neutral state
//! machine to distinguish a reboot from normal ownership transitions such as
//! GDM → GNOME, lock/unlock, and logout. OS discovery stays outside this module
//! so it can be tested without a running display manager.

pub mod state;

// This runs inside GDM's or the logged-in user's existing GNOME session. It
// deliberately has no relay credentials or elevated device access: it accepts
// bounded capture and normalized input for the session that owns the physical
// console, plus — in a logged-in desktop only — text clipboard and transfers
// confined to ~/Downloads/RivetLink.
#[cfg(target_os = "linux")]
pub mod broker;

// The LightDM integration is a deliberately tiny root-only launcher. It
// discovers LightDM's own greeter process, then drops to that greeter account
// before starting the ordinary X11 worker. It never captures or injects input
// while privileged.
#[cfg(target_os = "linux")]
pub mod lightdm;

#[cfg(target_os = "linux")]
pub mod worker;

// Clipboard and shared-folder support for the logged-in desktop session. Both
// run inside the worker (as the logged-in user) and are only reachable after
// the broker's trusted-client and remote-control checks.
#[cfg(target_os = "linux")]
pub mod clipboard;
#[cfg(target_os = "linux")]
pub mod shared_folder;

pub use state::{ConsoleObservation, ConsoleStateMachine};
