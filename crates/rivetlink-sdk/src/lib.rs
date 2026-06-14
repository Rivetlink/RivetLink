//! RivetLink SDK — high-level client for building support tooling on top of
//! the RivetLink relay.
//!
//! The [`RivetClient`] facade handles login, device listing, and the
//! end-to-end encrypted session handshake. Lower-level modules ([`rest`],
//! [`session`], [`identity`], [`config`]) are exposed for advanced use, but
//! most integrators only need [`RivetClient`].
//!
//! Security model: the server is never a trusted authority. The host decides
//! who connects (TOFU); session content is end-to-end encrypted and the relay
//! sees only ciphertext. See the module docs of [`session`] for the handshake
//! state machine.

pub mod config;
pub mod direct;
pub mod error;
pub mod identity;
pub mod lan;
pub mod rest;
pub mod session;

mod client;

pub use client::RivetClient;
pub use config::ClientConfig;
pub use error::{SdkError, SdkResult};
pub use identity::Identity;
pub use lan::{Advertiser, LanDevice, LanRequest, LanResponse};
pub use rest::Device;

// Re-export the wire vocabulary integrators may need without depending on the
// lower-level crates directly.
pub use rivetlink_core::{ConnectionMode, DeviceId, SessionId, SessionRole};
pub use rivetlink_protocol::{InputPacket, SignalPacket};
