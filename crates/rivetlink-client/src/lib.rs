//! RivetLink Support Client.
//!
//! A thin CLI over [`rivetlink_sdk`]: parses arguments and drives the SDK's
//! `RivetClient` to log in, list devices, and run the encrypted screenshot
//! handshake against a host device. All the protocol/crypto logic lives in
//! the SDK so the desktop app and third-party integrators share one codebase.

pub mod cli;
