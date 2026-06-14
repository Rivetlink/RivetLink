//! RivetLink Support Client library.
//!
//! Drives a support session against a host device through the relay: logs in,
//! lists devices, and runs the encrypted screenshot handshake.

pub mod cli;
pub mod config;
pub mod error;
pub mod identity;
pub mod rest;
pub mod session;
