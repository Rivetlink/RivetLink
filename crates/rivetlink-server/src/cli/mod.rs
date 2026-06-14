//! Command-line interface for the RivetLink relay server.
//!
//! Exposes the `init` subcommand for first-time provisioning (generates a
//! `.env` file with a cryptographically random `JWT_SECRET`) and the
//! `serve` subcommand (the default) for actually running the server.

use clap::{Parser, Subcommand};

pub mod init;

/// RivetLink Relay Server — zero-trust signaling for remote desktop sessions.
#[derive(Debug, Parser)]
#[command(name = "rivet-relay", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Available subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate a `.env` file with a random JWT secret and sensible defaults.
    Init(init::InitArgs),

    /// Run the relay server (default when no subcommand is given).
    Serve,
}
