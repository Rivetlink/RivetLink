//! Command-line interface for the support client.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// RivetLink Support Client — connect to a host and view its screen.
#[derive(Debug, Parser)]
#[command(name = "rivet-client", version, about)]
pub struct Cli {
    /// Path to the client config file.
    #[arg(long, default_value = "client-config.json")]
    pub config: PathBuf,

    #[command(subcommand)]
    pub command: Command,
}

/// Supported subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create config + identity and print this client's public key.
    Init {
        /// Relay WebSocket URL.
        #[arg(long, default_value = "ws://127.0.0.1:8080/ws")]
        relay_ws_url: String,
        /// Relay HTTP base URL.
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        relay_http_url: String,
        /// Identity file path.
        #[arg(long, default_value = "client_identity.json")]
        identity_path: PathBuf,
    },

    /// Print this client's identity public key (give it to the host to trust).
    Whoami,

    /// Log in and list devices in the organization.
    Devices {
        #[arg(long)]
        email: String,
        #[arg(long)]
        password: String,
    },

    /// Connect to a host device and capture one screenshot.
    View {
        #[arg(long)]
        email: String,
        #[arg(long)]
        password: String,
        /// Target device ID (from `devices`).
        #[arg(long)]
        device: String,
        /// Output path for the captured PNG.
        #[arg(long, default_value = "screenshot.png")]
        out: PathBuf,
        /// Don't auto-open the image in the OS viewer.
        #[arg(long)]
        no_open: bool,
    },
}
