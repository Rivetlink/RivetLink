//! Command-line interface for the host agent.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// RivetLink Host Agent — runs on the controlled machine.
#[derive(Debug, Parser)]
#[command(name = "rivet-agent", version, about)]
pub struct Cli {
    /// Path to the agent's configuration file.
    #[arg(long, default_value = "config.json")]
    pub config: PathBuf,

    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Supported subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate or refresh the keystore and write a starter config file.
    Init {
        /// Relay server WebSocket URL.
        #[arg(long, default_value = "ws://127.0.0.1:8080/ws")]
        relay_url: String,

        /// Relay server HTTP base URL for REST calls (register etc.).
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        relay_http_url: String,

        /// Device display name reported to the relay.
        #[arg(long)]
        device_name: String,

        /// Keystore directory.
        #[arg(long, default_value = "keys")]
        keystore_path: PathBuf,

        /// Configure this host for the dedicated virtual GNOME monitor. This
        /// alone does not grant unattended access.
        #[arg(long)]
        headless: bool,

        /// Explicitly permit already trusted, view-authorized clients when
        /// running in headless mode. Requires `--headless`.
        #[arg(long, requires = "headless")]
        allow_trusted_headless: bool,
    },

    /// Enroll this agent as a device on the relay.
    ///
    /// Performs a one-shot REST call against `/devices/register` using the
    /// supplied user JWT. The returned `device_id` is persisted into the
    /// agent's config file so that subsequent `run` invocations can
    /// authenticate via DEVICE_HELLO / DEVICE_AUTH.
    Register {
        /// User access token used to authorize the registration request.
        #[arg(long)]
        token: String,

        /// Optional platform string (`linux`, `macos`, `windows`).
        #[arg(long)]
        platform: Option<String>,
    },

    /// Locally pre-trust a support-client identity for screenshot viewing.
    /// This command never grants input, file, shell, or administrative access.
    TrustClient {
        /// Base64 Ed25519 public identity from `rivet-client whoami`.
        #[arg(long)]
        public_key: String,

        /// Human-readable local label written to the trusted-client store.
        #[arg(long)]
        name: String,
    },

    /// Connect to the relay and run until disconnected (device auth).
    ///
    /// The agent must have been registered first — `device_id` is read
    /// from the config file and the agent's stored Ed25519 key signs the
    /// challenge.
    Run {
        /// Use the locally configured virtual GNOME monitor. Only a known
        /// client with `can_view` can be admitted, and only after the owner has
        /// enabled `allow_trusted_clients` in the local config.
        #[arg(long)]
        headless: bool,
    },

    /// Serve direct-LAN sessions: advertise on the local network and accept
    /// connections without a relay. Standalone — no `init`/`register` or relay
    /// config needed; the keystore is created on first run if absent.
    Lan {
        /// TCP port to listen on (0 = pick a free port, announced via mDNS).
        #[arg(long, default_value_t = 0)]
        port: u16,

        /// Shared PIN for password (PAKE) auth. If set, clients authenticate
        /// with this PIN. If omitted, key-mode (TOFU) auth is used against the
        /// trusted-clients store.
        #[arg(long)]
        pin: Option<String>,

        /// Friendly name advertised on the network.
        #[arg(long, default_value = "RivetLink Host")]
        device_name: String,

        /// Keystore directory (created if it does not exist).
        #[arg(long, default_value = "keys")]
        keystore_path: PathBuf,

        /// In key mode, auto-accept and trust any client without prompting.
        /// Unattended / testing only.
        #[arg(long)]
        auto_accept: bool,
    },
}
