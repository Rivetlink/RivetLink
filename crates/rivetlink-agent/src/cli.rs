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

        /// Configure this host for a physical unattended console. This alone
        /// does not grant unattended access.
        #[arg(long, visible_alias = "headless")]
        unattended_console: bool,

        /// Explicitly permit already trusted, view-authorized clients when
        /// running in unattended-console mode. Requires
        /// `--unattended-console`.
        #[arg(
            long,
            visible_alias = "allow-trusted-headless",
            requires = "unattended_console"
        )]
        allow_trusted_unattended_console: bool,

        /// Also expose the physical console over the authenticated direct LAN
        /// transport. This never enables PIN/TOFU pairing.
        #[arg(long)]
        enable_lan: bool,

        /// Do not enable the relay transport. Required for a LAN-only install
        /// without relay credentials.
        #[arg(long)]
        disable_relay: bool,

        /// TCP port for direct-LAN physical-console access.
        #[arg(long, default_value_t = 47823)]
        lan_port: u16,
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

    /// Print this agent's long-term public identity key. This exposes no
    /// secret and lets a desktop installer register the device without passing
    /// its relay token to a privileged command.
    PublicKey,

    /// Persist a device id returned by an already authenticated relay client.
    /// This changes only the local RivetLink config; it is not a generic RPC.
    SetDeviceId {
        #[arg(long)]
        device_id: uuid::Uuid,
    },

    /// Print the already registered device id. This exposes no secret and is
    /// used by the desktop installer to repair an interrupted enrolment.
    DeviceId,

    /// Set the explicit transport exposure of an existing physical-console
    /// broker. This command changes no trust entries or relay registration.
    ConfigureConsoleTransports {
        #[arg(long)]
        lan: bool,
        #[arg(long)]
        relay: bool,
        #[arg(long, default_value_t = 47823)]
        lan_port: u16,
    },

    /// Locally pre-trust a support-client identity. Console input is impossible
    /// unless both explicit unattended flags are supplied; file, shell, and
    /// administrative access are never granted by this command.
    TrustClient {
        /// Base64 Ed25519 public identity from `rivet-client whoami`.
        #[arg(long)]
        public_key: String,

        /// Human-readable local label written to the trusted-client store.
        #[arg(long)]
        name: String,

        /// Explicitly opt this already trusted client into unattended physical
        /// console viewing. This flag alone never grants input control.
        #[arg(long)]
        allow_unattended_console: bool,

        /// Also grant normalized pointer/keyboard input for the unattended
        /// console. Requires the explicit unattended-console opt-in.
        #[arg(long, requires = "allow_unattended_console")]
        allow_console_control: bool,
    },

    /// Connect to the relay and run until disconnected (device auth).
    ///
    /// The agent must have been registered first — `device_id` is read
    /// from the config file and the agent's stored Ed25519 key signs the
    /// challenge.
    Run {
        /// Use the locally configured unattended-console policy. Only a known
        /// client with explicit physical-console permission can be admitted.
        #[arg(long, visible_alias = "headless")]
        unattended_console: bool,
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

    /// Run the narrow GDM/GNOME session worker for a system console broker.
    /// This command must be launched by the active graphical session, never as
    /// a root system service. It has no relay credentials or shell API.
    ConsoleWorker {
        /// Broker-owned Unix socket path. The broker pre-creates it with
        /// restrictive owner/group permissions.
        #[arg(long)]
        socket: PathBuf,
    },

    /// Start the narrowly scoped LightDM greeter-worker launcher. This command
    /// is called only by a root-owned LightDM setup hook installed by RivetLink.
    #[command(hide = true)]
    ConsoleLightdmGreeterStart,

    /// Internal detached half of the LightDM launcher. It accepts only a
    /// locally validated X11 display from its parent command.
    #[command(hide = true)]
    ConsoleLightdmGreeterWatch {
        #[arg(long)]
        display: String,
    },

    /// Stop the fixed LightDM worker recorded in RivetLink's protected runtime
    /// directory. This has no arbitrary PID or command parameter.
    #[command(hide = true)]
    ConsoleLightdmGreeterStop,

    /// Run the non-root relay broker for one authenticated GDM/GNOME worker.
    /// This is intentionally separate from `console-worker`: the broker owns
    /// network identity but never accesses Mutter directly.
    ConsoleBroker {
        /// Broker-owned Unix socket path in a protected system runtime dir.
        #[arg(long)]
        socket: PathBuf,

        /// Numeric UID allowed to attach as the GDM or configured desktop
        /// worker. May be supplied once for GDM and once for the desktop user.
        #[arg(long = "allowed-worker-uid", required = true)]
        allowed_worker_uids: Vec<u32>,
    },
}
