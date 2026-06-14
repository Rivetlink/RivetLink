//! `rivet-client` binary entry point.

use clap::Parser;
use std::path::Path;
use tracing_subscriber::EnvFilter;

use rivetlink_client::cli::{Cli, Command};
use rivetlink_client::config::ClientConfig;
use rivetlink_client::error::{ClientError, ClientResult};
use rivetlink_client::identity::ClientIdentity;
use rivetlink_client::rest;
use rivetlink_client::session::{self, SessionRequest};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    let result = match cli.command {
        Command::Init {
            relay_ws_url,
            relay_http_url,
            identity_path,
        } => init(&cli.config, relay_ws_url, relay_http_url, identity_path),
        Command::Whoami => whoami(&cli.config),
        Command::Devices { email, password } => devices(&cli.config, &email, &password).await,
        Command::View {
            email,
            password,
            device,
            out,
            no_open,
        } => view(&cli.config, &email, &password, &device, out, no_open).await,
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "client failed");
            eprintln!("error: {e}");
            std::process::ExitCode::FAILURE
        },
    }
}

/// `init` — write config + create identity, print public key.
fn init(
    config_path: &Path,
    relay_ws_url: String,
    relay_http_url: String,
    identity_path: std::path::PathBuf,
) -> ClientResult<()> {
    let cfg = ClientConfig {
        relay_ws_url,
        relay_http_url,
        identity_path,
    };
    cfg.validate()?;
    cfg.save(config_path)?;

    let identity = ClientIdentity::load_or_create(&cfg.identity_path)?;

    println!("Client initialized.");
    println!("  config:        {}", config_path.display());
    println!("  relay ws:      {}", cfg.relay_ws_url);
    println!("  relay http:    {}", cfg.relay_http_url);
    println!("  identity:      {}", cfg.identity_path.display());
    println!("  public key:    {}", identity.public_key_b64());
    println!();
    println!("Give the public key above to the host operator if they want to");
    println!("pre-trust this client (otherwise the host will prompt on first connect).");
    Ok(())
}

/// `whoami` — print the client identity public key.
fn whoami(config_path: &Path) -> ClientResult<()> {
    let cfg = ClientConfig::load(config_path)?;
    let identity = ClientIdentity::load_or_create(&cfg.identity_path)?;
    println!("{}", identity.public_key_b64());
    Ok(())
}

/// `devices` — log in and list devices.
async fn devices(config_path: &Path, email: &str, password: &str) -> ClientResult<()> {
    let cfg = ClientConfig::load(config_path)?;
    let token = rest::login(&cfg.relay_http_url, email, password).await?;
    let devices = rest::list_devices(&cfg.relay_http_url, &token).await?;

    if devices.is_empty() {
        println!("No devices registered in your organization yet.");
        return Ok(());
    }

    println!("{:<38}  {:<20}  {:<10}  LAST SEEN", "DEVICE ID", "HOSTNAME", "PLATFORM");
    for d in devices {
        println!(
            "{:<38}  {:<20}  {:<10}  {}",
            d.id,
            d.hostname.unwrap_or_else(|| "-".to_string()),
            d.platform.unwrap_or_else(|| "-".to_string()),
            d.last_seen.unwrap_or_else(|| "never".to_string()),
        );
    }
    Ok(())
}

/// `view` — capture one screenshot from a host and open it.
async fn view(
    config_path: &Path,
    email: &str,
    password: &str,
    device: &str,
    out: std::path::PathBuf,
    no_open: bool,
) -> ClientResult<()> {
    let cfg = ClientConfig::load(config_path)?;
    let identity = ClientIdentity::load_or_create(&cfg.identity_path)?;

    let token = rest::login(&cfg.relay_http_url, email, password).await?;
    let device_list = rest::list_devices(&cfg.relay_http_url, &token).await?;
    let target = device_list
        .iter()
        .find(|d| d.id == device)
        .ok_or_else(|| ClientError::Config(format!("device {device} not found in your org")))?;

    let device_id = uuid::Uuid::parse_str(device)
        .map_err(|e| ClientError::Config(format!("invalid device id: {e}")))?;

    println!("Requesting session with host {device}…");
    println!("(the host may prompt its operator to approve this connection)");

    let path = session::capture_screenshot(SessionRequest {
        relay_ws_url: &cfg.relay_ws_url,
        token: &token,
        identity: &identity,
        device_id,
        host_public_key_b64: &target.public_key,
        output_path: out,
    })
    .await?;

    println!("Screenshot saved to {}", path.display());

    if !no_open {
        open_in_viewer(&path);
    }
    Ok(())
}

/// Open a file in the platform's default viewer (best-effort).
fn open_in_viewer(path: &Path) {
    #[cfg(target_os = "macos")]
    let cmd = "open";
    #[cfg(target_os = "windows")]
    let cmd = "explorer";
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    let cmd = "xdg-open";

    match std::process::Command::new(cmd).arg(path).spawn() {
        Ok(_) => {},
        Err(e) => tracing::warn!(error = %e, "could not open viewer; file is saved on disk"),
    }
}
