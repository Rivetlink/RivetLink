//! `rivet-client` binary entry point.

use clap::Parser;
use std::path::Path;
use tracing_subscriber::EnvFilter;

use rivetlink_client::cli::{Cli, Command};
use rivetlink_sdk::{ClientConfig, Identity, RivetClient, SdkResult};

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
) -> SdkResult<()> {
    let cfg = ClientConfig {
        relay_ws_url,
        relay_http_url,
        identity_path,
    };
    cfg.validate()?;
    cfg.save(config_path)?;

    // Build the client to load/create the identity and read its public key.
    let client = RivetClient::new(cfg.clone())?;

    println!("Client initialized.");
    println!("  config:        {}", config_path.display());
    println!("  relay ws:      {}", cfg.relay_ws_url);
    println!("  relay http:    {}", cfg.relay_http_url);
    println!("  identity:      {}", cfg.identity_path.display());
    println!("  public key:    {}", client.public_key());
    println!();
    println!("Give the public key above to the host operator if they want to");
    println!("pre-trust this client (otherwise the host will prompt on first connect).");
    Ok(())
}

/// `whoami` — print the client identity public key.
fn whoami(config_path: &Path) -> SdkResult<()> {
    let cfg = ClientConfig::load(config_path)?;
    let identity = Identity::load_or_create(&cfg.identity_path)?;
    println!("{}", identity.public_key_b64());
    Ok(())
}

/// `devices` — log in and list devices.
async fn devices(config_path: &Path, email: &str, password: &str) -> SdkResult<()> {
    let mut client = RivetClient::from_config_file(config_path)?;
    client.login(email, password).await?;
    let devices = client.list_devices().await?;

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
) -> SdkResult<()> {
    let mut client = RivetClient::from_config_file(config_path)?;
    client.login(email, password).await?;

    let target = client.find_device(device).await?;

    println!("Requesting session with host {device}…");
    println!("(the host may prompt its operator to approve this connection)");

    let path = client.capture_screenshot(&target, out).await?;
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
