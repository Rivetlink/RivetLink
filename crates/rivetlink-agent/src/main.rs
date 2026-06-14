//! `rivet-agent` binary entry point.

use clap::Parser;
use ed25519_dalek::SigningKey;
use std::time::Duration;
use tracing_subscriber::EnvFilter;

use rivetlink_agent::cli::{Cli, Command};
use rivetlink_agent::config::AgentConfig;
use rivetlink_agent::error::{AgentError, AgentResult};
use rivetlink_agent::keystore::file::FileKeyStore;
use rivetlink_agent::keystore::{KeyStore, SigningKey as KsSigningKey};
use rivetlink_agent::registration;
use rivetlink_agent::relay::RelayClient;
use rivetlink_agent::session::{ConsentPolicy, ScreenshotHost};
use rivetlink_agent::trusted::TrustedClients;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    let result = match cli.command {
        Some(Command::Init {
            relay_url,
            relay_http_url,
            device_name,
            keystore_path,
        }) => init(&cli.config, relay_url, relay_http_url, device_name, keystore_path).await,
        Some(Command::Register { token, platform }) => {
            register(&cli.config, &token, platform.as_deref()).await
        },
        Some(Command::Run { auto_accept }) => run(&cli.config, auto_accept).await,
        None => {
            eprintln!("no subcommand given — use `rivet-agent --help`");
            return std::process::ExitCode::FAILURE;
        },
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "agent failed");
            std::process::ExitCode::FAILURE
        },
    }
}

/// `init` subcommand — provision keys and write a starter config.
async fn init(
    config_path: &std::path::Path,
    relay_url: String,
    relay_http_url: String,
    device_name: String,
    keystore_path: std::path::PathBuf,
) -> AgentResult<()> {
    let cfg = AgentConfig {
        relay_url,
        relay_http_url,
        device_name,
        keystore_path: keystore_path.clone(),
        device_id: None,
        heartbeat_secs: 10,
        reconnect_cap_secs: 60,
    };
    cfg.validate()?;
    cfg.save(config_path)?;

    let store = FileKeyStore::new(keystore_path)?;
    let signing = store.ensure_signing_key().await?;
    let encryption = store.ensure_encryption_key().await?;

    println!("Agent initialized.");
    println!("  config:     {}", config_path.display());
    println!("  device:     {}", cfg.device_name);
    println!("  relay ws:   {}", cfg.relay_url);
    println!("  relay http: {}", cfg.relay_http_url);
    println!(
        "  signing pk: {}",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, signing.public)
    );
    println!(
        "  ecdh pk:    {}",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            encryption.public
        )
    );
    Ok(())
}

/// `register` subcommand — enroll this agent against the relay.
async fn register(
    config_path: &std::path::Path,
    token: &str,
    platform: Option<&str>,
) -> AgentResult<()> {
    let mut cfg = AgentConfig::load(config_path)?;
    let store = FileKeyStore::new(cfg.keystore_path.clone())?;
    let signing = store.ensure_signing_key().await?;

    let result = registration::register_device(
        &cfg.relay_http_url,
        token,
        &signing.public,
        &cfg.device_name,
        platform,
    )
    .await?;

    cfg.device_id = Some(result.device_id);
    cfg.save(config_path)?;

    println!("Device registered.");
    println!("  device_id: {}", result.device_id);
    Ok(())
}

/// `run` subcommand — connect to relay via device auth and serve sessions.
#[allow(clippy::cognitive_complexity)] // linear startup sequence
async fn run(config_path: &std::path::Path, auto_accept: bool) -> AgentResult<()> {
    let cfg = AgentConfig::load(config_path)?;
    let device_id = cfg.device_id.ok_or_else(|| {
        AgentError::Config(
            "device_id missing — run `rivet-agent register` first".to_string(),
        )
    })?;

    tracing::info!(device = %cfg.device_name, %device_id, relay = %cfg.relay_url, "agent starting");

    let store = FileKeyStore::new(cfg.keystore_path.clone())?;
    let signing = store.ensure_signing_key().await?;
    let signing_key = ed25519_signing_key(&signing)?;
    let _encryption = store.ensure_encryption_key().await?;

    // Host-owned trusted-client store lives next to the keystore.
    let trusted_path = cfg.keystore_path.join("trusted_clients.json");
    let trusted = TrustedClients::load_or_empty(&trusted_path)?;
    let policy = if auto_accept {
        tracing::warn!("auto-accept enabled — all clients will be trusted without prompting");
        ConsentPolicy::AutoAccept
    } else {
        ConsentPolicy::Prompt
    };

    let client = RelayClient::connect_device(
        &cfg.relay_url,
        device_id,
        &signing_key,
        Duration::from_secs(cfg.heartbeat_secs),
    )
    .await?;

    tracing::info!(
        trusted_clients = trusted.len(),
        "relay connected, waiting for session requests"
    );

    let mut host = ScreenshotHost::new(signing_key, trusted, policy);
    client.run_host(&mut host).await?;

    Ok(())
}

/// Convert the agent's stored signing key into an Ed25519 `SigningKey`.
fn ed25519_signing_key(stored: &KsSigningKey) -> AgentResult<SigningKey> {
    Ok(SigningKey::from_bytes(&stored.secret))
}
