//! Reusable command runner for the standalone agent and the desktop AppImage
//! worker.  Keeping the command handling here means an AppImage can run the
//! exact same, screenshot-only host agent without extracting a second binary.

use clap::Parser;
use ed25519_dalek::SigningKey;
use std::time::Duration;

use crate::cli::{Cli, Command};
use crate::config::{AgentConfig, HeadlessConfig};
use crate::error::{AgentError, AgentResult};
use crate::keystore::file::FileKeyStore;
use crate::keystore::{KeyStore, SigningKey as KsSigningKey};
use crate::lan::{self, LanAuth};
use crate::registration;
use crate::relay::RelayClient;
use crate::session::{ConsentPolicy, ScreenshotHost};
use crate::trusted::TrustedClients;

/// Parse and run an agent command. Callers are responsible for installing a
/// tracing subscriber appropriate to their process.
pub async fn run_from<I, T>(args: I) -> AgentResult<()>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    run(Cli::try_parse_from(args).map_err(|e| AgentError::Config(e.to_string()))?).await
}

/// Run a command that was already parsed by the standalone binary.
pub async fn run(cli: Cli) -> AgentResult<()> {
    match cli.command {
        Some(Command::Init {
            relay_url,
            relay_http_url,
            device_name,
            keystore_path,
            headless,
            allow_trusted_headless,
        }) => {
            init(
                &cli.config,
                InitOptions {
                    relay_url,
                    relay_http_url,
                    device_name,
                    keystore_path,
                    headless,
                    allow_trusted_headless,
                },
            )
            .await
        },
        Some(Command::Register { token, platform }) => {
            register(&cli.config, &token, platform.as_deref()).await
        },
        Some(Command::TrustClient { public_key, name }) => {
            trust_client(&cli.config, &public_key, &name)
        },
        Some(Command::Run { headless }) => run_host(&cli.config, headless).await,
        Some(Command::Lan {
            port,
            pin,
            device_name,
            keystore_path,
            auto_accept,
        }) => lan(port, pin, device_name, keystore_path, auto_accept).await,
        None => Err(AgentError::Config(
            "no subcommand given — use `rivet-agent --help`".to_string(),
        )),
    }
}

struct InitOptions {
    relay_url: String,
    relay_http_url: String,
    device_name: String,
    keystore_path: std::path::PathBuf,
    headless: bool,
    allow_trusted_headless: bool,
}

async fn init(config_path: &std::path::Path, options: InitOptions) -> AgentResult<()> {
    let cfg = AgentConfig {
        relay_url: options.relay_url,
        relay_http_url: options.relay_http_url,
        device_name: options.device_name,
        keystore_path: options.keystore_path.clone(),
        device_id: None,
        heartbeat_secs: 10,
        reconnect_cap_secs: 60,
        headless: HeadlessConfig {
            enabled: options.headless,
            allow_trusted_clients: options.allow_trusted_headless,
            ..HeadlessConfig::default()
        },
    };
    cfg.validate()?;
    cfg.save(config_path)?;

    let store = FileKeyStore::new(options.keystore_path)?;
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
    Ok(())
}

fn trust_client(config_path: &std::path::Path, public_key: &str, name: &str) -> AgentResult<()> {
    if name.trim().is_empty() {
        return Err(AgentError::Config(
            "trusted client name is required".to_string(),
        ));
    }
    let raw = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        public_key.trim(),
    )
    .map_err(|e| AgentError::Base64(e.to_string()))?;
    if raw.len() != 32 {
        return Err(AgentError::Config(
            "trusted client identity must be a 32-byte Ed25519 public key".to_string(),
        ));
    }
    let key: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| AgentError::Config("invalid trusted client key length".to_string()))?;
    ed25519_dalek::VerifyingKey::from_bytes(&key)
        .map_err(|e| AgentError::Config(format!("invalid trusted client identity: {e}")))?;
    let cfg = AgentConfig::load(config_path)?;
    let path = cfg.keystore_path.join("trusted_clients.json");
    let mut trusted = TrustedClients::load_or_empty(&path)?;
    trusted.trust(
        public_key,
        crate::trusted::TrustedEntry {
            name: name.trim().to_string(),
            can_view: true,
            can_control: false,
        },
    )?;
    println!(
        "Trusted screenshot-only client added to {}.",
        path.display()
    );
    Ok(())
}

#[allow(clippy::cognitive_complexity)]
async fn run_host(config_path: &std::path::Path, headless: bool) -> AgentResult<()> {
    let cfg = AgentConfig::load(config_path)?;
    let device_id = cfg.device_id.ok_or_else(|| {
        AgentError::Config("device_id missing — run `rivet-agent register` first".to_string())
    })?;
    tracing::info!(device = %cfg.device_name, %device_id, relay = %cfg.relay_url, "agent starting");
    let store = FileKeyStore::new(cfg.keystore_path.clone())?;
    let signing = store.ensure_signing_key().await?;
    let signing_key = ed25519_signing_key(&signing)?;
    let _encryption = store.ensure_encryption_key().await?;
    let trusted_path = cfg.keystore_path.join("trusted_clients.json");
    let trusted = TrustedClients::load_or_empty(&trusted_path)?;
    let policy = if headless {
        if !cfg.headless.enabled || !cfg.headless.allow_trusted_clients {
            return Err(AgentError::Config(
                "headless mode requires local config with headless.enabled and headless.allow_trusted_clients both set to true".to_string(),
            ));
        }
        tracing::info!(
            min_capture_interval_secs = cfg.headless.min_capture_interval_secs,
            max_capture_bytes = cfg.headless.max_capture_bytes,
            "headless screenshot-only mode enabled for pre-trusted clients"
        );
        ConsentPolicy::HeadlessTrustedOnly {
            min_capture_interval: Duration::from_secs(cfg.headless.min_capture_interval_secs),
            capture_timeout: Duration::from_secs(cfg.headless.capture_timeout_secs),
            max_capture_bytes: cfg.headless.max_capture_bytes,
        }
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
    client.run_host(&mut host).await
}

async fn lan(
    port: u16,
    pin: Option<String>,
    device_name: String,
    keystore_path: std::path::PathBuf,
    auto_accept: bool,
) -> AgentResult<()> {
    let store = FileKeyStore::new(keystore_path.clone())?;
    let signing = store.ensure_signing_key().await?;
    let signing_key = ed25519_signing_key(&signing)?;
    let auth = match pin {
        Some(pin) => LanAuth::Password(pin),
        None => {
            let trusted =
                TrustedClients::load_or_empty(&keystore_path.join("trusted_clients.json"))?;
            if auto_accept {
                tracing::warn!("auto-accept enabled — all clients trusted without prompting");
            }
            LanAuth::Key {
                trusted,
                auto_accept,
            }
        },
    };
    lan::serve(signing_key, device_name, port, auth).await
}

fn ed25519_signing_key(stored: &KsSigningKey) -> AgentResult<SigningKey> {
    Ok(SigningKey::from_bytes(&stored.secret))
}

#[cfg(test)]
mod tests {
    use super::run_from;

    #[tokio::test]
    async fn runner_requires_an_explicit_command() {
        let error = run_from(["rivet-agent"]).await.unwrap_err();
        assert!(error.to_string().contains("no subcommand given"));
    }
}
