//! Reusable command runner for the standalone agent and the desktop AppImage
//! worker.  Keeping the command handling here means an AppImage can run the
//! exact same, screenshot-only host agent without extracting a second binary.

use clap::Parser;
use ed25519_dalek::SigningKey;
use std::time::Duration;

use crate::cli::{Cli, Command};
use crate::config::{
    AgentConfig, ConsoleTransportConfig, LanConsoleTransportConfig, RelayConsoleTransportConfig,
    UnattendedConsoleConfig,
};
use crate::error::{AgentError, AgentResult};
use crate::keystore::file::FileKeyStore;
use crate::keystore::{KeyStore, SigningKey as KsSigningKey};
use crate::lan::{self, LanAuth};
use crate::registration;
use crate::relay::RelayClient;
use crate::session::{
    ConsentPolicy, ConsoleInputSink, ConsoleStateProvider, LocalScreenshotCapturer,
    ScreenshotCapturer, ScreenshotHost,
};
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
            unattended_console,
            allow_trusted_unattended_console,
            enable_lan,
            disable_relay,
            lan_port,
        }) => {
            init(
                &cli.config,
                InitOptions {
                    relay_url,
                    relay_http_url,
                    device_name,
                    keystore_path,
                    unattended_console,
                    allow_trusted_unattended_console,
                    enable_lan,
                    disable_relay,
                    lan_port,
                },
            )
            .await
        },
        Some(Command::Register { token, platform }) => {
            register(&cli.config, &token, platform.as_deref()).await
        },
        Some(Command::PublicKey) => public_key(&cli.config).await,
        Some(Command::SetDeviceId { device_id }) => set_device_id(&cli.config, device_id),
        Some(Command::DeviceId) => device_id(&cli.config),
        Some(Command::ConfigureConsoleTransports {
            lan,
            relay,
            lan_port,
        }) => configure_console_transports(&cli.config, lan, relay, lan_port),
        Some(Command::TrustClient {
            public_key,
            name,
            allow_unattended_console,
            allow_console_control,
        }) => trust_client(
            &cli.config,
            &public_key,
            &name,
            allow_unattended_console,
            allow_console_control,
        ),
        Some(Command::Run { unattended_console }) => {
            run_host(&cli.config, unattended_console).await
        },
        Some(Command::Lan {
            port,
            pin,
            device_name,
            keystore_path,
            auto_accept,
        }) => lan(port, pin, device_name, keystore_path, auto_accept).await,
        Some(Command::ConsoleWorker { socket }) => console_worker(&socket).await,
        Some(Command::ConsoleBroker {
            socket,
            allowed_worker_uids,
        }) => console_broker(&cli.config, &socket, allowed_worker_uids).await,
        None => Err(AgentError::Config(
            "no subcommand given — use `rivet-agent --help`".to_string(),
        )),
    }
}

async fn console_worker(socket: &std::path::Path) -> AgentResult<()> {
    #[cfg(target_os = "linux")]
    {
        crate::console::worker::run(socket).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = socket;
        Err(AgentError::Config(
            "console worker is supported on Ubuntu GNOME only".to_string(),
        ))
    }
}

async fn console_broker(
    config_path: &std::path::Path,
    socket: &std::path::Path,
    allowed_worker_uids: Vec<u32>,
) -> AgentResult<()> {
    #[cfg(target_os = "linux")]
    {
        let allowed_worker_uids = allowed_worker_uids.into_iter().collect();
        let listener =
            crate::console::broker::ConsoleBrokerListener::bind(socket, allowed_worker_uids)?;
        tracing::info!("console broker waiting for an authenticated graphical worker");
        let capturer = listener.into_pool();
        capturer.wait_until_ready().await?;
        run_physical_console_broker(config_path, capturer).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (config_path, socket, allowed_worker_uids);
        Err(AgentError::Config(
            "console broker is supported on Ubuntu GNOME only".to_string(),
        ))
    }
}

struct InitOptions {
    relay_url: String,
    relay_http_url: String,
    device_name: String,
    keystore_path: std::path::PathBuf,
    unattended_console: bool,
    allow_trusted_unattended_console: bool,
    enable_lan: bool,
    disable_relay: bool,
    lan_port: u16,
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
        unattended_console: UnattendedConsoleConfig {
            enabled: options.unattended_console,
            allow_trusted_clients: options.allow_trusted_unattended_console,
            ..UnattendedConsoleConfig::default()
        },
        console_transports: ConsoleTransportConfig {
            lan: LanConsoleTransportConfig {
                enabled: options.enable_lan,
                port: options.lan_port,
                ..LanConsoleTransportConfig::default()
            },
            relay: RelayConsoleTransportConfig {
                enabled: !options.disable_relay,
            },
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
    if cfg.console_transports.relay.enabled {
        println!("  relay ws:   {}", cfg.relay_url);
        println!("  relay http: {}", cfg.relay_http_url);
    }
    if cfg.console_transports.lan.enabled {
        println!(
            "  LAN:        {}:{}",
            cfg.console_transports.lan.bind_address, cfg.console_transports.lan.port
        );
    }
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

async fn public_key(config_path: &std::path::Path) -> AgentResult<()> {
    let cfg = AgentConfig::load(config_path)?;
    let store = FileKeyStore::new(cfg.keystore_path)?;
    let signing = store.ensure_signing_key().await?;
    println!(
        "{}",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, signing.public)
    );
    Ok(())
}

fn set_device_id(config_path: &std::path::Path, device_id: uuid::Uuid) -> AgentResult<()> {
    let mut cfg = AgentConfig::load(config_path)?;
    cfg.device_id = Some(device_id);
    cfg.save(config_path)
}

fn device_id(config_path: &std::path::Path) -> AgentResult<()> {
    let cfg = AgentConfig::load(config_path)?;
    let device_id = cfg
        .device_id
        .ok_or_else(|| AgentError::Config("device_id is not registered yet".to_string()))?;
    println!("{device_id}");
    Ok(())
}

fn configure_console_transports(
    config_path: &std::path::Path,
    lan: bool,
    relay: bool,
    lan_port: u16,
) -> AgentResult<()> {
    let mut cfg = AgentConfig::load(config_path)?;
    if !lan && !relay {
        return Err(AgentError::Config(
            "select at least one console transport".to_string(),
        ));
    }
    cfg.console_transports.lan.enabled = lan;
    cfg.console_transports.lan.port = lan_port;
    cfg.console_transports.relay.enabled = relay;
    cfg.validate()?;
    cfg.save(config_path)
}

fn trust_client(
    config_path: &std::path::Path,
    public_key: &str,
    name: &str,
    allow_unattended_console: bool,
    allow_console_control: bool,
) -> AgentResult<()> {
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
            can_control: allow_console_control,
            can_unattended_console: allow_unattended_console,
        },
    )?;
    println!("Trusted client added to {}.", path.display());
    Ok(())
}

#[allow(clippy::cognitive_complexity)]
async fn run_host(config_path: &std::path::Path, headless: bool) -> AgentResult<()> {
    run_host_with_capturer(config_path, headless, false, || {
        (Box::<LocalScreenshotCapturer>::default(), None, None)
    })
    .await
}

async fn run_host_with_capturer<F>(
    config_path: &std::path::Path,
    headless: bool,
    physical_console: bool,
    capturer_factory: F,
) -> AgentResult<()>
where
    F: Fn() -> (
        Box<dyn ScreenshotCapturer>,
        Option<Box<dyn ConsoleInputSink>>,
        Option<Box<dyn ConsoleStateProvider>>,
    ),
{
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
        if !cfg.unattended_console.enabled || !cfg.unattended_console.allow_trusted_clients {
            return Err(AgentError::Config(
                "unattended console requires local config with unattended_console.enabled and unattended_console.allow_trusted_clients both set to true".to_string(),
            ));
        }
        tracing::info!(
            min_capture_interval_secs = cfg.unattended_console.min_capture_interval_secs,
            max_capture_bytes = cfg.unattended_console.max_capture_bytes,
            physical_console,
            "unattended screenshot mode enabled for pre-trusted clients"
        );
        let min_capture_interval =
            Duration::from_secs(cfg.unattended_console.min_capture_interval_secs);
        let capture_timeout = Duration::from_secs(cfg.unattended_console.capture_timeout_secs);
        let max_capture_bytes = cfg.unattended_console.max_capture_bytes;
        if physical_console {
            ConsentPolicy::UnattendedConsole {
                min_capture_interval,
                capture_timeout,
                max_capture_bytes,
            }
        } else {
            ConsentPolicy::HeadlessTrustedOnly {
                min_capture_interval,
                capture_timeout,
                max_capture_bytes,
            }
        }
    } else {
        ConsentPolicy::Prompt
    };
    // A host in a cupboard must recover from a relay, DNS, or Ethernet outage
    // without waiting for an interactive desktop session (or systemd's restart
    // budget). Each successful relay connection gets fresh session state; the
    // device identity and local trust store remain unchanged.
    let mut failed_attempts = 0_u32;
    loop {
        match RelayClient::connect_device(
            &cfg.relay_url,
            device_id,
            &signing_key,
            Duration::from_secs(cfg.heartbeat_secs),
        )
        .await
        {
            Ok(client) => {
                failed_attempts = 0;
                tracing::info!(
                    trusted_clients = trusted.len(),
                    "relay connected, waiting for session requests"
                );
                let (capturer, input_sink, console_state_provider) = capturer_factory();
                let mut host = ScreenshotHost::new(signing_key.clone(), trusted.clone(), policy)
                    .with_capturer(capturer);
                if let Some(input_sink) = input_sink {
                    host = host.with_console_input_sink(input_sink);
                }
                if let Some(provider) = console_state_provider {
                    host = host.with_console_state_provider(provider);
                }
                if let Err(error) = client.run_host(&mut host).await {
                    tracing::warn!(error = %error, "relay session ended; reconnecting");
                } else {
                    tracing::info!("relay connection closed; reconnecting");
                }
            },
            Err(error) => {
                tracing::warn!(error = %error, "relay connection failed; retrying");
            },
        }

        let delay = reconnect_delay(failed_attempts);
        failed_attempts = failed_attempts.saturating_add(1);
        tokio::time::sleep(delay).await;
    }
}

/// Start the single physical-console broker source through every explicitly
/// configured transport. Capture, input, state and trust stay shared; LAN and
/// relay differ only in how an authenticated session reaches this function.
#[cfg(target_os = "linux")]
async fn run_physical_console_broker(
    config_path: &std::path::Path,
    source: crate::console::broker::ConsoleWorkerPool,
) -> AgentResult<()> {
    let cfg = AgentConfig::load(config_path)?;
    if !cfg.unattended_console.enabled || !cfg.unattended_console.allow_trusted_clients {
        return Err(AgentError::Config(
            "physical console requires local unattended_console.enabled and unattended_console.allow_trusted_clients".to_string(),
        ));
    }
    let store = FileKeyStore::new(cfg.keystore_path.clone())?;
    let signing = store.ensure_signing_key().await?;
    let signing_key = ed25519_signing_key(&signing)?;
    let _encryption = store.ensure_encryption_key().await?;
    let trusted_path = cfg.keystore_path.join("trusted_clients.json");
    let trusted = TrustedClients::load_or_empty(&trusted_path)?;
    let policy = physical_console_policy(&cfg);

    tracing::info!(
        lan = cfg.console_transports.lan.enabled,
        relay = cfg.console_transports.relay.enabled,
        "physical-console broker started"
    );
    let mut transports = tokio::task::JoinSet::new();
    if cfg.console_transports.lan.enabled {
        transports.spawn(run_lan_physical_console(
            signing_key.clone(),
            cfg.device_name.clone(),
            cfg.console_transports.lan.clone(),
            trusted.clone(),
            cfg.unattended_console.clone(),
            source.clone(),
        ));
    }
    if cfg.console_transports.relay.enabled {
        let device_id = cfg.device_id.ok_or_else(|| {
            AgentError::Config(
                "device_id missing — register the relay transport before enabling it".to_string(),
            )
        })?;
        transports.spawn(run_relay_physical_console(
            cfg.clone(),
            device_id,
            signing_key,
            trusted,
            policy,
            source,
        ));
    }
    // Both transport supervisors are intentionally long-running and retry
    // independently. One unavailable route must not make the other route or
    // its trust policy disappear.
    match transports.join_next().await {
        Some(Ok(result)) => result,
        Some(Err(error)) => Err(AgentError::Config(format!(
            "physical-console transport crashed: {error}"
        ))),
        None => Err(AgentError::Config(
            "no physical-console transport enabled".to_string(),
        )),
    }
}

#[cfg(target_os = "linux")]
async fn run_lan_physical_console(
    signing_key: SigningKey,
    device_name: String,
    transport: LanConsoleTransportConfig,
    trusted: TrustedClients,
    limits: UnattendedConsoleConfig,
    source: crate::console::broker::ConsoleWorkerPool,
) -> AgentResult<()> {
    loop {
        if let Err(error) = lan::serve_physical_console(
            signing_key.clone(),
            device_name.clone(),
            transport.clone(),
            trusted.clone(),
            limits.clone(),
            source.clone(),
        )
        .await
        {
            tracing::warn!(error = %error, "physical-console LAN listener failed; retrying");
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

#[cfg(target_os = "linux")]
fn physical_console_policy(cfg: &AgentConfig) -> ConsentPolicy {
    ConsentPolicy::UnattendedConsole {
        min_capture_interval: Duration::from_secs(cfg.unattended_console.min_capture_interval_secs),
        capture_timeout: Duration::from_secs(cfg.unattended_console.capture_timeout_secs),
        max_capture_bytes: cfg.unattended_console.max_capture_bytes,
    }
}

#[cfg(target_os = "linux")]
async fn run_relay_physical_console(
    cfg: AgentConfig,
    device_id: uuid::Uuid,
    signing_key: SigningKey,
    trusted: TrustedClients,
    policy: ConsentPolicy,
    source: crate::console::broker::ConsoleWorkerPool,
) -> AgentResult<()> {
    let mut failed_attempts = 0_u32;
    loop {
        match RelayClient::connect_device(
            &cfg.relay_url,
            device_id,
            &signing_key,
            Duration::from_secs(cfg.heartbeat_secs),
        )
        .await
        {
            Ok(client) => {
                failed_attempts = 0;
                tracing::info!("physical-console relay connected, waiting for trusted sessions");
                let mut host = ScreenshotHost::new(signing_key.clone(), trusted.clone(), policy)
                    .with_capturer(Box::new(source.clone()))
                    .with_console_input_sink(Box::new(source.clone()))
                    .with_console_state_provider(Box::new(source.clone()));
                if let Err(error) = client.run_host(&mut host).await {
                    tracing::warn!(error = %error, "physical-console relay session ended; reconnecting");
                }
            },
            Err(error) => {
                tracing::warn!(error = %error, "physical-console relay connection failed; retrying")
            },
        }
        let delay = reconnect_delay(failed_attempts);
        failed_attempts = failed_attempts.saturating_add(1);
        tokio::time::sleep(delay).await;
    }
}

/// Bounded exponential reconnect delay: 1, 2, 4, 8, 16, then 30 seconds.
/// Keeping this deterministic makes the recovery behavior testable and avoids
/// a tight reconnect loop when a relay is intentionally offline.
fn reconnect_delay(failed_attempts: u32) -> Duration {
    let seconds = match failed_attempts {
        0..=4 => 1_u64 << failed_attempts,
        _ => 30,
    };
    Duration::from_secs(seconds)
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
    use super::{reconnect_delay, run_from};

    #[tokio::test]
    async fn runner_requires_an_explicit_command() {
        let error = run_from(["rivet-agent"]).await.unwrap_err();
        assert!(error.to_string().contains("no subcommand given"));
    }

    #[test]
    fn relay_reconnect_backoff_is_bounded() {
        assert_eq!(reconnect_delay(0), std::time::Duration::from_secs(1));
        assert_eq!(reconnect_delay(3), std::time::Duration::from_secs(8));
        assert_eq!(reconnect_delay(4), std::time::Duration::from_secs(16));
        assert_eq!(reconnect_delay(5), std::time::Duration::from_secs(30));
        assert_eq!(reconnect_delay(100), std::time::Duration::from_secs(30));
    }
}
