//! Direct-LAN host: advertise via mDNS and serve screenshot sessions over TCP.
//!
//! No relay involved. The agent binds a TCP listener, advertises itself on the
//! local network (`_rivetlink._tcp`), and for each incoming connection runs the
//! SDK's direct handshake (PIN/PAKE or key/TOFU) to derive an end-to-end
//! encrypted channel, then serves screenshot requests over it.

use std::sync::Arc;
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::SigningKey;
use socket2::{SockRef, TcpKeepalive};
use tokio::io::AsyncWrite;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::Sender;
use tokio::sync::Semaphore;
use tokio::sync::{oneshot, watch};

use rivetlink_crypto::sealed::SealedChannel;
#[cfg(target_os = "linux")]
use rivetlink_protocol::{ConsoleInputPacket, HostConsoleState};
use rivetlink_sdk::direct;
use rivetlink_sdk::identity::Identity;
use rivetlink_sdk::lan::{
    self, Advertiser, DisplayInfo, LanRequest, LanResponse, PROTOCOL_VERSION,
};

use crate::capture::screenshot;
#[cfg(target_os = "linux")]
use crate::config::{LanConsoleTransportConfig, UnattendedConsoleConfig};
#[cfg(target_os = "linux")]
use crate::console::broker::ConsoleWorkerPool;
use crate::error::{AgentError, AgentResult};
#[cfg(target_os = "linux")]
use crate::session::{ConsentPolicy, ConsoleInputSink, ConsoleStateProvider, ScreenshotCapturer};
use crate::trusted::TrustedClients;

#[cfg(target_os = "linux")]
const LOGIN_SCREEN_AVAILABLE_MESSAGE: &str = "physical-console login screen is available";
const MAX_LAN_SESSIONS: usize = 32;
#[cfg(target_os = "linux")]
const MAX_PHYSICAL_CONSOLE_SESSIONS: usize = 16;
#[cfg(target_os = "linux")]
const PHYSICAL_CONSOLE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// A viewer that disappears without closing its socket (laptop sleep, Wi-Fi
/// drop) must not keep its session — and the single desktop-stream slot —
/// forever. Idle connections are probed after `DEAD_PEER_IDLE`, then every
/// `DEAD_PEER_PROBE_INTERVAL`, and dropped after `DEAD_PEER_PROBES` misses.
const DEAD_PEER_IDLE: Duration = Duration::from_secs(10);
const DEAD_PEER_PROBE_INTERVAL: Duration = Duration::from_secs(3);
const DEAD_PEER_PROBES: u32 = 3;
/// While frames are in flight keepalive does not probe, so Linux additionally
/// drops a connection whose sent data stays unacknowledged this long.
#[cfg(target_os = "linux")]
const DEAD_PEER_UNACKED_TIMEOUT: Duration = Duration::from_secs(15);
/// A frame write that cannot complete in this time means the viewer stopped
/// reading (the send buffer is full); end the stream instead of blocking.
const FRAME_SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Arm dead-peer detection on an accepted LAN connection. Failure only costs
/// the faster cleanup, so it is logged rather than refusing the client.
fn arm_dead_peer_detection(stream: &TcpStream) {
    let socket = SockRef::from(stream);
    let keepalive = TcpKeepalive::new()
        .with_time(DEAD_PEER_IDLE)
        .with_interval(DEAD_PEER_PROBE_INTERVAL)
        .with_retries(DEAD_PEER_PROBES);
    if let Err(error) = socket.set_tcp_keepalive(&keepalive) {
        tracing::debug!(error = %error, "could not enable TCP keepalive on LAN session");
    }
    #[cfg(target_os = "linux")]
    if let Err(error) = socket.set_tcp_user_timeout(Some(DEAD_PEER_UNACKED_TIMEOUT)) {
        tracing::debug!(error = %error, "could not set TCP user timeout on LAN session");
    }
}

/// Send one stream frame, treating a stalled write like a closed connection.
async fn send_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    channel: &SealedChannel,
    delta: lan::FrameDelta,
) -> bool {
    matches!(
        tokio::time::timeout(
            FRAME_SEND_TIMEOUT,
            lan::send_response(writer, channel, &LanResponse::Frame(delta)),
        )
        .await,
        Ok(Ok(()))
    )
}

/// A change in LAN host session state, for an embedding app to drive its UI.
/// The CLI agent ignores these (it logs instead); a desktop host surfaces them
/// as "waiting" / "connected" status.
#[derive(Debug, Clone)]
pub enum HostEvent {
    /// A client started *viewing* the screen (sent a `StartStream`, not merely
    /// finished the handshake). `label` is the client's device name when it sent
    /// one, else a short network label (peer IP / client identity). `key` is the
    /// client's verified Ed25519 identity (base64) when it announced one with a
    /// valid proof-of-possession — what the host remembers for trust-on-connect;
    /// `None` for a bare PIN client that offered no (or an invalid) identity.
    ClientConnected { label: String, key: Option<String> },
    /// A client's session ended (disconnect, error, or host-initiated kick).
    ClientDisconnected,
}

/// A host-consent request: a not-yet-trusted client (connected by PIN) is asking
/// to view the screen. The embedding app shows an accept/reject prompt and sends
/// the decision back on `reply` (`true` = accept). `key` is the client's verified
/// identity (base64) when it announced one, so the app can offer to remember it.
#[derive(Debug)]
pub struct ConsentRequest {
    pub key: Option<String>,
    pub name: String,
    pub reply: oneshot::Sender<bool>,
}

/// How a LAN host authenticates incoming clients.
#[derive(Debug)]
pub enum LanAuth {
    /// Shared PIN, authenticated via SPAKE2 (a wrong PIN fails the handshake).
    Password(String),
    /// Client Ed25519 identity (TOFU), checked against a trusted store.
    /// `auto_accept` trusts any client without prompting.
    Key {
        trusted: TrustedClients,
        auto_accept: bool,
    },
    /// Accept either a correct `pin` (SPAKE2) OR a client whose identity key is
    /// in `trusted_keys` (base64). The client picks: an empty PIN means it
    /// connects with its key, which is allowed only if it's trusted. The list is
    /// shared so the embedding app can update it live (add/remove a device)
    /// without restarting the host. Used by the desktop host so a remembered
    /// device skips the session code.
    PinOrKey {
        pin: String,
        trusted_keys: Arc<std::sync::Mutex<Vec<String>>>,
        auto_accept: bool,
    },
}

/// Bind, advertise, and serve LAN screenshot sessions until the task is
/// cancelled (the returned future runs the accept loop forever).
pub async fn serve(
    signing_key: SigningKey,
    device_name: String,
    port: u16,
    auth: LanAuth,
) -> AgentResult<()> {
    // CLI agent: no UI gates — `None` control means input control is open to any
    // authenticated client (a headless agent's whole purpose is remote control).
    serve_with_events(
        signing_key,
        device_name,
        port,
        auth,
        None,
        None,
        None,
        None,
        None,
    )
    .await
}

/// Serve the real GDM/GNOME physical-console source on direct LAN. This is a
/// transport adapter only: it deliberately reuses the broker's capture/input
/// source and the same trusted-client permissions as relay sessions.
///
/// There is no PIN or TOFU fallback here. A peer must first complete the
/// signed direct handshake with a locally trusted device identity, then have
/// the explicit unattended-console opt-in in the shared trust store.
#[cfg(target_os = "linux")]
pub async fn serve_physical_console(
    signing_key: SigningKey,
    device_name: String,
    transport: LanConsoleTransportConfig,
    trusted: TrustedClients,
    limits: UnattendedConsoleConfig,
    source: ConsoleWorkerPool,
) -> AgentResult<()> {
    // Physical-console deployments document a fixed firewall port. Do not
    // silently fall back to another port if it is occupied: retrying visibly is
    // safer than exposing a service on an unexpected port.
    let bind_ip: std::net::IpAddr = transport
        .bind_address
        .parse()
        .map_err(|_| AgentError::Config("invalid LAN bind address".to_string()))?;
    tracing::info!(
        address = %transport.bind_address,
        port = transport.port,
        "physical-console LAN listener binding"
    );
    let listener = TcpListener::bind((bind_ip, transport.port)).await?;
    let local_port = listener.local_addr()?.port();
    let public_key = B64.encode(signing_key.verifying_key().as_bytes());
    let _advertiser = Advertiser::start_with_mode(
        &device_name,
        local_port,
        &public_key,
        PROTOCOL_VERSION,
        Some("physical-console"),
    )
    .map_err(|e| AgentError::Lan(e.to_string()))?;
    tracing::info!(
        address = %transport.bind_address,
        port = local_port,
        trusted_clients = trusted.len(),
        service = "_rivetlink._tcp.local.",
        "physical-console LAN listener started and advertised"
    );

    let trusted = Arc::new(trusted);
    let session_slots = Arc::new(Semaphore::new(MAX_PHYSICAL_CONSOLE_SESSIONS));
    let mut sessions = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let _ = stream.set_nodelay(true);
                arm_dead_peer_detection(&stream);
                let signing_key = signing_key.clone();
                let trusted = Arc::clone(&trusted);
                let limits = limits.clone();
                let source = source.clone();
                let Ok(slot) = Arc::clone(&session_slots).try_acquire_owned() else {
                    tracing::warn!(%peer, "physical-console LAN connection refused: session limit reached");
                    continue;
                };
                sessions.spawn(async move {
                    let _slot = slot;
                    // The desktop app performs a lightweight TCP health probe for
                    // saved LAN devices.  It intentionally opens and closes the
                    // socket without starting the authenticated protocol, so keep
                    // that routine traffic out of the normal service journal.
                    tracing::debug!(%peer, "physical-console LAN TCP connection accepted");
                    if let Err(error) = serve_physical_console_client(stream, signing_key, trusted, limits, source).await {
                        // This intentionally contains no request/input material.
                        if is_lan_health_probe_disconnect(&error) {
                            tracing::debug!(%peer, "physical-console LAN health probe closed");
                        } else {
                            tracing::info!(%peer, error = %error, "physical-console LAN session closed");
                        }
                    }
                });
            },
            Some(_) = sessions.join_next(), if !sessions.is_empty() => {},
        }
    }
}

/// A saved-device health probe reaches the TCP listener but deliberately does
/// not send a direct-LAN handshake.  SDK framing reports that as an early EOF.
/// It occurs before authentication and cannot carry capture or input data.
#[cfg(any(target_os = "linux", test))]
fn is_lan_health_probe_disconnect(error: &AgentError) -> bool {
    matches!(error, AgentError::Lan(message) if message.contains("early eof"))
}

// One sequential authenticated transaction loop; splitting it would obscure
// the trust-before-input ordering that is security-critical here.
#[allow(clippy::too_many_lines)]
#[cfg(target_os = "linux")]
async fn serve_physical_console_client(
    mut stream: TcpStream,
    signing_key: SigningKey,
    trusted: Arc<TrustedClients>,
    limits: UnattendedConsoleConfig,
    source: ConsoleWorkerPool,
) -> AgentResult<()> {
    let identity = Identity::from_signing_key(signing_key);
    let (channel, client) = tokio::time::timeout(
        PHYSICAL_CONSOLE_HANDSHAKE_TIMEOUT,
        direct::host_accept_key(&mut stream, &identity, |id| {
            // Reload at the handshake boundary too, so revoking a key takes
            // effect for the next LAN connection without restarting the broker.
            TrustedClients::load_or_empty(trusted.path())
                .is_ok_and(|live| live.may_view_unattended_console(id))
        }),
    )
    .await
    .map_err(|_| AgentError::Lan("physical-console handshake timed out".to_string()))?
    .map_err(|e| AgentError::Lan(e.to_string()))?;
    tracing::info!(client = %client, "trusted physical-console LAN client authenticated");

    let policy = ConsentPolicy::UnattendedConsole {
        min_capture_interval: Duration::from_secs(limits.min_capture_interval_secs),
        capture_timeout: Duration::from_secs(limits.capture_timeout_secs),
        max_capture_bytes: limits.max_capture_bytes,
    };
    let mut last_capture = None;
    loop {
        let Ok(request) = lan::recv_request(&mut stream, &channel).await else {
            return Ok(());
        };
        match request {
            // The same broker and trusted identity now serve the normal
            // desktop stream after a successful LightDM login. This is a
            // backend handoff, not a second LAN listener or a new trust path.
            LanRequest::ListDisplays => {
                let response = match source.console_state().await {
                    Some((HostConsoleState::DesktopReady, _)) => LanResponse::Displays {
                        // Linux's Mutter backend owns monitor selection. An
                        // empty list retains the existing client's primary
                        // monitor behaviour and avoids leaking local topology.
                        displays: Vec::new(),
                        // Devices allowed to control the desktop may also
                        // share its clipboard and the RivetLink folder.
                        features: if TrustedClients::load_or_empty(trusted.path())
                            .is_ok_and(|live| live.may_control_unattended_console(&client))
                        {
                            vec![
                                rivetlink_sdk::share::FEATURE_CLIPBOARD.to_string(),
                                rivetlink_sdk::share::FEATURE_FILES.to_string(),
                            ]
                        } else {
                            Vec::new()
                        },
                    },
                    _ => LanResponse::Error {
                        message: "normal desktop engine is not ready".to_string(),
                    },
                };
                lan::send_response(&mut stream, &channel, &response)
                    .await
                    .map_err(|error| AgentError::Lan(error.to_string()))?;
                continue;
            },
            LanRequest::StartStream { fps, .. } => {
                return stream_authenticated_desktop(
                    stream,
                    Arc::new(channel),
                    client,
                    trusted,
                    source,
                    fps,
                )
                .await;
            },
            LanRequest::ConsoleCapture { inputs } => {
                serve_console_capture_request(
                    &mut stream,
                    &channel,
                    &client,
                    &trusted,
                    &limits,
                    &source,
                    &policy,
                    &mut last_capture,
                    inputs,
                )
                .await?;
            },
            _ => {
                let _ = lan::send_response(
                    &mut stream,
                    &channel,
                    &LanResponse::Error {
                        message: "this physical-console listener accepts console capture before login or the normal desktop stream after login".to_string(),
                    },
                )
                .await;
                return Ok(());
            },
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
async fn serve_console_capture_request(
    stream: &mut TcpStream,
    channel: &rivetlink_crypto::sealed::SealedChannel,
    client: &str,
    trusted: &Arc<TrustedClients>,
    limits: &UnattendedConsoleConfig,
    source: &ConsoleWorkerPool,
    policy: &ConsentPolicy,
    last_capture: &mut Option<Instant>,
    inputs: Vec<ConsoleInputPacket>,
) -> AgentResult<()> {
    if inputs.is_empty()
        && last_capture.is_some_and(|at: Instant| {
            at.elapsed() < Duration::from_secs(limits.min_capture_interval_secs)
        })
    {
        lan::send_response(
            stream,
            channel,
            &LanResponse::Error {
                message: "screenshot request rate limit reached; try again shortly".to_string(),
            },
        )
        .await
        .map_err(|e| AgentError::Lan(e.to_string()))?;
        return Ok(());
    }
    if !inputs.is_empty() {
        // Authentication completed above, but view authorization does not
        // imply control. Re-check the live trust store before injection so
        // an entry revoked between handshake and request cannot send input.
        let live = TrustedClients::load_or_empty(trusted.path())?;
        if !live.may_control_unattended_console(client) {
            lan::send_response(
                stream,
                channel,
                &LanResponse::Error {
                    message: "this trusted device is not authorized for physical-console input"
                        .to_string(),
                },
            )
            .await
            .map_err(|e| AgentError::Lan(e.to_string()))?;
            return Ok(());
        }
        let mut input_source = source.clone();
        for event in inputs {
            input_source.inject(event).await?;
        }
    }
    *last_capture = Some(Instant::now());
    let mut capture_source = source.clone();
    let response = match tokio::time::timeout(
        Duration::from_secs(limits.capture_timeout_secs),
        capture_source.capture(*policy),
    )
    .await
    {
        Ok(Ok(png)) if png.len() <= limits.max_capture_bytes => {
            let (state, generation) = source
                .console_state()
                .await
                .map_or((None, None), |(state, generation)| {
                    (Some(state), Some(generation))
                });
            LanResponse::ConsoleCapture {
                png_b64: B64.encode(png),
                state,
                generation,
            }
        },
        Ok(Ok(_)) => LanResponse::Error {
            message: "screenshot exceeds the configured safety limit".to_string(),
        },
        Ok(Err(error)) => {
            tracing::warn!(client = %client, error = %error, "physical-console LAN capture failed");
            LanResponse::Error {
                message: "physical-console capture failed".to_string(),
            }
        },
        Err(_) => {
            tracing::warn!(client = %client, "physical-console LAN capture timed out");
            LanResponse::Error {
                message: "physical-console capture timed out".to_string(),
            }
        },
    };
    lan::send_response(stream, channel, &response)
        .await
        .map_err(|e| AgentError::Lan(e.to_string()))?;
    Ok(())
}

/// Run the existing normal 30fps desktop engine through the authenticated
/// physical-console listener. This preserves the direct-LAN identity and trust
/// relationship across LightDM → GNOME; only the capture backend changes.
// One select loop owns the socket's write half: frames, input, clipboard and
// file traffic all funnel through it, so splitting it would add shared-writer
// plumbing without making the authorization checks easier to follow.
#[allow(clippy::too_many_lines)]
#[cfg(target_os = "linux")]
async fn stream_authenticated_desktop(
    stream: TcpStream,
    channel: Arc<SealedChannel>,
    client: String,
    trusted: Arc<TrustedClients>,
    source: ConsoleWorkerPool,
    fps: u16,
) -> AgentResult<()> {
    if !matches!(
        source.console_state().await,
        Some((HostConsoleState::DesktopReady, _))
    ) {
        let mut stream = stream;
        let _ = lan::send_response(
            &mut stream,
            &channel,
            &LanResponse::Error {
                message: "normal desktop engine is not ready".to_string(),
            },
        )
        .await;
        return Ok(());
    }
    let mut desktop = match source.start_desktop_stream(fps.clamp(1, 30)).await {
        Ok(stream) => stream,
        Err(error) => {
            tracing::warn!(client = %client, error = %error, "normal desktop engine could not start");
            let mut stream = stream;
            let _ = lan::send_response(
                &mut stream,
                &channel,
                &LanResponse::Error {
                    message: "normal desktop engine is unavailable".to_string(),
                },
            )
            .await;
            return Ok(());
        },
    };
    tracing::info!(
        client = %client,
        backend = "NormalDesktopEngine",
        state = "DesktopReady",
        fps = fps.clamp(1, 30),
        "physical-console handoff: normal desktop engine started"
    );

    let (mut reader, mut writer) = stream.into_split();
    let (control_tx, mut control_rx) = tokio::sync::mpsc::channel::<LanRequest>(64);
    let reader_channel = Arc::clone(&channel);
    let reader_task = tokio::spawn(async move {
        while let Ok(request) = lan::recv_request(&mut reader, &reader_channel).await {
            if control_tx.send(request).await.is_err() {
                break;
            }
        }
    });

    // Clipboard and file sharing (only after the client sends EnableSharing).
    // Download chunks are produced by background tasks and sent from here so
    // the socket keeps a single writer.
    let worker = desktop.worker();
    let mut clipboard_changes = worker.clipboard_changes();
    let mut clipboard_enabled = false;
    let (share_tx, mut share_rx) = tokio::sync::mpsc::channel::<LanResponse>(8);
    let mut downloads = tokio::task::JoinSet::new();
    let mut held = HeldInput::default();
    // A modifier stuck by an earlier viewer (before held input was released
    // on disconnect) would otherwise survive until the worker restarts.
    HeldInput::release_modifiers(&source).await;

    let result = loop {
        tokio::select! {
            frame = desktop.next() => match frame {
                Ok(delta) => {
                    if !send_frame(&mut writer, &channel, delta).await {
                        tracing::info!(client = %client, "physical-console viewer stopped receiving frames");
                        break Ok(());
                    }
                },
                Err(error) => {
                    tracing::warn!(client = %client, error = %error, "normal desktop engine ended");
                    let message = if wait_for_login_screen(&source).await {
                        LOGIN_SCREEN_AVAILABLE_MESSAGE.to_string()
                    } else {
                        "normal desktop engine ended".to_string()
                    };
                    let _ = lan::send_response(&mut writer, &channel, &LanResponse::Error {
                        message,
                    }).await;
                    break Ok(());
                },
            },
            text = clipboard_changes.recv(), if clipboard_enabled => match text {
                Ok(text) => {
                    if !send_share(&mut writer, &channel, &LanResponse::ClipboardText { text }).await {
                        break Ok(());
                    }
                },
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {},
                Err(tokio::sync::broadcast::error::RecvError::Closed) => clipboard_enabled = false,
            },
            Some(response) = share_rx.recv() => {
                if !send_share(&mut writer, &channel, &response).await {
                    break Ok(());
                }
            },
            request = control_rx.recv() => match request {
                Some(request) if is_share_request(&request) => {
                    let live = TrustedClients::load_or_empty(trusted.path())?;
                    let response = if live.may_control_unattended_console(&client) {
                        handle_share_request(
                            request,
                            &worker,
                            &mut clipboard_enabled,
                            &share_tx,
                            &mut downloads,
                        )
                        .await
                    } else {
                        Some(LanResponse::Error {
                            message: "this trusted device is not authorized for clipboard or file sharing".to_string(),
                        })
                    };
                    if let Some(response) = response {
                        if !send_share(&mut writer, &channel, &response).await {
                            break Ok(());
                        }
                    }
                },
                Some(request) => {
                    if let Some(input) = desktop_input(request) {
                        let live = TrustedClients::load_or_empty(trusted.path())?;
                        if !live.may_control_unattended_console(&client) {
                            let _ = lan::send_response(&mut writer, &channel, &LanResponse::Error {
                                message: "this trusted device is not authorized for remote input".to_string(),
                            }).await;
                            break Ok(());
                        }
                        held.track(&input);
                        let mut input_source = source.clone();
                        if let Err(error) = input_source.inject(input).await {
                            tracing::warn!(client = %client, error = %error, "normal desktop input failed");
                            let _ = lan::send_response(&mut writer, &channel, &LanResponse::Error {
                                message: "normal desktop input is unavailable".to_string(),
                            }).await;
                            break Ok(());
                        }
                    }
                },
                None => break Ok(()),
            },
            Some(_) = downloads.join_next(), if !downloads.is_empty() => {},
        }
    };
    downloads.abort_all();
    reader_task.abort();
    held.release(&source).await;
    let _ = desktop.stop().await;
    tracing::info!(client = %client, "physical-console handoff: normal desktop engine stopped");
    result
}

/// Keys and buttons a viewer holds down on the host. The console worker keeps
/// one input session across viewers, so anything still pressed when a viewer
/// goes away (a keyup lost to a focus change, a dropped connection) would stay
/// pressed for every later viewer: a held Ctrl turns `d` into Ctrl+D. Released
/// when the viewer ends.
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
struct HeldInput {
    keys: std::collections::BTreeSet<String>,
    /// Left, right, middle.
    buttons: [bool; 3],
}

#[cfg(target_os = "linux")]
impl HeldInput {
    fn button_index(button: rivetlink_protocol::MouseButton) -> usize {
        match button {
            rivetlink_protocol::MouseButton::Left => 0,
            rivetlink_protocol::MouseButton::Right => 1,
            rivetlink_protocol::MouseButton::Middle => 2,
        }
    }

    fn track(&mut self, input: &ConsoleInputPacket) {
        match input {
            ConsoleInputPacket::Key { code, down: true } => {
                self.keys.insert(code.clone());
            },
            ConsoleInputPacket::Key { code, down: false } => {
                self.keys.remove(code);
            },
            ConsoleInputPacket::PointerButton { button, down } => {
                self.buttons[Self::button_index(*button)] = *down;
            },
            ConsoleInputPacket::PointerMove { .. } | ConsoleInputPacket::Scroll { .. } => {},
        }
    }

    fn releases(self) -> Vec<ConsoleInputPacket> {
        let buttons = [
            rivetlink_protocol::MouseButton::Left,
            rivetlink_protocol::MouseButton::Right,
            rivetlink_protocol::MouseButton::Middle,
        ]
        .into_iter()
        .zip(self.buttons)
        .filter(|(_, down)| *down)
        .map(|(button, _)| ConsoleInputPacket::PointerButton {
            button,
            down: false,
        });
        self.keys
            .into_iter()
            .map(|code| ConsoleInputPacket::Key { code, down: false })
            .chain(buttons)
            .collect()
    }

    /// Modifiers released when a viewer starts. Releasing a key that is not
    /// pressed is ignored by Mutter. `CommandMod` is `ControlLeft` on Linux.
    const MODIFIERS: [&'static str; 8] = [
        "ShiftLeft",
        "ShiftRight",
        "ControlLeft",
        "ControlRight",
        "AltLeft",
        "AltRight",
        "MetaLeft",
        "MetaRight",
    ];

    async fn release_modifiers(source: &ConsoleWorkerPool) {
        let held = Self {
            keys: Self::MODIFIERS.iter().map(ToString::to_string).collect(),
            buttons: [false; 3],
        };
        held.release(source).await;
    }

    async fn release(self, source: &ConsoleWorkerPool) {
        let releases = self.releases();
        if releases.is_empty() {
            return;
        }
        tracing::info!(
            count = releases.len(),
            "physical-console: releasing held keys and buttons"
        );
        let mut source = source.clone();
        for input in releases {
            if source.inject(input).await.is_err() {
                return;
            }
        }
    }
}

/// A successful logout replaces the GNOME desktop worker with LightDM's X11
/// worker. Wait briefly for that normal transition before telling the client to
/// return to physical-console mode; a capture failure while still desktop-ready
/// must not masquerade as a logout.
#[cfg(target_os = "linux")]
async fn wait_for_login_screen(source: &ConsoleWorkerPool) -> bool {
    for _ in 0..30 {
        if matches!(
            source.console_state().await,
            Some((HostConsoleState::GdmLogin, _))
        ) {
            return true;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    false
}

#[cfg(target_os = "linux")]
fn desktop_input(request: LanRequest) -> Option<ConsoleInputPacket> {
    match request {
        LanRequest::PointerMove { x, y } => Some(ConsoleInputPacket::PointerMove { x, y }),
        LanRequest::PointerButton { button, down } => Some(ConsoleInputPacket::PointerButton {
            button: match button {
                rivetlink_sdk::lan::PtrButton::Left => rivetlink_protocol::MouseButton::Left,
                rivetlink_sdk::lan::PtrButton::Right => rivetlink_protocol::MouseButton::Right,
                rivetlink_sdk::lan::PtrButton::Middle => rivetlink_protocol::MouseButton::Middle,
            },
            down,
        }),
        LanRequest::Scroll { dx, dy } => Some(ConsoleInputPacket::Scroll { dx, dy }),
        LanRequest::Key { code, down } => Some(ConsoleInputPacket::Key { code, down }),
        _ => None,
    }
}

#[cfg(target_os = "linux")]
fn is_share_request(request: &LanRequest) -> bool {
    matches!(
        request,
        LanRequest::EnableSharing
            | LanRequest::ClipboardSet { .. }
            | LanRequest::FileUploadStart { .. }
            | LanRequest::FileUploadChunk { .. }
            | LanRequest::FileUploadEnd { .. }
            | LanRequest::ListSharedFiles
            | LanRequest::FileDownload { .. }
    )
}

/// Send one clipboard/file response, bounded like a frame write.
#[cfg(target_os = "linux")]
async fn send_share<W: AsyncWrite + Unpin>(
    writer: &mut W,
    channel: &SealedChannel,
    response: &LanResponse,
) -> bool {
    matches!(
        tokio::time::timeout(
            FRAME_SEND_TIMEOUT,
            lan::send_response(writer, channel, response)
        )
        .await,
        Ok(Ok(()))
    )
}

/// Serve one sharing request for an authorized client. Returns the immediate
/// response, if any; downloads stream their chunks through `share_tx`.
#[cfg(target_os = "linux")]
async fn handle_share_request(
    request: LanRequest,
    worker: &crate::console::broker::ConsoleWorkerClient,
    clipboard_enabled: &mut bool,
    share_tx: &tokio::sync::mpsc::Sender<LanResponse>,
    downloads: &mut tokio::task::JoinSet<()>,
) -> Option<LanResponse> {
    use rivetlink_sdk::share::MAX_CLIPBOARD_BYTES;
    let file_error = |id: u32, error: AgentError| LanResponse::FileError {
        id,
        message: share_message(&error),
    };
    match request {
        LanRequest::EnableSharing => {
            let clipboard = match worker.enable_clipboard().await {
                Ok(()) => true,
                Err(error) => {
                    tracing::warn!(error = %error, "clipboard sharing unavailable");
                    false
                },
            };
            *clipboard_enabled = clipboard;
            Some(LanResponse::SharingEnabled {
                clipboard,
                files: true,
            })
        },
        LanRequest::ClipboardSet { text } => {
            if !*clipboard_enabled || text.len() > MAX_CLIPBOARD_BYTES {
                return Some(LanResponse::Error {
                    message: "clipboard text was not accepted".to_string(),
                });
            }
            worker
                .set_clipboard(text)
                .await
                .err()
                .map(|error| LanResponse::Error {
                    message: share_message(&error),
                })
        },
        LanRequest::FileUploadStart { id, path, size } => worker
            .upload_start(id, path, size)
            .await
            .err()
            .map(|error| file_error(id, error)),
        LanRequest::FileUploadChunk { id, data_b64 } => worker
            .upload_chunk(id, data_b64)
            .await
            .err()
            .map(|error| file_error(id, error)),
        LanRequest::FileUploadEnd { id } => Some(match worker.upload_end(id).await {
            Ok(path) => LanResponse::FileUploaded { id, path },
            Err(error) => file_error(id, error),
        }),
        LanRequest::ListSharedFiles => Some(match worker.list_shared().await {
            Ok(entries) => LanResponse::SharedFiles { entries },
            Err(error) => LanResponse::Error {
                message: share_message(&error),
            },
        }),
        LanRequest::FileDownload { id, path } => {
            let worker = worker.clone();
            let share_tx = share_tx.clone();
            downloads.spawn(async move {
                let mut offset = 0_u64;
                loop {
                    let response = match worker.read_shared(path.clone(), offset).await {
                        Ok((data_b64, size, eof)) => {
                            let read = base64_decoded_len(&data_b64);
                            offset += read;
                            let done = eof || read == 0;
                            let chunk = LanResponse::FileChunk {
                                id,
                                size,
                                data_b64,
                                eof: done,
                            };
                            if share_tx.send(chunk).await.is_err() || done {
                                return;
                            }
                            continue;
                        },
                        Err(error) => file_error(id, error),
                    };
                    let _ = share_tx.send(response).await;
                    return;
                }
            });
            None
        },
        _ => None,
    }
}

/// Byte length of a padded base64 string without decoding it.
#[cfg(target_os = "linux")]
fn base64_decoded_len(data_b64: &str) -> u64 {
    let padding = data_b64.bytes().rev().take_while(|&b| b == b'=').count();
    ((data_b64.len() / 4 * 3).saturating_sub(padding)) as u64
}

/// A client-safe message for a sharing failure.
#[cfg(target_os = "linux")]
fn share_message(error: &AgentError) -> String {
    match error {
        AgentError::Share(message) => message.clone(),
        _ => "the host could not complete the clipboard or file request".to_string(),
    }
}

/// Like [`serve`], but reports session lifecycle on `events` (if given) so an
/// embedding desktop app can show "waiting" / "connected". Cancel by dropping
/// the future (aborting the task): the listener and mDNS advertisement are
/// released on drop.
///
/// `kick` lets the host hang up on the *active* viewer without stopping the
/// listener: every change to the watched value drops the current stream (the
/// client sees a disconnect), while advertising and the PIN stay live.
///
/// `share_all` gates multi-screen access live: `true` (or `None`, the CLI
/// default) lets the client list and switch every display; `false` restricts it
/// to the primary screen — the host offers only that one and refuses switches.
/// Toggling it mid-stream takes effect immediately (the host pushes a fresh
/// display list and snaps back to the primary on revoke).
/// `consent` (if given) gates not-yet-trusted (PIN) clients: before such a
/// client may view, the agent sends a [`ConsentRequest`] and waits for the host
/// to accept. A trusted-key client skips it (that's the point of remembering).
#[allow(clippy::too_many_arguments)] // distinct host knobs; a struct adds ceremony
pub async fn serve_with_events(
    signing_key: SigningKey,
    device_name: String,
    port: u16,
    auth: LanAuth,
    events: Option<Sender<HostEvent>>,
    kick: Option<watch::Receiver<u64>>,
    share_all: Option<watch::Receiver<bool>>,
    control: Option<watch::Receiver<bool>>,
    consent: Option<Sender<ConsentRequest>>,
) -> AgentResult<()> {
    let listener = bind_listener(port).await?;
    let local_port = listener.local_addr()?.port();
    let pubkey_b64 = B64.encode(signing_key.verifying_key().as_bytes());

    // Held for the lifetime of the accept loop; dropping unregisters the mDNS
    // advertisement.
    let _advertiser = Advertiser::start(&device_name, local_port, &pubkey_b64, PROTOCOL_VERSION)
        .map_err(|e| AgentError::Lan(e.to_string()))?;

    tracing::info!(
        port = local_port,
        device = %device_name,
        "advertising on LAN, waiting for clients"
    );

    let auth = Arc::new(auth);
    let session_slots = Arc::new(Semaphore::new(MAX_LAN_SESSIONS));
    // Sessions live in a JoinSet owned by this future. Cancelling serve
    // (dropping the future — e.g. the desktop app stopping the host) drops the
    // set, which aborts every active session and closes its socket, so the
    // connected client disconnects instead of streaming on forever.
    let mut sessions = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                tracing::info!(%peer, "LAN: accepted connection, starting handshake");
                // Disable Nagle: live streaming pushes many small sealed frames;
                // coalescing them adds bursty stalls to the real-time view.
                let _ = stream.set_nodelay(true);
                arm_dead_peer_detection(&stream);
                let signing_key = signing_key.clone();
                let auth = Arc::clone(&auth);
                let events = events.clone();
                // Each session watches the same kick channel; a bump drops
                // whichever client is currently streaming. Catch the fresh
                // receiver up to the current value first — a watch clone inherits
                // the parent's *seen* version, so a kick from a PAST client would
                // otherwise read as unseen and instantly drop this new session
                // (symptom: after one kick, no one can reconnect until restart).
                let kick = kick.clone().map(|mut rx| {
                    let _ = rx.borrow_and_update();
                    rx
                });
                // Same catch-up as kick: a fresh watch clone inherits the parent's
                // seen version, so the stream's `changed()` arm only fires on
                // toggles that happen *after* this session starts.
                let share_all = share_all.clone().map(|mut rx| {
                    let _ = rx.borrow_and_update();
                    rx
                });
                // Same catch-up: control is the remote-input gate (default off in
                // the app; open for the CLI agent when `None`).
                let control = control.clone().map(|mut rx| {
                    let _ = rx.borrow_and_update();
                    rx
                });
                let consent = consent.clone();
                let Ok(slot) = Arc::clone(&session_slots).try_acquire_owned() else {
                    tracing::warn!(%peer, "LAN connection refused: session limit reached");
                    continue;
                };
                sessions.spawn(async move {
                    let _slot = slot;
                    if let Err(e) = handle(
                        stream, signing_key, &auth, peer, events, kick, share_all, control, consent,
                    )
                    .await
                    {
                        tracing::warn!(%peer, error = %e, "LAN session ended with error");
                    }
                });
            },
            // Reap finished sessions so the set doesn't grow unbounded.
            Some(_) = sessions.join_next(), if !sessions.is_empty() => {},
        }
    }
}

/// Bind the requested port; if it's already taken, fall back to an OS-assigned
/// port so a stale socket never blocks hosting (the real port is advertised
/// over mDNS either way). Port 0 means "OS-assigned" up front.
async fn bind_listener(port: u16) -> AgentResult<TcpListener> {
    bind_listener_at("0.0.0.0", port).await
}

/// Bind to a deliberate numeric address. The physical-console config accepts
/// only an IP address, avoiding ambiguous hostname resolution at boot.
async fn bind_listener_at(address: &str, port: u16) -> AgentResult<TcpListener> {
    let ip: std::net::IpAddr = address
        .parse()
        .map_err(|_| AgentError::Config("invalid LAN bind address".to_string()))?;
    match TcpListener::bind((ip, port)).await {
        Ok(listener) => Ok(listener),
        Err(e) if port != 0 && e.kind() == std::io::ErrorKind::AddrInUse => {
            tracing::warn!(port, "LAN port busy, falling back to an OS-assigned port");
            Ok(TcpListener::bind((ip, 0)).await?)
        },
        Err(e) => Err(e.into()),
    }
}

#[allow(clippy::too_many_arguments)] // session params; bundling them adds ceremony
async fn handle(
    mut stream: TcpStream,
    signing_key: SigningKey,
    auth: &LanAuth,
    peer: std::net::SocketAddr,
    events: Option<Sender<HostEvent>>,
    kick: Option<watch::Receiver<u64>>,
    share_all: Option<watch::Receiver<bool>>,
    control: Option<watch::Receiver<bool>>,
    consent: Option<Sender<ConsentRequest>>,
) -> AgentResult<()> {
    // `needs_consent` = the client authenticated by PIN (not a remembered key),
    // so the host should approve it before it can view (trusted keys skip this).
    let (channel, label, needs_consent) = match auth {
        LanAuth::Password(pin) => {
            let channel = direct::host_accept_password(&mut stream, pin)
                .await
                .map_err(|e| AgentError::Lan(e.to_string()))?;
            (channel, peer.ip().to_string(), true)
        },
        LanAuth::Key {
            trusted,
            auto_accept,
        } => {
            let identity = Identity::from_signing_key(signing_key);
            let (channel, client_id) = direct::host_accept_key(&mut stream, &identity, |id| {
                *auto_accept || trusted.is_trusted(id)
            })
            .await
            .map_err(|e| AgentError::Lan(e.to_string()))?;
            tracing::info!(client = %client_id, "LAN client accepted (key mode)");
            (channel, client_id.clone(), false)
        },
        LanAuth::PinOrKey {
            pin,
            trusted_keys,
            auto_accept,
        } => {
            let identity = Identity::from_signing_key(signing_key);
            let (channel, client_id) =
                direct::host_accept_auto(&mut stream, &identity, pin, |id| {
                    *auto_accept
                        || trusted_keys
                            .lock()
                            .is_ok_and(|keys| keys.iter().any(|k| k == id))
                })
                .await
                .map_err(|e| AgentError::Lan(e.to_string()))?;
            match client_id {
                Some(id) => {
                    tracing::info!(client = %id, "LAN client accepted (trusted key)");
                    (channel, id, false)
                },
                None => (channel, peer.ip().to_string(), true),
            }
        },
    };

    tracing::info!(%peer, label = %label, "LAN: session established, serving");
    // Share the channel (Arc) so a live stream can read control messages in a
    // side task while it writes frames. Directional send/receive counters are
    // independent, so this preserves ordered anti-replay semantics.
    // The connected/disconnected events are emitted inside serve_loop, bracketing
    // the *stream* (StartStream..end) — not the bare handshake — so the host only
    // shows "connected" once the client is actually viewing.
    let result = serve_loop(
        stream,
        Arc::new(channel),
        events,
        label,
        kick,
        share_all,
        control,
        needs_consent,
        consent,
    )
    .await;
    tracing::info!(%peer, ok = result.is_ok(), "LAN: session ended");
    result
}

/// Aborts a spawned task when dropped — keeps the stream's reader task from
/// outliving the session.
struct AbortOnDrop(tokio::task::AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Serve requests on an established channel until the client disconnects.
///
/// `events`/`label` report the *viewing* lifecycle: `ClientConnected` fires when
/// the client sends `StartStream` (using its device name if given, else the
/// network `label`), and `ClientDisconnected` when that stream ends. A
/// screenshot-only or connect-then-leave session never reports "connected".
// One flat dispatch over every LanRequest variant; session params are bundled
// as arguments because a struct would only add ceremony.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn serve_loop(
    mut stream: TcpStream,
    channel: Arc<SealedChannel>,
    events: Option<Sender<HostEvent>>,
    label: String,
    kick: Option<watch::Receiver<u64>>,
    share_all: Option<watch::Receiver<bool>>,
    control: Option<watch::Receiver<bool>>,
    needs_consent: bool,
    consent: Option<Sender<ConsentRequest>>,
) -> AgentResult<()> {
    loop {
        let Ok(req) = lan::recv_request(&mut stream, &channel).await else {
            tracing::debug!("LAN serve: client closed channel");
            return Ok(());
        };
        match req {
            LanRequest::Screenshot => {
                tracing::info!("LAN serve: Screenshot request");
                let resp = match screenshot::capture_png().await {
                    Ok(png) => LanResponse::Screenshot {
                        png_b64: B64.encode(png),
                    },
                    Err(e) => LanResponse::Error {
                        message: e.to_string(),
                    },
                };
                lan::send_response(&mut stream, &channel, &resp)
                    .await
                    .map_err(|e| AgentError::Lan(e.to_string()))?;
            },
            LanRequest::ListDisplays => {
                // When the host hasn't granted "share all screens", offer only the
                // primary display so the client's picker stays hidden.
                let displays = allowed_displays(share_all_now(&share_all)).await;
                tracing::info!(count = displays.len(), "LAN serve: ListDisplays request");
                lan::send_response(
                    &mut stream,
                    &channel,
                    &LanResponse::Displays {
                        displays,
                        features: Vec::new(),
                    },
                )
                .await
                .map_err(|e| AgentError::Lan(e.to_string()))?;
            },
            LanRequest::StartStream {
                fps,
                display,
                name,
                identity_key,
                identity_sig,
            } => {
                // Honour the requested screen only when sharing all screens is on;
                // otherwise pin to the primary (`None`).
                let display = if share_all_now(&share_all) {
                    display
                } else {
                    None
                };
                let scr = display;
                tracing::info!(fps, screen = ?scr, "LAN serve: StartStream request");
                // Now the client is actually viewing: announce who, falling back
                // to the network label when it sent no name.
                let who = name
                    .filter(|n| !n.trim().is_empty())
                    .unwrap_or_else(|| label.clone());
                // Verify the announced identity (proof-of-possession) before we
                // surface it — an unverified key must never reach the host's
                // "remember this device" prompt.
                let key = match (identity_key, identity_sig) {
                    (Some(k), Some(s)) => match lan::verify_identity(&k, &s) {
                        Some(verified) => Some(verified),
                        None => {
                            tracing::warn!("LAN serve: client identity proof invalid, ignoring");
                            None
                        },
                    },
                    _ => None,
                };
                // A not-yet-trusted (PIN) client must be approved by the host
                // before it can view. A trusted key skips this. No `consent`
                // channel (CLI agent) = accept silently, as before.
                if needs_consent {
                    if let Some(tx) = &consent {
                        if !ask_consent(tx, key.clone(), who.clone()).await {
                            tracing::info!(%who, "LAN serve: host rejected (or timed out) the client");
                            let _ = lan::send_response(
                                &mut stream,
                                &channel,
                                &LanResponse::Error {
                                    message: "the host declined the connection".to_string(),
                                },
                            )
                            .await;
                            return Ok(());
                        }
                    }
                }
                if let Some(ev) = &events {
                    let _ = ev
                        .send(HostEvent::ClientConnected { label: who, key })
                        .await;
                }
                // The stream runs until the client disconnects or the host kicks.
                let result =
                    stream_screen(stream, channel, fps, display, kick, share_all, control).await;
                if let Some(ev) = &events {
                    let _ = ev.send(HostEvent::ClientDisconnected).await;
                }
                return result;
            },
            // Only meaningful while streaming; ignore outside a stream.
            LanRequest::SwitchDisplay { .. }
            | LanRequest::PointerMove { .. }
            | LanRequest::PointerButton { .. }
            | LanRequest::Scroll { .. }
            | LanRequest::Key { .. }
            | LanRequest::ConsoleCapture { .. } => {},
            // This host never advertises sharing features, so a conforming
            // client does not send these; ignore them.
            LanRequest::EnableSharing
            | LanRequest::ClipboardSet { .. }
            | LanRequest::FileUploadStart { .. }
            | LanRequest::FileUploadChunk { .. }
            | LanRequest::FileUploadEnd { .. }
            | LanRequest::ListSharedFiles
            | LanRequest::FileDownload { .. } => {},
        }
    }
}

/// The displays this host can offer to share. Empty where there's no capture
/// backend that enumerates screens (Linux's portal owns selection; Windows has
/// no host backend).
fn displays_for_host() -> Vec<DisplayInfo> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        crate::capture::screencast::list_displays()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Vec::new()
    }
}

/// Current "share all screens" state. `None` (CLI agent) or `true` means the
/// client sees and can switch every display; `false` restricts it to the primary.
fn share_all_now(share_all: &Option<watch::Receiver<bool>>) -> bool {
    share_all.as_ref().is_none_or(|rx| *rx.borrow())
}

/// Whether the host currently grants remote *input* control. `None` (CLI agent)
/// = open, since a headless agent's whole purpose is remote control; the desktop
/// app passes `Some(false)` and flips it on explicitly (a viewer never controls
/// the host until the person at the keyboard allows it).
fn control_now(control: &Option<watch::Receiver<bool>>) -> bool {
    control.as_ref().is_none_or(|rx| *rx.borrow())
}

/// Forward one remote input event to the injector thread, spawning it on first
/// use (a Mutter RemoteDesktop session for the monitor being shared). Sending is
/// non-blocking, so this never stalls the frame loop. Linux only.
#[cfg(target_os = "linux")]
fn apply_input(
    handle: &mut Option<crate::input::InputHandle>,
    display: Option<u32>,
    req: &LanRequest,
) {
    use rivetlink_sdk::lan::LanRequest as R;

    use crate::input::{InputAction, InputHandle};

    let handle = handle.get_or_insert_with(|| InputHandle::spawn(display));
    let action = match req {
        R::PointerMove { x, y } => InputAction::Move { x: *x, y: *y },
        R::PointerButton { button, down } => InputAction::Button {
            button: *button,
            down: *down,
        },
        R::Scroll { dx, dy } => InputAction::Scroll { dx: *dx, dy: *dy },
        R::Key { code, down } => InputAction::Key {
            code: code.clone(),
            down: *down,
        },
        _ => return,
    };
    handle.send(action);
}

/// Ask the host to accept a not-yet-trusted client; returns the decision
/// (`false` on reject, timeout, or a dropped channel). Bounded so a connection
/// never hangs forever waiting on an absent or distracted host.
async fn ask_consent(tx: &Sender<ConsentRequest>, key: Option<String>, name: String) -> bool {
    let (reply, rx) = oneshot::channel();
    if tx.send(ConsentRequest { key, name, reply }).await.is_err() {
        return false; // the app side is gone
    }
    matches!(
        tokio::time::timeout(std::time::Duration::from_secs(60), rx).await,
        Ok(Ok(true))
    )
}

/// The displays to offer the client: all of them when sharing is unrestricted,
/// else just the primary (the first one) so the client's screen picker hides.
async fn allowed_displays(share_all: bool) -> Vec<DisplayInfo> {
    // `displays_for_host` blocks on D-Bus (Mutter) — keep it off the async worker.
    let mut displays = tokio::task::spawn_blocking(displays_for_host)
        .await
        .unwrap_or_default();
    if !share_all {
        displays.truncate(1);
    }
    displays
}

/// Capture a screen continuously and send JPEG frames over the sealed channel
/// until the client disconnects. `display` is the initial screen (`None` =
/// primary); a [`LanRequest::SwitchDisplay`] from the client mid-stream restarts
/// capture on another screen (macOS). On macOS capture starts with no dialog; on
/// Linux one ScreenCast portal prompt covers the stream and switching is a no-op.
/// Resolve when the host bumps the `kick` channel (host-initiated disconnect);
/// stay pending forever when there's no channel, so the `select!` arm is inert.
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn wait_kick(kick: &mut Option<watch::Receiver<u64>>) {
    match kick {
        Some(rx) => {
            let _ = rx.changed().await;
        },
        None => std::future::pending().await,
    }
}

/// Resolve when the host toggles "share all screens"; stay pending forever when
/// there's no channel, so the `select!` arm is inert (CLI agent).
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn wait_share_change(share_all: &mut Option<watch::Receiver<bool>>) {
    match share_all {
        Some(rx) => {
            let _ = rx.changed().await;
        },
        None => std::future::pending().await,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(
    clippy::too_many_arguments,
    clippy::cognitive_complexity,
    clippy::too_many_lines
)]
async fn stream_screen(
    stream: TcpStream,
    channel: Arc<SealedChannel>,
    fps: u16,
    mut display: Option<u32>,
    mut kick: Option<watch::Receiver<u64>>,
    mut share_all: Option<watch::Receiver<bool>>,
    control: Option<watch::Receiver<bool>>,
) -> AgentResult<()> {
    use rivetlink_sdk::lan::FrameDelta;

    let scr = display; // reserved token in tracing fields — log a copy
    tracing::info!(fps, screen = ?scr, "LAN stream: starting");
    let (mut rd, mut wr) = stream.into_split();

    // Read client control messages in a side task and forward them over a
    // channel. That keeps the (non-cancel-safe) request read off the frame-send
    // path: the main loop only selects on cancel-safe mpsc receivers.
    // Sized for input bursts (mouse moves/keys) interleaved with the rare
    // display switch, so high-frequency control doesn't head-of-line block.
    let (ctrl_tx, mut ctrl_rx) = tokio::sync::mpsc::channel::<LanRequest>(64);
    let reader_ch = Arc::clone(&channel);
    let reader = tokio::spawn(async move {
        while let Ok(req) = lan::recv_request(&mut rd, &reader_ch).await {
            if ctrl_tx.send(req).await.is_err() {
                break; // main loop gone
            }
        }
    });
    let _reader_guard = AbortOnDrop(reader.abort_handle());

    // The remote-input injector (a Mutter RemoteDesktop session on a worker
    // thread) is spawned lazily on the first granted input event, then reused for
    // the session. Linux only; macOS has no injector backend yet, so remote input
    // is silently dropped.
    #[cfg(target_os = "linux")]
    let mut injector: Option<crate::input::InputHandle> = None;

    // Re-enter on every display switch: tear down the capturer and start a new
    // one targeting the requested screen.
    'session: loop {
        // Small bounded channel: the capture thread drops frames the network
        // can't keep up with, so we stream the freshest frame, not stale ones.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<FrameDelta>(2);
        let cap_display = display;
        let capture = tokio::task::spawn_blocking(move || {
            // 720p + moderate JPEG quality keeps the keyframe small enough to
            // stay usable over a weak Wi-Fi link; deltas after that are tiny.
            crate::capture::screencast::stream_tiles_blocking(fps, 60, cap_display, tx)
        });

        let switch_to: u32 = loop {
            tokio::select! {
                frame = rx.recv() => match frame {
                    Some(delta) => {
                        if !send_frame(&mut wr, &channel, delta).await {
                            tracing::info!("LAN stream: client disconnected or stopped reading");
                            break 'session;
                        }
                    },
                    None => {
                        // Capture stopped on its own. Await the task to learn WHY
                        // (build failure, missing Screen Recording permission on
                        // macOS, portal closed) and surface it — to the host log
                        // and to the client, which otherwise just sees the stream
                        // die ("connection ended") with no reason.
                        let reason = match capture.await {
                            Ok(Ok(())) => "capture stopped".to_string(),
                            Ok(Err(e)) => e.to_string(),
                            Err(e) => format!("capture task crashed: {e}"),
                        };
                        tracing::warn!(reason, "LAN stream: capture ended");
                        let _ = lan::send_response(
                            &mut wr,
                            &channel,
                            &LanResponse::Error { message: reason },
                        )
                        .await;
                        break 'session;
                    },
                },
                ctrl = ctrl_rx.recv() => match ctrl {
                    Some(LanRequest::SwitchDisplay { display: d }) => {
                        // Refuse switches the host hasn't allowed: with "share all
                        // screens" off the client is pinned to the primary. Enforced
                        // here regardless of what the client's picker shows.
                        if share_all_now(&share_all) {
                            tracing::info!(display = d, "LAN stream: switching display");
                            break d;
                        }
                        tracing::info!(display = d, "LAN stream: switch refused (share-all off)");
                    },
                    Some(LanRequest::ListDisplays) => {
                        let displays = allowed_displays(share_all_now(&share_all)).await;
                        let _ = lan::send_response(
                            &mut wr,
                            &channel,
                            &LanResponse::Displays {
                                displays,
                                features: Vec::new(),
                            },
                        )
                        .await;
                    },
                    // Remote input — only when the host has granted control.
                    Some(
                        req @ (LanRequest::PointerMove { .. }
                        | LanRequest::PointerButton { .. }
                        | LanRequest::Scroll { .. }
                        | LanRequest::Key { .. }),
                    ) => {
                        if control_now(&control) {
                            #[cfg(target_os = "linux")]
                            apply_input(&mut injector, display, &req);
                            #[cfg(not(target_os = "linux"))]
                            let _ = req; // no host input backend on this platform
                        }
                    },
                    // Ignore a stray Screenshot/StartStream sent mid-stream.
                    Some(_) => {},
                    None => {
                        tracing::info!("LAN stream: client disconnected (control closed)");
                        break 'session; // reader stopped (client disconnected)
                    },
                },
                // The host hit "disconnect" on the Receive-help page: drop this
                // viewer, but leave the listener/advertisement up for the next one.
                () = wait_kick(&mut kick) => {
                    tracing::info!("LAN stream: host disconnected the client");
                    break 'session;
                },
                // The host toggled "share all screens": push the client a fresh
                // display list so its picker shows/hides live, and on revoke snap
                // capture back to the primary screen.
                () = wait_share_change(&mut share_all) => {
                    let on = share_all_now(&share_all);
                    let displays = allowed_displays(on).await;
                    tracing::info!(on, count = displays.len(), "LAN stream: share-all toggled");
                    let _ = lan::send_response(
                        &mut wr,
                        &channel,
                        &LanResponse::Displays {
                            displays: displays.clone(),
                            features: Vec::new(),
                        },
                    )
                    .await;
                    if !on {
                        let already_primary =
                            display.is_none() || display == displays.first().map(|d| d.id);
                        if !already_primary {
                            if let Some(first) = displays.first() {
                                break first.id;
                            }
                        }
                    }
                },
            }
        };

        // Stop the current capture before restarting on the new display.
        drop(rx);
        let _ = capture.await;
        display = Some(switch_to);
    }

    Ok(())
}

/// Fallback for platforms without a host capture backend (e.g. Windows).
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
async fn stream_screen(
    mut stream: TcpStream,
    channel: Arc<SealedChannel>,
    _fps: u16,
    _display: Option<u32>,
    _kick: Option<watch::Receiver<u64>>,
    _share_all: Option<watch::Receiver<bool>>,
    _control: Option<watch::Receiver<bool>>,
) -> AgentResult<()> {
    let _ = lan::send_response(
        &mut stream,
        &channel,
        &LanResponse::Error {
            message: "live streaming is not supported on this platform yet".to_string(),
        },
    )
    .await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // The privacy default: a `None` channel (the CLI agent, no UI gate) shares
    // every screen; an explicit flag is honoured verbatim. If this flips, an
    // app host that set `false` would leak all screens — so pin it.
    #[test]
    fn share_all_now_defaults_open_only_without_channel() {
        assert!(share_all_now(&None));
        let (_tx, rx) = watch::channel(false);
        assert!(!share_all_now(&Some(rx)));
        let (_tx2, rx2) = watch::channel(true);
        assert!(share_all_now(&Some(rx2)));
    }

    #[test]
    fn only_an_early_eof_is_treated_as_a_lan_health_probe() {
        assert!(is_lan_health_probe_disconnect(&AgentError::Lan(
            "direct-LAN error: io error: early eof".to_string()
        )));
        assert!(!is_lan_health_probe_disconnect(&AgentError::Lan(
            "untrusted controller".to_string()
        )));
        assert!(!is_lan_health_probe_disconnect(&AgentError::Relay(
            "no active graphical console worker".to_string()
        )));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_input_releases_only_what_is_still_pressed() {
        let mut held = HeldInput::default();
        let key = |code: &str, down| ConsoleInputPacket::Key {
            code: code.to_string(),
            down,
        };
        held.track(&key("CommandMod", true));
        held.track(&key("KeyD", true));
        held.track(&key("KeyD", false));
        held.track(&ConsoleInputPacket::PointerButton {
            button: rivetlink_protocol::MouseButton::Left,
            down: true,
        });
        held.track(&ConsoleInputPacket::PointerButton {
            button: rivetlink_protocol::MouseButton::Right,
            down: true,
        });
        held.track(&ConsoleInputPacket::PointerButton {
            button: rivetlink_protocol::MouseButton::Right,
            down: false,
        });
        let releases = held.releases();
        assert_eq!(releases.len(), 2);
        assert!(matches!(
            &releases[0],
            ConsoleInputPacket::Key { code, down: false } if code == "CommandMod"
        ));
        assert!(matches!(
            releases[1],
            ConsoleInputPacket::PointerButton {
                button: rivetlink_protocol::MouseButton::Left,
                down: false,
            }
        ));
        assert!(HeldInput::default().releases().is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn desktop_handoff_forwards_only_normalized_input() {
        assert!(matches!(
            desktop_input(LanRequest::Key {
                code: "Enter".to_string(),
                down: true,
            }),
            Some(ConsoleInputPacket::Key { .. })
        ));
        assert!(desktop_input(LanRequest::StartStream {
            fps: 30,
            display: None,
            name: None,
            identity_key: None,
            identity_sig: None,
        })
        .is_none());
    }
}
