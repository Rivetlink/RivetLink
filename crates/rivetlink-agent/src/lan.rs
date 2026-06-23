//! Direct-LAN host: advertise via mDNS and serve screenshot sessions over TCP.
//!
//! No relay involved. The agent binds a TCP listener, advertises itself on the
//! local network (`_rivetlink._tcp`), and for each incoming connection runs the
//! SDK's direct handshake (PIN/PAKE or key/TOFU) to derive an end-to-end
//! encrypted channel, then serves screenshot requests over it.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::SigningKey;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::Sender;

use rivetlink_crypto::sealed::SealedChannel;
use rivetlink_sdk::direct;
use rivetlink_sdk::identity::Identity;
use rivetlink_sdk::lan::{
    self, Advertiser, DisplayInfo, LanRequest, LanResponse, PROTOCOL_VERSION,
};

use crate::capture::screenshot;
use crate::error::{AgentError, AgentResult};
use crate::trusted::TrustedClients;

/// A change in LAN host session state, for an embedding app to drive its UI.
/// The CLI agent ignores these (it logs instead); a desktop host surfaces them
/// as "waiting" / "connected" status.
#[derive(Debug, Clone)]
pub enum HostEvent {
    /// A client finished the handshake and now holds a session. The string is a
    /// short label (peer address in PIN mode, client identity in key mode).
    ClientConnected(String),
    /// A client's session ended (disconnect or error).
    ClientDisconnected,
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
    serve_with_events(signing_key, device_name, port, auth, None).await
}

/// Like [`serve`], but reports session lifecycle on `events` (if given) so an
/// embedding desktop app can show "waiting" / "connected". Cancel by dropping
/// the future (aborting the task): the listener and mDNS advertisement are
/// released on drop.
pub async fn serve_with_events(
    signing_key: SigningKey,
    device_name: String,
    port: u16,
    auth: LanAuth,
    events: Option<Sender<HostEvent>>,
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
                let signing_key = signing_key.clone();
                let auth = Arc::clone(&auth);
                let events = events.clone();
                sessions.spawn(async move {
                    if let Err(e) = handle(stream, signing_key, &auth, peer, events).await {
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
    match TcpListener::bind(("0.0.0.0", port)).await {
        Ok(listener) => Ok(listener),
        Err(e) if port != 0 && e.kind() == std::io::ErrorKind::AddrInUse => {
            tracing::warn!(port, "LAN port busy, falling back to an OS-assigned port");
            Ok(TcpListener::bind(("0.0.0.0", 0)).await?)
        },
        Err(e) => Err(e.into()),
    }
}

async fn handle(
    mut stream: TcpStream,
    signing_key: SigningKey,
    auth: &LanAuth,
    peer: std::net::SocketAddr,
    events: Option<Sender<HostEvent>>,
) -> AgentResult<()> {
    let (channel, label) = match auth {
        LanAuth::Password(pin) => {
            let channel = direct::host_accept_password(&mut stream, pin)
                .await
                .map_err(|e| AgentError::Lan(e.to_string()))?;
            (channel, peer.ip().to_string())
        },
        LanAuth::Key {
            trusted,
            auto_accept,
        } => {
            let identity = Identity::from_signing_key(signing_key);
            let (channel, client_id) =
                direct::host_accept_key(&mut stream, &identity, |id| {
                    *auto_accept || trusted.is_trusted(id)
                })
                .await
                .map_err(|e| AgentError::Lan(e.to_string()))?;
            tracing::info!(client = %client_id, "LAN client accepted (key mode)");
            (channel, client_id.clone())
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
                    (channel, id)
                },
                None => (channel, peer.ip().to_string()),
            }
        },
    };

    tracing::info!(%peer, label = %label, "LAN: session established, serving");
    if let Some(ev) = &events {
        let _ = ev.send(HostEvent::ClientConnected(label)).await;
    }
    // Share the channel (Arc) so a live stream can read control messages in a
    // side task while it writes frames — the sealed channel is stateless.
    let result = serve_loop(stream, Arc::new(channel)).await;
    tracing::info!(%peer, "LAN: session ended");
    if let Some(ev) = &events {
        let _ = ev.send(HostEvent::ClientDisconnected).await;
    }
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
async fn serve_loop(mut stream: TcpStream, channel: Arc<SealedChannel>) -> AgentResult<()> {
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
                let displays = displays_for_host();
                tracing::info!(count = displays.len(), "LAN serve: ListDisplays request");
                lan::send_response(&mut stream, &channel, &LanResponse::Displays { displays })
                    .await
                    .map_err(|e| AgentError::Lan(e.to_string()))?;
            },
            LanRequest::StartStream { fps, display } => {
                let scr = display;
                tracing::info!(fps, screen = ?scr, "LAN serve: StartStream request");
                // The stream runs until the client disconnects; then done.
                return stream_screen(stream, channel, fps, display).await;
            },
            // Only meaningful while streaming; ignore it outside a stream.
            LanRequest::SwitchDisplay { .. } => {},
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

/// Capture a screen continuously and send JPEG frames over the sealed channel
/// until the client disconnects. `display` is the initial screen (`None` =
/// primary); a [`LanRequest::SwitchDisplay`] from the client mid-stream restarts
/// capture on another screen (macOS). On macOS capture starts with no dialog; on
/// Linux one ScreenCast portal prompt covers the stream and switching is a no-op.
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn stream_screen(
    stream: TcpStream,
    channel: Arc<SealedChannel>,
    fps: u16,
    mut display: Option<u32>,
) -> AgentResult<()> {
    use rivetlink_sdk::lan::FrameDelta;

    let scr = display; // reserved token in tracing fields — log a copy
    tracing::info!(fps, screen = ?scr, "LAN stream: starting");
    let (mut rd, mut wr) = stream.into_split();

    // Read client control messages in a side task and forward them over a
    // channel. That keeps the (non-cancel-safe) request read off the frame-send
    // path: the main loop only selects on cancel-safe mpsc receivers.
    let (ctrl_tx, mut ctrl_rx) = tokio::sync::mpsc::channel::<LanRequest>(4);
    let reader_ch = Arc::clone(&channel);
    let reader = tokio::spawn(async move {
        while let Ok(req) = lan::recv_request(&mut rd, &reader_ch).await {
            if ctrl_tx.send(req).await.is_err() {
                break; // main loop gone
            }
        }
    });
    let _reader_guard = AbortOnDrop(reader.abort_handle());

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
                        if lan::send_response(&mut wr, &channel, &LanResponse::Frame(delta))
                            .await
                            .is_err()
                        {
                            tracing::info!("LAN stream: client disconnected (frame send failed)");
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
                        tracing::info!(display = d, "LAN stream: switching display");
                        break d;
                    },
                    Some(LanRequest::ListDisplays) => {
                        let displays = displays_for_host();
                        let _ = lan::send_response(
                            &mut wr,
                            &channel,
                            &LanResponse::Displays { displays },
                        )
                        .await;
                    },
                    // Ignore a stray Screenshot/StartStream sent mid-stream.
                    Some(_) => {},
                    None => {
                        tracing::info!("LAN stream: client disconnected (control closed)");
                        break 'session; // reader stopped (client disconnected)
                    },
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
) -> AgentResult<()> {
    let _ = lan::send_response(&mut stream, &channel, &LanResponse::Error {
        message: "live streaming is not supported on this platform yet".to_string(),
    })
    .await;
    Ok(())
}
