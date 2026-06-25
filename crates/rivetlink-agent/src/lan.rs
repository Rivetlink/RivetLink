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
use tokio::sync::watch;

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
    /// A client started *viewing* the screen (sent a `StartStream`, not merely
    /// finished the handshake). The string is the client's device name when it
    /// sent one, else a short network label (peer IP / client identity).
    ClientConnected(String),
    /// A client's session ended (disconnect, error, or host-initiated kick).
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
    serve_with_events(signing_key, device_name, port, auth, None, None, None).await
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
#[allow(clippy::too_many_arguments)] // distinct host knobs; a struct adds ceremony
pub async fn serve_with_events(
    signing_key: SigningKey,
    device_name: String,
    port: u16,
    auth: LanAuth,
    events: Option<Sender<HostEvent>>,
    kick: Option<watch::Receiver<u64>>,
    share_all: Option<watch::Receiver<bool>>,
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
                sessions.spawn(async move {
                    if let Err(e) =
                        handle(stream, signing_key, &auth, peer, events, kick, share_all).await
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
    match TcpListener::bind(("0.0.0.0", port)).await {
        Ok(listener) => Ok(listener),
        Err(e) if port != 0 && e.kind() == std::io::ErrorKind::AddrInUse => {
            tracing::warn!(port, "LAN port busy, falling back to an OS-assigned port");
            Ok(TcpListener::bind(("0.0.0.0", 0)).await?)
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
    // Share the channel (Arc) so a live stream can read control messages in a
    // side task while it writes frames — the sealed channel is stateless.
    // The connected/disconnected events are emitted inside serve_loop, bracketing
    // the *stream* (StartStream..end) — not the bare handshake — so the host only
    // shows "connected" once the client is actually viewing.
    let result = serve_loop(stream, Arc::new(channel), events, label, kick, share_all).await;
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
async fn serve_loop(
    mut stream: TcpStream,
    channel: Arc<SealedChannel>,
    events: Option<Sender<HostEvent>>,
    label: String,
    kick: Option<watch::Receiver<u64>>,
    share_all: Option<watch::Receiver<bool>>,
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
                lan::send_response(&mut stream, &channel, &LanResponse::Displays { displays })
                    .await
                    .map_err(|e| AgentError::Lan(e.to_string()))?;
            },
            LanRequest::StartStream { fps, display, name } => {
                // Honour the requested screen only when sharing all screens is on;
                // otherwise pin to the primary (`None`).
                let display = if share_all_now(&share_all) { display } else { None };
                let scr = display;
                tracing::info!(fps, screen = ?scr, "LAN serve: StartStream request");
                // Now the client is actually viewing: announce who, falling back
                // to the network label when it sent no name.
                let who = name
                    .filter(|n| !n.trim().is_empty())
                    .unwrap_or_else(|| label.clone());
                if let Some(ev) = &events {
                    let _ = ev.send(HostEvent::ClientConnected(who)).await;
                }
                // The stream runs until the client disconnects or the host kicks.
                let result = stream_screen(stream, channel, fps, display, kick, share_all).await;
                if let Some(ev) = &events {
                    let _ = ev.send(HostEvent::ClientDisconnected).await;
                }
                return result;
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

/// Current "share all screens" state. `None` (CLI agent) or `true` means the
/// client sees and can switch every display; `false` restricts it to the primary.
fn share_all_now(share_all: &Option<watch::Receiver<bool>>) -> bool {
    share_all.as_ref().is_none_or(|rx| *rx.borrow())
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
#[allow(clippy::too_many_arguments, clippy::cognitive_complexity, clippy::too_many_lines)]
async fn stream_screen(
    stream: TcpStream,
    channel: Arc<SealedChannel>,
    fps: u16,
    mut display: Option<u32>,
    mut kick: Option<watch::Receiver<u64>>,
    mut share_all: Option<watch::Receiver<bool>>,
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
                        &LanResponse::Displays { displays: displays.clone() },
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
) -> AgentResult<()> {
    let _ = lan::send_response(&mut stream, &channel, &LanResponse::Error {
        message: "live streaming is not supported on this platform yet".to_string(),
    })
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
}
