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
use rivetlink_sdk::lan::{self, Advertiser, LanRequest, LanResponse, PROTOCOL_VERSION};

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
    };

    if let Some(ev) = &events {
        let _ = ev.send(HostEvent::ClientConnected(label)).await;
    }
    let result = serve_loop(&mut stream, &channel).await;
    if let Some(ev) = &events {
        let _ = ev.send(HostEvent::ClientDisconnected).await;
    }
    result
}

/// Serve requests on an established channel until the client disconnects.
async fn serve_loop(stream: &mut TcpStream, channel: &SealedChannel) -> AgentResult<()> {
    loop {
        let Ok(req) = lan::recv_request(stream, channel).await else {
            return Ok(());
        };
        match req {
            LanRequest::Screenshot => {
                let resp = match screenshot::capture_png().await {
                    Ok(png) => LanResponse::Screenshot {
                        png_b64: B64.encode(png),
                    },
                    Err(e) => LanResponse::Error {
                        message: e.to_string(),
                    },
                };
                lan::send_response(stream, channel, &resp)
                    .await
                    .map_err(|e| AgentError::Lan(e.to_string()))?;
            },
            LanRequest::StartStream { fps } => {
                // The stream runs until the client disconnects; then done.
                return stream_screen(stream, channel, fps).await;
            },
        }
    }
}

/// Capture the screen continuously and send JPEG frames over the sealed channel
/// until the client disconnects. One portal prompt covers the whole stream.
#[cfg(target_os = "linux")]
async fn stream_screen(stream: &mut TcpStream, channel: &SealedChannel, fps: u16) -> AgentResult<()> {
    use rivetlink_sdk::lan::FrameDelta;

    // Small bounded channel: the capture thread drops frames the network can't
    // keep up with, so we stream the freshest frame rather than build latency.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<FrameDelta>(2);
    let capture = tokio::task::spawn_blocking(move || {
        // 720p + moderate JPEG quality keeps the keyframe small enough to stay
        // usable over a weak Wi-Fi link; deltas after that are tiny.
        crate::capture::screencast::stream_tiles_blocking(fps, 60, tx)
    });

    while let Some(delta) = rx.recv().await {
        if lan::send_response(stream, channel, &LanResponse::Frame(delta))
            .await
            .is_err()
        {
            break; // client disconnected
        }
    }

    drop(rx); // closes the channel so the capture thread stops
    if let Ok(Err(e)) = capture.await {
        tracing::debug!(error = %e, "screen capture stream ended with error");
    }
    Ok(())
}

/// Streaming is Linux-only for now (ScreenCast portal + PipeWire).
#[cfg(not(target_os = "linux"))]
async fn stream_screen(
    stream: &mut TcpStream,
    channel: &SealedChannel,
    _fps: u16,
) -> AgentResult<()> {
    let _ = lan::send_response(stream, channel, &LanResponse::Error {
        message: "live streaming is not supported on this platform yet".to_string(),
    })
    .await;
    Ok(())
}
