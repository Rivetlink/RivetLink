//! Broker-side endpoint for the active login-manager/GNOME session worker.
//!
//! The broker may own device identity and relay connectivity, but cannot call
//! Mutter or inject input itself. It must receive a worker from an explicitly
//! allow-listed local UID over a restrictive Unix socket first.

use base64::Engine;
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::RwLock;
use std::time::Duration;
use tokio::net::unix::OwnedWriteHalf;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc, watch, Mutex};

use super::worker::{
    read_packet_with_limit, write_packet, ConsoleInput, WorkerErrorCode, WorkerRequest,
    WorkerResponse,
};
use crate::error::{AgentError, AgentResult};
use crate::session::{ConsentPolicy, ConsoleInputSink, ConsoleStateProvider, ScreenshotCapturer};
use rivetlink_protocol::{ConsoleInputPacket, HostConsoleState, MouseButton};
use rivetlink_sdk::lan::{DisplayInfo, PtrButton, StreamFrame};

/// Upper bound for a base64 PNG response (~9 MiB decoded), matching the
/// unattended host's configured maximum without trusting worker input blindly.
const MAX_WORKER_RESPONSE: usize = 12 * 1024 * 1024;

/// A listener whose peer-credential allow-list is enforced before any capture
/// or input request reaches a session worker.
#[derive(Debug)]
pub struct ConsoleBrokerListener {
    listener: UnixListener,
    /// Stable, installer-provided desktop/legacy-GDM UIDs.
    allowed_worker_uids: BTreeSet<u32>,
    /// The current greeter may use a systemd DynamicUser. These UIDs are
    /// discovered from logind and replaced as their sessions change, rather
    /// than turning an old dynamic UID into a permanent local privilege.
    active_greeter_uids: Arc<RwLock<BTreeSet<u32>>>,
}

impl ConsoleBrokerListener {
    /// Bind the broker socket. Its parent directory must already be a
    /// systemd-created runtime directory inaccessible to arbitrary users.
    pub fn bind(path: &Path, allowed_worker_uids: BTreeSet<u32>) -> AgentResult<Self> {
        if allowed_worker_uids.is_empty() {
            return Err(AgentError::Config(
                "console broker requires at least one allowed worker UID".to_string(),
            ));
        }
        let listener = UnixListener::bind(path)
            .map_err(|error| AgentError::Config(format!("bind console broker: {error}")))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
            .map_err(|error| AgentError::Config(format!("secure console socket: {error}")))?;
        grant_worker_socket_access(path, &allowed_worker_uids)?;
        let active_greeter_uids = Arc::new(RwLock::new(BTreeSet::new()));
        #[cfg(target_os = "linux")]
        spawn_greeter_refresh(path.to_path_buf(), Arc::clone(&active_greeter_uids));
        Ok(Self {
            listener,
            allowed_worker_uids,
            active_greeter_uids,
        })
    }

    /// Wait for one authenticated GDM/desktop session worker.
    pub async fn accept(&self) -> AgentResult<ConsoleWorkerClient> {
        loop {
            let (stream, _) = self.listener.accept().await?;
            let uid = stream
                .peer_cred()
                .map_err(|error| {
                    AgentError::Config(format!("read console peer credentials: {error}"))
                })?
                .uid();
            let dynamic_allowed = self
                .active_greeter_uids
                .read()
                .is_ok_and(|uids| uids.contains(&uid));
            if !self.allowed_worker_uids.contains(&uid) && !dynamic_allowed {
                tracing::warn!(uid, "console worker rejected by local UID policy");
                drop(stream);
                continue;
            }
            return ConsoleWorkerClient::from_stream(stream).await;
        }
    }

    /// Continuously accept workers as GDM, lock, logout and GNOME ownership
    /// changes replace the graphical session. A new connection atomically
    /// supersedes the old worker for subsequent capture/input requests.
    #[must_use]
    pub fn into_pool(self) -> ConsoleWorkerPool {
        let (tx, rx) = watch::channel(None::<ConsoleWorkerClient>);
        let generation = Arc::new(AtomicU64::new(0));
        let generation_for_accept = generation.clone();
        tokio::spawn(async move {
            loop {
                match self.accept().await {
                    Ok(worker) => {
                        let generation = generation_for_accept.fetch_add(1, Ordering::Relaxed) + 1;
                        tracing::info!(generation, "graphical console worker became active");
                        let mut closed = worker.closed.clone();
                        let _ = tx.send(Some(worker));
                        let clear_tx = tx.clone();
                        let clear_generation = Arc::clone(&generation_for_accept);
                        tokio::spawn(async move {
                            let already_closed = *closed.borrow();
                            if !already_closed && closed.changed().await.is_err() {
                                return;
                            }
                            if clear_generation.load(Ordering::Relaxed) == generation {
                                tracing::warn!(
                                    generation,
                                    "active graphical console worker disconnected"
                                );
                                let _ = clear_tx.send(None);
                            }
                        });
                    },
                    Err(error) => {
                        tracing::warn!(error = %error, "console worker accept failed; retrying");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    },
                }
            }
        });
        ConsoleWorkerPool {
            receiver: Arc::new(Mutex::new(rx)),
            generation,
            desktop_owner: Arc::new(watch::channel(0).0),
            desktop_claim: Arc::new(Mutex::new(())),
        }
    }
}

/// Grant only the explicitly allow-listed graphical-worker UIDs traversal of
/// the broker runtime directory and read/write access to its socket.
///
/// GDM launches its greeter from a long-lived user manager.  Supplementary
/// groups added during installation are not reliably picked up by that manager
/// on every Ubuntu/GDM combination, even after the broker restarts.  A POSIX
/// ACL on the broker-owned directory/socket is both narrower and independent
/// of that inherited group list.  The broker still verifies `SO_PEERCRED`
/// against the same UID allow-list before accepting any worker protocol data.
fn grant_worker_socket_access(path: &Path, allowed_worker_uids: &BTreeSet<u32>) -> AgentResult<()> {
    let parent = path.parent().ok_or_else(|| {
        AgentError::Config("console broker socket has no parent directory".to_string())
    })?;
    for uid in allowed_worker_uids {
        set_acl(
            parent,
            &format!("u:{uid}:x"),
            "grant console directory traversal",
        )?;
        set_acl(path, &format!("u:{uid}:rw"), "grant console socket access")?;
    }
    tracing::debug!(
        workers = allowed_worker_uids.len(),
        "granted per-worker console socket ACLs"
    );
    Ok(())
}

/// The installer guarantees `setfacl` is present (`acl` package).  This is a
/// fixed binary with fixed targets and numeric UID ACL specs; no caller input
/// is interpreted by a shell.
fn set_acl(path: &Path, spec: &str, action: &str) -> AgentResult<()> {
    let status = std::process::Command::new("/usr/bin/setfacl")
        .args(["-m", spec])
        .arg(path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|error| AgentError::Config(format!("{action}: start setfacl: {error}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(AgentError::Config(format!("{action}: setfacl failed")))
    }
}

/// Current Ubuntu GDM can run its greeter with a transient systemd DynamicUser
/// UID (for example `gdm-greeter` / 60578). LightDM instead uses its dedicated
/// `lightdm` greeter account. Static installer-time lookups cannot safely
/// predict a DynamicUser UID after a reboot, so refresh *active greeter*
/// sessions from logind, grant the matching ACL, and replace the dynamic
/// authorization set as sessions change.
#[cfg(target_os = "linux")]
fn spawn_greeter_refresh(path: std::path::PathBuf, active: Arc<RwLock<BTreeSet<u32>>>) {
    tokio::spawn(async move {
        loop {
            let discovered = active_greeter_uids();
            if let Ok(mut permitted) = active.write() {
                let new_uids = discovered
                    .difference(&permitted)
                    .copied()
                    .collect::<BTreeSet<_>>();
                if !new_uids.is_empty() {
                    match grant_worker_socket_access(&path, &new_uids) {
                        Ok(()) => {
                            tracing::info!(uids = ?new_uids, "authorized active login-manager greeter worker");
                        },
                        Err(error) => {
                            tracing::warn!(error = %error, "could not grant active login-manager greeter socket ACL");
                            // Do not add a UID that lacks the filesystem ACL.
                            continue;
                        },
                    }
                }
                *permitted = discovered;
            } else {
                tracing::warn!("login-manager greeter UID policy lock poisoned");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

#[cfg(target_os = "linux")]
fn active_greeter_uids() -> BTreeSet<u32> {
    let output = std::process::Command::new("/usr/bin/loginctl")
        .args(["list-sessions", "--no-legend", "--no-pager"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output();
    let Ok(output) = output else {
        return BTreeSet::new();
    };
    if !output.status.success() {
        return BTreeSet::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(parse_greeter_session_uid)
        .collect()
}

/// `loginctl list-sessions --no-legend` begins each row with session ID, UID,
/// and user. Only exact, known login-manager greeter accounts are accepted; a
/// LAN client or arbitrary local process cannot nominate an UID through this
/// path. The static systemd allow-list remains authoritative for peer checks.
fn parse_greeter_session_uid(line: &str) -> Option<u32> {
    let mut fields = line.split_whitespace();
    let _session_id = fields.next()?;
    let uid = fields.next()?.parse().ok()?;
    matches!(fields.next()?, "gdm-greeter" | "gdm" | "lightdm").then_some(uid)
}

/// Switchable source that follows the current seat0 worker. It owns neither a
/// session bus nor identity key; only the broker's relay host uses it.
#[derive(Clone, Debug)]
pub struct ConsoleWorkerPool {
    receiver: Arc<Mutex<watch::Receiver<Option<ConsoleWorkerClient>>>>,
    generation: Arc<AtomicU64>,
    /// Bumped by every viewer that claims the desktop stream. The viewer
    /// holding it watches for a newer claim and then ends its session.
    desktop_owner: Arc<watch::Sender<u64>>,
    /// Held for a whole claim, so check, takeover and start are one step and
    /// a view-only device cannot slip in while a controller takes over.
    desktop_claim: Arc<Mutex<()>>,
}

/// How long a viewer taking over waits for the previous one to stop.
const TAKEOVER_WAIT: Duration = Duration::from_secs(5);

/// A viewer's claim on the desktop stream, see
/// [`ConsoleWorkerPool::claim_desktop_stream`].
#[derive(Debug)]
pub struct DesktopClaim {
    id: u64,
    owner: watch::Receiver<u64>,
}

impl DesktopClaim {
    /// Resolves once another viewer has claimed the desktop stream.
    pub async fn taken_over(&mut self) {
        let id = self.id;
        if self.owner.wait_for(|owner| *owner != id).await.is_err() {
            // The pool is gone, so nobody can take over any more.
            std::future::pending::<()>().await;
        }
    }
}

#[async_trait::async_trait]
impl ConsoleStateProvider for ConsoleWorkerPool {
    async fn console_state(&self) -> Option<(HostConsoleState, u64)> {
        let worker = self.receiver.lock().await.borrow().clone()?;
        Some((worker.state, self.generation.load(Ordering::Relaxed)))
    }
}

impl ConsoleWorkerPool {
    /// Wait until GDM or GNOME has attached a worker. No busy polling occurs.
    pub async fn wait_until_ready(&self) -> AgentResult<()> {
        let mut receiver = self.receiver.lock().await;
        while receiver.borrow().is_none() {
            receiver.changed().await.map_err(|_| {
                AgentError::Config("console worker supervisor stopped unexpectedly".to_string())
            })?;
        }
        Ok(())
    }

    async fn current(&self) -> AgentResult<ConsoleWorkerClient> {
        self.receiver
            .lock()
            .await
            .borrow()
            .clone()
            .ok_or_else(|| AgentError::Relay("no active graphical console worker".to_string()))
    }

    /// Open the normal high-performance desktop engine for a new viewer, only
    /// after the active graphical worker has reported `DesktopReady`. When another viewer has it
    /// and `take_over` is set, that viewer's [`DesktopClaim::taken_over`]
    /// fires so its session stops the stream, which this waits for (bounded
    /// by [`TAKEOVER_WAIT`]). Without `take_over` a busy stream is refused.
    pub async fn claim_desktop_stream(
        &self,
        fps: u16,
        h264: bool,
        take_over: bool,
    ) -> AgentResult<(ConsoleDesktopStream, DesktopClaim)> {
        let _claiming = self.desktop_claim.lock().await;
        if !take_over && self.current().await?.desktop_stream_active() {
            return Err(AgentError::Relay(
                "normal desktop stream is already active".to_string(),
            ));
        }
        let mut id = 0;
        self.desktop_owner.send_modify(|owner| {
            *owner += 1;
            id = *owner;
        });
        let claim = DesktopClaim {
            id,
            owner: self.desktop_owner.subscribe(),
        };
        let deadline = tokio::time::Instant::now() + TAKEOVER_WAIT;
        loop {
            let worker = self.current().await?;
            if !worker.desktop_stream_active() {
                let stream = worker.start_desktop_stream(fps, h264, None).await?;
                return Ok((stream, claim));
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(AgentError::Relay(
                    "the previous viewer did not release the desktop stream".to_string(),
                ));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Monitors of the current desktop worker, empty when it cannot switch.
    pub async fn list_displays(&self) -> AgentResult<Vec<DisplayInfo>> {
        self.current().await?.list_displays().await
    }

    /// Restart the viewer's stream on another monitor, keeping its claim: the
    /// owner counter is not bumped, and the claim lock keeps every other
    /// viewer out of the gap between stop and start. Refused while a takeover
    /// holds that lock (it waits for this viewer to stop, so waiting here
    /// would deadlock) and after this viewer was taken over.
    pub async fn switch_desktop_display(
        &self,
        desktop: &mut ConsoleDesktopStream,
        claim: &DesktopClaim,
        fps: u16,
        h264: bool,
        display: u32,
    ) -> AgentResult<()> {
        let Ok(_claiming) = self.desktop_claim.try_lock() else {
            return Err(AgentError::Relay(
                "another device is taking the desktop over".to_string(),
            ));
        };
        if *claim.owner.borrow() != claim.id {
            return Err(AgentError::Relay(
                "this viewer no longer owns the desktop stream".to_string(),
            ));
        }
        let worker = desktop.worker();
        if !worker.display_switch {
            return Err(AgentError::Relay(
                "the console worker cannot switch displays".to_string(),
            ));
        }
        worker.stop_desktop_stream().await?;
        *desktop = worker
            .start_desktop_stream(fps, h264, Some(display))
            .await?;
        Ok(())
    }
}

/// A single, authenticated connection to the current physical-console owner.
/// Cloning keeps a serial request queue, so no capture and input request can be
/// interleaved across a GDM ↔ GNOME handover.
#[derive(Clone, Debug)]
pub struct ConsoleWorkerClient {
    writer: Arc<Mutex<OwnedWriteHalf>>,
    responses: Arc<Mutex<mpsc::Receiver<WorkerResponse>>>,
    request_lock: Arc<Mutex<()>>,
    desktop_frames: broadcast::Sender<StreamFrame>,
    desktop_ended: broadcast::Sender<WorkerErrorCode>,
    desktop_stream_active: Arc<std::sync::atomic::AtomicBool>,
    /// A keyframe request is being written; further ones coalesce into it.
    keyframe_in_flight: Arc<std::sync::atomic::AtomicBool>,
    clipboard_changes: broadcast::Sender<String>,
    closed: watch::Receiver<bool>,
    state: HostConsoleState,
    /// The worker understands display listing and selection.
    display_switch: bool,
}

/// An active normal desktop stream from a worker in an authenticated GNOME
/// session. It is impossible to create this handle from a login worker.
#[derive(Debug)]
pub struct ConsoleDesktopStream {
    worker: ConsoleWorkerClient,
    frames: broadcast::Receiver<StreamFrame>,
    ended: broadcast::Receiver<WorkerErrorCode>,
    /// The worker streams H.264 (it sent a video frame), so it understands
    /// keyframe requests.
    video: bool,
    /// Video deltas are useless until the next keyframe: at the start, and
    /// after frames were lost to lag.
    awaiting_keyframe: bool,
    keyframe_requested: bool,
    lagged: bool,
    /// Last keyframe request on the viewer's behalf (rate limit).
    last_viewer_keyframe: Option<std::time::Instant>,
}

impl ConsoleWorkerClient {
    async fn from_stream(stream: UnixStream) -> AgentResult<Self> {
        let (mut reader, writer) = stream.into_split();
        let ready: WorkerResponse =
            read_packet_with_limit(&mut reader, MAX_WORKER_RESPONSE).await?;
        let WorkerResponse::Ready {
            state,
            display_switch,
        } = ready
        else {
            return Err(AgentError::Config(
                "console worker did not send a ready handshake".to_string(),
            ));
        };
        tracing::info!(?state, "authenticated graphical console worker connected");
        let (responses_tx, responses_rx) = mpsc::channel(16);
        let (desktop_frames, _) = broadcast::channel(4);
        let (desktop_ended, _) = broadcast::channel(4);
        let (clipboard_changes, _) = broadcast::channel(4);
        let reader_clipboard = clipboard_changes.clone();
        let active = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader_frames = desktop_frames.clone();
        let reader_ended = desktop_ended.clone();
        let reader_active = Arc::clone(&active);
        let (closed_tx, closed) = watch::channel(false);
        tokio::spawn(async move {
            loop {
                let response: AgentResult<WorkerResponse> =
                    read_packet_with_limit(&mut reader, MAX_WORKER_RESPONSE).await;
                match response {
                    Ok(WorkerResponse::DesktopFrame { delta }) => {
                        let _ = reader_frames.send(StreamFrame::Tiles(delta));
                    },
                    Ok(WorkerResponse::DesktopVideo { frame }) => {
                        let _ = reader_frames.send(StreamFrame::Video(frame));
                    },
                    Ok(WorkerResponse::ClipboardChanged { text }) => {
                        let _ = reader_clipboard.send(text);
                    },
                    Ok(WorkerResponse::DesktopStreamEnded { code }) => {
                        reader_active.store(false, Ordering::Release);
                        let _ = reader_ended.send(code);
                    },
                    Ok(response) => {
                        if responses_tx.send(response).await.is_err() {
                            break;
                        }
                    },
                    Err(error) => {
                        tracing::warn!(error = %error, "console worker IPC reader ended");
                        reader_active.store(false, Ordering::Release);
                        let _ = reader_ended.send(WorkerErrorCode::CompositorFailure);
                        let _ = closed_tx.send(true);
                        break;
                    },
                }
            }
        });
        Ok(Self {
            writer: Arc::new(Mutex::new(writer)),
            responses: Arc::new(Mutex::new(responses_rx)),
            request_lock: Arc::new(Mutex::new(())),
            desktop_frames,
            desktop_ended,
            desktop_stream_active: active,
            keyframe_in_flight: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            clipboard_changes,
            closed,
            state,
            display_switch,
        })
    }

    /// Capture the monitor the connected login-manager/GNOME worker owns.
    pub async fn capture_png(&self, timeout: Duration) -> AgentResult<Vec<u8>> {
        let millis = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        let response = self
            .request(WorkerRequest::Capture { timeout_ms: millis })
            .await?;
        match response {
            WorkerResponse::Capture { png_b64 } => {
                let png = base64::engine::general_purpose::STANDARD
                    .decode(png_b64)
                    .map_err(|error| AgentError::Base64(error.to_string()))?;
                if png.len() > MAX_WORKER_RESPONSE {
                    return Err(AgentError::Config(
                        "console worker capture exceeds maximum size".to_string(),
                    ));
                }
                Ok(png)
            },
            WorkerResponse::Error { code } => Err(worker_error(code)),
            _ => Err(AgentError::Config(
                "unexpected console worker capture response".to_string(),
            )),
        }
    }

    /// Deliver normalized input only after the broker's trusted-client and
    /// session authorization checks. The caller must never log `event`.
    pub async fn send_input(&self, event: ConsoleInput) -> AgentResult<()> {
        match self.request(WorkerRequest::Input { event }).await? {
            WorkerResponse::InputAccepted => Ok(()),
            WorkerResponse::Error { code } => Err(worker_error(code)),
            _ => Err(AgentError::Config(
                "unexpected console worker input response".to_string(),
            )),
        }
    }

    /// Start the existing normal Mutter/PipeWire engine in the authenticated
    /// desktop worker, as H.264 when `h264` (an older worker may still send
    /// tiles). The socket remains local; only the broker's already-
    /// authenticated network session receives these frames.
    pub async fn start_desktop_stream(
        &self,
        fps: u16,
        h264: bool,
        display: Option<u32>,
    ) -> AgentResult<ConsoleDesktopStream> {
        if self.state != HostConsoleState::DesktopReady {
            return Err(AgentError::Relay(
                "normal desktop stream is unavailable before an authenticated desktop is ready"
                    .to_string(),
            ));
        }
        if self
            .desktop_stream_active
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return Err(AgentError::Relay(
                "normal desktop stream is already active".to_string(),
            ));
        }
        let frames = self.desktop_frames.subscribe();
        let ended = self.desktop_ended.subscribe();
        // A keyframe request still being written for a previous stream would
        // swallow this stream's first one.
        self.keyframe_in_flight.store(false, Ordering::Release);
        match self
            .request(WorkerRequest::StartDesktopStream { fps, h264, display })
            .await
        {
            Ok(WorkerResponse::DesktopStreamStarted) => Ok(ConsoleDesktopStream {
                worker: self.clone(),
                frames,
                ended,
                video: false,
                awaiting_keyframe: true,
                keyframe_requested: false,
                lagged: false,
                last_viewer_keyframe: None,
            }),
            Ok(WorkerResponse::Error { code }) => {
                self.desktop_stream_active
                    .store(false, std::sync::atomic::Ordering::Release);
                Err(worker_error(code))
            },
            Ok(_) => {
                self.desktop_stream_active
                    .store(false, std::sync::atomic::Ordering::Release);
                Err(AgentError::Config(
                    "unexpected console worker desktop-stream response".to_string(),
                ))
            },
            Err(error) => {
                self.desktop_stream_active
                    .store(false, std::sync::atomic::Ordering::Release);
                Err(error)
            },
        }
    }

    /// The desktop worker's monitors, primary first. Empty without asking
    /// when the worker predates display switching (it would drop the
    /// connection on the unknown request) or no desktop is signed in.
    pub async fn list_displays(&self) -> AgentResult<Vec<DisplayInfo>> {
        if !self.display_switch || self.state != HostConsoleState::DesktopReady {
            return Ok(Vec::new());
        }
        match self.request(WorkerRequest::ListDisplays).await? {
            WorkerResponse::Displays { displays } => Ok(displays),
            WorkerResponse::Error { code } => Err(worker_error(code)),
            _ => Err(AgentError::Config(
                "unexpected console worker display-list response".to_string(),
            )),
        }
    }

    /// Ask the worker's H.264 stream for a keyframe. Fire-and-forget on its
    /// own task: the worker sends no reply, and a write cancelled halfway (the
    /// caller sits in a `select!`) would corrupt the IPC framing. Requests
    /// made while one is still being written coalesce into it, so a flood
    /// cannot pile up tasks or delay input on the shared writer.
    fn request_keyframe(&self, congested: bool) {
        if self.keyframe_in_flight.swap(true, Ordering::AcqRel) {
            return;
        }
        let writer = Arc::clone(&self.writer);
        let in_flight = Arc::clone(&self.keyframe_in_flight);
        tokio::spawn(async move {
            let mut writer = writer.lock().await;
            if let Err(error) =
                write_packet(&mut *writer, &WorkerRequest::RequestKeyframe { congested }).await
            {
                tracing::debug!(error = %error, "console worker keyframe request failed");
            }
            in_flight.store(false, Ordering::Release);
        });
    }

    pub(crate) fn desktop_stream_active(&self) -> bool {
        self.desktop_stream_active
            .load(std::sync::atomic::Ordering::Acquire)
    }

    async fn stop_desktop_stream(&self) -> AgentResult<()> {
        self.desktop_stream_active
            .store(false, std::sync::atomic::Ordering::Release);
        match self.request(WorkerRequest::StopDesktopStream).await? {
            WorkerResponse::DesktopStreamStopped => Ok(()),
            WorkerResponse::Error { code } => Err(worker_error(code)),
            _ => Err(AgentError::Config(
                "unexpected console worker desktop-stream stop response".to_string(),
            )),
        }
    }

    /// Start the worker's clipboard bridge. Host copies are then delivered to
    /// every [`Self::clipboard_changes`] subscriber.
    pub async fn enable_clipboard(&self) -> AgentResult<()> {
        match self.request(WorkerRequest::ClipboardEnable).await? {
            WorkerResponse::ClipboardEnabled => Ok(()),
            response => Err(unexpected_share_response(&response)),
        }
    }

    pub fn clipboard_changes(&self) -> broadcast::Receiver<String> {
        self.clipboard_changes.subscribe()
    }

    pub async fn set_clipboard(&self, text: String) -> AgentResult<()> {
        match self.request(WorkerRequest::ClipboardSet { text }).await? {
            WorkerResponse::ClipboardAccepted => Ok(()),
            response => Err(unexpected_share_response(&response)),
        }
    }

    pub async fn upload_start(&self, id: u32, path: String, size: u64) -> AgentResult<()> {
        match self
            .request(WorkerRequest::FileUploadStart { id, path, size })
            .await?
        {
            WorkerResponse::FileAccepted => Ok(()),
            response => Err(unexpected_share_response(&response)),
        }
    }

    pub async fn upload_chunk(&self, id: u32, data_b64: String) -> AgentResult<()> {
        match self
            .request(WorkerRequest::FileUploadChunk { id, data_b64 })
            .await?
        {
            WorkerResponse::FileAccepted => Ok(()),
            response => Err(unexpected_share_response(&response)),
        }
    }

    /// Finish an upload; returns its final path inside the shared folder.
    pub async fn upload_end(&self, id: u32) -> AgentResult<String> {
        match self.request(WorkerRequest::FileUploadEnd { id }).await? {
            WorkerResponse::FileUploaded { path } => Ok(path),
            response => Err(unexpected_share_response(&response)),
        }
    }

    pub async fn list_shared(&self) -> AgentResult<Vec<rivetlink_sdk::share::SharedEntry>> {
        match self.request(WorkerRequest::ListSharedFiles).await? {
            WorkerResponse::SharedFiles { entries } => Ok(entries),
            response => Err(unexpected_share_response(&response)),
        }
    }

    /// One chunk of a shared file: base64 data, full size, and end-of-file.
    pub async fn read_shared(&self, path: String, offset: u64) -> AgentResult<(String, u64, bool)> {
        match self
            .request(WorkerRequest::ReadSharedFile { path, offset })
            .await?
        {
            WorkerResponse::SharedFileData {
                data_b64,
                size,
                eof,
            } => Ok((data_b64, size, eof)),
            response => Err(unexpected_share_response(&response)),
        }
    }

    async fn request(&self, request: WorkerRequest) -> AgentResult<WorkerResponse> {
        // Control requests stay ordered, while the independent IPC reader
        // forwards desktop frames through a lossy newest-frame channel.
        let _request = self.request_lock.lock().await;
        {
            let mut writer = self.writer.lock().await;
            write_packet(&mut *writer, &request).await?;
        }
        self.responses
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| AgentError::Relay("console worker disconnected".to_string()))
    }
}

fn unexpected_share_response(response: &WorkerResponse) -> AgentError {
    match response {
        WorkerResponse::Error { code } => worker_error(*code),
        _ => AgentError::Share("the console worker sent an unexpected response".to_string()),
    }
}

impl ConsoleDesktopStream {
    /// The worker serving this stream, for clipboard and file requests that
    /// must reach the same logged-in session.
    pub fn worker(&self) -> ConsoleWorkerClient {
        self.worker.clone()
    }

    /// Return the freshest encoded desktop frame, or a non-sensitive terminal
    /// error when the worker/session disappears. Cancellation-safe.
    ///
    /// Tile frames may be dropped under lag (the next keyframe heals them).
    /// Video frames may not: after a lag every delta is held back until the
    /// worker, asked once, sends a keyframe.
    pub async fn next(&mut self) -> AgentResult<StreamFrame> {
        loop {
            tokio::select! {
                frame = self.frames.recv() => match frame {
                    Ok(StreamFrame::Video(video)) => {
                        self.video = true;
                        if video.keyframe {
                            self.awaiting_keyframe = false;
                            self.keyframe_requested = false;
                        } else if self.awaiting_keyframe {
                            if !self.keyframe_requested {
                                self.worker.request_keyframe(std::mem::take(&mut self.lagged));
                                self.keyframe_requested = true;
                            }
                            continue;
                        }
                        return Ok(StreamFrame::Video(video));
                    },
                    Ok(frame) => return Ok(frame),
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        self.awaiting_keyframe = true;
                        if self.video {
                            // Lag is the console path's congestion signal.
                            self.worker.request_keyframe(true);
                            self.keyframe_requested = true;
                        } else {
                            // Not known to be video yet: ask on the first
                            // delta, never a worker that streams tiles.
                            self.keyframe_requested = false;
                            self.lagged = true;
                        }
                    },
                    Err(broadcast::error::RecvError::Closed) => return Err(AgentError::Relay("normal desktop stream closed".to_string())),
                },
                ended = self.ended.recv() => match ended {
                    Ok(code) => return Err(worker_error(code)),
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return Err(AgentError::Relay("normal desktop stream closed".to_string())),
                },
            }
        }
    }

    /// The viewer could not decode a frame: get a keyframe. Ignored for tile
    /// streams, whose (possibly older) worker would not know the request, and
    /// at most twice a second.
    pub fn request_keyframe(&mut self) {
        const MIN_GAP: Duration = Duration::from_millis(500);
        if !self.video
            || self
                .last_viewer_keyframe
                .is_some_and(|at| at.elapsed() < MIN_GAP)
        {
            return;
        }
        self.last_viewer_keyframe = Some(std::time::Instant::now());
        self.worker.request_keyframe(false);
    }

    pub async fn stop(self) -> AgentResult<()> {
        self.worker.stop_desktop_stream().await
    }
}

#[async_trait::async_trait]
impl ScreenshotCapturer for ConsoleWorkerClient {
    async fn capture(&mut self, policy: ConsentPolicy) -> AgentResult<Vec<u8>> {
        let timeout = match policy {
            ConsentPolicy::HeadlessTrustedOnly {
                capture_timeout, ..
            }
            | ConsentPolicy::UnattendedConsole {
                capture_timeout, ..
            } => capture_timeout,
            ConsentPolicy::Prompt => Duration::from_secs(10),
        };
        self.capture_png(timeout).await
    }
}

#[async_trait::async_trait]
impl ConsoleInputSink for ConsoleWorkerClient {
    async fn inject(&mut self, event: ConsoleInputPacket) -> AgentResult<()> {
        let event = match event {
            ConsoleInputPacket::PointerMove { x, y } => ConsoleInput::PointerMove { x, y },
            ConsoleInputPacket::PointerButton { button, down } => ConsoleInput::PointerButton {
                button: match button {
                    MouseButton::Left => PtrButton::Left,
                    MouseButton::Right => PtrButton::Right,
                    MouseButton::Middle => PtrButton::Middle,
                },
                down,
            },
            ConsoleInputPacket::Scroll { dx, dy } => ConsoleInput::Scroll { dx, dy },
            ConsoleInputPacket::Key { code, down } => ConsoleInput::Key { code, down },
        };
        self.send_input(event).await
    }
}

#[async_trait::async_trait]
impl ScreenshotCapturer for ConsoleWorkerPool {
    async fn capture(&mut self, policy: ConsentPolicy) -> AgentResult<Vec<u8>> {
        let mut worker = self.current().await?;
        worker.capture(policy).await
    }
}

#[async_trait::async_trait]
impl ConsoleInputSink for ConsoleWorkerPool {
    async fn inject(&mut self, event: ConsoleInputPacket) -> AgentResult<()> {
        let mut worker = self.current().await?;
        worker.inject(event).await
    }
}

fn worker_error(code: WorkerErrorCode) -> AgentError {
    let description = match code {
        WorkerErrorCode::NoGraphicalSession => "the graphical console session is unavailable",
        WorkerErrorCode::InvalidRequest => "the console worker rejected the request",
        WorkerErrorCode::GdmCaptureUnavailable => {
            "the existing GDM physical display cannot be captured through a supported GNOME API"
        },
        WorkerErrorCode::GdmInputUnavailable => {
            "the existing GDM physical display cannot accept remote input through a supported GNOME API"
        },
        WorkerErrorCode::ScreenCastUnavailable => "the Mutter ScreenCast service is unavailable",
        WorkerErrorCode::PipeWireUnavailable => "the PipeWire capture service is unavailable",
        WorkerErrorCode::CaptureAuthorizationDenied => "the compositor denied console capture",
        WorkerErrorCode::CompositorFailure => {
            "the console compositor could not capture the active display"
        },
        WorkerErrorCode::FrameEncodingFailed => "the console frame could not be encoded",
        WorkerErrorCode::SharingUnavailable => {
            return AgentError::Share(
                "clipboard and file sharing need a logged-in desktop".to_string(),
            );
        },
        WorkerErrorCode::ClipboardUnavailable => {
            return AgentError::Share("the host clipboard is unavailable".to_string());
        },
        WorkerErrorCode::FileRejected => {
            return AgentError::Share(
                crate::console::shared_folder::ShareError::Rejected
                    .message()
                    .to_string(),
            );
        },
        WorkerErrorCode::FileIoFailed => {
            return AgentError::Share(
                crate::console::shared_folder::ShareError::Io
                    .message()
                    .to_string(),
            );
        },
    };
    AgentError::Relay(description.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt as _;

    #[test]
    fn local_worker_uid_allow_list_must_not_be_empty() {
        let path =
            std::env::temp_dir().join(format!("rivet-console-{}.sock", uuid::Uuid::now_v7()));
        let error = ConsoleBrokerListener::bind(&path, BTreeSet::new()).unwrap_err();
        assert!(error.to_string().contains("allowed worker UID"));
    }

    #[test]
    fn worker_error_is_non_sensitive() {
        for code in [
            WorkerErrorCode::GdmCaptureUnavailable,
            WorkerErrorCode::GdmInputUnavailable,
        ] {
            let error = worker_error(code);
            assert!(!error.to_string().contains("password"));
            assert!(!error.to_string().contains("key"));
        }
    }

    #[test]
    fn accepts_only_known_login_manager_greeter_logind_rows() {
        assert_eq!(
            parse_greeter_session_uid("c1 60578 gdm-greeter seat0 1970 greeter tty1 no -"),
            Some(60_578)
        );
        assert_eq!(
            parse_greeter_session_uid("3 1000 gus user - 4583 user - no -"),
            None
        );
        assert_eq!(
            parse_greeter_session_uid("c2 110 lightdm seat0 2000 greeter tty7 no -"),
            Some(110)
        );
    }

    #[tokio::test]
    async fn oversized_worker_response_marks_connection_closed() {
        let (mut worker_stream, broker_stream) = UnixStream::pair().unwrap();
        let worker = tokio::spawn(async move {
            write_packet(
                &mut worker_stream,
                &WorkerResponse::Ready {
                    state: HostConsoleState::GdmLogin,
                    display_switch: true,
                },
            )
            .await
            .unwrap();
            worker_stream
                .write_u32(u32::try_from(MAX_WORKER_RESPONSE + 1).unwrap())
                .await
                .unwrap();
        });

        let client = ConsoleWorkerClient::from_stream(broker_stream)
            .await
            .unwrap();
        let mut closed = client.closed.clone();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !*closed.borrow() {
                closed.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        worker.await.unwrap();
    }

    fn video(keyframe: bool) -> WorkerResponse {
        WorkerResponse::DesktopVideo {
            frame: rivetlink_sdk::lan::VideoFrame {
                w: 2,
                h: 2,
                keyframe,
                data_b64: String::new(),
            },
        }
    }

    async fn next_request(stream: &mut UnixStream) -> WorkerRequest {
        tokio::time::timeout(
            Duration::from_secs(1),
            read_packet_with_limit(stream, MAX_WORKER_RESPONSE),
        )
        .await
        .unwrap()
        .unwrap()
    }

    async fn next_frame(stream: &mut ConsoleDesktopStream) -> StreamFrame {
        tokio::time::timeout(Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap()
    }

    // A video delta is useless without the frame before it: the broker must
    // hold deltas back until a keyframe, and ask the worker for one (marked
    // congested when frames were lost to lag) instead of forwarding garbage.
    #[tokio::test]
    async fn video_deltas_wait_for_a_keyframe_after_start_and_after_lag() {
        let (mut worker, broker_stream) = UnixStream::pair().unwrap();
        write_packet(
            &mut worker,
            &WorkerResponse::Ready {
                state: HostConsoleState::DesktopReady,
                display_switch: true,
            },
        )
        .await
        .unwrap();
        let client = ConsoleWorkerClient::from_stream(broker_stream)
            .await
            .unwrap();
        let start = tokio::spawn(async move { client.start_desktop_stream(30, true, None).await });
        assert!(matches!(
            next_request(&mut worker).await,
            WorkerRequest::StartDesktopStream { h264: true, .. }
        ));
        write_packet(&mut worker, &WorkerResponse::DesktopStreamStarted)
            .await
            .unwrap();
        let mut stream = start.await.unwrap().unwrap();

        // A delta before any keyframe is held back and triggers one request.
        write_packet(&mut worker, &video(false)).await.unwrap();
        write_packet(&mut worker, &video(false)).await.unwrap();
        write_packet(&mut worker, &video(true)).await.unwrap();
        assert!(matches!(next_frame(&mut stream).await, StreamFrame::Video(v) if v.keyframe));
        assert!(matches!(
            next_request(&mut worker).await,
            WorkerRequest::RequestKeyframe { congested: false }
        ));

        // Overflow the fan-out queue: the broker lags, then waits again.
        for _ in 0..8 {
            write_packet(&mut worker, &video(false)).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        write_packet(&mut worker, &video(true)).await.unwrap();
        write_packet(&mut worker, &video(false)).await.unwrap();
        assert!(matches!(next_frame(&mut stream).await, StreamFrame::Video(v) if v.keyframe));
        assert!(matches!(next_frame(&mut stream).await, StreamFrame::Video(v) if !v.keyframe));
        assert!(matches!(
            next_request(&mut worker).await,
            WorkerRequest::RequestKeyframe { congested: true }
        ));
    }

    /// A pool around one fake desktop worker. An old worker's ready packet
    /// lacks `display_switch` entirely.
    async fn desktop_pool(display_switch: bool) -> (UnixStream, ConsoleWorkerPool) {
        let (mut worker, broker_stream) = UnixStream::pair().unwrap();
        let mut ready = serde_json::to_value(WorkerResponse::Ready {
            state: HostConsoleState::DesktopReady,
            display_switch,
        })
        .unwrap();
        if !display_switch {
            ready.as_object_mut().unwrap().remove("display_switch");
        }
        write_packet(&mut worker, &ready).await.unwrap();
        let client = ConsoleWorkerClient::from_stream(broker_stream)
            .await
            .unwrap();
        let pool = ConsoleWorkerPool {
            receiver: Arc::new(Mutex::new(watch::channel(Some(client)).1)),
            generation: Arc::new(AtomicU64::new(0)),
            desktop_owner: Arc::new(watch::channel(0).0),
            desktop_claim: Arc::new(Mutex::new(())),
        };
        (worker, pool)
    }

    async fn claimed(
        worker: &mut UnixStream,
        pool: &ConsoleWorkerPool,
    ) -> (ConsoleDesktopStream, DesktopClaim) {
        let claiming = tokio::spawn({
            let pool = pool.clone();
            async move { pool.claim_desktop_stream(30, true, true).await }
        });
        assert!(matches!(
            next_request(worker).await,
            WorkerRequest::StartDesktopStream { display: None, .. }
        ));
        write_packet(worker, &WorkerResponse::DesktopStreamStarted)
            .await
            .unwrap();
        claiming.await.unwrap().unwrap()
    }

    async fn nothing_sent(worker: &mut UnixStream) -> bool {
        tokio::time::timeout(
            Duration::from_millis(100),
            read_packet_with_limit::<_, WorkerRequest>(worker, MAX_WORKER_RESPONSE),
        )
        .await
        .is_err()
    }

    // Switching monitors restarts the stream on the same worker: stop, then
    // start on the chosen display, without giving up the viewer's claim and
    // without forwarding the old monitor's frames.
    #[tokio::test]
    async fn a_viewer_switches_monitor_and_keeps_its_claim() {
        let (mut worker, pool) = desktop_pool(true).await;
        let listing = tokio::spawn({
            let pool = pool.clone();
            async move { pool.list_displays().await }
        });
        assert!(matches!(
            next_request(&mut worker).await,
            WorkerRequest::ListDisplays
        ));
        let displays = vec![
            DisplayInfo {
                id: 0,
                name: "DP-1".to_string(),
            },
            DisplayInfo {
                id: 1,
                name: "HDMI-1".to_string(),
            },
        ];
        write_packet(&mut worker, &WorkerResponse::Displays { displays })
            .await
            .unwrap();
        assert_eq!(listing.await.unwrap().unwrap().len(), 2);

        let (mut desktop, claim) = claimed(&mut worker, &pool).await;
        let switching = tokio::spawn(async move {
            pool.switch_desktop_display(&mut desktop, &claim, 30, true, 1)
                .await
                .map(|()| (desktop, claim))
        });
        assert!(matches!(
            next_request(&mut worker).await,
            WorkerRequest::StopDesktopStream
        ));
        write_packet(&mut worker, &WorkerResponse::DesktopStreamStopped)
            .await
            .unwrap();
        assert!(matches!(
            next_request(&mut worker).await,
            WorkerRequest::StartDesktopStream {
                display: Some(1),
                ..
            }
        ));
        write_packet(&mut worker, &WorkerResponse::DesktopStreamStarted)
            .await
            .unwrap();
        let (mut desktop, mut claim) = switching.await.unwrap().unwrap();

        write_packet(&mut worker, &video(false)).await.unwrap();
        write_packet(&mut worker, &video(true)).await.unwrap();
        assert!(matches!(next_frame(&mut desktop).await, StreamFrame::Video(v) if v.keyframe));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), claim.taken_over())
                .await
                .is_err()
        );
    }

    // An old worker drops its connection on an unknown request, so it is
    // never asked; a switch during a takeover or after one is refused
    // without touching the running stream.
    #[tokio::test]
    async fn display_switch_is_refused_without_touching_the_stream() {
        let (mut worker, pool) = desktop_pool(false).await;
        assert!(pool.list_displays().await.unwrap().is_empty());
        let (mut desktop, claim) = claimed(&mut worker, &pool).await;
        assert!(pool
            .switch_desktop_display(&mut desktop, &claim, 30, true, 1)
            .await
            .is_err());
        assert!(nothing_sent(&mut worker).await);

        let (mut worker, pool) = desktop_pool(true).await;
        let (mut desktop, claim) = claimed(&mut worker, &pool).await;
        {
            let _takeover = pool.desktop_claim.lock().await;
            assert!(pool
                .switch_desktop_display(&mut desktop, &claim, 30, true, 1)
                .await
                .is_err());
        }
        pool.desktop_owner.send_modify(|owner| *owner += 1);
        assert!(pool
            .switch_desktop_display(&mut desktop, &claim, 30, true, 1)
            .await
            .is_err());
        assert!(nothing_sent(&mut worker).await);
        assert!(desktop.worker().desktop_stream_active());
    }

    // The owner's Windows PC must be able to take the desktop over from their
    // MacBook: the first viewer is told to stop, and the second one starts
    // only after the worker has released the first stream.
    #[tokio::test]
    async fn a_controlling_viewer_takes_the_desktop_stream_over() {
        let (mut worker, broker_stream) = UnixStream::pair().unwrap();
        write_packet(
            &mut worker,
            &WorkerResponse::Ready {
                state: HostConsoleState::DesktopReady,
                display_switch: true,
            },
        )
        .await
        .unwrap();
        let client = ConsoleWorkerClient::from_stream(broker_stream)
            .await
            .unwrap();
        let pool = ConsoleWorkerPool {
            receiver: Arc::new(Mutex::new(watch::channel(Some(client)).1)),
            generation: Arc::new(AtomicU64::new(0)),
            desktop_owner: Arc::new(watch::channel(0).0),
            desktop_claim: Arc::new(Mutex::new(())),
        };
        // Like the real worker: one stream at a time, and a stop is answered
        // only when the test opens `stop_gate`.
        let stop_gate = Arc::new(tokio::sync::Notify::new());
        let fake_worker = tokio::spawn({
            let stop_gate = Arc::clone(&stop_gate);
            async move {
                let mut streaming = false;
                while let Ok(request) =
                    read_packet_with_limit::<_, WorkerRequest>(&mut worker, MAX_WORKER_RESPONSE)
                        .await
                {
                    let response = match request {
                        WorkerRequest::StartDesktopStream { .. } if streaming => {
                            WorkerResponse::Error {
                                code: WorkerErrorCode::InvalidRequest,
                            }
                        },
                        WorkerRequest::StartDesktopStream { .. } => {
                            streaming = true;
                            WorkerResponse::DesktopStreamStarted
                        },
                        WorkerRequest::StopDesktopStream => {
                            stop_gate.notified().await;
                            streaming = false;
                            WorkerResponse::DesktopStreamStopped
                        },
                        _ => continue,
                    };
                    write_packet(&mut worker, &response).await.unwrap();
                }
            }
        });

        let (first, mut first_claim) = pool.claim_desktop_stream(30, true, true).await.unwrap();
        // A view-only device cannot push the first viewer off.
        assert!(pool.claim_desktop_stream(30, true, false).await.is_err());

        let second = tokio::spawn({
            let pool = pool.clone();
            async move { pool.claim_desktop_stream(30, true, true).await }
        });
        tokio::time::timeout(Duration::from_secs(1), first_claim.taken_over())
            .await
            .unwrap();
        let stopping = tokio::spawn(first.stop());
        // The worker has not confirmed the stop yet: the stream stays taken.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !second.is_finished(),
            "started before the first stream stopped"
        );
        stop_gate.notify_one();
        stopping.await.unwrap().unwrap();
        let (second, mut second_claim) = tokio::time::timeout(Duration::from_secs(1), second)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), second_claim.taken_over())
                .await
                .is_err()
        );
        stop_gate.notify_one();
        second.stop().await.unwrap();
        fake_worker.abort();
    }
}
