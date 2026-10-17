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
use rivetlink_sdk::lan::{FrameDelta, PtrButton};

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

    /// Open the normal high-performance desktop engine only after the active
    /// graphical worker has reported `DesktopReady`.
    pub async fn start_desktop_stream(&self, fps: u16) -> AgentResult<ConsoleDesktopStream> {
        self.current().await?.start_desktop_stream(fps).await
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
    desktop_frames: broadcast::Sender<FrameDelta>,
    desktop_ended: broadcast::Sender<WorkerErrorCode>,
    desktop_stream_active: Arc<std::sync::atomic::AtomicBool>,
    clipboard_changes: broadcast::Sender<String>,
    closed: watch::Receiver<bool>,
    state: HostConsoleState,
}

/// An active normal desktop stream from a worker in an authenticated GNOME
/// session. It is impossible to create this handle from a login worker.
#[derive(Debug)]
pub struct ConsoleDesktopStream {
    worker: ConsoleWorkerClient,
    frames: broadcast::Receiver<FrameDelta>,
    ended: broadcast::Receiver<WorkerErrorCode>,
}

impl ConsoleWorkerClient {
    async fn from_stream(stream: UnixStream) -> AgentResult<Self> {
        let (mut reader, writer) = stream.into_split();
        let ready: WorkerResponse =
            read_packet_with_limit(&mut reader, MAX_WORKER_RESPONSE).await?;
        let WorkerResponse::Ready { state } = ready else {
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
                        let _ = reader_frames.send(delta);
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
            clipboard_changes,
            closed,
            state,
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

    /// Start the existing normal Mutter/PipeWire tile-delta engine in the
    /// authenticated desktop worker. The socket remains local; only the
    /// broker's already-authenticated network session receives these frames.
    pub async fn start_desktop_stream(&self, fps: u16) -> AgentResult<ConsoleDesktopStream> {
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
        match self
            .request(WorkerRequest::StartDesktopStream { fps })
            .await
        {
            Ok(WorkerResponse::DesktopStreamStarted) => Ok(ConsoleDesktopStream {
                worker: self.clone(),
                frames,
                ended,
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
    /// error when the worker/session disappears.
    pub async fn next(&mut self) -> AgentResult<FrameDelta> {
        loop {
            tokio::select! {
                frame = self.frames.recv() => match frame {
                    Ok(frame) => return Ok(frame),
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
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
}
