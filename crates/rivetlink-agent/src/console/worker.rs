//! Narrow per-session worker for the real login-manager/GNOME console.
//!
//! A system broker can run before login without display privileges. This worker
//! is instead started by the *actual* GDM or GNOME systemd user session and
//! talks to that session's Mutter D-Bus APIs. It has no relay credential and
//! only accepts length-bounded requests over a local Unix socket.

use base64::Engine;
use rivetlink_protocol::HostConsoleState;
use rivetlink_sdk::lan::{FrameDelta, PtrButton};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::console::clipboard::ClipboardBridge;
use crate::console::shared_folder::{ShareError, SharedFolder};
use crate::error::{AgentError, AgentResult};
use crate::input::{InputAction, InputHandle};

/// Maximum accepted JSON IPC frame. Capture output is encoded in a response,
/// while commands remain small and are rejected before allocation grows. The
/// largest command is one base64 file chunk or clipboard text.
const MAX_IPC_FRAME: usize = 512 * 1024;
/// Capture is deliberately bounded even if a compromised broker requests more.
const MAX_CAPTURE_TIMEOUT_MS: u64 = 15_000;
/// GDM's user manager can start before the boot-time broker has created its
/// socket. Wait quietly for that narrow normal-boot race instead of emitting a
/// restart-loop error every few seconds. Permission failures still surface
/// immediately and remain diagnosable.
const BROKER_SOCKET_WAIT: Duration = Duration::from_secs(12);
const BROKER_SOCKET_RETRY: Duration = Duration::from_millis(250);
/// A user manager can outlive the graphical seat that originally started it.
/// Do not let that stale worker supersede the currently visible login greeter.
#[cfg(target_os = "linux")]
const ACTIVE_SEAT_RETRY: Duration = Duration::from_secs(1);

/// Input accepted from the broker after its independent trusted-client check.
/// This excludes shell commands and arbitrary keycode data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConsoleInput {
    PointerMove { x: u16, y: u16 },
    PointerButton { button: PtrButton, down: bool },
    Scroll { dx: i16, dy: i16 },
    Key { code: String, down: bool },
}

/// Commands from a local broker to this session worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerRequest {
    Ping,
    Capture {
        timeout_ms: u64,
    },
    /// Start the normal low-latency desktop stream. This is intentionally
    /// accepted only from the authenticated seat owner after login; the X11
    /// login worker remains a bounded PNG capture/input path.
    StartDesktopStream {
        fps: u16,
    },
    /// Stop the desktop stream and release its Mutter/PipeWire resources.
    StopDesktopStream,
    Input {
        event: ConsoleInput,
    },
    /// Start the clipboard bridge; host copies then arrive as
    /// [`WorkerResponse::ClipboardChanged`].
    ClipboardEnable,
    ClipboardSet {
        text: String,
    },
    FileUploadStart {
        id: u32,
        path: String,
        size: u64,
    },
    FileUploadChunk {
        id: u32,
        data_b64: String,
    },
    FileUploadEnd {
        id: u32,
    },
    ListSharedFiles,
    ReadSharedFile {
        path: String,
        offset: u64,
    },
    Stop,
}

/// Responses intentionally contain no session identifiers, account names,
/// passwords, or key material.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerResponse {
    Ready {
        state: HostConsoleState,
    },
    Pong,
    Capture {
        png_b64: String,
    },
    DesktopStreamStarted,
    /// A tile-delta frame from the normal desktop engine. Pixels stay on the
    /// local worker → broker Unix socket until the broker seals them for its
    /// already-authorized LAN or relay client.
    DesktopFrame {
        delta: FrameDelta,
    },
    DesktopStreamStopped,
    DesktopStreamEnded {
        code: WorkerErrorCode,
    },
    InputAccepted,
    ClipboardEnabled,
    ClipboardAccepted,
    /// Pushed asynchronously when the host clipboard gets new text.
    ClipboardChanged {
        text: String,
    },
    FileAccepted,
    FileUploaded {
        path: String,
    },
    SharedFiles {
        entries: Vec<rivetlink_sdk::share::SharedEntry>,
    },
    SharedFileData {
        data_b64: String,
        size: u64,
        eof: bool,
    },
    Error {
        code: WorkerErrorCode,
    },
}

/// Stable, non-sensitive worker errors for the broker/client UX.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerErrorCode {
    NoGraphicalSession,
    InvalidRequest,
    GdmCaptureUnavailable,
    GdmInputUnavailable,
    ScreenCastUnavailable,
    PipeWireUnavailable,
    CaptureAuthorizationDenied,
    CompositorFailure,
    FrameEncodingFailed,
    /// Clipboard/file sharing is only available in a logged-in desktop.
    SharingUnavailable,
    ClipboardUnavailable,
    FileRejected,
    FileIoFailed,
}

/// The compositor/socket family owned by this graphical worker. This is kept
/// local to the worker: the broker exposes only the stable host state, never a
/// display address or Xauthority path to a remote RivetLink client.
#[derive(Debug, Clone, PartialEq, Eq)]
enum GraphicalBackend {
    Wayland,
    X11 { display: String },
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GraphicalSession {
    state: HostConsoleState,
    backend: GraphicalBackend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureBackend {
    X11,
    Mutter,
}

/// The broker accepts a 12 MiB JSON packet. Base64 expands binary data by
/// roughly one third, so cap the PNG itself at 8 MiB before serialization.
/// This turns an unexpected high-entropy frame into a bounded capture error
/// instead of blocking the worker forever on a response the broker rejects.
const MAX_CAPTURE_PNG_BYTES: usize = 8 * 1024 * 1024;
const BROKER_RECONNECT_DELAY: Duration = Duration::from_secs(1);

/// Run the worker against the broker's already-created Unix socket.
///
/// The systemd unit must arrange the socket permissions; this process never
/// creates one and never changes ownership or mode itself.
pub async fn run(socket_path: &Path) -> AgentResult<()> {
    let session = graphical_session();
    require_graphical_session(&session)?;
    loop {
        wait_until_worker_owns_active_seat(&session).await;
        let stream = connect_to_broker(socket_path).await.map_err(|error| {
            // This is a local Unix-socket access failure, not an invalid RivetLink
            // configuration.  Keeping its OS error kind lets the journal and UI
            // distinguish a permission boundary problem from a missing display.
            AgentError::Io(std::io::Error::new(
                error.kind(),
                format!("connect console broker: {error}"),
            ))
        })?;
        match serve_with_session(stream, session.clone()).await {
            Ok(()) => return Ok(()),
            Err(error) => {
                tracing::warn!(error = %error, "console broker connection ended; reconnecting");
                tokio::time::sleep(BROKER_RECONNECT_DELAY).await;
            },
        }
    }
}

async fn connect_to_broker(socket_path: &Path) -> std::io::Result<UnixStream> {
    let deadline = tokio::time::Instant::now() + BROKER_SOCKET_WAIT;
    loop {
        match UnixStream::connect(socket_path).await {
            Ok(stream) => return Ok(stream),
            Err(error)
                if should_retry_broker_connect(error.kind())
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(BROKER_SOCKET_RETRY).await;
            },
            Err(error) => return Err(error),
        }
    }
}

fn should_retry_broker_connect(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
    )
}

/// Serve one broker connection. A broker must open a fresh worker connection
/// after an ownership transition, which makes GDM → GNOME and logout explicit
/// rather than accidentally reusing a stale D-Bus session.
pub async fn serve(stream: UnixStream) -> AgentResult<()> {
    let session = graphical_session();
    serve_with_session(stream, session).await
}

// One flat dispatch over every WorkerRequest; each arm delegates to a helper.
#[allow(clippy::too_many_lines)]
async fn serve_with_session(stream: UnixStream, session: GraphicalSession) -> AgentResult<()> {
    let (mut reader, writer) = stream.into_split();
    let writer = std::sync::Arc::new(tokio::sync::Mutex::new(writer));
    // A worker belongs to exactly one graphical D-Bus session.  On GDM →
    // GNOME the broker accepts a fresh worker rather than reusing this state.
    write_worker_response(
        &writer,
        &WorkerResponse::Ready {
            state: session.state,
        },
    )
    .await?;
    let mut input: Option<InputHandle> = None;
    let mut clipboard: Option<ClipboardBridge> = None;
    let mut clipboard_forwarder: Option<tokio::task::JoinHandle<()>> = None;
    let mut shared: Option<SharedFolder> = None;
    let mut desktop_stream: Option<tokio::task::JoinHandle<()>> = None;
    let desktop_stream_active = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

    loop {
        let request: WorkerRequest = read_packet(&mut reader).await?;
        let response = match request {
            WorkerRequest::Ping => WorkerResponse::Pong,
            WorkerRequest::Capture { timeout_ms } => capture(timeout_ms, &session).await,
            WorkerRequest::StartDesktopStream { fps } => {
                if !supports_normal_desktop_stream(&session) {
                    WorkerResponse::Error {
                        code: WorkerErrorCode::ScreenCastUnavailable,
                    }
                } else if desktop_stream_active.swap(true, std::sync::atomic::Ordering::AcqRel) {
                    // One authenticated viewer gets one PipeWire session. This
                    // avoids accidentally retaining both the PNG physical
                    // capture loop and a duplicate desktop stream.
                    WorkerResponse::Error {
                        code: WorkerErrorCode::InvalidRequest,
                    }
                } else {
                    // A start acknowledgement is emitted before the capture
                    // task can publish a frame, so the broker can switch its
                    // own protocol cleanly at this boundary.
                    write_worker_response(&writer, &WorkerResponse::DesktopStreamStarted).await?;
                    let (frames_tx, mut frames_rx) = tokio::sync::mpsc::channel(2);
                    let active = std::sync::Arc::clone(&desktop_stream_active);
                    let stream_writer = std::sync::Arc::clone(&writer);
                    let handle = tokio::spawn(async move {
                        let capture = tokio::task::spawn_blocking(move || {
                            crate::capture::screencast::stream_tiles_blocking(
                                fps.clamp(1, 30),
                                60,
                                None,
                                frames_tx,
                            )
                        });
                        while let Some(delta) = frames_rx.recv().await {
                            if write_worker_response(
                                &stream_writer,
                                &WorkerResponse::DesktopFrame { delta },
                            )
                            .await
                            .is_err()
                            {
                                break;
                            }
                        }
                        let code = match capture.await {
                            Ok(Ok(())) => WorkerErrorCode::CompositorFailure,
                            Ok(Err(error)) => {
                                tracing::warn!(error = %error, "desktop stream capture failed");
                                capture_error_code(HostConsoleState::DesktopReady, &error)
                            },
                            Err(error) => {
                                tracing::warn!(error = %error, "desktop stream capture task failed");
                                WorkerErrorCode::CompositorFailure
                            },
                        };
                        active.store(false, std::sync::atomic::Ordering::Release);
                        let _ = write_worker_response(
                            &stream_writer,
                            &WorkerResponse::DesktopStreamEnded { code },
                        )
                        .await;
                    });
                    desktop_stream = Some(handle);
                    // Start was already sent before the producer was launched.
                    continue;
                }
            },
            WorkerRequest::StopDesktopStream => {
                if let Some(handle) = desktop_stream.take() {
                    handle.abort();
                }
                desktop_stream_active.store(false, std::sync::atomic::Ordering::Release);
                WorkerResponse::DesktopStreamStopped
            },
            WorkerRequest::Input { event } => apply_input(&session, &mut input, event),
            WorkerRequest::ClipboardEnable => {
                enable_clipboard(&session, &writer, &mut clipboard, &mut clipboard_forwarder).await
            },
            WorkerRequest::ClipboardSet { text } => set_clipboard(clipboard.as_ref(), text).await,
            request @ (WorkerRequest::FileUploadStart { .. }
            | WorkerRequest::FileUploadChunk { .. }
            | WorkerRequest::FileUploadEnd { .. }
            | WorkerRequest::ListSharedFiles
            | WorkerRequest::ReadSharedFile { .. }) => {
                shared_folder_request(&session, &mut shared, request)
            },
            WorkerRequest::Stop => {
                if let Some(handle) = desktop_stream.take() {
                    handle.abort();
                }
                if let Some(handle) = clipboard_forwarder.take() {
                    handle.abort();
                }
                return Ok(());
            },
        };
        write_worker_response(&writer, &response).await?;
    }
}

async fn write_worker_response(
    writer: &std::sync::Arc<tokio::sync::Mutex<tokio::net::unix::OwnedWriteHalf>>,
    response: &WorkerResponse,
) -> AgentResult<()> {
    let mut writer = writer.lock().await;
    write_packet(&mut *writer, response).await
}

/// The normal engine is Mutter/PipeWire's tile-delta stream, not a faster
/// variant of the pre-login PNG poller. It can only run inside the authenticated
/// GNOME Wayland session which owns the current worker.
fn supports_normal_desktop_stream(session: &GraphicalSession) -> bool {
    session.state == HostConsoleState::DesktopReady
        && matches!(session.backend, GraphicalBackend::Wayland)
}

/// Classify only the session that owns this worker. Both GDM and LightDM set
/// `XDG_SESSION_CLASS=greeter`; a normal GNOME user session is desktop. This
/// does not infer a password field or inspect any screen content.
#[allow(clippy::disallowed_methods)] // systemd supplies these session-scoped facts
#[cfg(test)]
fn graphical_session_state() -> HostConsoleState {
    graphical_session().state
}

#[allow(clippy::disallowed_methods)] // systemd supplies session-scoped facts
fn graphical_session() -> GraphicalSession {
    let state = if std::env::var("XDG_SESSION_CLASS").is_ok_and(|class| class == "greeter")
        || std::env::var("USER").is_ok_and(|user| user == "gdm")
    {
        // `GdmLogin` is the protocol's established, manager-neutral pre-login
        // state name. The actual manager/backend stays local to this worker.
        HostConsoleState::GdmLogin
    } else {
        HostConsoleState::DesktopReady
    };
    let backend = match std::env::var("XDG_SESSION_TYPE").as_deref() {
        Ok("wayland") => GraphicalBackend::Wayland,
        Ok("x11") => x11_backend_from_environment().unwrap_or(GraphicalBackend::Unknown),
        _ => GraphicalBackend::Unknown,
    };
    GraphicalSession { state, backend }
}

/// Select only an X11 display owned by this graphical worker. Reject network
/// display syntax so configuring GDM Xorg never turns RivetLink into an X11
/// TCP client/server, and require a regular session Xauthority file rather
/// than broadening access with `xhost`.
#[allow(clippy::disallowed_methods)] // systemd supplies session-scoped values
fn x11_backend_from_environment() -> Option<GraphicalBackend> {
    let display = std::env::var("DISPLAY").ok()?;
    if !is_local_x11_display(&display) {
        return None;
    }
    let authority = PathBuf::from(std::env::var_os("XAUTHORITY")?);
    if !authority.is_absolute() || !authority.is_file() {
        return None;
    }
    Some(GraphicalBackend::X11 { display })
}

fn is_local_x11_display(display: &str) -> bool {
    let Some(number) = display.strip_prefix(':') else {
        return false;
    };
    let (screen, suffix) = number.split_once('.').unwrap_or((number, ""));
    !screen.is_empty()
        && screen.bytes().all(|byte| byte.is_ascii_digit())
        && (suffix.is_empty() || suffix.bytes().all(|byte| byte.is_ascii_digit()))
}

fn session_capture_png(session: &GraphicalSession, timeout: Duration) -> AgentResult<Vec<u8>> {
    match capture_backend(session)? {
        CaptureBackend::X11 => match &session.backend {
            GraphicalBackend::X11 { display } => crate::capture::x11::capture_png(display),
            _ => unreachable!("X11 capture routing requires an X11 session"),
        },
        CaptureBackend::Mutter => {
            crate::capture::mutter::capture_console_png(timeout, session.state)
        },
    }
}

fn capture_backend(session: &GraphicalSession) -> AgentResult<CaptureBackend> {
    match (&session.state, &session.backend) {
        (HostConsoleState::GdmLogin, GraphicalBackend::X11 { .. })
        | (HostConsoleState::DesktopReady, GraphicalBackend::X11 { .. }) => Ok(CaptureBackend::X11),
        (HostConsoleState::DesktopReady, GraphicalBackend::Wayland) => Ok(CaptureBackend::Mutter),
        (HostConsoleState::GdmLogin, GraphicalBackend::Wayland) => Err(AgentError::Config(
            "the protected Wayland login display cannot be captured; RivetLink requires the optional local LightDM X11 login mode for pre-login capture"
                .to_string(),
        )),
        (HostConsoleState::GdmLogin, GraphicalBackend::Unknown) => Err(AgentError::Config(
            "login display server is not a supported local Xorg session".to_string(),
        )),
        (HostConsoleState::SessionLocked, _) => Err(AgentError::Config(
            "the locked physical display cannot be captured through a supported backend"
                .to_string(),
        )),
        _ => Err(AgentError::Config(
            "graphical console capture is unavailable while the session is transitioning"
                .to_string(),
        )),
    }
}

fn require_graphical_session(session: &GraphicalSession) -> AgentResult<()> {
    // LightDM's X11 greeter is not backed by a systemd user manager. It has a
    // valid, cookie-authenticated Xauthority session but no per-user D-Bus
    // session. X11 capture/input need neither; requiring D-Bus here would
    // incorrectly force a root worker or a global access relaxation.
    if matches!(session.backend, GraphicalBackend::X11 { .. }) {
        return Ok(());
    }
    let has_runtime = std::env::var_os("XDG_RUNTIME_DIR").is_some();
    let has_session_bus = std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some();
    if has_runtime && has_session_bus {
        Ok(())
    } else {
        Err(AgentError::Config(
            "console worker requires an active login-manager or GNOME graphical session"
                .to_string(),
        ))
    }
}

/// Minimal logind facts used solely to keep a stale per-user worker from
/// claiming a display it no longer owns.  They are deliberately not sent over
/// the RivetLink protocol and contain neither account names nor display paths.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveSeatSession {
    uid: u32,
    seat: String,
    class: String,
    session_type: String,
    active: bool,
}

/// A systemd user manager can remain alive after logout (or while the desktop
/// is suspended behind LightDM).  It must wait until its UID owns the active
/// graphical seat before it may connect to the broker.  Without this check an
/// old Wayland worker can overwrite the active LightDM X11 worker and route a
/// client to an invisible desktop.
async fn wait_until_worker_owns_active_seat(session: &GraphicalSession) {
    #[cfg(target_os = "linux")]
    loop {
        if worker_owns_active_seat(session) {
            return;
        }
        tracing::debug!(state = ?session.state, "console worker waiting for its active seat0 session");
        tokio::time::sleep(ACTIVE_SEAT_RETRY).await;
    }

    #[cfg(not(target_os = "linux"))]
    let _ = session;
}

#[cfg(target_os = "linux")]
fn worker_owns_active_seat(session: &GraphicalSession) -> bool {
    let Some(uid) = worker_uid() else {
        return false;
    };
    active_logind_sessions()
        .iter()
        .any(|candidate| active_session_matches_worker(candidate, uid, session))
}

#[cfg(target_os = "linux")]
fn worker_uid() -> Option<u32> {
    let output = std::process::Command::new("/usr/bin/id")
        .arg("-u")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    output.status.success().then_some(())?;
    std::str::from_utf8(&output.stdout)
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(target_os = "linux")]
fn active_logind_sessions() -> Vec<ActiveSeatSession> {
    let output = std::process::Command::new("/usr/bin/loginctl")
        .args(["list-sessions", "--no-legend", "--no-pager"])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter_map(logind_session_details)
        .collect()
}

#[cfg(target_os = "linux")]
fn logind_session_details(session_id: &str) -> Option<ActiveSeatSession> {
    let output = std::process::Command::new("/usr/bin/loginctl")
        .args([
            "show-session",
            session_id,
            "-p",
            "User",
            "-p",
            "Seat",
            "-p",
            "Class",
            "-p",
            "Type",
            "-p",
            "Active",
        ])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_logind_session_details(&String::from_utf8_lossy(&output.stdout))
}

fn parse_logind_session_details(output: &str) -> Option<ActiveSeatSession> {
    let mut uid = None;
    let mut seat = None;
    let mut class = None;
    let mut session_type = None;
    let mut active = None;
    for line in output.lines() {
        let (key, value) = line.split_once('=')?;
        match key {
            "User" => uid = value.parse().ok(),
            "Seat" => seat = Some(value.to_string()),
            "Class" => class = Some(value.to_string()),
            "Type" => session_type = Some(value.to_string()),
            // logind prints these booleans as `yes`/`no`, unlike Rust's
            // `bool` parser. Accept only those two values so a malformed
            // response cannot accidentally authorize a worker.
            "Active" => {
                active = match value {
                    "yes" => Some(true),
                    "no" => Some(false),
                    _ => None,
                }
            },
            _ => {},
        }
    }
    Some(ActiveSeatSession {
        uid: uid?,
        seat: seat?,
        class: class?,
        session_type: session_type?,
        active: active?,
    })
}

fn active_session_matches_worker(
    candidate: &ActiveSeatSession,
    worker_uid: u32,
    session: &GraphicalSession,
) -> bool {
    if !candidate.active || candidate.seat != "seat0" || candidate.uid != worker_uid {
        return false;
    }
    let expected_class = if session.state == HostConsoleState::GdmLogin {
        "greeter"
    } else {
        "user"
    };
    if candidate.class != expected_class {
        return false;
    }
    match session.backend {
        GraphicalBackend::Wayland => candidate.session_type == "wayland",
        GraphicalBackend::X11 { .. } => candidate.session_type == "x11",
        GraphicalBackend::Unknown => false,
    }
}

async fn capture(timeout_ms: u64, session: &GraphicalSession) -> WorkerResponse {
    let timeout_ms = timeout_ms.clamp(1, MAX_CAPTURE_TIMEOUT_MS);
    let session = session.clone();
    let capture_session = session.clone();
    match tokio::task::spawn_blocking(move || {
        session_capture_png(&capture_session, Duration::from_millis(timeout_ms))
    })
    .await
    {
        Ok(Ok(png)) if png.len() <= MAX_CAPTURE_PNG_BYTES => WorkerResponse::Capture {
            png_b64: base64::engine::general_purpose::STANDARD.encode(png),
        },
        Ok(Ok(_)) => {
            tracing::warn!("console capture exceeded the in-memory frame limit");
            WorkerResponse::Error {
                code: WorkerErrorCode::FrameEncodingFailed,
            }
        },
        Ok(Err(error)) => {
            tracing::warn!(error = %error, "console capture failed");
            WorkerResponse::Error {
                code: capture_error_code(session.state, &error),
            }
        },
        Err(error) => {
            tracing::warn!(error = %error, "console capture task failed");
            WorkerResponse::Error {
                code: WorkerErrorCode::CompositorFailure,
            }
        },
    }
}

/// Convert local compositor diagnostics into a stable, non-sensitive broker
/// result.  Raw D-Bus/GStreamer text stays in the local journal only; it is
/// never sent over a physical-console connection.
fn capture_error_code(state: HostConsoleState, error: &AgentError) -> WorkerErrorCode {
    let text = error.to_string().to_ascii_lowercase();
    if text.contains("access denied") || text.contains("not authorized") {
        WorkerErrorCode::CaptureAuthorizationDenied
    } else if text.contains("pipewire") || text.contains("gst-launch") || text.contains("gstreamer")
    {
        WorkerErrorCode::PipeWireUnavailable
    } else if text.contains("encode") || text.contains("png") {
        WorkerErrorCode::FrameEncodingFailed
    } else if state == HostConsoleState::GdmLogin || state == HostConsoleState::SessionLocked {
        WorkerErrorCode::GdmCaptureUnavailable
    } else if text.contains("screencast") || text.contains("session creation inhibited") {
        WorkerErrorCode::ScreenCastUnavailable
    } else {
        WorkerErrorCode::CompositorFailure
    }
}

fn apply_input(
    session: &GraphicalSession,
    handle: &mut Option<InputHandle>,
    event: ConsoleInput,
) -> WorkerResponse {
    if session.state == HostConsoleState::SessionLocked {
        return WorkerResponse::Error {
            code: WorkerErrorCode::GdmInputUnavailable,
        };
    }
    if session.state == HostConsoleState::GdmLogin && !uses_x11_input(session) {
        // Do not probe a protected Wayland greeter. The only pre-login route
        // is RivetLink's explicitly configured local LightDM X11 session.
        return WorkerResponse::Error {
            code: WorkerErrorCode::GdmInputUnavailable,
        };
    }
    let action = match event {
        ConsoleInput::PointerMove { x, y } => InputAction::Move { x, y },
        ConsoleInput::PointerButton { button, down } => InputAction::Button { button, down },
        ConsoleInput::Scroll { dx, dy } => InputAction::Scroll { dx, dy },
        ConsoleInput::Key { code, down } if is_valid_key_code(&code) => {
            InputAction::Key { code, down }
        },
        ConsoleInput::Key { .. } => {
            return WorkerResponse::Error {
                code: WorkerErrorCode::InvalidRequest,
            };
        },
    };
    let handle = handle.get_or_insert_with(|| match &session.backend {
        GraphicalBackend::X11 { display } => InputHandle::spawn_x11(display.clone()),
        // The handle owns a Mutter RemoteDesktop session in this same D-Bus
        // session; it cannot target another seat or act as root.
        GraphicalBackend::Wayland | GraphicalBackend::Unknown => InputHandle::spawn(None),
    });
    handle.send(action);
    WorkerResponse::InputAccepted
}

/// Start the clipboard bridge once and forward host copies to the broker.
async fn enable_clipboard(
    session: &GraphicalSession,
    writer: &std::sync::Arc<tokio::sync::Mutex<tokio::net::unix::OwnedWriteHalf>>,
    clipboard: &mut Option<ClipboardBridge>,
    forwarder: &mut Option<tokio::task::JoinHandle<()>>,
) -> WorkerResponse {
    if !supports_normal_desktop_stream(session) {
        return WorkerResponse::Error {
            code: WorkerErrorCode::SharingUnavailable,
        };
    }
    if clipboard.is_some() {
        return WorkerResponse::ClipboardEnabled;
    }
    let (changes_tx, mut changes_rx) = tokio::sync::mpsc::channel(4);
    match ClipboardBridge::start(changes_tx).await {
        Ok(bridge) => {
            *clipboard = Some(bridge);
            let writer = std::sync::Arc::clone(writer);
            *forwarder = Some(tokio::spawn(async move {
                while let Some(text) = changes_rx.recv().await {
                    let changed = WorkerResponse::ClipboardChanged { text };
                    if write_worker_response(&writer, &changed).await.is_err() {
                        break;
                    }
                }
            }));
            WorkerResponse::ClipboardEnabled
        },
        Err(error) => {
            tracing::warn!(error = %error, "clipboard bridge unavailable");
            WorkerResponse::Error {
                code: WorkerErrorCode::ClipboardUnavailable,
            }
        },
    }
}

async fn set_clipboard(clipboard: Option<&ClipboardBridge>, text: String) -> WorkerResponse {
    let Some(bridge) = clipboard else {
        return WorkerResponse::Error {
            code: WorkerErrorCode::ClipboardUnavailable,
        };
    };
    if text.len() > rivetlink_sdk::share::MAX_CLIPBOARD_BYTES {
        return WorkerResponse::Error {
            code: WorkerErrorCode::InvalidRequest,
        };
    }
    match bridge.set(text).await {
        Ok(()) => WorkerResponse::ClipboardAccepted,
        Err(_) => WorkerResponse::Error {
            code: WorkerErrorCode::ClipboardUnavailable,
        },
    }
}

/// Apply one shared-folder request, only in a logged-in desktop. Paths are
/// validated inside [`SharedFolder`].
fn shared_folder_request(
    session: &GraphicalSession,
    shared: &mut Option<SharedFolder>,
    request: WorkerRequest,
) -> WorkerResponse {
    if !supports_normal_desktop_stream(session) {
        return WorkerResponse::Error {
            code: WorkerErrorCode::SharingUnavailable,
        };
    }
    if shared.is_none() {
        *shared = SharedFolder::for_current_user();
    }
    let Some(folder) = shared.as_mut() else {
        return WorkerResponse::Error {
            code: WorkerErrorCode::FileIoFailed,
        };
    };
    let result = match request {
        WorkerRequest::FileUploadStart { id, path, size } => folder
            .start_upload(id, &path, size)
            .map(|()| WorkerResponse::FileAccepted),
        WorkerRequest::FileUploadChunk { id, data_b64 } => {
            match base64::engine::general_purpose::STANDARD.decode(data_b64) {
                Ok(data) => folder
                    .write_chunk(id, &data)
                    .map(|()| WorkerResponse::FileAccepted),
                Err(_) => {
                    folder.abort_upload(id);
                    Err(ShareError::Rejected)
                },
            }
        },
        WorkerRequest::FileUploadEnd { id } => folder
            .finish_upload(id)
            .map(|path| WorkerResponse::FileUploaded { path }),
        WorkerRequest::ListSharedFiles => folder
            .list()
            .map(|entries| WorkerResponse::SharedFiles { entries }),
        WorkerRequest::ReadSharedFile { path, offset } => {
            folder.read_chunk(&path, offset).map(|(data, size, eof)| {
                WorkerResponse::SharedFileData {
                    data_b64: base64::engine::general_purpose::STANDARD.encode(data),
                    size,
                    eof,
                }
            })
        },
        _ => Err(ShareError::Rejected),
    };
    result.unwrap_or_else(|error| WorkerResponse::Error {
        code: match error {
            ShareError::Rejected => WorkerErrorCode::FileRejected,
            ShareError::Io => WorkerErrorCode::FileIoFailed,
        },
    })
}

fn uses_x11_input(session: &GraphicalSession) -> bool {
    matches!(session.backend, GraphicalBackend::X11 { .. })
}

fn is_valid_key_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 64
        && code
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

async fn read_packet<R, T>(reader: &mut R) -> AgentResult<T>
where
    R: AsyncRead + Unpin,
    T: serde::de::DeserializeOwned,
{
    read_packet_with_limit(reader, MAX_IPC_FRAME).await
}

pub(crate) async fn read_packet_with_limit<R, T>(reader: &mut R, maximum: usize) -> AgentResult<T>
where
    R: AsyncRead + Unpin,
    T: serde::de::DeserializeOwned,
{
    let size = reader.read_u32().await?;
    let size = usize::try_from(size)
        .map_err(|_| AgentError::Config("console IPC frame length overflow".to_string()))?;
    if size > maximum {
        return Err(AgentError::Config(
            "console IPC request exceeds the maximum size".to_string(),
        ));
    }
    let mut body = vec![0_u8; size];
    reader.read_exact(&mut body).await?;
    serde_json::from_slice(&body).map_err(AgentError::Serde)
}

pub(crate) async fn write_packet<W, T>(writer: &mut W, value: &T) -> AgentResult<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = serde_json::to_vec(value)?;
    let size = u32::try_from(body.len())
        .map_err(|_| AgentError::Config("console IPC response exceeds u32".to_string()))?;
    writer.write_u32(size).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_normalized_browser_key_codes_are_accepted() {
        assert!(is_valid_key_code("KeyA"));
        assert!(is_valid_key_code("Shift-Left"));
        assert!(!is_valid_key_code(""));
        assert!(!is_valid_key_code("password value"));
        assert!(!is_valid_key_code(&"x".repeat(65)));
    }

    #[test]
    fn session_state_is_limited_to_graphical_worker_states() {
        assert!(matches!(
            graphical_session_state(),
            HostConsoleState::GdmLogin | HostConsoleState::DesktopReady
        ));
    }

    #[test]
    fn x11_display_addresses_are_local_unix_sockets_only() {
        assert!(is_local_x11_display(":0"));
        assert!(is_local_x11_display(":12.0"));
        assert!(!is_local_x11_display("localhost:0"));
        assert!(!is_local_x11_display("tcp/localhost:0"));
        assert!(!is_local_x11_display(":one"));
    }

    #[test]
    fn capture_backend_follows_the_actual_display_server() {
        let gdm_x11 = GraphicalSession {
            state: HostConsoleState::GdmLogin,
            backend: GraphicalBackend::X11 {
                display: ":0".to_string(),
            },
        };
        assert_eq!(capture_backend(&gdm_x11).unwrap(), CaptureBackend::X11);
        assert!(uses_x11_input(&gdm_x11));

        let gdm_wayland = GraphicalSession {
            state: HostConsoleState::GdmLogin,
            backend: GraphicalBackend::Wayland,
        };
        assert!(capture_backend(&gdm_wayland).is_err());
        assert!(!uses_x11_input(&gdm_wayland));

        let desktop_wayland = GraphicalSession {
            state: HostConsoleState::DesktopReady,
            backend: GraphicalBackend::Wayland,
        };
        assert_eq!(
            capture_backend(&desktop_wayland).unwrap(),
            CaptureBackend::Mutter
        );

        let desktop_x11 = GraphicalSession {
            state: HostConsoleState::DesktopReady,
            backend: GraphicalBackend::X11 {
                display: ":1".to_string(),
            },
        };
        assert_eq!(capture_backend(&desktop_x11).unwrap(), CaptureBackend::X11);
        assert!(!supports_normal_desktop_stream(&gdm_x11));
        assert!(supports_normal_desktop_stream(&desktop_wayland));
        assert!(!supports_normal_desktop_stream(&desktop_x11));
    }

    #[test]
    fn missing_or_not_yet_listening_broker_socket_is_a_normal_boot_race() {
        assert!(should_retry_broker_connect(std::io::ErrorKind::NotFound));
        assert!(should_retry_broker_connect(
            std::io::ErrorKind::ConnectionRefused
        ));
        assert!(!should_retry_broker_connect(
            std::io::ErrorKind::PermissionDenied
        ));
    }

    #[test]
    fn only_the_active_seat_owner_may_claim_the_console() {
        let lightdm = ActiveSeatSession {
            uid: 112,
            seat: "seat0".to_string(),
            class: "greeter".to_string(),
            session_type: "x11".to_string(),
            active: true,
        };
        let inactive_wayland_user = ActiveSeatSession {
            uid: 1000,
            seat: "seat0".to_string(),
            class: "user".to_string(),
            session_type: "wayland".to_string(),
            active: false,
        };
        let greeter = GraphicalSession {
            state: HostConsoleState::GdmLogin,
            backend: GraphicalBackend::X11 {
                display: ":0".to_string(),
            },
        };
        let desktop = GraphicalSession {
            state: HostConsoleState::DesktopReady,
            backend: GraphicalBackend::Wayland,
        };

        assert!(active_session_matches_worker(&lightdm, 112, &greeter));
        assert!(!active_session_matches_worker(
            &inactive_wayland_user,
            1000,
            &desktop
        ));
        assert!(!active_session_matches_worker(&lightdm, 1000, &desktop));
    }

    #[test]
    fn parses_only_complete_logind_session_details() {
        let session = parse_logind_session_details(
            "User=112\nSeat=seat0\nClass=greeter\nType=x11\nActive=yes\n",
        )
        .unwrap();
        assert_eq!(session.uid, 112);
        assert_eq!(session.seat, "seat0");
        assert!(session.active);
        assert!(parse_logind_session_details("User=112\nSeat=seat0\n").is_none());
    }

    #[test]
    fn capture_errors_are_classified_without_disclosing_compositor_text() {
        let gdm = capture_error_code(
            HostConsoleState::GdmLogin,
            &AgentError::Lan("Mutter RemoteDesktop D-Bus error: unavailable".to_string()),
        );
        assert_eq!(gdm, WorkerErrorCode::GdmCaptureUnavailable);
        let pipewire = capture_error_code(
            HostConsoleState::DesktopReady,
            &AgentError::Config("gst-launch-1.0 failed to start".to_string()),
        );
        assert_eq!(pipewire, WorkerErrorCode::PipeWireUnavailable);
        let denied = capture_error_code(
            HostConsoleState::DesktopReady,
            &AgentError::Lan("Mutter ScreenCast D-Bus error: Access denied".to_string()),
        );
        assert_eq!(denied, WorkerErrorCode::CaptureAuthorizationDenied);
    }

    #[test]
    fn protected_sessions_reject_input_before_creating_a_mutter_handle() {
        for session in [
            GraphicalSession {
                state: HostConsoleState::GdmLogin,
                backend: GraphicalBackend::Wayland,
            },
            GraphicalSession {
                state: HostConsoleState::SessionLocked,
                backend: GraphicalBackend::X11 {
                    display: ":0".to_string(),
                },
            },
        ] {
            let response = apply_input(
                &session,
                &mut None,
                ConsoleInput::Key {
                    code: "Enter".to_string(),
                    down: true,
                },
            );
            assert!(matches!(
                response,
                WorkerResponse::Error {
                    code: WorkerErrorCode::GdmInputUnavailable
                }
            ));
        }
    }

    #[tokio::test]
    async fn ipc_packets_roundtrip_with_length_prefix() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        let task = tokio::spawn(async move {
            write_packet(
                &mut writer,
                &WorkerRequest::Input {
                    event: ConsoleInput::Key {
                        code: "Enter".to_string(),
                        down: true,
                    },
                },
            )
            .await
            .unwrap();
        });
        let request: WorkerRequest = read_packet(&mut reader).await.unwrap();
        task.await.unwrap();
        assert!(matches!(
            request,
            WorkerRequest::Input {
                event: ConsoleInput::Key { code, down: true }
            } if code == "Enter"
        ));
    }
}
