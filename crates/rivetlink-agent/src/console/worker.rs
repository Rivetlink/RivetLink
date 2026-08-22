//! Narrow per-session worker for the real login-manager/GNOME console.
//!
//! A system broker can run before login without display privileges. This worker
//! is instead started by the *actual* GDM or GNOME systemd user session and
//! talks to that session's Mutter D-Bus APIs. It has no relay credential and
//! only accepts length-bounded requests over a local Unix socket.

use base64::Engine;
use rivetlink_protocol::HostConsoleState;
use rivetlink_sdk::lan::PtrButton;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::error::{AgentError, AgentResult};
use crate::input::{InputAction, InputHandle};

/// Maximum accepted JSON IPC frame. Capture output is encoded in a response,
/// while commands remain small and are rejected before allocation grows.
const MAX_IPC_FRAME: usize = 64 * 1024;
/// Capture is deliberately bounded even if a compromised broker requests more.
const MAX_CAPTURE_TIMEOUT_MS: u64 = 15_000;
/// GDM's user manager can start before the boot-time broker has created its
/// socket. Wait quietly for that narrow normal-boot race instead of emitting a
/// restart-loop error every few seconds. Permission failures still surface
/// immediately and remain diagnosable.
const BROKER_SOCKET_WAIT: Duration = Duration::from_secs(12);
const BROKER_SOCKET_RETRY: Duration = Duration::from_millis(250);

/// Input accepted from the broker after its independent trusted-client check.
/// This excludes clipboard, files, shell commands, and arbitrary keycode data.
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
    Capture { timeout_ms: u64 },
    Input { event: ConsoleInput },
    Stop,
}

/// Responses intentionally contain no session identifiers, account names,
/// passwords, or key material.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerResponse {
    Ready { state: HostConsoleState },
    Pong,
    Capture { png_b64: String },
    InputAccepted,
    Error { code: WorkerErrorCode },
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

/// Run the worker against the broker's already-created Unix socket.
///
/// The systemd unit must arrange the socket permissions; this process never
/// creates one and never changes ownership or mode itself.
pub async fn run(socket_path: &Path) -> AgentResult<()> {
    require_graphical_session()?;
    let stream = connect_to_broker(socket_path).await.map_err(|error| {
        // This is a local Unix-socket access failure, not an invalid RivetLink
        // configuration.  Keeping its OS error kind lets the journal and UI
        // distinguish a permission boundary problem from a missing display.
        AgentError::Io(std::io::Error::new(
            error.kind(),
            format!("connect console broker: {error}"),
        ))
    })?;
    serve(stream).await
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
    kind == std::io::ErrorKind::NotFound
}

/// Serve one broker connection. A broker must open a fresh worker connection
/// after an ownership transition, which makes GDM → GNOME and logout explicit
/// rather than accidentally reusing a stale D-Bus session.
pub async fn serve(stream: UnixStream) -> AgentResult<()> {
    let (mut reader, mut writer) = stream.into_split();
    // A worker belongs to exactly one graphical D-Bus session.  On GDM →
    // GNOME the broker accepts a fresh worker rather than reusing this state.
    let session = graphical_session();
    write_packet(
        &mut writer,
        &WorkerResponse::Ready {
            state: session.state,
        },
    )
    .await?;
    let mut input: Option<InputHandle> = None;

    loop {
        let request: WorkerRequest = read_packet(&mut reader).await?;
        let response = match request {
            WorkerRequest::Ping => WorkerResponse::Pong,
            WorkerRequest::Capture { timeout_ms } => capture(timeout_ms, &session).await,
            WorkerRequest::Input { event } => apply_input(&session, &mut input, event),
            WorkerRequest::Stop => return Ok(()),
        };
        write_packet(&mut writer, &response).await?;
    }
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

fn require_graphical_session() -> AgentResult<()> {
    // LightDM's X11 greeter is not backed by a systemd user manager. It has a
    // valid, cookie-authenticated Xauthority session but no per-user D-Bus
    // session. X11 capture/input need neither; requiring D-Bus here would
    // incorrectly force a root worker or a global access relaxation.
    if matches!(graphical_session().backend, GraphicalBackend::X11 { .. }) {
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

async fn capture(timeout_ms: u64, session: &GraphicalSession) -> WorkerResponse {
    let timeout_ms = timeout_ms.clamp(1, MAX_CAPTURE_TIMEOUT_MS);
    let session = session.clone();
    let capture_session = session.clone();
    match tokio::task::spawn_blocking(move || {
        session_capture_png(&capture_session, Duration::from_millis(timeout_ms))
    })
    .await
    {
        Ok(Ok(png)) => WorkerResponse::Capture {
            png_b64: base64::engine::general_purpose::STANDARD.encode(png),
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
    }

    #[test]
    fn only_a_missing_broker_socket_is_a_normal_boot_race() {
        assert!(should_retry_broker_connect(std::io::ErrorKind::NotFound));
        assert!(!should_retry_broker_connect(
            std::io::ErrorKind::PermissionDenied
        ));
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
