//! Narrow per-session worker for the real GNOME/Mutter console.
//!
//! A system broker can run before login without display privileges. This worker
//! is instead started by the *actual* GDM or GNOME systemd user session and
//! talks to that session's Mutter D-Bus APIs. It has no relay credential and
//! only accepts length-bounded requests over a local Unix socket.

use base64::Engine;
use rivetlink_protocol::HostConsoleState;
use rivetlink_sdk::lan::PtrButton;
use serde::{Deserialize, Serialize};
use std::path::Path;
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
    CaptureUnavailable,
}

/// Run the worker against the broker's already-created Unix socket.
///
/// The systemd unit must arrange the socket permissions; this process never
/// creates one and never changes ownership or mode itself.
pub async fn run(socket_path: &Path) -> AgentResult<()> {
    require_graphical_session()?;
    let stream = UnixStream::connect(socket_path).await.map_err(|error| {
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

/// Serve one broker connection. A broker must open a fresh worker connection
/// after an ownership transition, which makes GDM → GNOME and logout explicit
/// rather than accidentally reusing a stale D-Bus session.
pub async fn serve(stream: UnixStream) -> AgentResult<()> {
    let (mut reader, mut writer) = stream.into_split();
    write_packet(
        &mut writer,
        &WorkerResponse::Ready {
            state: graphical_session_state(),
        },
    )
    .await?;
    let mut input: Option<InputHandle> = None;

    loop {
        let request: WorkerRequest = read_packet(&mut reader).await?;
        let response = match request {
            WorkerRequest::Ping => WorkerResponse::Pong,
            WorkerRequest::Capture { timeout_ms } => capture(timeout_ms).await,
            WorkerRequest::Input { event } => apply_input(&mut input, event),
            WorkerRequest::Stop => return Ok(()),
        };
        write_packet(&mut writer, &response).await?;
    }
}

/// Classify only the session that owns this worker. `greeter` is emitted by
/// GDM's actual systemd user session; a normal GNOME user session is desktop.
/// This does not infer a password field or inspect any screen content.
fn graphical_session_state() -> HostConsoleState {
    if std::env::var("XDG_SESSION_CLASS").is_ok_and(|class| class == "greeter")
        || std::env::var("USER").is_ok_and(|user| user == "gdm")
    {
        HostConsoleState::GdmLogin
    } else {
        HostConsoleState::DesktopReady
    }
}

fn require_graphical_session() -> AgentResult<()> {
    let has_runtime = std::env::var_os("XDG_RUNTIME_DIR").is_some();
    let has_session_bus = std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some();
    if has_runtime && has_session_bus {
        Ok(())
    } else {
        Err(AgentError::Config(
            "console worker requires the active GDM or GNOME graphical session".to_string(),
        ))
    }
}

async fn capture(timeout_ms: u64) -> WorkerResponse {
    let timeout_ms = timeout_ms.clamp(1, MAX_CAPTURE_TIMEOUT_MS);
    match tokio::task::spawn_blocking(move || {
        crate::capture::mutter::capture_console_png(Duration::from_millis(timeout_ms))
    })
    .await
    {
        Ok(Ok(png)) => WorkerResponse::Capture {
            png_b64: base64::engine::general_purpose::STANDARD.encode(png),
        },
        Ok(Err(error)) => {
            tracing::warn!(error = %error, "console capture failed");
            WorkerResponse::Error {
                code: WorkerErrorCode::CaptureUnavailable,
            }
        },
        Err(error) => {
            tracing::warn!(error = %error, "console capture task failed");
            WorkerResponse::Error {
                code: WorkerErrorCode::CaptureUnavailable,
            }
        },
    }
}

fn apply_input(handle: &mut Option<InputHandle>, event: ConsoleInput) -> WorkerResponse {
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
    // The handle owns a Mutter RemoteDesktop session in this very same D-Bus
    // session; it cannot target another seat or act as root.
    handle
        .get_or_insert_with(|| InputHandle::spawn(None))
        .send(action);
    WorkerResponse::InputAccepted
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
