//! Broker-side endpoint for the active GDM/GNOME session worker.
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
use std::time::Duration;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;
use tokio::sync::Mutex;

use super::worker::{
    read_packet_with_limit, write_packet, ConsoleInput, WorkerErrorCode, WorkerRequest,
    WorkerResponse,
};
use crate::error::{AgentError, AgentResult};
use crate::session::{ConsentPolicy, ConsoleInputSink, ConsoleStateProvider, ScreenshotCapturer};
use rivetlink_protocol::{ConsoleInputPacket, HostConsoleState, MouseButton};
use rivetlink_sdk::lan::PtrButton;

/// Upper bound for a base64 PNG response (~9 MiB decoded), matching the
/// unattended host's configured maximum without trusting worker input blindly.
const MAX_WORKER_RESPONSE: usize = 12 * 1024 * 1024;

/// A listener whose peer-credential allow-list is enforced before any capture
/// or input request reaches a session worker.
#[derive(Debug)]
pub struct ConsoleBrokerListener {
    listener: UnixListener,
    allowed_worker_uids: BTreeSet<u32>,
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
        Ok(Self {
            listener,
            allowed_worker_uids,
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
            if !self.allowed_worker_uids.contains(&uid) {
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
                        let _ = tx.send(Some(worker));
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
}

/// A single, authenticated connection to the current physical-console owner.
/// Cloning keeps a serial request queue, so no capture and input request can be
/// interleaved across a GDM ↔ GNOME handover.
#[derive(Clone, Debug)]
pub struct ConsoleWorkerClient {
    inner: Arc<Mutex<WorkerConnection>>,
    state: HostConsoleState,
}

#[derive(Debug)]
struct WorkerConnection {
    reader: OwnedReadHalf,
    writer: OwnedWriteHalf,
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
        Ok(Self {
            inner: Arc::new(Mutex::new(WorkerConnection { reader, writer })),
            state,
        })
    }

    /// Capture the monitor the connected GDM/GNOME worker owns.
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

    async fn request(&self, request: WorkerRequest) -> AgentResult<WorkerResponse> {
        let mut connection = self.inner.lock().await;
        write_packet(&mut connection.writer, &request).await?;
        read_packet_with_limit(&mut connection.reader, MAX_WORKER_RESPONSE).await
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
        WorkerErrorCode::CaptureUnavailable => {
            "the console worker could not capture the active display"
        },
    };
    AgentError::Relay(description.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_worker_uid_allow_list_must_not_be_empty() {
        let path =
            std::env::temp_dir().join(format!("rivet-console-{}.sock", uuid::Uuid::now_v7()));
        let error = ConsoleBrokerListener::bind(&path, BTreeSet::new()).unwrap_err();
        assert!(error.to_string().contains("allowed worker UID"));
    }

    #[test]
    fn worker_error_is_non_sensitive() {
        let error = worker_error(WorkerErrorCode::CaptureUnavailable);
        assert!(!error.to_string().contains("password"));
        assert!(!error.to_string().contains("key"));
    }
}
