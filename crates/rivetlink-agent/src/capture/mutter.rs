//! Linux live capture via GNOME **Mutter ScreenCast** (D-Bus) + **GStreamer**.
//!
//! Why not `scap`/the portal? scap's libspa binding targets PipeWire ~1.0 and
//! can't negotiate a stream with the 1.6+ daemons on Ubuntu 25.10/26.04 (it
//! panics "Failed to setup capturer"), and it won't even build against those
//! headers. The XDG ScreenCast portal also forces an interactive "share your
//! screen" dialog on every session.
//!
//! Mutter's lower-level `org.gnome.Mutter.ScreenCast` API sidesteps both:
//! - **No dialog** — we cast a chosen monitor directly.
//! - **Monitor-selectable** — `RecordMonitor(connector)` picks the screen, so
//!   the host shares "screen 1" by default and the client can switch.
//! - **Version-proof** — we pull frames with the system's `gst-launch-1.0`
//!   (`pipewiresrc`), which speaks whatever PipeWire the host runs.
//!
//! GNOME-only (Mutter). Other compositors fall back to nothing here for now.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc::Sender;
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Str, Value};

use rivetlink_protocol::HostConsoleState;
use rivetlink_sdk::lan::{DisplayInfo, FrameDelta};

use crate::error::{AgentError, AgentResult};

/// Upper bound on the streamed frame. The capture is downscaled to fit this box
/// **while preserving the monitor's aspect ratio** — so a 21:9 ultrawide streams
/// as e.g. 1920×824 (full width, no letterbox), not squished into a 16:9 box.
/// Never upscales (a small screen streams at its native size). 1080p-ish keeps
/// keyframes reasonable over weak Wi-Fi; tile-delta keeps the steady state tiny.
const MAX_W: u32 = 1920;
const MAX_H: u32 = 1080;
/// Fallback when the monitor's mode resolution can't be read.
const FALLBACK_W: usize = 1280;
const FALLBACK_H: usize = 720;

const SC_DEST: &str = "org.gnome.Mutter.ScreenCast";
const SC_PATH: &str = "/org/gnome/Mutter/ScreenCast";
const RD_DEST: &str = "org.gnome.Mutter.RemoteDesktop";
const RD_PATH: &str = "/org/gnome/Mutter/RemoteDesktop";
const RD_SESSION_IFACE: &str = "org.gnome.Mutter.RemoteDesktop.Session";

/// One monitor Mutter can cast, with its current-mode pixel resolution (0×0 when
/// unknown — capture then falls back to a fixed size).
struct MonitorInfo {
    connector: String,
    label: String,
    width: u32,
    height: u32,
}

/// Scale `src` down to fit the `MAX_W`×`MAX_H` box, preserving aspect ratio and
/// never upscaling; result dimensions are even (videoconvert/JPEG prefer it).
/// Returns the fallback size when the source resolution is unknown.
fn fit_output(src_w: u32, src_h: u32) -> (usize, usize) {
    if src_w == 0 || src_h == 0 {
        return (FALLBACK_W, FALLBACK_H);
    }
    // Integer math (no float casts): shrink to the width bound, then the height
    // bound; each step scales the other side by the same ratio.
    let (mut w, mut h) = (src_w, src_h);
    if w > MAX_W {
        h = u32::try_from(u64::from(h) * u64::from(MAX_W) / u64::from(w)).unwrap_or(MAX_H);
        w = MAX_W;
    }
    if h > MAX_H {
        w = u32::try_from(u64::from(w) * u64::from(MAX_H) / u64::from(h)).unwrap_or(MAX_W);
        h = MAX_H;
    }
    let even = |v: u32| (v & !1).max(2) as usize;
    (even(w), even(h))
}

// ---- Public API ------------------------------------------------------------

/// The monitors this host can share, in Mutter's order (index = `DisplayInfo.id`).
pub fn list_displays() -> Vec<DisplayInfo> {
    monitors()
        .unwrap_or_default()
        .into_iter()
        .enumerate()
        .map(|(i, m)| DisplayInfo {
            id: u32::try_from(i).unwrap_or(0),
            name: m.label,
        })
        .collect()
}

/// The `(connector, width, height)` of the shared monitor at index `display`
/// (`None` = primary) — what the remote-input injector records so its absolute
/// coordinates land on the same screen the viewer sees. `None` if no monitors.
pub fn monitor_target(display: Option<u32>) -> Option<(String, u32, u32)> {
    let mons = monitors().ok()?;
    if mons.is_empty() {
        return None;
    }
    let idx = display
        .map(|d| d as usize)
        .filter(|i| *i < mons.len())
        .unwrap_or(0);
    let m = &mons[idx];
    Some((m.connector.clone(), m.width, m.height))
}

/// Capture the primary monitor in the current Mutter session once and encode it
/// as PNG. The caller may be a normal GNOME desktop or the actual GDM greeter;
/// it does not create a virtual display. `timeout` is enforced by GNU
/// coreutils' `timeout`, present on supported Ubuntu releases, so a wedged
/// PipeWire source cannot keep an agent task alive indefinitely.
pub fn capture_png(timeout: Duration) -> AgentResult<Vec<u8>> {
    capture_primary_png(timeout, MutterSession::record_monitor)
}

/// Capture the real GDM or locked desktop through an in-memory PipeWire stream
/// bound to a Mutter RemoteDesktop session.  Mutter documents this binding for
/// remote-desktop-driven screen casts, and GNOME Remote Desktop uses the same
/// API shape for its GDM remote-login mode.  No PNG/JPEG is ever written to a
/// filesystem: GStreamer emits raw pixels to stdout and the worker encodes them
/// entirely in process memory.
fn capture_remote_desktop_png(timeout: Duration) -> AgentResult<Vec<u8>> {
    capture_primary_png(timeout, MutterSession::record_monitor_remote_desktop)
}

/// The only backends permitted for a physical console session.  In particular,
/// this intentionally has no screenshot-file backend: a greeter frame can
/// contain account information and must not be persisted as a convenience
/// fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsoleCaptureBackend {
    DirectScreenCast,
    RemoteDesktopScreenCast,
}

fn console_capture_backend(state: HostConsoleState) -> AgentResult<ConsoleCaptureBackend> {
    match state {
        // GDM (and a locked session if a worker reports it in a later release)
        // needs the ScreenCast session to be owned by RemoteDesktop.
        HostConsoleState::GdmLogin | HostConsoleState::SessionLocked => {
            Ok(ConsoleCaptureBackend::RemoteDesktopScreenCast)
        },
        HostConsoleState::DesktopReady => Ok(ConsoleCaptureBackend::DirectScreenCast),
        HostConsoleState::Booting
        | HostConsoleState::SessionStarting
        | HostConsoleState::SessionSwitching
        | HostConsoleState::Offline => Err(AgentError::Config(
            "graphical console capture is unavailable while the session is transitioning"
                .to_string(),
        )),
    }
}

fn capture_primary_png(
    timeout: Duration,
    open_session: fn(&str) -> AgentResult<MutterSession>,
) -> AgentResult<Vec<u8>> {
    let mons = monitors()?;
    let Some(monitor) = mons.first() else {
        return Err(AgentError::Config(
            "no active GNOME monitor is available in this graphical session".to_string(),
        ));
    };
    let (width, height) = fit_output(monitor.width, monitor.height);
    let session = open_session(&monitor.connector)?;
    let mut child = spawn_one_frame_gst(session.node_id, width, height, timeout)?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| AgentError::Config("Mutter capture stdout missing".to_string()))?;
    // Keep GStreamer diagnostics separate from the raw-frame pipe. This is
    // bounded local journal data only; it cannot contain screen pixels.
    let stderr = child.stderr.take().map(collect_gstreamer_stderr);
    let frame_bytes = width
        .checked_mul(height)
        .and_then(|v| v.checked_mul(4))
        .ok_or_else(|| {
            AgentError::Config("virtual monitor dimensions are too large".to_string())
        })?;
    let mut bgrx = vec![0u8; frame_bytes];
    let read_result = stdout.read_exact(&mut bgrx);
    let _ = child.kill();
    let _ = child.wait();
    let gstreamer_error = stderr
        .and_then(|reader| reader.join().ok())
        .unwrap_or_default();
    read_result.map_err(|e| {
        let diagnostic = if gstreamer_error.is_empty() {
            String::new()
        } else {
            format!("; GStreamer: {gstreamer_error}")
        };
        AgentError::Config(format!(
            "Mutter capture did not produce a frame within {} seconds: {e}{diagnostic}",
            timeout.as_secs().max(1),
        ))
    })?;
    encode_bgrx_png(width, height, &bgrx)
}

/// Capture the physical console using the backend appropriate to the graphical
/// session that owns this worker.  GDM intentionally rejects standalone
/// ScreenCast sessions and disables disk screenshots.  Its compatible path is
/// an in-memory ScreenCast tied to a RemoteDesktop session.  A normal unlocked
/// desktop retains the existing standalone ScreenCast path, with the same
/// in-memory fallback when Mutter explicitly inhibits it (for example while
/// that desktop is locked).
pub fn capture_console_png(timeout: Duration, state: HostConsoleState) -> AgentResult<Vec<u8>> {
    match console_capture_backend(state)? {
        ConsoleCaptureBackend::RemoteDesktopScreenCast => capture_remote_desktop_png(timeout),
        ConsoleCaptureBackend::DirectScreenCast => match capture_png(timeout) {
            Err(error) if session_creation_inhibited(&error) => {
                tracing::info!(
                    "physical console ScreenCast inhibited; retrying through RemoteDesktop-bound PipeWire"
                );
                capture_remote_desktop_png(timeout)
            },
            result => result,
        },
    }
}

fn session_creation_inhibited(error: &AgentError) -> bool {
    error
        .to_string()
        .to_ascii_lowercase()
        .contains("session creation inhibited")
}

/// Capture `display` (a monitor index, `None` = first/primary) and push delta
/// frames to `tx` until the consumer drops or capture ends. Blocking.
#[allow(clippy::needless_pass_by_value)]
pub fn stream(
    fps: u16,
    quality: u8,
    display: Option<u32>,
    tx: Sender<FrameDelta>,
) -> AgentResult<()> {
    let mons = monitors()?;
    if mons.is_empty() {
        return Err(AgentError::Lan("no monitors found to share".to_string()));
    }
    let idx = display
        .map(|d| d as usize)
        .filter(|i| *i < mons.len())
        .unwrap_or(0);
    let connector = mons[idx].connector.clone();
    // Output keeps the monitor's aspect ratio (capped at MAX_W×MAX_H) so an
    // ultrawide host doesn't get letterboxed into 16:9 and look low-res.
    let (out_w, out_h) = fit_output(mons[idx].width, mons[idx].height);
    tracing::info!(
        connector = %connector,
        fps,
        src = format!("{}x{}", mons[idx].width, mons[idx].height),
        out = format!("{out_w}x{out_h}"),
        "screencast(linux): starting Mutter ScreenCast"
    );

    // 1. Dialog-free Mutter session -> PipeWire node id.
    let session = MutterSession::record_monitor(&connector)?;
    tracing::info!(
        node = session.node_id,
        "screencast(linux): got PipeWire node"
    );

    // 2. gst-launch pulls that node and writes fixed-size BGRx frames to stdout.
    let mut child = spawn_gst(session.node_id, out_w, out_h)?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| AgentError::Lan("gst-launch stdout missing".to_string()))?;

    // 3. A reader thread keeps only the *freshest* frame (the source can emit
    // faster than we encode, and screen capture is damage-driven — bursts then
    // quiet). The main loop ticks at the target rate, encoding the latest frame
    // or sending a heartbeat when the screen is idle.
    let frame_bytes = out_w * out_h * 4;
    let latest: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let alive = Arc::new(AtomicBool::new(true));
    let saw_frame = Arc::new(AtomicBool::new(false));
    let (l2, a2, s2) = (
        Arc::clone(&latest),
        Arc::clone(&alive),
        Arc::clone(&saw_frame),
    );
    let reader = std::thread::spawn(move || {
        loop {
            let mut buf = vec![0u8; frame_bytes];
            if stdout.read_exact(&mut buf).is_err() {
                break; // gst exited / pipe closed
            }
            s2.store(true, Ordering::Relaxed);
            *l2.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(buf);
        }
        a2.store(false, Ordering::Relaxed);
    });

    let interval = Duration::from_millis((1000 / u64::from(fps).max(1)).max(1));
    let mut enc = super::screencast::TileEncoder::new();
    loop {
        if tx.is_closed() {
            break; // viewer disconnected
        }
        std::thread::sleep(interval);
        let frame = latest
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let keep_going = match frame {
            Some(buf) => enc.push(out_w, out_h, buf, quality, &tx),
            None => {
                if !alive.load(Ordering::Relaxed) {
                    break; // capture ended (gst gone)
                }
                enc.heartbeat(&tx)
            },
        };
        if !keep_going {
            break; // consumer gone
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    let _ = reader.join();
    drop(session); // Stop the Mutter session
    if !saw_frame.load(Ordering::Relaxed) {
        return Err(AgentError::Lan(
            "screen capture produced no frames (is gst-launch-1.0 + the pipewire \
             plugin installed?)"
                .to_string(),
        ));
    }
    Ok(())
}

// ---- Mutter ScreenCast session ---------------------------------------------

/// A live Mutter ScreenCast session.  The GDM-compatible variant is tied to a
/// RemoteDesktop session, which is also torn down on drop.  Both variants
/// expose their pixels solely through the PipeWire node id.
struct MutterSession {
    conn: Connection,
    session_path: OwnedObjectPath,
    remote_desktop_path: Option<OwnedObjectPath>,
    node_id: u32,
}

impl MutterSession {
    fn record_monitor(connector: &str) -> AgentResult<Self> {
        let conn = Connection::session().map_err(dbus_err)?;

        let screencast = Proxy::new(&conn, SC_DEST, SC_PATH, SC_DEST).map_err(dbus_err)?;
        let empty: BTreeMap<&str, Value> = BTreeMap::new();
        let session_path: OwnedObjectPath = screencast
            .call("CreateSession", &(empty,))
            .map_err(dbus_err)?;

        let session = Proxy::new(
            &conn,
            SC_DEST,
            session_path.clone(),
            "org.gnome.Mutter.ScreenCast.Session",
        )
        .map_err(dbus_err)?;

        // Embed the cursor so the helper can see where the host is pointing.
        let mut props: BTreeMap<&str, Value> = BTreeMap::new();
        props.insert("cursor-mode", Value::U32(1));
        let stream_path: OwnedObjectPath = session
            .call("RecordMonitor", &(connector, props))
            .map_err(dbus_err)?;

        // Subscribe to the node-ready signal BEFORE Start so we can't miss it.
        let stream = Proxy::new(
            &conn,
            SC_DEST,
            stream_path,
            "org.gnome.Mutter.ScreenCast.Stream",
        )
        .map_err(dbus_err)?;
        let mut signal = stream
            .receive_signal("PipeWireStreamAdded")
            .map_err(dbus_err)?;

        session.call::<_, _, ()>("Start", &()).map_err(dbus_err)?;

        let msg = signal
            .next()
            .ok_or_else(|| AgentError::Lan("Mutter sent no PipeWireStreamAdded".to_string()))?;
        let node_id: u32 = msg.body().deserialize().map_err(dbus_err)?;

        Ok(Self {
            conn,
            session_path,
            remote_desktop_path: None,
            node_id,
        })
    }

    /// Create an in-memory monitor capture whose ScreenCast session is driven
    /// by a RemoteDesktop session.  This is the Mutter API arrangement used by
    /// GNOME Remote Desktop for remote-login sessions, and unlike GNOME Shell's
    /// screenshot D-Bus API it never needs a filename.
    fn record_monitor_remote_desktop(connector: &str) -> AgentResult<Self> {
        let conn = Connection::session().map_err(dbus_err)?;

        let remote_desktop =
            Proxy::new(&conn, RD_DEST, RD_PATH, RD_DEST).map_err(remote_desktop_dbus_err)?;
        let remote_desktop_path: OwnedObjectPath = remote_desktop
            .call("CreateSession", &())
            .map_err(remote_desktop_dbus_err)?;
        let remote_desktop_session = Proxy::new(
            &conn,
            RD_DEST,
            remote_desktop_path.clone(),
            RD_SESSION_IFACE,
        )
        .map_err(remote_desktop_dbus_err)?;
        let remote_desktop_session_id: String = remote_desktop_session
            .get_property("SessionId")
            .map_err(remote_desktop_dbus_err)?;

        let screencast = Proxy::new(&conn, SC_DEST, SC_PATH, SC_DEST).map_err(dbus_err)?;
        let mut session_props: BTreeMap<&str, Value> = BTreeMap::new();
        session_props.insert(
            "remote-desktop-session-id",
            Value::Str(Str::from(remote_desktop_session_id)),
        );
        // Match GNOME Remote Desktop's remote-login session: animations are
        // not useful to a remote physical-console viewer and can delay the
        // first stable frame during a GDM ↔ GNOME handover.
        session_props.insert("disable-animations", Value::Bool(true));
        let session_path: OwnedObjectPath = screencast
            .call("CreateSession", &(session_props,))
            .map_err(dbus_err)?;
        let session = Proxy::new(
            &conn,
            SC_DEST,
            session_path.clone(),
            "org.gnome.Mutter.ScreenCast.Session",
        )
        .map_err(dbus_err)?;

        // Remote-desktop-driven ScreenCast sessions are started by this parent
        // session.  Start it before recording the monitor, following GNOME
        // Remote Desktop's established ordering.
        remote_desktop_session
            .call::<_, _, ()>("Start", &())
            .map_err(remote_desktop_dbus_err)?;

        let mut stream_props: BTreeMap<&str, Value> = BTreeMap::new();
        stream_props.insert("cursor-mode", Value::U32(1));
        let stream_path: OwnedObjectPath = session
            .call("RecordMonitor", &(connector, stream_props))
            .map_err(dbus_err)?;
        let stream = Proxy::new(
            &conn,
            SC_DEST,
            stream_path,
            "org.gnome.Mutter.ScreenCast.Stream",
        )
        .map_err(dbus_err)?;
        let mut signal = stream
            .receive_signal("PipeWireStreamAdded")
            .map_err(dbus_err)?;
        stream.call::<_, _, ()>("Start", &()).map_err(dbus_err)?;

        let msg = signal
            .next()
            .ok_or_else(|| AgentError::Lan("Mutter sent no PipeWireStreamAdded".to_string()))?;
        let node_id: u32 = msg.body().deserialize().map_err(dbus_err)?;

        Ok(Self {
            conn,
            session_path,
            remote_desktop_path: Some(remote_desktop_path),
            node_id,
        })
    }
}

impl Drop for MutterSession {
    fn drop(&mut self) {
        if let Ok(session) = Proxy::new(
            &self.conn,
            SC_DEST,
            self.session_path.clone(),
            "org.gnome.Mutter.ScreenCast.Session",
        ) {
            let _ = session.call::<_, _, ()>("Stop", &());
        }
        if let Some(path) = &self.remote_desktop_path {
            if let Ok(session) = Proxy::new(&self.conn, RD_DEST, path.clone(), RD_SESSION_IFACE) {
                let _ = session.call::<_, _, ()>("Stop", &());
            }
        }
    }
}

// ---- GStreamer subprocess --------------------------------------------------

/// Spawn `gst-launch-1.0` pulling `node` into fixed-size BGRx frames on stdout.
/// `-q` keeps gst's own chatter off stdout so only raw frame bytes flow.
///
/// No `videorate`: it withholds the first buffer until a second arrives (to time
/// it), so on a static screen the client would never see the initial frame. We
/// let `pipewiresrc` deliver at the monitor's damage-driven rate and throttle in
/// [`stream`] instead.
fn spawn_gst(node: u32, out_w: usize, out_h: usize) -> AgentResult<Child> {
    let out_caps = format!("video/x-raw,format=BGRx,width={out_w},height={out_h}");
    let mut cmd = Command::new("gst-launch-1.0");
    cmd.args([
        "-q",
        "pipewiresrc",
        &format!("path={node}"),
        "do-timestamp=true",
        "!",
        "videoscale",
        "add-borders=true",
        "!",
        "videoconvert",
        "!",
        &out_caps,
        "!",
        "fdsink",
        "fd=1",
        // Push each frame the moment it arrives instead of pacing it to the
        // pipeline clock — clock-sync withholds buffers up to a frame interval,
        // pure latency on a real-time share. The reader thread already keeps
        // only the freshest frame, so unpaced output can't build a backlog.
        "sync=false",
    ])
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());

    configure_system_gstreamer(&mut cmd);

    let mut child = cmd.spawn().map_err(|e| {
        AgentError::Lan(format!(
            "gst-launch-1.0 failed to start (install gstreamer1.0-tools + \
             gstreamer1.0-pipewire): {e}"
        ))
    })?;
    drain_gstreamer_stderr(&mut child);
    Ok(child)
}

/// Spawn GStreamer through a bounded Ubuntu `timeout` wrapper for a one-shot
/// capture. It deliberately uses the same PipeWire pipeline as [`spawn_gst`].
/// The former `num-buffers=1` variant can close stdout before the first frame
/// is negotiated on some Ubuntu PipeWire/GStreamer combinations. The caller
/// reads one frame then terminates this process itself.
fn spawn_one_frame_gst(
    node: u32,
    out_w: usize,
    out_h: usize,
    timeout: Duration,
) -> AgentResult<Child> {
    let out_caps = format!("video/x-raw,format=BGRx,width={out_w},height={out_h}");
    let mut cmd = Command::new("timeout");
    cmd.args([
        "--signal=TERM",
        &format!("{}s", timeout.as_secs().max(1)),
        "gst-launch-1.0",
        "-q",
        "pipewiresrc",
        &format!("path={node}"),
        "do-timestamp=true",
        "!",
        "videoscale",
        "add-borders=true",
        "!",
        "videoconvert",
        "!",
        &out_caps,
        "!",
        "fdsink",
        "fd=1",
        "sync=false",
    ])
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    configure_system_gstreamer(&mut cmd);
    let mut child = cmd.spawn().map_err(|e| {
        AgentError::Config(format!(
            "headless capture requires Ubuntu coreutils and gstreamer1.0-tools + \
             gstreamer1.0-pipewire: {e}"
        ))
    })?;
    drain_gstreamer_stderr(&mut child);
    Ok(child)
}

/// Strip AppImage-specific library paths so the system GStreamer talks to the
/// host PipeWire stack.
fn configure_system_gstreamer(cmd: &mut Command) {
    // We run inside an AppImage, which exports LD_LIBRARY_PATH + GST_PLUGIN_*
    // pointing at its *bundled* libs. The system gst-launch-1.0 we spawn must
    // load the host's GLib/GStreamer, not ours — a version mismatch makes it
    // crash on startup (no frames, silent). Strip those so the child runs in a
    // clean system environment. Harmless when run from a deb (vars unset).
    for var in [
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "GST_PLUGIN_PATH",
        "GST_PLUGIN_PATH_1_0",
        "GST_PLUGIN_SYSTEM_PATH",
        "GST_PLUGIN_SYSTEM_PATH_1_0",
        "GST_PLUGIN_SCANNER",
        "GIO_MODULE_DIR",
        "GTK_PATH",
    ] {
        cmd.env_remove(var);
    }
}

fn drain_gstreamer_stderr(child: &mut Child) {
    // Drain gst's stderr to the agent log so a setup failure (missing plugin,
    // bad pipewire node, lib mismatch) shows up instead of just "no frames".
    if let Some(err) = child.stderr.take() {
        std::thread::spawn(move || {
            for line in BufReader::new(err).lines().map_while(Result::ok) {
                tracing::debug!(target: "gst", "{line}");
            }
        });
    }
}

/// Read at most a small diagnostic prefix from a one-shot GStreamer process.
/// Raw frames travel solely on stdout, so retaining stderr cannot expose
/// desktop pixels. The bound prevents a broken plugin from consuming unbounded
/// worker memory before the timeout terminates its process.
fn collect_gstreamer_stderr(
    mut stderr: impl Read + Send + 'static,
) -> std::thread::JoinHandle<String> {
    const MAX_DIAGNOSTIC_BYTES: u64 = 4 * 1024;
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stderr
            .by_ref()
            .take(MAX_DIAGNOSTIC_BYTES)
            .read_to_end(&mut bytes);
        String::from_utf8_lossy(&bytes).trim().to_string()
    })
}

/// Encode tightly packed BGRx data from PipeWire as a PNG without writing a
/// plaintext image to disk.
fn encode_bgrx_png(width: usize, height: usize, bgrx: &[u8]) -> AgentResult<Vec<u8>> {
    let mut rgba = Vec::with_capacity(bgrx.len());
    for pixel in bgrx.chunks_exact(4) {
        rgba.extend_from_slice(&[pixel[2], pixel[1], pixel[0], 255]);
    }
    let width = u32::try_from(width)
        .map_err(|_| AgentError::Config("virtual monitor width is invalid".to_string()))?;
    let height = u32::try_from(height)
        .map_err(|_| AgentError::Config("virtual monitor height is invalid".to_string()))?;
    let mut out = Vec::new();
    let mut encoder = png::Encoder::new(&mut out, width, height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder
        .write_header()
        .map_err(|e| AgentError::Config(format!("encode headless PNG header: {e}")))?;
    writer
        .write_image_data(&rgba)
        .map_err(|e| AgentError::Config(format!("encode headless PNG data: {e}")))?;
    drop(writer);
    Ok(out)
}

// ---- Monitor enumeration (Mutter DisplayConfig) ----------------------------

/// `org.gnome.Mutter.DisplayConfig.GetCurrentState` reply shape, typed enough to
/// pull each monitor's connector + model. The mode list and prop dicts are read
/// but unused.
type MonitorId = (String, String, String, String); // connector, vendor, product, serial
type Mode = (
    String,
    i32,
    i32,
    f64,
    f64,
    Vec<f64>,
    BTreeMap<String, OwnedValue>,
);
type MonitorEntry = (MonitorId, Vec<Mode>, BTreeMap<String, OwnedValue>);
type LogicalMonitor = (
    i32,
    i32,
    f64,
    u32,
    bool,
    Vec<MonitorId>,
    BTreeMap<String, OwnedValue>,
);
type CurrentState = (
    u32,
    Vec<MonitorEntry>,
    Vec<LogicalMonitor>,
    BTreeMap<String, OwnedValue>,
);

fn monitors() -> AgentResult<Vec<MonitorInfo>> {
    let conn = Connection::session().map_err(dbus_err)?;
    let proxy = Proxy::new(
        &conn,
        "org.gnome.Mutter.DisplayConfig",
        "/org/gnome/Mutter/DisplayConfig",
        "org.gnome.Mutter.DisplayConfig",
    )
    .map_err(dbus_err)?;
    let state: CurrentState = proxy.call("GetCurrentState", &()).map_err(dbus_err)?;

    // The primary monitor's connector — so "screen 1" (display = None / index 0)
    // is the main display rather than whatever Mutter lists first.
    let primary: Option<String> = state
        .2
        .iter()
        .find(|lm| lm.4) // the `primary` bool
        .and_then(|lm| lm.5.first()) // its first monitor id
        .map(|id| id.0.clone()); // connector

    let mut monitors: Vec<MonitorInfo> = state
        .1
        .into_iter()
        .map(|((connector, vendor, product, _serial), modes, _props)| {
            let label = if !product.is_empty() {
                format!("{connector} · {product}")
            } else if !vendor.is_empty() {
                format!("{connector} · {vendor}")
            } else {
                connector.clone()
            };
            // The active mode carries the live pixel resolution; fall back to the
            // first listed mode, else 0×0 (capture uses a fixed size then).
            let (width, height) = modes
                .iter()
                .find(|m| mode_flag(&m.6, "is-current"))
                .or_else(|| modes.first())
                .map_or((0, 0), |m| {
                    (
                        u32::try_from(m.1).unwrap_or(0),
                        u32::try_from(m.2).unwrap_or(0),
                    )
                });
            MonitorInfo {
                connector,
                label,
                width,
                height,
            }
        })
        .collect();

    // Stable-sort the primary to the front (index 0 = default capture).
    if let Some(p) = primary {
        monitors.sort_by_key(|m| u8::from(m.connector != p));
    }
    Ok(monitors)
}

/// Read a boolean flag (e.g. `is-current`) from a Mutter mode's `a{sv}` props.
fn mode_flag(props: &BTreeMap<String, OwnedValue>, key: &str) -> bool {
    matches!(props.get(key).map(|v| &**v), Some(Value::Bool(true)))
}

fn dbus_err(e: impl std::fmt::Display) -> AgentError {
    AgentError::Lan(format!("Mutter ScreenCast D-Bus error: {e}"))
}

fn remote_desktop_dbus_err(e: impl std::fmt::Display) -> AgentError {
    AgentError::Lan(format!("Mutter RemoteDesktop D-Bus error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn fit_preserves_aspect_within_bounds() {
        // 21:9 ultrawide -> full width, no letterbox.
        assert_eq!(fit_output(3440, 1440), (1920, 802));
        // 16:9 1080p passes through unchanged.
        assert_eq!(fit_output(1920, 1080), (1920, 1080));
        // 1440p and 4K both clamp to the 1080p box.
        assert_eq!(fit_output(2560, 1440), (1920, 1080));
        assert_eq!(fit_output(3840, 2160), (1920, 1080));
        // Small screens are never upscaled.
        assert_eq!(fit_output(1366, 768), (1366, 768));
        // Unknown resolution -> fixed fallback.
        assert_eq!(fit_output(0, 0), (FALLBACK_W, FALLBACK_H));
        // Dimensions are always even.
        let (w, h) = fit_output(3441, 1441);
        assert_eq!((w % 2, h % 2), (0, 0));
    }

    #[test]
    fn one_shot_gstreamer_diagnostics_are_bounded_and_text_only() {
        let diagnostic = collect_gstreamer_stderr(Cursor::new(b"missing pipewiresrc\n".to_vec()))
            .join()
            .expect("diagnostic reader");
        assert_eq!(diagnostic, "missing pipewiresrc");
    }

    #[test]
    fn recognizes_only_mutters_explicit_inhibit_error() {
        assert!(session_creation_inhibited(&AgentError::Lan(
            "Mutter ScreenCast D-Bus error: Session creation inhibited".to_string(),
        )));
        assert!(!session_creation_inhibited(&AgentError::Lan(
            "Mutter ScreenCast D-Bus error: Access denied".to_string(),
        )));
    }

    #[test]
    fn gdm_and_locked_console_use_in_memory_remote_desktop_capture() {
        assert_eq!(
            console_capture_backend(HostConsoleState::GdmLogin).unwrap(),
            ConsoleCaptureBackend::RemoteDesktopScreenCast
        );
        assert_eq!(
            console_capture_backend(HostConsoleState::SessionLocked).unwrap(),
            ConsoleCaptureBackend::RemoteDesktopScreenCast
        );
        assert_eq!(
            console_capture_backend(HostConsoleState::DesktopReady).unwrap(),
            ConsoleCaptureBackend::DirectScreenCast
        );
    }

    #[test]
    fn transitioning_console_states_never_fall_back_to_disk_capture() {
        for state in [
            HostConsoleState::Booting,
            HostConsoleState::SessionStarting,
            HostConsoleState::SessionSwitching,
            HostConsoleState::Offline,
        ] {
            let error = console_capture_backend(state).unwrap_err();
            assert!(error.to_string().contains("session is transitioning"));
        }
    }
}
