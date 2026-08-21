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
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc::Sender;
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

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
    let mons = monitors()?;
    let Some(monitor) = mons.first() else {
        return Err(AgentError::Config(
            "no active GNOME monitor is available in this graphical session".to_string(),
        ));
    };
    let (width, height) = fit_output(monitor.width, monitor.height);
    let session = MutterSession::record_monitor(&monitor.connector)?;
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
        let diagnostic = (!gstreamer_error.is_empty())
            .then(|| format!("; GStreamer: {gstreamer_error}"))
            .unwrap_or_default();
        AgentError::Config(format!(
            "Mutter capture did not produce a frame within {} seconds: {e}{diagnostic}",
            timeout.as_secs().max(1),
        ))
    })?;
    encode_bgrx_png(width, height, &bgrx)
}

/// Capture the GDM greeter safely when its Mutter ScreenCast policy explicitly
/// inhibits new cast sessions. GDM does this before login, even for its own
/// graphical worker. GNOME Shell exposes a separate one-shot screenshot API
/// for the session it owns; unlike the portal it shows no chooser and never
/// targets another seat. This fallback is deliberately limited to GDM — a
/// locked/ordinary desktop must continue to obey the normal ScreenCast policy.
pub fn capture_console_png(timeout: Duration, gdm_login: bool) -> AgentResult<Vec<u8>> {
    match capture_png(timeout) {
        Err(error) if gdm_login && session_creation_inhibited(&error) => {
            tracing::info!("GDM inhibits ScreenCast; using GNOME Shell one-shot screenshot");
            shell_screenshot_png()
        },
        result => result,
    }
}

fn session_creation_inhibited(error: &AgentError) -> bool {
    error
        .to_string()
        .to_ascii_lowercase()
        .contains("session creation inhibited")
}

/// Ask the GNOME Shell owned by this session for one whole-screen PNG. The
/// output lives in a newly-created 0700 child of the worker's runtime dir and
/// is read only if Shell confirms that exact path, so no D-Bus reply can trick
/// the worker into reading an unrelated local file.
fn shell_screenshot_png() -> AgentResult<Vec<u8>> {
    const SHELL_SCREENSHOT_DEST: &str = "org.gnome.Shell.Screenshot";
    const SHELL_SCREENSHOT_PATH: &str = "/org/gnome/Shell/Screenshot";
    const SHELL_SCREENSHOT_IFACE: &str = "org.gnome.Shell.Screenshot";

    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| AgentError::Config("GDM screenshot requires XDG_RUNTIME_DIR".to_string()))?;
    let directory = runtime.join(format!("rivetlink-console-{}", uuid::Uuid::now_v7()));
    fs::create_dir(&directory)
        .map_err(|error| AgentError::Config(format!("create GDM screenshot directory: {error}")))?;
    let cleanup = || {
        let _ = fs::remove_dir_all(&directory);
    };
    if let Err(error) = fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)) {
        cleanup();
        return Err(AgentError::Config(format!(
            "secure GDM screenshot directory: {error}"
        )));
    }
    let requested = directory.join("screen.png");
    let result = (|| {
        let conn = Connection::session().map_err(dbus_err)?;
        let shell = Proxy::new(
            &conn,
            SHELL_SCREENSHOT_DEST,
            SHELL_SCREENSHOT_PATH,
            SHELL_SCREENSHOT_IFACE,
        )
        .map_err(dbus_err)?;
        let path = requested.to_string_lossy().to_string();
        let (success, used): (bool, String) = shell
            .call("Screenshot", &(true, false, path))
            .map_err(dbus_err)?;
        if !success {
            return Err(AgentError::Config(
                "GNOME Shell declined the GDM screenshot".to_string(),
            ));
        }
        let used = PathBuf::from(used);
        if used != requested {
            return Err(AgentError::Config(
                "GNOME Shell returned an unexpected screenshot path".to_string(),
            ));
        }
        fs::read(&used).map_err(|error| AgentError::Config(format!("read GDM screenshot: {error}")))
    })();
    cleanup();
    result
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

/// A live Mutter ScreenCast session. Dropping it stops the cast.
struct MutterSession {
    conn: Connection,
    session_path: OwnedObjectPath,
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
}
