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
use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc::Sender;
use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

use rivetlink_sdk::lan::{DisplayInfo, FrameDelta};

use crate::error::{AgentError, AgentResult};

/// Fixed output size for the stream. `videoscale add-borders=true` pillar/letter-
/// boxes the monitor into this box, so every frame is exactly `W*H*4` bytes and
/// the aspect ratio is preserved. 720p keeps keyframes small over weak Wi-Fi.
const OUT_W: usize = 1280;
const OUT_H: usize = 720;

const SC_DEST: &str = "org.gnome.Mutter.ScreenCast";
const SC_PATH: &str = "/org/gnome/Mutter/ScreenCast";

/// One monitor Mutter can cast.
struct MonitorInfo {
    connector: String,
    label: String,
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
    tracing::info!(connector = %connector, fps, "screencast(linux): starting Mutter ScreenCast");

    // 1. Dialog-free Mutter session -> PipeWire node id.
    let session = MutterSession::record_monitor(&connector)?;
    tracing::info!(node = session.node_id, "screencast(linux): got PipeWire node");

    // 2. gst-launch pulls that node and writes fixed-size BGRx frames to stdout.
    let mut child = spawn_gst(session.node_id)?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| AgentError::Lan("gst-launch stdout missing".to_string()))?;

    // 3. A reader thread keeps only the *freshest* frame (the source can emit
    // faster than we encode, and screen capture is damage-driven — bursts then
    // quiet). The main loop ticks at the target rate, encoding the latest frame
    // or sending a heartbeat when the screen is idle.
    let frame_bytes = OUT_W * OUT_H * 4;
    let latest: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let alive = Arc::new(AtomicBool::new(true));
    let saw_frame = Arc::new(AtomicBool::new(false));
    let (l2, a2, s2) = (Arc::clone(&latest), Arc::clone(&alive), Arc::clone(&saw_frame));
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
        let frame = latest.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
        let keep_going = match frame {
            Some(buf) => enc.push(OUT_W, OUT_H, buf, quality, &tx),
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
        let session_path: OwnedObjectPath =
            screencast.call("CreateSession", &(empty,)).map_err(dbus_err)?;

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
        let mut signal = stream.receive_signal("PipeWireStreamAdded").map_err(dbus_err)?;

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
fn spawn_gst(node: u32) -> AgentResult<Child> {
    let out_caps = format!("video/x-raw,format=BGRx,width={OUT_W},height={OUT_H}");
    Command::new("gst-launch-1.0")
        .args([
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
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            AgentError::Lan(format!(
                "gst-launch-1.0 failed to start (install gstreamer1.0-tools + \
                 gstreamer1.0-pipewire): {e}"
            ))
        })
}

// ---- Monitor enumeration (Mutter DisplayConfig) ----------------------------

/// `org.gnome.Mutter.DisplayConfig.GetCurrentState` reply shape, typed enough to
/// pull each monitor's connector + model. The mode list and prop dicts are read
/// but unused.
type MonitorId = (String, String, String, String); // connector, vendor, product, serial
type Mode = (String, i32, i32, f64, f64, Vec<f64>, BTreeMap<String, OwnedValue>);
type MonitorEntry = (MonitorId, Vec<Mode>, BTreeMap<String, OwnedValue>);
type LogicalMonitor = (i32, i32, f64, u32, bool, Vec<MonitorId>, BTreeMap<String, OwnedValue>);
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
        .map(|((connector, vendor, product, _serial), _modes, _props)| {
            let label = if !product.is_empty() {
                format!("{connector} · {product}")
            } else if !vendor.is_empty() {
                format!("{connector} · {vendor}")
            } else {
                connector.clone()
            };
            MonitorInfo { connector, label }
        })
        .collect();

    // Stable-sort the primary to the front (index 0 = default capture).
    if let Some(p) = primary {
        monitors.sort_by_key(|m| u8::from(m.connector != p));
    }
    Ok(monitors)
}

fn dbus_err(e: impl std::fmt::Display) -> AgentError {
    AgentError::Lan(format!("Mutter ScreenCast D-Bus error: {e}"))
}
