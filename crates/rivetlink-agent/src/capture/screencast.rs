//! Live single-screen capture for the tile-delta stream.
//!
//! The pixel source is platform-specific:
//! - **macOS**: `scap` (ScreenCaptureKit). We pick the display programmatically,
//!   so capture starts with no picker dialog and the client can switch screens.
//! - **Linux**: GNOME **Mutter ScreenCast** (D-Bus) + **GStreamer** — see
//!   [`crate::capture::mutter`]. Dialog-free, monitor-selectable, and version-
//!   proof against the host's PipeWire (scap's old libspa can't talk to PipeWire
//!   1.6+ on Ubuntu 26.04).
//!
//! The frame **encoding** (downscale-aware tile-delta JPEG) is shared by both
//! backends via [`TileEncoder`]: each backend just decodes its native frame to a
//! tightly-packed BGRA/BGRx buffer and pushes it in.

use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use jpeg_encoder::{ColorType, Encoder};
use tokio::sync::mpsc::{error::TrySendError, Sender};

use rivetlink_sdk::lan::{DisplayInfo, FrameDelta, TilePatch};

use crate::error::AgentResult;

/// Tile edge length for delta encoding.
const TILE: usize = 128;
/// Send a full keyframe at least this often (frames). Besides recovering tiles
/// skipped by an encode error, this re-fills any region that was stale in the
/// initial keyframe (e.g. a capture backend that warms up to a blank frame, or
/// delivers dirty-region frames): static areas never "change", so without a
/// periodic keyframe they'd stay wrong until something moves over them. At ~20
/// fps this is every ~8s — small over LAN, frequent enough to self-heal.
const KEYFRAME_INTERVAL: u32 = 160;
/// When the screen is static, still emit a tiny empty frame at least this often
/// so the client can tell a static screen from a stalled/slow link.
const HEARTBEAT: Duration = Duration::from_millis(1000);

// ---- Public API (platform-dispatched) --------------------------------------

/// The displays the host can offer to share.
pub fn list_displays() -> Vec<DisplayInfo> {
    #[cfg(target_os = "macos")]
    {
        macos::list_displays()
    }
    #[cfg(target_os = "linux")]
    {
        crate::capture::mutter::list_displays()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Vec::new()
    }
}

/// Capture `display` continuously and push delta frames to `tx` until the
/// receiver is dropped (client disconnected) or the stream ends. Blocking — run
/// on a dedicated thread. `display` selects the screen (`None` = primary).
///
/// `tx` is taken by value: dropping it on return closes the channel, signalling
/// the consumer that the stream ended.
#[allow(clippy::needless_pass_by_value)]
pub fn stream_tiles_blocking(
    fps: u16,
    quality: u8,
    display: Option<u32>,
    tx: Sender<FrameDelta>,
) -> AgentResult<()> {
    #[cfg(target_os = "macos")]
    {
        macos::stream(fps, quality, display, &tx)
    }
    #[cfg(target_os = "linux")]
    {
        crate::capture::mutter::stream(fps, quality, display, tx)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (fps, quality, display, tx);
        Err(crate::error::AgentError::Lan(
            "live capture not supported on this platform".to_string(),
        ))
    }
}

// ---- Shared tile-delta encoder ---------------------------------------------

/// A tile's rectangle within a frame: frame width plus the tile's origin/size.
struct TileRect {
    fw: usize,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
}

/// Stateful tile-delta encoder shared by every capture backend. Feed it raw
/// BGRA/BGRx frames; it diffs against the previous *sent* frame, JPEG-encodes
/// only the changed tiles, and pushes a [`FrameDelta`] onto `tx`.
pub(crate) struct TileEncoder {
    prev: Option<(usize, usize, Vec<u8>)>, // (w, h, BGRA)
    counter: u32,
    last_sent: Instant,
}

impl TileEncoder {
    pub(crate) fn new() -> Self {
        Self {
            prev: None,
            counter: 0,
            last_sent: Instant::now(),
        }
    }

    /// Encode one frame (BGRA/BGRx, `w*h*4` bytes) and queue the changed tiles.
    /// Returns `false` when the consumer is gone (caller should stop capturing).
    pub(crate) fn push(
        &mut self,
        w: usize,
        h: usize,
        data: Vec<u8>,
        quality: u8,
        tx: &Sender<FrameDelta>,
    ) -> bool {
        if w == 0 || h == 0 || data.len() < w * h * 4 {
            return true; // skip a malformed frame, keep going
        }

        let dims_changed = self
            .prev
            .as_ref()
            .is_none_or(|(pw, ph, _)| *pw != w || *ph != h);
        let keyframe = dims_changed || self.counter.is_multiple_of(KEYFRAME_INTERVAL);
        self.counter = self.counter.wrapping_add(1);

        let cols = w.div_ceil(TILE);
        let rows = h.div_ceil(TILE);
        let mut tiles = Vec::new();

        for ty in 0..rows {
            for tx_col in 0..cols {
                let (x0, y0) = (tx_col * TILE, ty * TILE);
                let rect = TileRect {
                    fw: w,
                    x: x0,
                    y: y0,
                    w: TILE.min(w - x0),
                    h: TILE.min(h - y0),
                };
                let changed = keyframe
                    || self
                        .prev
                        .as_ref()
                        .is_none_or(|(_, _, pd)| tile_differs(&data, pd, &rect));
                if !changed {
                    continue;
                }
                match encode_tile(&data, &rect, quality) {
                    Ok(jpeg) => tiles.push(TilePatch {
                        i: u32::try_from(ty * cols + tx_col).unwrap_or(0),
                        jpeg_b64: B64.encode(jpeg),
                    }),
                    Err(e) => tracing::debug!(error = %e, "skipping tile"),
                }
            }
        }

        // Nothing changed and not a keyframe: usually skip, but emit a tiny
        // heartbeat at most once per HEARTBEAT so the client can tell a static
        // screen from a stalled link.
        if tiles.is_empty() && !keyframe && self.last_sent.elapsed() < HEARTBEAT {
            return true;
        }

        let tile_count = tiles.len();
        let delta = FrameDelta {
            w: u32::try_from(w).unwrap_or(0),
            h: u32::try_from(h).unwrap_or(0),
            tile: u32::try_from(TILE).unwrap_or(0),
            keyframe,
            tiles,
        };
        // Drop frames the consumer can't keep up with rather than build lag. Only
        // commit `prev` once a frame is queued: a dropped frame re-diffs against
        // the last *sent* state, so accumulated changes get resent instead of
        // silently desyncing the client.
        match tx.try_send(delta) {
            Ok(()) => {
                self.last_sent = Instant::now();
                self.prev = Some((w, h, data));
                tracing::debug!(keyframe, tiles = tile_count, "lan frame sent");
                true
            },
            Err(TrySendError::Full(_)) => {
                tracing::debug!(tiles = tile_count, "lan frame dropped (consumer behind)");
                true
            },
            Err(TrySendError::Closed(_)) => false, // client gone
        }
    }

    /// Send an empty heartbeat frame if the screen has been idle for a while, so
    /// a static screen still reads as "alive, nothing moving" instead of tripping
    /// the client's slow-link indicator. No-op until a real frame has been sent.
    /// Returns `false` when the consumer is gone.
    ///
    /// Only the Linux (Mutter+GStreamer) backend needs this — its capture is
    /// damage-driven, so a static screen produces no frames; the macOS scap loop
    /// blocks on `get_next_frame` and drives heartbeats from the capturer itself.
    #[cfg(target_os = "linux")]
    pub(crate) fn heartbeat(&mut self, tx: &Sender<FrameDelta>) -> bool {
        let Some((w, h, _)) = self.prev.as_ref() else {
            return true; // nothing to anchor a heartbeat to yet
        };
        if self.last_sent.elapsed() < HEARTBEAT {
            return true;
        }
        let delta = FrameDelta {
            w: u32::try_from(*w).unwrap_or(0),
            h: u32::try_from(*h).unwrap_or(0),
            tile: u32::try_from(TILE).unwrap_or(0),
            keyframe: false,
            tiles: Vec::new(),
        };
        match tx.try_send(delta) {
            Ok(()) => {
                self.last_sent = Instant::now();
                true
            },
            Err(TrySendError::Full(_)) => true,
            Err(TrySendError::Closed(_)) => false,
        }
    }
}

/// Whether a tile's pixels differ between the current and previous frame.
fn tile_differs(cur: &[u8], prev: &[u8], r: &TileRect) -> bool {
    let row_bytes = r.w * 4;
    (0..r.h).any(|row| {
        let start = ((r.y + row) * r.fw + r.x) * 4;
        cur[start..start + row_bytes] != prev[start..start + row_bytes]
    })
}

/// JPEG-encode one tile (a sub-rectangle of the BGRA frame).
fn encode_tile(frame: &[u8], r: &TileRect, quality: u8) -> AgentResult<Vec<u8>> {
    let row_bytes = r.w * 4;
    let mut buf = Vec::with_capacity(r.w * r.h * 4);
    for row in 0..r.h {
        let start = ((r.y + row) * r.fw + r.x) * 4;
        buf.extend_from_slice(&frame[start..start + row_bytes]);
    }
    let (tw16, th16) = (
        u16::try_from(r.w).unwrap_or(0),
        u16::try_from(r.h).unwrap_or(0),
    );
    let mut out = Vec::new();
    Encoder::new(&mut out, quality)
        .encode(&buf, tw16, th16, ColorType::Bgra)
        .map_err(|e| crate::error::AgentError::Lan(format!("jpeg encode: {e}")))?;
    Ok(out)
}

// ---- macOS backend (scap / ScreenCaptureKit) -------------------------------

#[cfg(target_os = "macos")]
mod macos {
    use scap::capturer::{Capturer, Options, Resolution};
    use scap::frame::{Frame, FrameType};
    use tokio::sync::mpsc::Sender;

    use rivetlink_sdk::lan::{DisplayInfo, FrameDelta};

    use crate::error::{AgentError, AgentResult};

    /// The displays scap can share (real screens on macOS).
    pub(super) fn list_displays() -> Vec<DisplayInfo> {
        scap::get_all_targets()
            .into_iter()
            .filter_map(|t| match t {
                scap::Target::Display(d) => Some(DisplayInfo {
                    id: d.id,
                    name: d.title,
                }),
                scap::Target::Window(_) => None,
            })
            .collect()
    }

    pub(super) fn stream(
        fps: u16,
        quality: u8,
        display: Option<u32>,
        tx: &Sender<FrameDelta>,
    ) -> AgentResult<()> {
        let mut capturer = build_capturer(fps, display)?;
        capturer.start_capture();
        tracing::info!(fps, "screencast(macos): capturer started");

        // ScreenCaptureKit's first frames after start can be blank/partial while
        // the capture warms up. Discard a few so the keyframe is a complete
        // screen (otherwise static regions stay black until they're damaged).
        for _ in 0..5 {
            let _ = capturer.get_next_frame();
        }

        let mut enc = super::TileEncoder::new();
        let mut got_frame = false;
        loop {
            let frame = match capturer.get_next_frame() {
                Ok(f) => f,
                Err(e) => {
                    tracing::warn!(error = %e, got_any = got_frame, "screencast(macos): capture ended");
                    if !got_frame {
                        capturer.stop_capture();
                        return Err(AgentError::Lan(format!(
                            "screen capture failed to start (Screen Recording permission?): {e}"
                        )));
                    }
                    break;
                },
            };
            got_frame = true;
            if let Some((w, h, data)) = frame_to_bgra(frame) {
                if !enc.push(w, h, data, quality, tx) {
                    break;
                }
            }
        }
        capturer.stop_capture();
        Ok(())
    }

    /// Build a 720p BGRA capturer for the chosen display (`None` = first).
    fn build_capturer(fps: u16, display: Option<u32>) -> AgentResult<Capturer> {
        if !scap::is_supported() {
            return Err(AgentError::Lan(
                "screen capture not supported here".to_string(),
            ));
        }
        let all = scap::get_all_targets();
        let mut displays = all
            .into_iter()
            .filter(|t| matches!(t, scap::Target::Display(_)));
        let target = match display {
            Some(id) => displays.find(|t| matches!(t, scap::Target::Display(d) if d.id == id)),
            None => displays.next(),
        };
        let req = display; // `display` is a reserved token in tracing fields
        tracing::info!(requested = ?req, picked = target.is_some(), "screencast(macos): target");

        let options = Options {
            fps: u32::from(fps).max(1),
            show_cursor: true,
            target,
            output_type: FrameType::BGRAFrame,
            output_resolution: Resolution::_720p,
            ..Default::default()
        };
        Capturer::build(options).map_err(|e| {
            tracing::warn!(error = %e, "screencast(macos): Capturer::build failed");
            AgentError::Lan(format!("screencast: {e}"))
        })
    }

    /// Convert a captured frame into a tightly-packed BGRA buffer + dimensions.
    fn frame_to_bgra(frame: Frame) -> Option<(usize, usize, Vec<u8>)> {
        let (w, h, mut data) = match frame {
            Frame::BGRA(f) => (f.width, f.height, f.data),
            Frame::BGRx(f) => (f.width, f.height, f.data),
            _ => return None,
        };
        let w = usize::try_from(w).unwrap_or(0);
        let h = usize::try_from(h).unwrap_or(0);
        let expected = w * h * 4;
        if w == 0 || h == 0 || data.len() < expected {
            return None;
        }
        data.truncate(expected);
        Some((w, h, data))
    }
}
