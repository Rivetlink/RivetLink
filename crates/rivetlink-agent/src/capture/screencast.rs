//! Native single-screen capture via the XDG ScreenCast portal + PipeWire.
//!
//! Uses `scap`, which drives the desktop portal (the user picks **one** screen
//! in the compositor's own dialog) and reads frames over PipeWire — the same
//! mechanism RustDesk/TeamViewer use on Wayland. Nothing extra is installed:
//! only the PipeWire runtime, which ships with every modern Linux desktop.
//!
//! This grabs a single frame for the screenshot path. Live streaming reuses the
//! same capturer and keeps pulling frames.

use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use jpeg_encoder::{ColorType, Encoder};
use scap::capturer::{Capturer, Options, Resolution};
use scap::frame::{Frame, FrameType};
use tokio::sync::mpsc::{error::TrySendError, Sender};

use rivetlink_sdk::lan::{DisplayInfo, FrameDelta, TilePatch};

use crate::error::{AgentError, AgentResult};

/// Tile edge length for delta encoding.
const TILE: usize = 128;
/// Send a full keyframe at least this often (frames) as a safety net. We only
/// commit `prev` on a successful send, so dropped frames already self-heal
/// (the next frame re-diffs against the last *sent* state). This rare keyframe
/// only guards the residual case — a tile skipped by an encode error. Keeping
/// it rare avoids the periodic full-screen spike that showed up as a ~1s
/// hiccup, especially while the mouse was moving.
const KEYFRAME_INTERVAL: u32 = 600;
/// When the screen is static, still emit a tiny empty frame at least this often
/// so the client can tell a static screen ("alive, nothing moving") from a
/// stalled/slow link — it drives the viewer's "poor connection" indicator.
const HEARTBEAT: Duration = Duration::from_millis(1000);

/// A tile's rectangle within a frame: frame width plus the tile's origin/size.
struct TileRect {
    fw: usize,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
}

/// Build a screen-cast capturer (BGRA frames at `fps`, scaled to `resolution`).
///
/// `display` selects which screen to capture by its id (`None` = the first /
/// primary display). On macOS we can pick a `target` programmatically, so
/// capture starts with **no picker dialog** — the host shares the requested
/// screen (or screen 1 by default), and the client can switch displays. On
/// Linux there is no programmatic pick: `scap` drives the ScreenCast portal,
/// whose own dialog handles selection, so `display` is ignored and `target`
/// stays unset.
fn build_capturer(fps: u16, resolution: Resolution, display: Option<u32>) -> AgentResult<Capturer> {
    if !scap::is_supported() {
        return Err(AgentError::Lan("screen capture not supported here".to_string()));
    }

    let target = {
        #[cfg(target_os = "macos")]
        {
            // scap only exposes `get_all_targets()` publicly (`get_main_display`
            // is crate-private and panics on Linux). Pick the requested display
            // by id, else the first one — "screen 1".
            let mut displays = scap::get_all_targets()
                .into_iter()
                .filter(|t| matches!(t, scap::Target::Display(_)));
            match display {
                Some(id) => displays.find(
                    |t| matches!(t, scap::Target::Display(d) if d.id == id),
                ),
                None => displays.next(),
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = display; // portal picks the screen on Linux
            None
        }
    };

    let options = Options {
        fps: u32::from(fps).max(1),
        show_cursor: true,
        target,
        output_type: FrameType::BGRAFrame,
        output_resolution: resolution,
        ..Default::default()
    };
    Capturer::build(options).map_err(|e| AgentError::Lan(format!("screencast: {e}")))
}

/// The displays the host can share. Empty on Linux, where scap can't enumerate
/// screens (the ScreenCast portal owns selection).
pub fn list_displays() -> Vec<DisplayInfo> {
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

/// Capture continuously and push delta frames (only the tiles that changed) to
/// `tx` until the receiver is dropped (client disconnected) or the stream ends.
/// Blocking — run on a dedicated thread. A single portal prompt covers the
/// whole stream.
///
/// `tx` is taken by value on purpose: dropping it when this returns closes the
/// channel, signalling the consumer that the stream has ended.
#[allow(clippy::needless_pass_by_value)]
pub fn stream_tiles_blocking(
    fps: u16,
    quality: u8,
    display: Option<u32>,
    tx: Sender<FrameDelta>,
) -> AgentResult<()> {
    // Downscale to 720p server-side; tile-delta then sends only the changed
    // regions, so a mostly-static desktop is nearly free on the wire. 720p
    // keeps the initial keyframe small enough to stay usable over weak Wi-Fi.
    let mut capturer = build_capturer(fps, Resolution::_720p, display)?;
    capturer.start_capture();

    let mut prev: Option<(usize, usize, Vec<u8>)> = None; // (w, h, BGRA)
    let mut counter: u32 = 0;
    let mut last_sent = Instant::now();

    loop {
        let Ok(frame) = capturer.get_next_frame() else {
            break; // stream ended
        };
        let Some((w, h, data)) = frame_to_bgra(frame) else {
            continue;
        };

        // Keyframe on the first frame, on a resize, or periodically.
        let dims_changed = prev.as_ref().is_none_or(|(pw, ph, _)| *pw != w || *ph != h);
        let keyframe = dims_changed || counter.is_multiple_of(KEYFRAME_INTERVAL);
        counter = counter.wrapping_add(1);

        let cols = w.div_ceil(TILE);
        let rows = h.div_ceil(TILE);
        let mut tiles = Vec::new();
        let mut jpeg_bytes = 0usize;
        let encode_start = Instant::now();

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
                    || prev.as_ref().is_none_or(|(_, _, pd)| tile_differs(&data, pd, &rect));
                if !changed {
                    continue;
                }
                match encode_tile(&data, &rect, quality) {
                    Ok(jpeg) => {
                        jpeg_bytes += jpeg.len();
                        tiles.push(TilePatch {
                            i: u32::try_from(ty * cols + tx_col).unwrap_or(0),
                            jpeg_b64: B64.encode(jpeg),
                        });
                    },
                    Err(e) => tracing::debug!(error = %e, "skipping tile"),
                }
            }
        }
        let encode_us = encode_start.elapsed().as_micros();

        // Nothing changed and it isn't a keyframe: usually skip, but emit a tiny
        // empty heartbeat frame at most once per HEARTBEAT so the client can
        // tell a static screen from a stalled/slow link. `prev` is unchanged — a
        // frame with no differing tiles already matches it.
        if tiles.is_empty() && !keyframe && last_sent.elapsed() < HEARTBEAT {
            continue;
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
        // commit `prev` once a frame is actually queued: if it's dropped, the
        // next frame still diffs against the last *sent* state, so accumulated
        // changes get resent instead of silently desyncing the client. That
        // self-healing is what lets keyframes stay rare.
        match tx.try_send(delta) {
            Ok(()) => {
                last_sent = Instant::now();
                prev = Some((w, h, data));
                tracing::debug!(keyframe, tiles = tile_count, encode_us, jpeg_bytes, "lan frame sent");
            },
            Err(TrySendError::Full(_)) => {
                tracing::debug!(tiles = tile_count, "lan frame dropped (consumer behind)");
            },
            Err(TrySendError::Closed(_)) => break, // client gone
        }
    }
    capturer.stop_capture();
    Ok(())
}

/// Convert a captured frame into a tightly-packed BGRA buffer + dimensions.
fn frame_to_bgra(frame: Frame) -> Option<(usize, usize, Vec<u8>)> {
    let (w, h, mut data) = match frame {
        Frame::BGRA(f) => (f.width, f.height, f.data),
        Frame::BGRx(f) => (f.width, f.height, f.data),
        _ => return None, // we requested BGRA; ignore unexpected formats
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
    let (tw16, th16) = (u16::try_from(r.w).unwrap_or(0), u16::try_from(r.h).unwrap_or(0));
    let mut out = Vec::new();
    Encoder::new(&mut out, quality)
        .encode(&buf, tw16, th16, ColorType::Bgra)
        .map_err(|e| AgentError::Lan(format!("jpeg encode: {e}")))?;
    Ok(out)
}

/// Capture one frame from a user-selected screen and return PNG bytes.
///
/// Blocking: the portal shows a "pick a screen" dialog and PipeWire delivery is
/// synchronous. Call from `spawn_blocking`. Linux only — it backs the Linux
/// screenshot fallback; macOS/Windows screenshots use native CLI tools.
#[cfg(target_os = "linux")]
pub fn capture_png_blocking() -> AgentResult<Vec<u8>> {
    // Full native resolution for a crisp one-shot screenshot.
    let mut capturer = build_capturer(30, Resolution::Captured, None)?;
    capturer.start_capture();
    // The first frame(s) after a portal start can be blank while the stream
    // warms up; take a few and keep the last good one.
    let mut frame = None;
    for _ in 0..3 {
        match capturer.get_next_frame() {
            Ok(f) => frame = Some(f),
            Err(e) => return Err(AgentError::Lan(format!("screencast frame: {e}"))),
        }
    }
    capturer.stop_capture();

    let (width, height, data) = into_rgba(frame.ok_or_else(|| {
        AgentError::Lan("screencast produced no frame".to_string())
    })?)?;
    encode_png(width, height, &data)
}

/// Convert a captured frame into tightly-packed RGBA8 + dimensions.
#[cfg(target_os = "linux")]
fn into_rgba(frame: Frame) -> AgentResult<(u32, u32, Vec<u8>)> {
    // We requested BGRA, but handle the common variants defensively.
    let (w, h, mut data, swap_rb) = match frame {
        Frame::BGRA(f) => (f.width, f.height, f.data, true),
        Frame::BGRx(f) => (f.width, f.height, f.data, true),
        Frame::RGBx(f) => (f.width, f.height, f.data, false),
        Frame::XBGR(f) => (f.width, f.height, f.data, true),
        other => {
            return Err(AgentError::Lan(format!(
                "unsupported frame format from screencast: {other:?}"
            )))
        },
    };
    let (w, h) = (u32::try_from(w).unwrap_or(0), u32::try_from(h).unwrap_or(0));
    let expected = (w as usize) * (h as usize) * 4;
    if w == 0 || h == 0 || data.len() < expected {
        return Err(AgentError::Lan(format!(
            "screencast frame too small: {}x{}, {} bytes (need {expected})",
            w,
            h,
            data.len()
        )));
    }
    data.truncate(expected); // drop any trailing stride padding on the last row
    if swap_rb {
        for px in data.chunks_exact_mut(4) {
            px.swap(0, 2); // BGRA -> RGBA
        }
    }
    Ok((w, h, data))
}

#[cfg(target_os = "linux")]
fn encode_png(width: u32, height: u32, rgba: &[u8]) -> AgentResult<Vec<u8>> {
    let mut out = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut out, width, height);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder
            .write_header()
            .map_err(|e| AgentError::Lan(format!("png header: {e}")))?;
        writer
            .write_image_data(rgba)
            .map_err(|e| AgentError::Lan(format!("png data: {e}")))?;
    }
    Ok(out)
}
