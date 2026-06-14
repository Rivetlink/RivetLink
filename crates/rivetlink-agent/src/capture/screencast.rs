//! Native single-screen capture via the XDG ScreenCast portal + PipeWire.
//!
//! Uses `scap`, which drives the desktop portal (the user picks **one** screen
//! in the compositor's own dialog) and reads frames over PipeWire — the same
//! mechanism RustDesk/TeamViewer use on Wayland. Nothing extra is installed:
//! only the PipeWire runtime, which ships with every modern Linux desktop.
//!
//! This grabs a single frame for the screenshot path. Live streaming reuses the
//! same capturer and keeps pulling frames.

use jpeg_encoder::{ColorType, Encoder};
use scap::capturer::{Capturer, Options, Resolution};
use scap::frame::{Frame, FrameType};
use tokio::sync::mpsc::{error::TrySendError, Sender};

use crate::error::{AgentError, AgentResult};

/// Build a screen-cast capturer (BGRA frames at `fps`, scaled to `resolution`).
/// Triggers the portal "pick a screen" dialog.
fn build_capturer(fps: u16, resolution: Resolution) -> AgentResult<Capturer> {
    if !scap::is_supported() {
        return Err(AgentError::Lan("screen capture not supported here".to_string()));
    }
    let options = Options {
        fps: u32::from(fps).max(1),
        show_cursor: true,
        output_type: FrameType::BGRAFrame,
        output_resolution: resolution,
        ..Default::default()
    };
    Capturer::build(options).map_err(|e| AgentError::Lan(format!("screencast: {e}")))
}

/// Capture continuously, JPEG-encode each frame, and push it to `tx` until the
/// receiver is dropped (client disconnected) or the stream ends. Blocking — run
/// on a dedicated thread. A single portal prompt covers the whole stream.
///
/// `tx` is taken by value on purpose: dropping it when this returns closes the
/// channel, signalling the consumer that the stream has ended.
#[allow(clippy::needless_pass_by_value)]
pub fn stream_jpeg_blocking(fps: u16, quality: u8, tx: Sender<Vec<u8>>) -> AgentResult<()> {
    // Downscale to 1080p server-side: a single 4K/multi-mon source is far too
    // much data for JPEG-over-the-wire. Real low-latency uses H.264 later.
    let mut capturer = build_capturer(fps, Resolution::_1080p)?;
    capturer.start_capture();
    loop {
        let Ok(frame) = capturer.get_next_frame() else {
            break; // stream ended
        };
        let jpeg = match frame_to_jpeg(frame, quality) {
            Ok(j) => j,
            Err(e) => {
                tracing::debug!(error = %e, "skipping unencodable frame");
                continue;
            },
        };
        // Drop frames the consumer can't keep up with rather than build lag.
        match tx.try_send(jpeg) {
            Ok(()) => {},
            Err(TrySendError::Full(_)) => {},
            Err(TrySendError::Closed(_)) => break, // client gone
        }
    }
    capturer.stop_capture();
    Ok(())
}

/// JPEG-encode one captured frame.
fn frame_to_jpeg(frame: Frame, quality: u8) -> AgentResult<Vec<u8>> {
    let (w, h, mut data, color, bpp) = match frame {
        Frame::BGRA(f) => (f.width, f.height, f.data, ColorType::Bgra, 4),
        Frame::BGRx(f) => (f.width, f.height, f.data, ColorType::Bgra, 4),
        Frame::RGBx(f) => (f.width, f.height, f.data, ColorType::Rgba, 4),
        Frame::RGB(f) => (f.width, f.height, f.data, ColorType::Rgb, 3),
        other => {
            return Err(AgentError::Lan(format!("unsupported frame format: {other:?}")))
        },
    };
    let (w16, h16) = (u16::try_from(w).unwrap_or(0), u16::try_from(h).unwrap_or(0));
    let expected = usize::from(w16) * usize::from(h16) * bpp;
    if w16 == 0 || h16 == 0 || data.len() < expected {
        return Err(AgentError::Lan(format!(
            "frame too small: {w}x{h}, {} bytes (need {expected})",
            data.len()
        )));
    }
    data.truncate(expected); // drop any trailing stride padding

    let mut out = Vec::new();
    Encoder::new(&mut out, quality)
        .encode(&data, w16, h16, color)
        .map_err(|e| AgentError::Lan(format!("jpeg encode: {e}")))?;
    Ok(out)
}

/// Capture one frame from a user-selected screen and return PNG bytes.
///
/// Blocking: the portal shows a "pick a screen" dialog and PipeWire delivery is
/// synchronous. Call from `spawn_blocking`.
pub fn capture_png_blocking() -> AgentResult<Vec<u8>> {
    // Full native resolution for a crisp one-shot screenshot.
    let mut capturer = build_capturer(30, Resolution::Captured)?;
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
