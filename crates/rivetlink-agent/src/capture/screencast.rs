//! Native single-screen capture via the XDG ScreenCast portal + PipeWire.
//!
//! Uses `scap`, which drives the desktop portal (the user picks **one** screen
//! in the compositor's own dialog) and reads frames over PipeWire — the same
//! mechanism RustDesk/TeamViewer use on Wayland. Nothing extra is installed:
//! only the PipeWire runtime, which ships with every modern Linux desktop.
//!
//! This grabs a single frame for the screenshot path. Live streaming reuses the
//! same capturer and keeps pulling frames.

use scap::capturer::{Capturer, Options};
use scap::frame::{Frame, FrameType};

use crate::error::{AgentError, AgentResult};

/// Capture one frame from a user-selected screen and return PNG bytes.
///
/// Blocking: the portal shows a "pick a screen" dialog and PipeWire delivery is
/// synchronous. Call from `spawn_blocking`.
pub fn capture_png_blocking() -> AgentResult<Vec<u8>> {
    if !scap::is_supported() {
        return Err(AgentError::Config("screen capture not supported here".to_string()));
    }

    let options = Options {
        fps: 30,
        show_cursor: true,
        output_type: FrameType::BGRAFrame,
        ..Default::default()
    };
    let mut capturer =
        Capturer::build(options).map_err(|e| AgentError::Lan(format!("screencast: {e}")))?;

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
