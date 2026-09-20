//! In-memory capture of the local, cookie-authenticated Xorg display.
//!
//! This backend exists for a GDM or desktop worker that is *already running in
//! an X11 graphical session*.  It deliberately does not discover another
//! user's display, alter X access control, or use a TCP display address.  The
//! caller validates `DISPLAY` and `XAUTHORITY`; x11rb then uses the normal
//! MIT-MAGIC-COOKIE for that worker session.

use x11rb::connection::Connection;
use x11rb::protocol::xproto::{ConnectionExt as _, ImageFormat, VisualClass, Visualtype};

use crate::error::{AgentError, AgentResult};

/// Never request an implausibly large root image from an X server. This is far
/// above common 4K output while bounding memory if a broken server reports
/// corrupt geometry.
const MAX_X11_PIXELS: usize = 33_554_432;

/// Keep the JSON/base64 worker response comfortably below the broker's
/// authenticated IPC limit.  Xorg may select a 4K mode for an HDMI dummy even
/// though the login stream is displayed in a much smaller client window.
/// Capturing the real root window first preserves the physical-console
/// semantics; only the in-memory frame sent to RivetLink is scaled.
const MAX_STREAM_WIDTH: usize = 1_920;
const MAX_STREAM_HEIGHT: usize = 1_080;

/// Capture the X screen belonging to `display` and encode it in memory.
///
/// X11's `GetImage` copies the root window without creating an image file.
/// This is intentionally a one-frame primitive because the physical-console
/// protocol requests bounded PNG frames; a persistent stream can be added
/// later without changing the display/session authorization boundary.
pub fn capture_png(display: &str) -> AgentResult<Vec<u8>> {
    let (connection, screen_index) = x11rb::connect(Some(display)).map_err(x11_error)?;
    let screen = connection
        .setup()
        .roots
        .get(screen_index)
        .ok_or_else(|| AgentError::Config("X11 display has no screen".to_string()))?;
    let geometry = connection
        .get_geometry(screen.root)
        .map_err(x11_error)?
        .reply()
        .map_err(x11_error)?;
    if geometry.width == 0 || geometry.height == 0 {
        return Err(AgentError::Config(
            "X11 display has no active monitor geometry".to_string(),
        ));
    }
    let _pixels = usize::from(geometry.width)
        .checked_mul(usize::from(geometry.height))
        .filter(|pixels| *pixels <= MAX_X11_PIXELS)
        .ok_or_else(|| AgentError::Config("X11 monitor geometry is too large".to_string()))?;
    let image = connection
        .get_image(
            ImageFormat::Z_PIXMAP,
            screen.root,
            0,
            0,
            geometry.width,
            geometry.height,
            u32::MAX,
        )
        .map_err(x11_error)?
        .reply()
        .map_err(x11_error)?;
    let visual = visual_for_root(connection.setup(), screen.root_depth, screen.root_visual)?;
    if !matches!(
        visual.class,
        VisualClass::TRUE_COLOR | VisualClass::DIRECT_COLOR
    ) {
        return Err(AgentError::Config(
            "unsupported X11 root visual class".to_string(),
        ));
    }
    let width = usize::from(geometry.width);
    let height = usize::from(geometry.height);
    let (stream_width, stream_height) = fit_stream_dimensions(width, height);
    let rgba = decode_root_image_scaled(
        &image.data,
        width,
        height,
        stream_width,
        stream_height,
        connection
            .setup()
            .pixmap_formats
            .iter()
            .find(|format| format.depth == screen.root_depth)
            .map(|format| format.bits_per_pixel)
            .ok_or_else(|| {
                AgentError::Config("X11 root pixel format is unavailable".to_string())
            })?,
        u8::from(connection.setup().image_byte_order),
        visual,
    )?;
    encode_rgba_png(
        u32::try_from(stream_width).expect("bounded stream width fits u32"),
        u32::try_from(stream_height).expect("bounded stream height fits u32"),
        &rgba,
    )
}

fn fit_stream_dimensions(width: usize, height: usize) -> (usize, usize) {
    if width <= MAX_STREAM_WIDTH && height <= MAX_STREAM_HEIGHT {
        return (width, height);
    }
    let width_limited_height = height.saturating_mul(MAX_STREAM_WIDTH) / width;
    if width_limited_height <= MAX_STREAM_HEIGHT {
        (MAX_STREAM_WIDTH, width_limited_height.max(1))
    } else {
        let height_limited_width = width.saturating_mul(MAX_STREAM_HEIGHT) / height;
        (height_limited_width.max(1), MAX_STREAM_HEIGHT)
    }
}

/// Decode only the pixels needed by the bounded login stream. X11 still
/// captures the real full root window, while avoiding a second 33 MiB RGBA
/// allocation when an HDMI dummy advertises 4K.
fn decode_root_image_scaled(
    bytes: &[u8],
    source_width: usize,
    source_height: usize,
    target_width: usize,
    target_height: usize,
    bits_per_pixel: u8,
    image_byte_order: u8,
    visual: &Visualtype,
) -> AgentResult<Vec<u8>> {
    if source_width == 0 || source_height == 0 || target_width == 0 || target_height == 0 {
        return Err(AgentError::Config(
            "invalid X11 image dimensions for scaling".to_string(),
        ));
    }
    let bytes_per_pixel = usize::from(bits_per_pixel).div_ceil(8);
    if !(1..=4).contains(&bytes_per_pixel) {
        return Err(AgentError::Config(
            "unsupported X11 root pixel format".to_string(),
        ));
    }
    let stride = bytes
        .len()
        .checked_div(source_height)
        .filter(|stride| {
            bytes.len().is_multiple_of(source_height)
                && *stride >= source_width.saturating_mul(bytes_per_pixel)
        })
        .ok_or_else(|| AgentError::Config("invalid X11 image stride".to_string()))?;
    let target_len = target_width
        .checked_mul(target_height)
        .and_then(|pixels| pixels.checked_mul(4))
        .ok_or_else(|| AgentError::Config("X11 stream dimensions are too large".to_string()))?;
    let mut target = Vec::with_capacity(target_len);
    for target_y in 0..target_height {
        let source_y = target_y.saturating_mul(source_height) / target_height;
        let row = &bytes[source_y * stride..(source_y + 1) * stride];
        for target_x in 0..target_width {
            let source_x = target_x.saturating_mul(source_width) / target_width;
            let source_offset = source_x * bytes_per_pixel;
            let value = read_pixel(
                &row[source_offset..source_offset + bytes_per_pixel],
                image_byte_order,
            );
            target.extend_from_slice(&[
                component(value, visual.red_mask),
                component(value, visual.green_mask),
                component(value, visual.blue_mask),
                255,
            ]);
        }
    }
    debug_assert_eq!(target.len(), target_len);
    Ok(target)
}

fn visual_for_root(
    setup: &x11rb::protocol::xproto::Setup,
    depth: u8,
    visual: u32,
) -> AgentResult<&Visualtype> {
    setup
        .roots
        .iter()
        .flat_map(|screen| screen.allowed_depths.iter())
        .filter(|candidate| candidate.depth == depth)
        .flat_map(|candidate| candidate.visuals.iter())
        .find(|candidate| candidate.visual_id == visual)
        .ok_or_else(|| AgentError::Config("X11 root visual is unavailable".to_string()))
}

/// Decode a ZPixmap image using its server byte order and TrueColor masks.
/// The output is tightly packed RGBA and never leaves process memory.
fn decode_root_image(
    bytes: &[u8],
    width: usize,
    height: usize,
    bits_per_pixel: u8,
    image_byte_order: u8,
    visual: &Visualtype,
) -> AgentResult<Vec<u8>> {
    decode_root_image_scaled(
        bytes,
        width,
        height,
        width,
        height,
        bits_per_pixel,
        image_byte_order,
        visual,
    )
}

fn read_pixel(bytes: &[u8], image_byte_order: u8) -> u32 {
    // X11 protocol: 0 = least-significant byte first, 1 = most-significant.
    if image_byte_order == 0 {
        bytes
            .iter()
            .enumerate()
            .fold(0_u32, |value, (index, byte)| {
                value | (u32::from(*byte) << (index * 8))
            })
    } else {
        bytes
            .iter()
            .fold(0_u32, |value, byte| (value << 8) | u32::from(*byte))
    }
}

fn component(pixel: u32, mask: u32) -> u8 {
    if mask == 0 {
        return 0;
    }
    let shift = mask.trailing_zeros();
    let maximum = mask >> shift;
    let value = (pixel & mask) >> shift;
    u8::try_from(value.saturating_mul(255) / maximum).unwrap_or(255)
}

fn encode_rgba_png(width: u32, height: u32, rgba: &[u8]) -> AgentResult<Vec<u8>> {
    let mut output = Vec::new();
    let mut encoder = png::Encoder::new(&mut output, width, height);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder
        .write_header()
        .map_err(|error| AgentError::Config(format!("encode X11 PNG header: {error}")))?;
    writer
        .write_image_data(rgba)
        .map_err(|error| AgentError::Config(format!("encode X11 PNG data: {error}")))?;
    drop(writer);
    Ok(output)
}

fn x11_error(error: impl std::fmt::Display) -> AgentError {
    // Keep display names and Xauthority paths out of errors: the broker turns
    // this into a stable local-only failure code before it reaches a client.
    AgentError::Config(format!("X11 console capture unavailable: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use x11rb::protocol::xproto::VisualClass;

    fn rgb_visual() -> Visualtype {
        Visualtype {
            visual_id: 1,
            class: VisualClass::TRUE_COLOR,
            bits_per_rgb_value: 8,
            colormap_entries: 256,
            red_mask: 0x00ff_0000,
            green_mask: 0x0000_ff00,
            blue_mask: 0x0000_00ff,
        }
    }

    #[test]
    fn decodes_little_endian_bgrx_without_a_disk_screenshot() {
        let rgba = decode_root_image(&[3, 2, 1, 0], 1, 1, 32, 0, &rgb_visual()).unwrap();
        assert_eq!(rgba, vec![1, 2, 3, 255]);
    }

    #[test]
    fn rejects_invalid_image_strides() {
        let error = decode_root_image(&[0; 3], 1, 1, 32, 0, &rgb_visual()).unwrap_err();
        assert!(error.to_string().contains("stride"));
    }

    #[test]
    fn bounds_four_k_dummy_frames_without_changing_aspect_ratio() {
        assert_eq!(fit_stream_dimensions(3_840, 2_160), (1_920, 1_080));
        assert_eq!(fit_stream_dimensions(3_440, 1_440), (1_920, 803));
        assert_eq!(fit_stream_dimensions(1_280, 720), (1_280, 720));
    }

    #[test]
    fn scales_rgba_frames_entirely_in_memory() {
        let source = vec![
            3, 2, 1, 0, 6, 5, 4, 0, // first X11 BGRX row
            9, 8, 7, 0, 12, 11, 10, 0, // second X11 BGRX row
        ];
        let scaled = decode_root_image_scaled(&source, 2, 2, 1, 1, 32, 0, &rgb_visual()).unwrap();
        assert_eq!(scaled, vec![1, 2, 3, 255]);
    }
}
