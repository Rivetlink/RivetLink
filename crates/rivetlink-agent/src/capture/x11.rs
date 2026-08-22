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
    let rgba = decode_root_image(
        &image.data,
        usize::from(geometry.width),
        usize::from(geometry.height),
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
    encode_rgba_png(u32::from(geometry.width), u32::from(geometry.height), &rgba)
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
    let bytes_per_pixel = usize::from(bits_per_pixel).div_ceil(8);
    if !(1..=4).contains(&bytes_per_pixel) {
        return Err(AgentError::Config(
            "unsupported X11 root pixel format".to_string(),
        ));
    }
    let stride = bytes
        .len()
        .checked_div(height)
        .filter(|stride| {
            bytes.len().is_multiple_of(height) && *stride >= width.saturating_mul(bytes_per_pixel)
        })
        .ok_or_else(|| AgentError::Config("invalid X11 image stride".to_string()))?;
    let size = width
        .checked_mul(height)
        .and_then(|pixel_count| pixel_count.checked_mul(4))
        .ok_or_else(|| AgentError::Config("X11 image dimensions are too large".to_string()))?;
    let mut rgba = Vec::with_capacity(size);
    for row in bytes.chunks_exact(stride).take(height) {
        for pixel in row.chunks_exact(bytes_per_pixel).take(width) {
            let value = read_pixel(pixel, image_byte_order);
            rgba.extend_from_slice(&[
                component(value, visual.red_mask),
                component(value, visual.green_mask),
                component(value, visual.blue_mask),
                255,
            ]);
        }
    }
    if rgba.len() != size {
        return Err(AgentError::Config("truncated X11 image data".to_string()));
    }
    Ok(rgba)
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
}
