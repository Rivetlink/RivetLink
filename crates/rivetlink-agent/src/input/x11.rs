//! Local X11/XTEST input for a worker's own cookie-authenticated display.
//!
//! The worker has already constrained DISPLAY to a Unix socket and confirmed
//! that XAUTHORITY belongs to its graphical session.  This module neither
//! changes X access control nor opens an X11 network listener.

use std::sync::mpsc::Receiver;

use x11rb::connection::Connection;
use x11rb::protocol::xtest::ConnectionExt as _;

use rivetlink_sdk::lan::PtrButton;

use super::mutter::{browser_evdev_key_code, InputAction};
use crate::error::{AgentError, AgentResult};

const KEY_PRESS: u8 = 2;
const KEY_RELEASE: u8 = 3;
const BUTTON_PRESS: u8 = 4;
const BUTTON_RELEASE: u8 = 5;
const MOTION_NOTIFY: u8 = 6;
const CURRENT_TIME: u32 = 0;

pub(crate) fn run(display: &str, receiver: &Receiver<InputAction>) {
    let injector = match X11Injector::new(display) {
        Ok(injector) => injector,
        Err(error) => {
            tracing::warn!(error = %error, "remote control: X11/XTEST unavailable");
            return;
        },
    };
    tracing::info!("remote control: X11/XTEST session ready");
    while let Ok(action) = receiver.recv() {
        if let Err(error) = injector.apply(&action) {
            // Never include individual key contents in logs.
            tracing::debug!(error = %error, "remote control: X11 inject failed");
        }
    }
}

struct X11Injector {
    connection: x11rb::rust_connection::RustConnection,
    root: u32,
    width: u16,
    height: u16,
}

impl X11Injector {
    fn new(display: &str) -> AgentResult<Self> {
        let (connection, screen_index) = x11rb::connect(Some(display)).map_err(x11_error)?;
        let screen = connection
            .setup()
            .roots
            .get(screen_index)
            .ok_or_else(|| AgentError::Input("X11 display has no screen".to_string()))?;
        let (root, width, height) = (screen.root, screen.width_in_pixels, screen.height_in_pixels);
        if width == 0 || height == 0 {
            return Err(AgentError::Input(
                "X11 display has no active monitor geometry".to_string(),
            ));
        }
        Ok(Self {
            connection,
            root,
            width,
            height,
        })
    }

    fn apply(&self, action: &InputAction) -> AgentResult<()> {
        match action {
            InputAction::Move { x, y } => {
                let x = scale_coordinate(*x, self.width);
                let y = scale_coordinate(*y, self.height);
                self.fake(MOTION_NOTIFY, 0, x, y)
            },
            InputAction::Button { button, down } => self.fake(
                if *down { BUTTON_PRESS } else { BUTTON_RELEASE },
                x11_button(*button),
                0,
                0,
            ),
            InputAction::Scroll { dx, dy } => {
                if *dy != 0 {
                    self.scroll(if *dy > 0 { 5 } else { 4 }, *dy)?;
                }
                if *dx != 0 {
                    self.scroll(if *dx > 0 { 7 } else { 6 }, *dx)?;
                }
                Ok(())
            },
            InputAction::Key { code, down } => {
                let Some(evdev) = browser_evdev_key_code(code) else {
                    return Ok(());
                };
                // Xorg's standard evdev/XKB mapping uses evdev + 8. It lets
                // the greeter's configured keyboard layout interpret keys;
                // RivetLink never derives or logs the resulting characters.
                let x11_keycode = u8::try_from(evdev + 8)
                    .map_err(|_| AgentError::Input("invalid X11 keycode".to_string()))?;
                self.fake(
                    if *down { KEY_PRESS } else { KEY_RELEASE },
                    x11_keycode,
                    0,
                    0,
                )
            },
        }
    }

    fn scroll(&self, button: u8, amount: i16) -> AgentResult<()> {
        for _ in 0..usize::from(amount.unsigned_abs().min(120)) {
            self.fake(BUTTON_PRESS, button, 0, 0)?;
            self.fake(BUTTON_RELEASE, button, 0, 0)?;
        }
        Ok(())
    }

    fn fake(&self, event_type: u8, detail: u8, x: i16, y: i16) -> AgentResult<()> {
        self.connection
            .xtest_fake_input(event_type, detail, CURRENT_TIME, self.root, x, y, 0)
            .map_err(x11_error)?
            .check()
            .map_err(x11_error)?;
        self.connection.flush().map_err(x11_error)
    }
}

fn scale_coordinate(value: u16, extent: u16) -> i16 {
    let pixel = u32::from(value).min(10_000) * u32::from(extent.saturating_sub(1)) / 10_000;
    i16::try_from(pixel).unwrap_or(i16::MAX)
}

fn x11_button(button: PtrButton) -> u8 {
    match button {
        PtrButton::Left => 1,
        PtrButton::Middle => 2,
        PtrButton::Right => 3,
    }
}

fn x11_error(error: impl std::fmt::Display) -> AgentError {
    AgentError::Input(format!("X11/XTEST input unavailable: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coordinates_are_bounded_to_the_local_x11_screen() {
        assert_eq!(scale_coordinate(0, 1920), 0);
        assert_eq!(scale_coordinate(10_000, 1920), 1919);
        assert_eq!(scale_coordinate(u16::MAX, 1920), 1919);
    }

    #[test]
    fn buttons_use_standard_xtest_numbers() {
        assert_eq!(x11_button(PtrButton::Left), 1);
        assert_eq!(x11_button(PtrButton::Middle), 2);
        assert_eq!(x11_button(PtrButton::Right), 3);
    }
}
