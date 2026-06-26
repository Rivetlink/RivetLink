//! Linux uinput virtual input device.
//!
//! Injects pointer + keyboard events at the kernel evdev layer, so it works
//! under both X11 AND Wayland/GNOME — the compositor just sees an ordinary
//! input device. Requires write access to `/dev/uinput` (root-only by default);
//! [`UinputInjector::new`] returns a clear, actionable error otherwise.

use std::io;

use evdev::{
    uinput::{VirtualDevice, VirtualDeviceBuilder},
    AbsInfo, AbsoluteAxisType, AttributeSet, EventType, InputEvent, Key, RelativeAxisType,
    UinputAbsSetup,
};
use rivetlink_sdk::lan::PtrButton;

use crate::error::{AgentError, AgentResult};

/// Absolute-axis range. The client sends coordinates already normalized to this
/// range (ten-thousandths of the streamed frame), so the device's logical
/// extent maps straight onto the screen — resolution-independent, no host
/// screen-size lookup needed.
const ABS_MAX: i32 = 10_000;

/// A virtual mouse+keyboard backed by `/dev/uinput`.
pub struct UinputInjector {
    dev: VirtualDevice,
}

impl std::fmt::Debug for UinputInjector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `VirtualDevice` isn't `Debug`; this type is just an opaque handle.
        f.debug_struct("UinputInjector").finish_non_exhaustive()
    }
}

impl UinputInjector {
    /// Create the virtual device. Blocks ~200ms while the kernel/libinput
    /// notices the new device (events emitted before that are dropped), so call
    /// this off the async runtime (e.g. `spawn_blocking`).
    pub fn new() -> AgentResult<Self> {
        let mut keys = AttributeSet::<Key>::new();
        keys.insert(Key::BTN_LEFT);
        keys.insert(Key::BTN_RIGHT);
        keys.insert(Key::BTN_MIDDLE);
        // Advertise the whole standard keyboard range so any mapped key can be
        // emitted; codes 1..=255 cover every KEY_* `code_to_key` returns.
        for code in 1..=255u16 {
            keys.insert(Key(code));
        }

        let mut rel = AttributeSet::<RelativeAxisType>::new();
        rel.insert(RelativeAxisType::REL_WHEEL);
        rel.insert(RelativeAxisType::REL_HWHEEL);

        // value, min, max, fuzz, flat, resolution
        let abs = AbsInfo::new(0, 0, ABS_MAX, 0, 0, 0);
        let abs_x = UinputAbsSetup::new(AbsoluteAxisType::ABS_X, abs);
        let abs_y = UinputAbsSetup::new(AbsoluteAxisType::ABS_Y, abs);

        let dev = VirtualDeviceBuilder::new()
            .map_err(map_err)?
            .name("RivetLink Virtual Input")
            .with_keys(&keys)
            .map_err(map_err)?
            .with_relative_axes(&rel)
            .map_err(map_err)?
            .with_absolute_axis(&abs_x)
            .map_err(map_err)?
            .with_absolute_axis(&abs_y)
            .map_err(map_err)?
            .build()
            .map_err(map_err)?;

        // ponytail: a fixed settle delay — the kernel needs a beat to register
        // the device with libinput before it routes events. Plain ABS+buttons,
        // no INPUT_PROP_DIRECT; if a compositor ignores it for absolute cursor
        // positioning, the upgrade path is a touchscreen-style device.
        std::thread::sleep(std::time::Duration::from_millis(200));
        tracing::info!("uinput: virtual input device ready");
        Ok(Self { dev })
    }

    /// Move the cursor to an absolute position (`x`/`y` in `0..=10_000`).
    pub fn pointer_move(&mut self, x: u16, y: u16) -> AgentResult<()> {
        let x = i32::from(x).clamp(0, ABS_MAX);
        let y = i32::from(y).clamp(0, ABS_MAX);
        self.emit(&[
            InputEvent::new(EventType::ABSOLUTE, AbsoluteAxisType::ABS_X.0, x),
            InputEvent::new(EventType::ABSOLUTE, AbsoluteAxisType::ABS_Y.0, y),
        ])
    }

    /// Press or release a mouse button.
    pub fn pointer_button(&mut self, button: PtrButton, down: bool) -> AgentResult<()> {
        let key = match button {
            PtrButton::Left => Key::BTN_LEFT,
            PtrButton::Right => Key::BTN_RIGHT,
            PtrButton::Middle => Key::BTN_MIDDLE,
        };
        self.emit(&[InputEvent::new(EventType::KEY, key.code(), i32::from(down))])
    }

    /// Scroll the wheel by `dx`/`dy` notch units.
    pub fn scroll(&mut self, dx: i16, dy: i16) -> AgentResult<()> {
        let mut evs = Vec::with_capacity(2);
        if dy != 0 {
            evs.push(InputEvent::new(
                EventType::RELATIVE,
                RelativeAxisType::REL_WHEEL.0,
                i32::from(-dy), // wheel: positive = up, but dy>0 means scroll down
            ));
        }
        if dx != 0 {
            evs.push(InputEvent::new(
                EventType::RELATIVE,
                RelativeAxisType::REL_HWHEEL.0,
                i32::from(dx),
            ));
        }
        if evs.is_empty() {
            return Ok(());
        }
        self.emit(&evs)
    }

    /// Press or release a key by its browser `KeyboardEvent.code`, or the
    /// `"CommandMod"` token (the peer's command modifier → our Ctrl on Linux).
    pub fn key(&mut self, code: &str, down: bool) -> AgentResult<()> {
        let key = if code == "CommandMod" {
            // Linux's "command" modifier (copy/paste/etc.) is Ctrl.
            Key::KEY_LEFTCTRL
        } else {
            match code_to_key(code) {
                Some(k) => k,
                None => {
                    // Don't log the code itself — a stream of keystrokes is
                    // sensitive (never log key content; see project rules).
                    tracing::debug!("uinput: unmapped key code, ignoring");
                    return Ok(());
                },
            }
        };
        self.emit(&[InputEvent::new(EventType::KEY, key.code(), i32::from(down))])
    }

    fn emit(&mut self, events: &[InputEvent]) -> AgentResult<()> {
        // `emit` appends a SYN_REPORT itself, so each call is a complete report.
        self.dev.emit(events).map_err(map_err)
    }
}

/// Map a uinput `io::Error` to an `AgentError`, with an actionable hint when
/// `/dev/uinput` is not writable (the common first-run failure).
// Takes `io::Error` by value so it can be used directly as a `Result::map_err`
// callback (which hands over an owned error).
#[allow(clippy::needless_pass_by_value)]
fn map_err(e: io::Error) -> AgentError {
    if e.kind() == io::ErrorKind::PermissionDenied || e.kind() == io::ErrorKind::NotFound {
        AgentError::Input(
            "cannot open /dev/uinput for remote control. Grant access once with: \
             sudo tee /etc/udev/rules.d/99-rivetlink-uinput.rules <<<'KERNEL==\"uinput\", \
             MODE=\"0660\", GROUP=\"input\"' && sudo udevadm control --reload && \
             sudo udevadm trigger && sudo usermod -aG input \"$USER\"  (then log out/in)"
                .to_string(),
        )
    } else {
        AgentError::Input(format!("uinput: {e}"))
    }
}

/// Map a browser `KeyboardEvent.code` (physical position, layout-independent)
/// to an evdev key. `None` for codes we don't replay.
#[allow(clippy::too_many_lines)] // a flat lookup table — one arm per key
fn code_to_key(code: &str) -> Option<Key> {
    let key = match code {
        // Letters
        "KeyA" => Key::KEY_A,
        "KeyB" => Key::KEY_B,
        "KeyC" => Key::KEY_C,
        "KeyD" => Key::KEY_D,
        "KeyE" => Key::KEY_E,
        "KeyF" => Key::KEY_F,
        "KeyG" => Key::KEY_G,
        "KeyH" => Key::KEY_H,
        "KeyI" => Key::KEY_I,
        "KeyJ" => Key::KEY_J,
        "KeyK" => Key::KEY_K,
        "KeyL" => Key::KEY_L,
        "KeyM" => Key::KEY_M,
        "KeyN" => Key::KEY_N,
        "KeyO" => Key::KEY_O,
        "KeyP" => Key::KEY_P,
        "KeyQ" => Key::KEY_Q,
        "KeyR" => Key::KEY_R,
        "KeyS" => Key::KEY_S,
        "KeyT" => Key::KEY_T,
        "KeyU" => Key::KEY_U,
        "KeyV" => Key::KEY_V,
        "KeyW" => Key::KEY_W,
        "KeyX" => Key::KEY_X,
        "KeyY" => Key::KEY_Y,
        "KeyZ" => Key::KEY_Z,
        // Digit row
        "Digit0" => Key::KEY_0,
        "Digit1" => Key::KEY_1,
        "Digit2" => Key::KEY_2,
        "Digit3" => Key::KEY_3,
        "Digit4" => Key::KEY_4,
        "Digit5" => Key::KEY_5,
        "Digit6" => Key::KEY_6,
        "Digit7" => Key::KEY_7,
        "Digit8" => Key::KEY_8,
        "Digit9" => Key::KEY_9,
        // Function keys
        "F1" => Key::KEY_F1,
        "F2" => Key::KEY_F2,
        "F3" => Key::KEY_F3,
        "F4" => Key::KEY_F4,
        "F5" => Key::KEY_F5,
        "F6" => Key::KEY_F6,
        "F7" => Key::KEY_F7,
        "F8" => Key::KEY_F8,
        "F9" => Key::KEY_F9,
        "F10" => Key::KEY_F10,
        "F11" => Key::KEY_F11,
        "F12" => Key::KEY_F12,
        // Whitespace + editing
        "Enter" => Key::KEY_ENTER,
        "Tab" => Key::KEY_TAB,
        "Space" => Key::KEY_SPACE,
        "Backspace" => Key::KEY_BACKSPACE,
        "Delete" => Key::KEY_DELETE,
        "Escape" => Key::KEY_ESC,
        // Modifiers
        "ShiftLeft" => Key::KEY_LEFTSHIFT,
        "ShiftRight" => Key::KEY_RIGHTSHIFT,
        "ControlLeft" => Key::KEY_LEFTCTRL,
        "ControlRight" => Key::KEY_RIGHTCTRL,
        "AltLeft" => Key::KEY_LEFTALT,
        "AltRight" => Key::KEY_RIGHTALT,
        "MetaLeft" => Key::KEY_LEFTMETA,
        "MetaRight" => Key::KEY_RIGHTMETA,
        "CapsLock" => Key::KEY_CAPSLOCK,
        // Arrows
        "ArrowUp" => Key::KEY_UP,
        "ArrowDown" => Key::KEY_DOWN,
        "ArrowLeft" => Key::KEY_LEFT,
        "ArrowRight" => Key::KEY_RIGHT,
        // Navigation
        "Home" => Key::KEY_HOME,
        "End" => Key::KEY_END,
        "PageUp" => Key::KEY_PAGEUP,
        "PageDown" => Key::KEY_PAGEDOWN,
        "Insert" => Key::KEY_INSERT,
        // Punctuation (US layout)
        "Minus" => Key::KEY_MINUS,
        "Equal" => Key::KEY_EQUAL,
        "BracketLeft" => Key::KEY_LEFTBRACE,
        "BracketRight" => Key::KEY_RIGHTBRACE,
        "Backslash" => Key::KEY_BACKSLASH,
        "Semicolon" => Key::KEY_SEMICOLON,
        "Quote" => Key::KEY_APOSTROPHE,
        "Backquote" => Key::KEY_GRAVE,
        "Comma" => Key::KEY_COMMA,
        "Period" => Key::KEY_DOT,
        "Slash" => Key::KEY_SLASH,
        "IntlBackslash" => Key::KEY_102ND,
        // Numpad
        "Numpad0" => Key::KEY_KP0,
        "Numpad1" => Key::KEY_KP1,
        "Numpad2" => Key::KEY_KP2,
        "Numpad3" => Key::KEY_KP3,
        "Numpad4" => Key::KEY_KP4,
        "Numpad5" => Key::KEY_KP5,
        "Numpad6" => Key::KEY_KP6,
        "Numpad7" => Key::KEY_KP7,
        "Numpad8" => Key::KEY_KP8,
        "Numpad9" => Key::KEY_KP9,
        "NumpadAdd" => Key::KEY_KPPLUS,
        "NumpadSubtract" => Key::KEY_KPMINUS,
        "NumpadMultiply" => Key::KEY_KPASTERISK,
        "NumpadDivide" => Key::KEY_KPSLASH,
        "NumpadDecimal" => Key::KEY_KPDOT,
        "NumpadEnter" => Key::KEY_KPENTER,
        "NumLock" => Key::KEY_NUMLOCK,
        // Misc
        "PrintScreen" => Key::KEY_SYSRQ,
        "ScrollLock" => Key::KEY_SCROLLLOCK,
        "Pause" => Key::KEY_PAUSE,
        "ContextMenu" => Key::KEY_COMPOSE,
        "AudioVolumeUp" => Key::KEY_VOLUMEUP,
        "AudioVolumeDown" => Key::KEY_VOLUMEDOWN,
        "AudioVolumeMute" => Key::KEY_MUTE,
        "MediaPlayPause" => Key::KEY_PLAYPAUSE,
        _ => return None,
    };
    Some(key)
}
