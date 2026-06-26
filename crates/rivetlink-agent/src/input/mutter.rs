//! Linux remote-input injection via GNOME **Mutter RemoteDesktop** (D-Bus).
//!
//! No kernel device, no `/dev/uinput`, no udev rule, no root — Mutter injects
//! the events itself (the same dialog-free path family as our ScreenCast
//! capture). For absolute pointer positioning Mutter needs a ScreenCast *stream*
//! to define the coordinate space, so we open our own RemoteDesktop session with
//! a bound ScreenCast of the shared monitor. We never consume that stream's
//! PipeWire node — it exists only to anchor the coordinates.
//!
//! GNOME/Mutter only; other compositors get no remote input.

use std::collections::BTreeMap;
use std::sync::mpsc;
use std::thread;

use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{OwnedObjectPath, Str, Value};

use rivetlink_sdk::lan::PtrButton;

use crate::error::{AgentError, AgentResult};

const RD_DEST: &str = "org.gnome.Mutter.RemoteDesktop";
const RD_PATH: &str = "/org/gnome/Mutter/RemoteDesktop";
const RD_SESSION_IFACE: &str = "org.gnome.Mutter.RemoteDesktop.Session";
const SC_DEST: &str = "org.gnome.Mutter.ScreenCast";
const SC_PATH: &str = "/org/gnome/Mutter/ScreenCast";
const SC_SESSION_IFACE: &str = "org.gnome.Mutter.ScreenCast.Session";

/// One remote input event to replay locally.
#[derive(Debug)]
pub enum InputAction {
    /// Absolute cursor position, normalized `0..=10_000` of the frame.
    Move { x: u16, y: u16 },
    Button { button: PtrButton, down: bool },
    Scroll { dx: i16, dy: i16 },
    Key { code: String, down: bool },
}

/// Handle to the dedicated injection thread. Sending is non-blocking; dropping
/// the handle stops the thread, which tears down its Mutter session.
#[derive(Debug)]
pub struct InputHandle {
    tx: mpsc::Sender<InputAction>,
}

impl InputHandle {
    /// Spawn the injector for the monitor at index `display` (`None` = primary).
    /// The thread sets up the Mutter session once, then replays actions until the
    /// handle drops. Cheap to call — real setup failures surface in its logs.
    pub fn spawn(display: Option<u32>) -> Self {
        let (tx, rx) = mpsc::channel::<InputAction>();
        thread::spawn(move || run(display, &rx));
        Self { tx }
    }

    /// Queue an action. Dropped silently if the injector thread is gone.
    pub fn send(&self, action: InputAction) {
        let _ = self.tx.send(action);
    }
}

/// Injector thread body: build the session, then drain actions until the handle
/// (and thus the channel) is dropped.
fn run(display: Option<u32>, rx: &mpsc::Receiver<InputAction>) {
    let injector = match MutterInjector::new(display) {
        Ok(inj) => inj,
        Err(e) => {
            tracing::warn!(error = %e, "remote control: Mutter RemoteDesktop unavailable");
            return;
        },
    };
    tracing::info!("remote control: Mutter RemoteDesktop session ready");
    while let Ok(action) = rx.recv() {
        if let Err(e) = injector.apply(&action) {
            tracing::debug!(error = %e, "remote control: inject failed");
        }
    }
}

/// A live Mutter RemoteDesktop session (+ a bound ScreenCast stream that anchors
/// absolute coordinates). Dropping it stops the session.
struct MutterInjector {
    conn: Connection,
    rd_session: OwnedObjectPath,
    /// The ScreenCast stream object path, as a string (Mutter's
    /// `NotifyPointerMotionAbsolute` takes it by `s`).
    stream: String,
    width: f64,
    height: f64,
}

impl MutterInjector {
    fn new(display: Option<u32>) -> AgentResult<Self> {
        let (connector, w, h) = crate::capture::mutter::monitor_target(display)
            .ok_or_else(|| AgentError::Input("no monitor available to control".to_string()))?;
        let conn = Connection::session().map_err(dbus_err)?;

        // 1. RemoteDesktop session + its id.
        let rd = Proxy::new(&conn, RD_DEST, RD_PATH, RD_DEST).map_err(dbus_err)?;
        let rd_session: OwnedObjectPath = rd.call("CreateSession", &()).map_err(dbus_err)?;
        let rd_sess = Proxy::new(&conn, RD_DEST, rd_session.clone(), RD_SESSION_IFACE)
            .map_err(dbus_err)?;
        let session_id: String = rd_sess.get_property("SessionId").map_err(dbus_err)?;

        // 2. ScreenCast session bound to it (anchors absolute coords). We never
        //    consume its PipeWire node — capture has its own session.
        let sc = Proxy::new(&conn, SC_DEST, SC_PATH, SC_DEST).map_err(dbus_err)?;
        let mut sc_opts: BTreeMap<&str, Value> = BTreeMap::new();
        sc_opts.insert("remote-desktop-session-id", Value::Str(Str::from(session_id)));
        let sc_session: OwnedObjectPath =
            sc.call("CreateSession", &(sc_opts,)).map_err(dbus_err)?;
        let sc_sess = Proxy::new(&conn, SC_DEST, sc_session, SC_SESSION_IFACE).map_err(dbus_err)?;
        let rec_opts: BTreeMap<&str, Value> = BTreeMap::new();
        let stream_path: OwnedObjectPath = sc_sess
            .call("RecordMonitor", &(connector.as_str(), rec_opts))
            .map_err(dbus_err)?;

        // 3. Start — binds the cast to the remote-desktop session.
        rd_sess.call::<_, _, ()>("Start", &()).map_err(dbus_err)?;

        Ok(Self {
            conn,
            rd_session,
            stream: stream_path.as_str().to_owned(),
            width: f64::from(w.max(1)),
            height: f64::from(h.max(1)),
        })
    }

    fn session(&self) -> AgentResult<Proxy<'_>> {
        Proxy::new(&self.conn, RD_DEST, self.rd_session.clone(), RD_SESSION_IFACE).map_err(dbus_err)
    }

    fn apply(&self, action: &InputAction) -> AgentResult<()> {
        let s = self.session()?;
        match action {
            InputAction::Move { x, y } => {
                let px = f64::from(*x) / 10_000.0 * self.width;
                let py = f64::from(*y) / 10_000.0 * self.height;
                s.call::<_, _, ()>("NotifyPointerMotionAbsolute", &(self.stream.as_str(), px, py))
                    .map_err(dbus_err)
            },
            InputAction::Button { button, down } => s
                .call::<_, _, ()>("NotifyPointerButton", &(button_code(*button), *down))
                .map_err(dbus_err),
            InputAction::Scroll { dx, dy } => {
                // Discrete wheel notches: axis 0 = vertical, 1 = horizontal.
                if *dy != 0 {
                    s.call::<_, _, ()>("NotifyPointerAxisDiscrete", &(0u32, i32::from(*dy)))
                        .map_err(dbus_err)?;
                }
                if *dx != 0 {
                    s.call::<_, _, ()>("NotifyPointerAxisDiscrete", &(1u32, i32::from(*dx)))
                        .map_err(dbus_err)?;
                }
                Ok(())
            },
            InputAction::Key { code, down } => {
                let Some(keycode) = key_code(code) else {
                    // Don't log the code — a stream of keystrokes is sensitive.
                    tracing::debug!("remote control: unmapped key, ignoring");
                    return Ok(());
                };
                s.call::<_, _, ()>("NotifyKeyboardKeycode", &(keycode, *down))
                    .map_err(dbus_err)
            },
        }
    }
}

impl Drop for MutterInjector {
    fn drop(&mut self) {
        if let Ok(s) = self.session() {
            let _ = s.call::<_, _, ()>("Stop", &());
        }
    }
}

/// evdev `BTN_*` codes — what `NotifyPointerButton` expects.
fn button_code(b: PtrButton) -> i32 {
    match b {
        PtrButton::Left => 0x110,   // BTN_LEFT
        PtrButton::Right => 0x111,  // BTN_RIGHT
        PtrButton::Middle => 0x112, // BTN_MIDDLE
    }
}

/// Map a browser `KeyboardEvent.code` (or the `"CommandMod"` token) to an evdev
/// keycode for `NotifyKeyboardKeycode`. `None` for codes we don't replay.
fn key_code(code: &str) -> Option<u32> {
    if code == "CommandMod" {
        return Some(29); // KEY_LEFTCTRL — Linux's command modifier (copy/paste)
    }
    code_to_key(code).map(|k| u32::from(k.code()))
}

/// Map a browser `KeyboardEvent.code` (physical position, layout-independent)
/// to an evdev key. `None` for codes we don't replay.
#[allow(clippy::too_many_lines)] // a flat lookup table — one arm per key
fn code_to_key(code: &str) -> Option<evdev::Key> {
    use evdev::Key;
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

fn dbus_err(e: impl std::fmt::Display) -> AgentError {
    AgentError::Input(format!("Mutter RemoteDesktop D-Bus error: {e}"))
}
