//! Text clipboard bridge for the logged-in GNOME session, via the clipboard
//! API of Mutter's RemoteDesktop session (`EnableClipboard`, `SetSelection`,
//! `SelectionRead`/`SelectionWrite`). No X11 or Wayland client is involved.
//!
//! The bridge owns its own RemoteDesktop session so it is independent of the
//! input injector. It forwards host copies (owner changes not made by us) as
//! text and serves our own selection when a local application pastes.

use std::collections::BTreeMap;
use std::io::{Read, Write};

use futures_util::StreamExt;
use rivetlink_sdk::share::MAX_CLIPBOARD_BYTES;
use tokio::sync::mpsc;
use zbus::zvariant::{OwnedFd, OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, Proxy};

use crate::error::{AgentError, AgentResult};

const RD_DEST: &str = "org.gnome.Mutter.RemoteDesktop";
const RD_PATH: &str = "/org/gnome/Mutter/RemoteDesktop";
const RD_SESSION_IFACE: &str = "org.gnome.Mutter.RemoteDesktop.Session";

/// MIME types we offer for our text, UTF-8 first. The X11 atoms keep Xwayland
/// applications working.
const OFFERED_MIME_TYPES: &[&str] = &[
    "text/plain;charset=utf-8",
    "text/plain",
    "UTF8_STRING",
    "STRING",
    "TEXT",
];
/// MIME types we read from a host copy, in order of preference.
const READ_MIME_TYPES: &[&str] = &["text/plain;charset=utf-8", "UTF8_STRING", "text/plain"];
/// A pasting or copying application that never closes its pipe must not stall
/// the bridge.
const TRANSFER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Handle to a running bridge. Dropping it ends the bridge and its session.
#[derive(Debug)]
pub struct ClipboardBridge {
    set_tx: mpsc::Sender<String>,
    task: tokio::task::JoinHandle<()>,
}

impl ClipboardBridge {
    /// Start the bridge. Host copies are delivered on `changes`.
    pub async fn start(changes: mpsc::Sender<String>) -> AgentResult<Self> {
        let conn = Connection::session().await.map_err(dbus_err)?;
        let rd = Proxy::new(&conn, RD_DEST, RD_PATH, RD_DEST)
            .await
            .map_err(dbus_err)?;
        let path: OwnedObjectPath = rd.call("CreateSession", &()).await.map_err(dbus_err)?;
        let session = Proxy::new(&conn, RD_DEST, path, RD_SESSION_IFACE)
            .await
            .map_err(dbus_err)?;
        let owner_changed = session
            .receive_signal("SelectionOwnerChanged")
            .await
            .map_err(dbus_err)?;
        let transfers = session
            .receive_signal("SelectionTransfer")
            .await
            .map_err(dbus_err)?;
        session
            .call::<_, _, ()>("Start", &())
            .await
            .map_err(dbus_err)?;
        let no_options: BTreeMap<&str, Value> = BTreeMap::new();
        if let Err(error) = session
            .call::<_, _, ()>("EnableClipboard", &(no_options,))
            .await
        {
            let _ = session.call::<_, _, ()>("Stop", &()).await;
            return Err(dbus_err(error));
        }
        tracing::info!("clipboard: Mutter RemoteDesktop clipboard enabled");

        let (set_tx, set_rx) = mpsc::channel(4);
        let task = tokio::spawn(run(session, owner_changed, transfers, set_rx, changes));
        Ok(Self { set_tx, task })
    }

    /// Make `text` the host clipboard content.
    pub async fn set(&self, text: String) -> AgentResult<()> {
        self.set_tx
            .send(text)
            .await
            .map_err(|_| AgentError::Input("clipboard bridge stopped".to_string()))
    }
}

impl Drop for ClipboardBridge {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn run(
    session: Proxy<'static>,
    mut owner_changed: zbus::proxy::SignalStream<'static>,
    mut transfers: zbus::proxy::SignalStream<'static>,
    mut set_rx: mpsc::Receiver<String>,
    changes: mpsc::Sender<String>,
) {
    // The text we currently offer as selection owner, and the last text that
    // crossed the bridge in either direction (to avoid echoing it back).
    let mut offered: Option<String> = None;
    let mut last: Option<String> = None;
    loop {
        tokio::select! {
            text = set_rx.recv() => {
                let Some(text) = text else { break };
                let mut options: BTreeMap<&str, Value> = BTreeMap::new();
                options.insert("mime-types", Value::from(OFFERED_MIME_TYPES.to_vec()));
                match session.call::<_, _, ()>("SetSelection", &(options,)).await {
                    Ok(()) => {
                        last = Some(text.clone());
                        offered = Some(text);
                    },
                    Err(error) => tracing::warn!(error = %error, "clipboard: SetSelection failed"),
                }
            },
            message = transfers.next() => {
                let Some(message) = message else { break };
                let Ok((_mime, serial)) = message.body().deserialize::<(String, u32)>() else {
                    continue;
                };
                serve_transfer(&session, serial, offered.as_deref()).await;
            },
            message = owner_changed.next() => {
                let Some(message) = message else { break };
                let Ok((options,)) = message
                    .body()
                    .deserialize::<(BTreeMap<String, OwnedValue>,)>()
                else {
                    continue;
                };
                let ours = options
                    .get("session-is-owner")
                    .and_then(|value| bool::try_from(value).ok())
                    .unwrap_or(false);
                if ours {
                    continue;
                }
                offered = None;
                let mime_types: Vec<String> = options
                    .get("mime-types")
                    .and_then(|value| value.try_clone().ok())
                    .and_then(|value| Vec::<String>::try_from(value).ok())
                    .unwrap_or_default();
                let Some(mime) = READ_MIME_TYPES
                    .iter()
                    .find(|wanted| mime_types.iter().any(|offered| offered == *wanted))
                else {
                    continue;
                };
                match read_selection(&session, mime).await {
                    Some(text) if last.as_deref() != Some(text.as_str()) => {
                        last = Some(text.clone());
                        if changes.send(text).await.is_err() {
                            break;
                        }
                    },
                    _ => {},
                }
            },
        }
    }
    let _ = session.call::<_, _, ()>("Stop", &()).await;
}

/// A local application pastes our selection: write it into Mutter's pipe.
async fn serve_transfer(session: &Proxy<'_>, serial: u32, offered: Option<&str>) {
    let Some(text) = offered.map(str::to_string) else {
        let _ = session
            .call::<_, _, ()>("SelectionWriteDone", &(serial, false))
            .await;
        return;
    };
    let ok = match session
        .call::<_, _, OwnedFd>("SelectionWrite", &(serial,))
        .await
    {
        Ok(fd) => {
            let write = tokio::task::spawn_blocking(move || {
                let mut file = std::fs::File::from(std::os::fd::OwnedFd::from(fd));
                file.write_all(text.as_bytes())
            });
            matches!(
                tokio::time::timeout(TRANSFER_TIMEOUT, write).await,
                Ok(Ok(Ok(())))
            )
        },
        Err(error) => {
            tracing::debug!(error = %error, "clipboard: SelectionWrite failed");
            false
        },
    };
    let _ = session
        .call::<_, _, ()>("SelectionWriteDone", &(serial, ok))
        .await;
}

/// Read the current host selection as UTF-8 text, bounded in size and time.
async fn read_selection(session: &Proxy<'_>, mime: &str) -> Option<String> {
    let fd: OwnedFd = session.call("SelectionRead", &(mime,)).await.ok()?;
    let read = tokio::task::spawn_blocking(move || {
        let file = std::fs::File::from(std::os::fd::OwnedFd::from(fd));
        let mut bytes = Vec::new();
        file.take(MAX_CLIPBOARD_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        (bytes.len() <= MAX_CLIPBOARD_BYTES).then_some(bytes)
    });
    let bytes = tokio::time::timeout(TRANSFER_TIMEOUT, read)
        .await
        .ok()?
        .ok()??;
    String::from_utf8(bytes)
        .ok()
        .filter(|text| !text.is_empty())
}

fn dbus_err(error: impl std::fmt::Display) -> AgentError {
    AgentError::Input(format!("Mutter clipboard D-Bus error: {error}"))
}
