//! Hosts known to speak the hybrid post-quantum direct-LAN handshake.
//!
//! Once a host completed a hybrid handshake, a later connection to it must
//! not fall back to the classical one: a network attacker could otherwise
//! force the downgrade by closing the connection. The set holds the hosts'
//! public identity keys (not secrets), one base64 key per line.
//!
//! Without [`use_store`] the set lives in memory for the process lifetime.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::error::SdkResult;

struct Pins {
    path: Option<PathBuf>,
    hosts: BTreeSet<String>,
    /// The store exists but could not be read. Which hosts were pinned is
    /// then unknown, so every key-mode downgrade is refused (fail closed).
    unreadable: bool,
}

impl Pins {
    fn refuses_downgrade(&self, host_b64: &str) -> Option<&'static str> {
        if self.unreadable {
            Some("the post-quantum host pin file could not be read; refusing a downgrade until it is fixed")
        } else if self.hosts.contains(host_b64) {
            Some("host previously supported post-quantum encryption; refusing a downgrade")
        } else {
            None
        }
    }
}

static PINS: Mutex<Pins> = Mutex::new(Pins {
    path: None,
    hosts: BTreeSet::new(),
    unreadable: false,
});
/// Serializes file writes so the newest set always lands last.
static SAVE: Mutex<()> = Mutex::new(());

fn pins() -> MutexGuard<'static, Pins> {
    PINS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Persist the set at `path`, loading what is already there. Call once at
/// startup, outside async code (it reads the file synchronously). A missing
/// file is an empty set. On a read error the file is left alone and every
/// key-mode downgrade is refused until it reads again.
pub fn use_store(path: PathBuf) -> SdkResult<()> {
    let loaded = load(&path);
    let mut pins = pins();
    match loaded {
        Ok(hosts) => {
            pins.hosts.extend(hosts);
            pins.path = Some(path);
            Ok(())
        },
        Err(e) => {
            pins.unreadable = true;
            Err(e)
        },
    }
}

fn load(path: &Path) -> SdkResult<BTreeSet<String>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e.into()),
    };
    // Lossy: a damaged line costs that one pin, not the whole set.
    Ok(String::from_utf8_lossy(&bytes)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect())
}

/// Write-then-rename, synced first so a power cut cannot leave an empty file.
fn save(path: &Path, hosts: &BTreeSet<String>) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut file = std::fs::File::create(&tmp)?;
    for host in hosts {
        writeln!(file, "{host}")?;
    }
    file.sync_all()?;
    std::fs::rename(&tmp, path)
}

/// Why a classical retry to `host_b64` must be refused, if it must.
pub(crate) fn refuses_downgrade(host_b64: &str) -> Option<&'static str> {
    pins().refuses_downgrade(host_b64)
}

/// Record that `host_b64` completed a hybrid handshake. Must run inside a
/// Tokio runtime when a store is set; the write happens off the async thread.
pub(crate) fn remember(host_b64: String) {
    {
        let mut guard = pins();
        if !guard.hosts.insert(host_b64) || guard.path.is_none() {
            return;
        }
    }
    tokio::task::spawn_blocking(|| {
        let _guard = SAVE.lock().unwrap_or_else(PoisonError::into_inner);
        let (path, hosts) = {
            let pins = pins();
            let Some(path) = pins.path.clone() else {
                return;
            };
            (path, pins.hosts.clone())
        };
        if let Err(e) = save(&path, &hosts) {
            tracing::warn!(error = %e, "could not save post-quantum host pins");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_pins_load_back_and_damage_is_contained() {
        let dir =
            std::env::temp_dir().join(format!("rl-pq-pins-{}", uuid::Uuid::now_v7().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pq_hosts");
        assert!(load(&path).unwrap().is_empty());

        let hosts: BTreeSet<String> = ["host-a", "host-b"].map(str::to_string).into();
        save(&path, &hosts).unwrap();
        assert_eq!(load(&path).unwrap(), hosts);

        std::fs::write(&path, b"host-a\n\xff\xfe\nhost-b\n").unwrap();
        let loaded = load(&path).unwrap();
        assert!(loaded.contains("host-a") && loaded.contains("host-b"));

        // A store that exists but cannot be read (here: a directory) fails
        // closed for every host, pinned or not.
        assert!(load(&dir).is_err());
        let pins = Pins {
            path: None,
            hosts: BTreeSet::new(),
            unreadable: true,
        };
        assert!(pins.refuses_downgrade("any-host").is_some());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
