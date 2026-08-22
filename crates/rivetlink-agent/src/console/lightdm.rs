//! Narrow LightDM X11 greeter-worker lifecycle.
//!
//! LightDM runs its configured greeter as the dedicated `lightdm` account, not
//! as a systemd user service. Its root-owned `greeter-setup-script` therefore
//! starts this small launcher. The launcher discovers the already running
//! greeter's local X11/Xauthority environment and starts *only* the normal
//! `console-worker` as `lightdm`. Root is never used to capture frames or
//! inject input, and no remote client can invoke this local-only command.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::{AgentError, AgentResult};

const LIGHTDM_USER: &str = "lightdm";
const WORKER_SOCKET: &str = "/run/rivetlink/console.sock";
const WORKER_PID: &str = "/run/rivetlink/lightdm-worker.pid";
const FIND_GREETER_TIMEOUT: Duration = Duration::from_secs(20);
const FIND_GREETER_INTERVAL: Duration = Duration::from_millis(200);

/// Spawn a detached, fixed watcher from LightDM's root hook.
#[allow(clippy::disallowed_methods)] // LightDM supplies this fixed hook environment.
pub fn start() -> AgentResult<()> {
    require_root()?;
    let display = std::env::var("DISPLAY")
        .ok()
        .filter(|value| is_local_x11_display(value))
        .ok_or_else(|| AgentError::Config("LightDM did not provide a local X11 DISPLAY".into()))?;
    let executable = std::env::current_exe()
        .map_err(|error| AgentError::Config(format!("locate RivetLink agent: {error}")))?;
    let child = Command::new(executable)
        .args(["console-lightdm-greeter-watch", "--display", &display])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| AgentError::Config(format!("start LightDM worker watcher: {error}")))?;
    // Do not wait: LightDM serially waits for this hook, while the watcher must
    // wait for the greeter's per-user Xauthority environment to exist.
    drop(child);
    Ok(())
}

/// Discover the exact LightDM greeter process for one local display and start
/// the ordinary unprivileged worker with only its required X11 environment.
pub fn watch(display: &str) -> AgentResult<()> {
    require_root()?;
    if !is_local_x11_display(display) {
        return Err(AgentError::Config("invalid LightDM X11 display".into()));
    }
    let deadline = Instant::now() + FIND_GREETER_TIMEOUT;
    loop {
        if let Some(authority) = find_lightdm_greeter_authority(display)? {
            stop()?;
            let pid = spawn_worker(display, &authority)?;
            write_worker_pid(pid)?;
            tracing::info!("started unprivileged LightDM X11 console worker");
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(AgentError::Config(
                "LightDM greeter did not expose an authorized local X11 session".into(),
            ));
        }
        thread::sleep(FIND_GREETER_INTERVAL);
    }
}

/// Stop only the PID previously created by [`watch`]. A stale or substituted
/// PID is rejected by UID and command-line checks before any signal is sent.
pub fn stop() -> AgentResult<()> {
    require_root()?;
    let path = Path::new(WORKER_PID);
    let pid = match fs::read_to_string(path) {
        Ok(value) => value
            .trim()
            .parse::<i32>()
            .map_err(|_| AgentError::Config("invalid LightDM worker PID file".into()))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(AgentError::Config(format!(
                "read LightDM worker PID file: {error}"
            )))
        },
    };
    if pid > 1 && is_our_lightdm_worker(pid)? {
        let status = Command::new("/usr/bin/kill")
            .args(["-TERM", &pid.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| AgentError::Config(format!("stop LightDM worker: {error}")))?;
        if !status.success() && Path::new(&format!("/proc/{pid}")).exists() {
            return Err(AgentError::Config("stop LightDM worker failed".into()));
        }
    }
    fs::remove_file(path)
        .or_else(ignore_not_found)
        .map_err(|error| AgentError::Config(format!("remove LightDM worker PID file: {error}")))
}

fn ignore_not_found(error: std::io::Error) -> Result<(), std::io::Error> {
    if error.kind() == std::io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(error)
    }
}

fn find_lightdm_greeter_authority(display: &str) -> AgentResult<Option<PathBuf>> {
    let lightdm_uid = account_id("-u")?;
    for entry in fs::read_dir("/proc")
        .map_err(|error| AgentError::Config(format!("inspect processes: {error}")))?
    {
        let Ok(entry) = entry else { continue };
        let Ok(_pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let proc_root = entry.path();
        let Ok(status) = fs::read_to_string(proc_root.join("status")) else {
            continue;
        };
        if process_real_uid(&status) != Some(lightdm_uid) {
            continue;
        }
        let Ok(environment) = read_process_environment(&proc_root.join("environ")) else {
            continue;
        };
        if environment
            .get("DISPLAY")
            .is_none_or(|candidate| candidate != display)
            || environment
                .get("XDG_SESSION_CLASS")
                .is_none_or(|class| class != "greeter")
        {
            continue;
        }
        let Some(authority) = environment.get("XAUTHORITY") else {
            continue;
        };
        let authority = PathBuf::from(authority);
        if valid_lightdm_authority(&authority, lightdm_uid) {
            return Ok(Some(authority));
        }
    }
    Ok(None)
}

fn spawn_worker(display: &str, authority: &Path) -> AgentResult<u32> {
    let executable = std::env::current_exe()
        .map_err(|error| AgentError::Config(format!("locate RivetLink agent: {error}")))?;
    // `runuser` (not a shell) resets uid, gid, and supplementary groups for
    // LightDM. The capture/input process is consequently never privileged.
    let child = Command::new("/usr/sbin/runuser")
        .args(["--user", LIGHTDM_USER, "--"])
        .arg(&executable)
        .args(["console-worker", "--socket", WORKER_SOCKET])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("DISPLAY", display)
        .env("XAUTHORITY", authority)
        .env("XDG_SESSION_CLASS", "greeter")
        .env("USER", LIGHTDM_USER)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| AgentError::Config(format!("start LightDM console worker: {error}")))?;
    Ok(child.id())
}

fn write_worker_pid(pid: u32) -> AgentResult<()> {
    let path = Path::new(WORKER_PID);
    let parent = path
        .parent()
        .ok_or_else(|| AgentError::Config("invalid LightDM worker PID path".into()))?;
    if !parent.is_dir() {
        return Err(AgentError::Config(
            "RivetLink runtime directory is unavailable".into(),
        ));
    }
    let temporary = path.with_extension("next");
    fs::write(&temporary, pid.to_string())
        .map_err(|error| AgentError::Config(format!("write LightDM worker PID: {error}")))?;
    fs::rename(&temporary, path)
        .map_err(|error| AgentError::Config(format!("activate LightDM worker PID: {error}")))?;
    Ok(())
}

fn is_our_lightdm_worker(pid: i32) -> AgentResult<bool> {
    let proc_root = PathBuf::from(format!("/proc/{pid}"));
    let status = match fs::read_to_string(proc_root.join("status")) {
        Ok(status) => status,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(AgentError::Config(format!(
                "inspect LightDM worker: {error}"
            )))
        },
    };
    if process_real_uid(&status) != Some(account_id("-u")?) {
        return Ok(false);
    }
    let cmdline = fs::read(proc_root.join("cmdline"))
        .map_err(|error| AgentError::Config(format!("inspect LightDM worker command: {error}")))?;
    let words = cmdline
        .split(|byte| *byte == 0)
        .filter_map(|word| std::str::from_utf8(word).ok())
        .collect::<Vec<_>>();
    Ok(words.iter().any(|word| word.ends_with("rivet-agent"))
        && words.contains(&"console-worker")
        && words.contains(&"--socket")
        && words.contains(&WORKER_SOCKET))
}

fn account_id(flag: &str) -> AgentResult<u32> {
    let output = Command::new("/usr/bin/id")
        .args([flag, LIGHTDM_USER])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|error| AgentError::Config(format!("look up LightDM account: {error}")))?;
    if !output.status.success() {
        return Err(AgentError::Config("LightDM account is unavailable".into()));
    }
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .map_err(|_| AgentError::Config("invalid LightDM account UID".into()))
}

fn read_process_environment(path: &Path) -> std::io::Result<BTreeMap<String, String>> {
    let bytes = fs::read(path)?;
    Ok(bytes
        .split(|byte| *byte == 0)
        .filter_map(|entry| std::str::from_utf8(entry).ok())
        .filter_map(|entry| entry.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect())
}

fn process_real_uid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn valid_lightdm_authority(path: &Path, lightdm_uid: u32) -> bool {
    path.is_absolute()
        && path.is_file()
        && fs::metadata(path)
            .is_ok_and(|metadata| metadata.uid() == lightdm_uid && metadata.mode() & 0o022 == 0)
}

fn is_local_x11_display(display: &str) -> bool {
    let Some(number) = display.strip_prefix(':') else {
        return false;
    };
    let (screen, suffix) = number.split_once('.').unwrap_or((number, ""));
    !screen.is_empty()
        && screen.bytes().all(|byte| byte.is_ascii_digit())
        && (suffix.is_empty() || suffix.bytes().all(|byte| byte.is_ascii_digit()))
}

fn require_root() -> AgentResult<()> {
    let uid = Command::new("/usr/bin/id")
        .arg("-u")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|error| AgentError::Config(format!("check LightDM hook identity: {error}")))?;
    if uid.status.success() && String::from_utf8_lossy(&uid.stdout).trim() == "0" {
        Ok(())
    } else {
        Err(AgentError::Config(
            "LightDM greeter integration must be started by LightDM's root hook".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_local_x11_display_syntax() {
        assert!(is_local_x11_display(":0"));
        assert!(is_local_x11_display(":1.0"));
        assert!(!is_local_x11_display("localhost:0"));
        assert!(!is_local_x11_display("tcp/host:0"));
        assert!(!is_local_x11_display(":abc"));
    }

    #[test]
    fn extracts_the_real_uid_only() {
        assert_eq!(
            process_real_uid("Name:\tfoo\nUid:\t110\t110\t110\t110\n"),
            Some(110)
        );
        assert_eq!(process_real_uid("Name:\tfoo\n"), None);
    }
}
