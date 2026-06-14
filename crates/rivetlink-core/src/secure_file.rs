//! Helpers for writing secret material (private keys, tokens) to disk safely.
//!
//! Secrets must not land in world- or group-readable files. On Unix these
//! helpers create the file with mode `0o600` and parent directories with
//! `0o700` before any bytes are written. On non-Unix platforms they fall back
//! to a plain write (filesystem ACLs are the operator's responsibility there).

use std::io;
use std::path::Path;

/// Create `path`'s parent directory tree, restricting it to the owner on Unix.
fn create_parent_dirs(path: &Path) -> io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(parent)
    }
}

/// Write `contents` to `path` as an owner-only secret file.
///
/// Creates parent directories as needed. On Unix the file is opened with mode
/// `0o600` (and truncated if it exists); on other platforms it falls back to a
/// plain overwrite.
pub fn write_secret(path: &Path, contents: &[u8]) -> io::Result<()> {
    create_parent_dirs(path)?;

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(contents)?;
        file.flush()
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("rivet-secure-{}-{name}", uuid::Uuid::now_v7().simple()));
        p
    }

    #[test]
    fn writes_contents() {
        let dir = tmp("dir");
        let path = dir.join("nested").join("secret.json");
        write_secret(&path, b"hunter2").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"hunter2");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn overwrites_existing() {
        let path = tmp("overwrite");
        write_secret(&path, b"old").unwrap();
        write_secret(&path, b"new").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = tmp("perms");
        write_secret(&path, b"secret").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "secret file must be 0o600");
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn parent_dir_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("parentperms");
        let path = dir.join("k.json");
        write_secret(&path, b"x").unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "secret dir must be 0o700");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
