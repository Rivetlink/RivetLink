//! Clipboard and file sharing over an established LAN stream.
//!
//! Both ends share these limits and the relative-path rules, so a client never
//! builds a request the host would reject and the host validates everything it
//! receives independently.

/// Feature token a host lists in [`crate::lan::LanResponse::Displays`] when the
/// connected client may share text clipboard contents.
pub const FEATURE_CLIPBOARD: &str = "clipboard";
/// Feature token for file/folder transfer in both directions.
pub const FEATURE_FILES: &str = "files";

/// Largest clipboard text exchanged in one message (UTF-8 bytes).
pub const MAX_CLIPBOARD_BYTES: usize = 256 * 1024;
/// Raw bytes per file chunk. Base64 grows this by a third, which stays well
/// inside both the sealed LAN frame limit and the host's local IPC limit.
pub const FILE_CHUNK_BYTES: usize = 192 * 1024;
/// Largest single file accepted in either direction.
pub const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
/// Longest relative path (bytes) and deepest folder nesting accepted.
pub const MAX_PATH_BYTES: usize = 1024;
pub const MAX_PATH_DEPTH: usize = 32;

/// One entry in the host's shared folder.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SharedEntry {
    /// Path relative to the shared folder, `/`-separated.
    pub path: String,
    /// File size in bytes (0 for folders).
    pub size: u64,
    pub dir: bool,
}

/// Validate a `/`-separated path relative to a shared folder and return its
/// components. Rejects anything that could leave the folder or that a common
/// filesystem cannot represent: absolute paths, `.`/`..`, empty components,
/// backslashes, control characters, and over-long or over-deep paths.
pub fn relative_components(path: &str) -> Option<Vec<&str>> {
    if path.is_empty() || path.len() > MAX_PATH_BYTES || path.starts_with('/') {
        return None;
    }
    let components: Vec<&str> = path.split('/').collect();
    if components.len() > MAX_PATH_DEPTH {
        return None;
    }
    let valid = components.iter().all(|part| {
        !part.is_empty()
            && *part != "."
            && *part != ".."
            && part.len() <= 255
            && !part
                .chars()
                .any(|c| c.is_control() || c == '\\' || c == ':')
    });
    valid.then_some(components)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_nested_paths() {
        assert_eq!(relative_components("a.txt"), Some(vec!["a.txt"]));
        assert_eq!(
            relative_components("Photos/2026/img 1.jpg"),
            Some(vec!["Photos", "2026", "img 1.jpg"])
        );
    }

    #[test]
    fn rejects_paths_that_could_escape_or_confuse_the_folder() {
        for bad in [
            "",
            "/etc/passwd",
            "../secret",
            "a/../../b",
            "a/./b",
            "a//b",
            "a/",
            "C:\\Windows",
            "a\\..\\b",
            "c:evil",
            "line\nbreak",
            "nul\0byte",
        ] {
            assert_eq!(relative_components(bad), None, "{bad:?} must be rejected");
        }
    }

    #[test]
    fn rejects_overlong_and_overdeep_paths() {
        assert_eq!(relative_components(&"a".repeat(256)), None);
        let too_deep = format!("{}f", "d/".repeat(MAX_PATH_DEPTH));
        assert_eq!(relative_components(&too_deep), None);
    }
}
