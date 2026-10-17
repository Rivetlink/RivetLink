//! The one folder a controlling client may read from and write to.
//!
//! Uploads land in `~/Downloads/RivetLink` of the logged-in user and downloads
//! are served only from there. Every path is validated with
//! [`rivetlink_sdk::share::relative_components`] and resolved one component at
//! a time without following symlinks, so a request can never reach outside the
//! folder. Uploads are written to a hidden `.part` file and renamed into place
//! on completion, never overwriting an existing file.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use rivetlink_sdk::share::{self, SharedEntry, FILE_CHUNK_BYTES, MAX_FILE_BYTES};

/// Simultaneous uploads per worker; a client uploads files one after another.
const MAX_OPEN_UPLOADS: usize = 4;
/// Listing stops after this many entries so a huge folder stays responsive.
const MAX_LISTED_ENTRIES: usize = 5_000;
const PART_SUFFIX: &str = ".rivetlink-part";

/// Why a shared-folder operation failed. Messages are safe to show the client:
/// they never contain host paths or account names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareError {
    /// The path, size or upload id is not acceptable.
    Rejected,
    /// The filesystem refused (disk full, permission, vanished file).
    Io,
}

impl ShareError {
    pub fn message(self) -> &'static str {
        match self {
            Self::Rejected => "the host rejected this file path or size",
            Self::Io => "the host could not read or write the shared folder",
        }
    }
}

type ShareResult<T> = Result<T, ShareError>;

impl From<std::io::Error> for ShareError {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}

#[derive(Debug)]
struct Upload {
    dir: PathBuf,
    name: String,
    part: PathBuf,
    file: File,
    expected: u64,
    written: u64,
}

#[derive(Debug)]
pub struct SharedFolder {
    root: PathBuf,
    uploads: BTreeMap<u32, Upload>,
}

impl SharedFolder {
    /// `~/Downloads/RivetLink` of the user this worker runs as.
    pub fn for_current_user() -> Option<Self> {
        let home = std::env::var_os("HOME").filter(|home| !home.is_empty())?;
        Some(Self::at(
            Path::new(&home).join("Downloads").join("RivetLink"),
        ))
    }

    pub fn at(root: PathBuf) -> Self {
        Self {
            root,
            uploads: BTreeMap::new(),
        }
    }

    fn ensure_root(&self) -> ShareResult<()> {
        fs::create_dir_all(&self.root)?;
        if fs::symlink_metadata(&self.root)?.file_type().is_symlink() {
            return Err(ShareError::Rejected);
        }
        Ok(())
    }

    /// Resolve the folders of `components` under the root, optionally creating
    /// them. Any existing component that is a symlink or a file is rejected.
    fn resolve_dirs(&self, components: &[&str], create: bool) -> ShareResult<PathBuf> {
        let mut dir = self.root.clone();
        for component in components {
            dir.push(component);
            match fs::symlink_metadata(&dir) {
                Ok(meta) if meta.is_dir() => {},
                Ok(_) => return Err(ShareError::Rejected),
                Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                    fs::create_dir(&dir)?;
                },
                Err(_) => return Err(ShareError::Rejected),
            }
        }
        Ok(dir)
    }

    pub fn start_upload(&mut self, id: u32, path: &str, size: u64) -> ShareResult<()> {
        let components = share::relative_components(path).ok_or(ShareError::Rejected)?;
        let (name, folders) = components.split_last().ok_or(ShareError::Rejected)?;
        if size > MAX_FILE_BYTES
            || name.ends_with(PART_SUFFIX)
            || self.uploads.contains_key(&id)
            || self.uploads.len() >= MAX_OPEN_UPLOADS
        {
            return Err(ShareError::Rejected);
        }
        self.ensure_root()?;
        let dir = self.resolve_dirs(folders, true)?;
        let part = dir.join(format!(".{name}.{id}{PART_SUFFIX}"));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&part)?;
        self.uploads.insert(
            id,
            Upload {
                dir,
                name: (*name).to_string(),
                part,
                file,
                expected: size,
                written: 0,
            },
        );
        Ok(())
    }

    pub fn write_chunk(&mut self, id: u32, data: &[u8]) -> ShareResult<()> {
        let upload = self.uploads.get_mut(&id).ok_or(ShareError::Rejected)?;
        let length = u64::try_from(data.len()).map_err(|_| ShareError::Rejected)?;
        if data.len() > FILE_CHUNK_BYTES || upload.written + length > upload.expected {
            self.abort_upload(id);
            return Err(ShareError::Rejected);
        }
        if let Err(error) = upload.file.write_all(data) {
            self.abort_upload(id);
            return Err(error.into());
        }
        upload.written += length;
        Ok(())
    }

    /// Complete an upload and return its final path relative to the folder.
    pub fn finish_upload(&mut self, id: u32) -> ShareResult<String> {
        let upload = self.uploads.remove(&id).ok_or(ShareError::Rejected)?;
        if upload.written != upload.expected {
            let _ = fs::remove_file(&upload.part);
            return Err(ShareError::Rejected);
        }
        upload.file.sync_all()?;
        let name = unused_name(&upload.dir, &upload.name).ok_or(ShareError::Io)?;
        fs::rename(&upload.part, upload.dir.join(&name))?;
        let relative = upload
            .dir
            .strip_prefix(&self.root)
            .map_err(|_| ShareError::Io)?
            .join(&name);
        Ok(relative
            .components()
            .map(|part| part.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/"))
    }

    pub fn abort_upload(&mut self, id: u32) {
        if let Some(upload) = self.uploads.remove(&id) {
            let _ = fs::remove_file(&upload.part);
        }
    }

    /// Every folder and regular file below the root, sorted, without symlinks
    /// or unfinished uploads.
    pub fn list(&self) -> ShareResult<Vec<SharedEntry>> {
        self.ensure_root()?;
        let mut entries = Vec::new();
        let mut pending = vec![(self.root.clone(), String::new(), 0_usize)];
        while let Some((dir, prefix, depth)) = pending.pop() {
            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                    continue;
                };
                if name.ends_with(PART_SUFFIX) {
                    continue;
                }
                let meta = entry.metadata()?;
                let file_type = entry.file_type()?;
                let path = if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                };
                if file_type.is_dir() {
                    if depth + 1 < share::MAX_PATH_DEPTH {
                        pending.push((entry.path(), path.clone(), depth + 1));
                    }
                    entries.push(SharedEntry {
                        path,
                        size: 0,
                        dir: true,
                    });
                } else if file_type.is_file() {
                    entries.push(SharedEntry {
                        path,
                        size: meta.len(),
                        dir: false,
                    });
                }
                if entries.len() >= MAX_LISTED_ENTRIES {
                    entries.sort_by(|a, b| a.path.cmp(&b.path));
                    return Ok(entries);
                }
            }
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(entries)
    }

    /// Read up to [`FILE_CHUNK_BYTES`] at `offset`. Returns the data, the full
    /// file size and whether this chunk reaches the end.
    pub fn read_chunk(&self, path: &str, offset: u64) -> ShareResult<(Vec<u8>, u64, bool)> {
        let components = share::relative_components(path).ok_or(ShareError::Rejected)?;
        let (name, folders) = components.split_last().ok_or(ShareError::Rejected)?;
        let file_path = self.resolve_dirs(folders, false)?.join(name);
        let meta = fs::symlink_metadata(&file_path).map_err(|_| ShareError::Rejected)?;
        if !meta.is_file() || name.ends_with(PART_SUFFIX) {
            return Err(ShareError::Rejected);
        }
        let size = meta.len();
        if size > MAX_FILE_BYTES || offset > size {
            return Err(ShareError::Rejected);
        }
        let mut file = File::open(&file_path)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut data = Vec::with_capacity(FILE_CHUNK_BYTES);
        file.take(FILE_CHUNK_BYTES as u64).read_to_end(&mut data)?;
        let length = u64::try_from(data.len()).map_err(|_| ShareError::Io)?;
        Ok((data, size, offset + length >= size))
    }
}

impl Drop for SharedFolder {
    fn drop(&mut self) {
        let ids: Vec<u32> = self.uploads.keys().copied().collect();
        for id in ids {
            self.abort_upload(id);
        }
    }
}

/// `name`, or `name (1).ext`, `name (2).ext`, … — the first that doesn't exist.
fn unused_name(dir: &Path, name: &str) -> Option<String> {
    let (stem, extension) = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem, Some(ext)),
        _ => (name, None),
    };
    (0..10_000).find_map(|n| {
        let candidate = match (n, extension) {
            (0, _) => name.to_string(),
            (_, Some(ext)) => format!("{stem} ({n}).{ext}"),
            (_, None) => format!("{stem} ({n})"),
        };
        fs::symlink_metadata(dir.join(&candidate))
            .is_err()
            .then_some(candidate)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_folder() -> SharedFolder {
        SharedFolder::at(std::env::temp_dir().join(format!("rivet-share-{}", uuid::Uuid::now_v7())))
    }

    fn upload(folder: &mut SharedFolder, id: u32, path: &str, data: &[u8]) -> ShareResult<String> {
        folder.start_upload(id, path, data.len() as u64)?;
        for chunk in data.chunks(FILE_CHUNK_BYTES) {
            folder.write_chunk(id, chunk)?;
        }
        folder.finish_upload(id)
    }

    #[test]
    fn uploads_nested_files_and_reads_them_back() {
        let mut folder = temp_folder();
        let data = vec![7_u8; FILE_CHUNK_BYTES + 10];
        assert_eq!(
            upload(&mut folder, 1, "Docs/2026/big.bin", &data).unwrap(),
            "Docs/2026/big.bin"
        );
        let (first, size, eof) = folder.read_chunk("Docs/2026/big.bin", 0).unwrap();
        assert_eq!(
            (first.len(), size, eof),
            (FILE_CHUNK_BYTES, data.len() as u64, false)
        );
        let (rest, _, eof) = folder
            .read_chunk("Docs/2026/big.bin", FILE_CHUNK_BYTES as u64)
            .unwrap();
        assert_eq!((rest.len(), eof), (10, true));

        let listing = folder.list().unwrap();
        let paths: Vec<_> = listing.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, ["Docs", "Docs/2026", "Docs/2026/big.bin"]);
        let _ = fs::remove_dir_all(&folder.root);
    }

    #[test]
    fn never_overwrites_an_existing_file() {
        let mut folder = temp_folder();
        assert_eq!(upload(&mut folder, 1, "a.txt", b"one").unwrap(), "a.txt");
        assert_eq!(
            upload(&mut folder, 2, "a.txt", b"two").unwrap(),
            "a (1).txt"
        );
        assert_eq!(upload(&mut folder, 3, "noext", b"x").unwrap(), "noext");
        assert_eq!(upload(&mut folder, 4, "noext", b"y").unwrap(), "noext (1)");
        assert_eq!(fs::read(folder.root.join("a.txt")).unwrap(), b"one");
        let _ = fs::remove_dir_all(&folder.root);
    }

    #[test]
    fn rejects_size_mismatch_and_cleans_up_the_part_file() {
        let mut folder = temp_folder();
        folder.start_upload(1, "short.txt", 10).unwrap();
        folder.write_chunk(1, b"abc").unwrap();
        assert_eq!(folder.finish_upload(1), Err(ShareError::Rejected));

        folder.start_upload(2, "long.txt", 2).unwrap();
        assert_eq!(folder.write_chunk(2, b"abc"), Err(ShareError::Rejected));
        assert!(folder.list().unwrap().is_empty(), "no partial files remain");
        let leftovers = fs::read_dir(&folder.root).unwrap().count();
        assert_eq!(leftovers, 0);
        let _ = fs::remove_dir_all(&folder.root);
    }

    #[test]
    fn refuses_paths_and_symlinks_that_leave_the_folder() {
        let mut folder = temp_folder();
        for bad in ["../escape.txt", "/etc/passwd", "a/../../b"] {
            assert_eq!(folder.start_upload(1, bad, 1), Err(ShareError::Rejected));
            assert_eq!(folder.read_chunk(bad, 0), Err(ShareError::Rejected));
        }
        folder.ensure_root().unwrap();
        let outside = std::env::temp_dir().join(format!("rivet-outside-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("secret.txt"), b"secret").unwrap();
        std::os::unix::fs::symlink(&outside, folder.root.join("link")).unwrap();
        std::os::unix::fs::symlink(outside.join("secret.txt"), folder.root.join("s.txt")).unwrap();

        assert_eq!(
            folder.read_chunk("link/secret.txt", 0),
            Err(ShareError::Rejected)
        );
        assert_eq!(folder.read_chunk("s.txt", 0), Err(ShareError::Rejected));
        assert_eq!(
            folder.start_upload(2, "link/new.txt", 1),
            Err(ShareError::Rejected)
        );
        assert!(folder.list().unwrap().is_empty(), "symlinks are not listed");
        let _ = fs::remove_dir_all(&folder.root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn bounds_concurrent_uploads_and_duplicate_ids() {
        let mut folder = temp_folder();
        folder.start_upload(1, "a", 1).unwrap();
        assert_eq!(folder.start_upload(1, "b", 1), Err(ShareError::Rejected));
        for id in 2..=u32::try_from(MAX_OPEN_UPLOADS).unwrap() {
            folder.start_upload(id, &format!("f{id}"), 1).unwrap();
        }
        assert_eq!(
            folder.start_upload(99, "over", 1),
            Err(ShareError::Rejected)
        );
        let root = folder.root.clone();
        drop(folder);
        assert_eq!(
            fs::read_dir(&root).unwrap().count(),
            0,
            "drop removes part files"
        );
        let _ = fs::remove_dir_all(root);
    }
}
