//! File-permission and safe-local-I/O policy: the owner-only mode the
//! supervisor applies everywhere it writes secrets or vault data, plus the
//! no-follow primitives used by the sync/backup sidecars.
//!
//! The vaultwarden child can write `/data`. Local files and sidecars are
//! therefore treated as untrusted path entries: a symlink is never followed
//! for a sidecar or a sync source, and atomic writes publish by rename over
//! the final name (which replaces a symlink instead of writing through it).

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

/// Restrict `path` to owner-only (0600).
pub fn make_private(path: &str) -> std::io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// Whether `path` is a regular file, never following a final symlink.
pub fn is_real_file(path: &str) -> bool {
    std::fs::symlink_metadata(path)
        .map(|meta| meta.file_type().is_file())
        .unwrap_or(false)
}

/// Whether `path` is a real directory, never following a final symlink.
pub fn is_real_dir(path: &str) -> bool {
    std::fs::symlink_metadata(path)
        .map(|meta| meta.file_type().is_dir())
        .unwrap_or(false)
}

/// Whether `path` is on a tmpfs mount (a PaaS ephemeral `/data` is often
/// one). The mountinfo line format is `id parent major:minor root mount
/// point options - fstype source super-options`; exact mount point.
fn mountinfo_is_tmpfs(text: &str, path: &str) -> bool {
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.get(4) != Some(&path) {
            continue;
        }
        if let Some(separator) = fields.iter().position(|field| *field == "-") {
            return fields.get(separator + 1) == Some(&"tmpfs");
        }
    }
    false
}

/// Whether the data root is a tmpfs. A missing/unreadable mountinfo is
/// "not provably temporary"; the explicit `SUPERVISOR_EPHEMERAL` knob covers
/// the rest.
pub fn on_tmpfs(path: &str) -> bool {
    std::fs::read_to_string("/proc/self/mountinfo")
        .map(|text| mountinfo_is_tmpfs(&text, path))
        .unwrap_or(false)
}

/// Create `root/rel_parent` one component at a time, refusing any existing
/// symlink component. The boot pull runs before the vault starts, so a
/// check-and-create is sufficient here; sidecar writes use `write_atomic`.
pub fn create_real_dirs(root: &Path, rel_parent: &Path) -> io::Result<()> {
    let root_str = root.to_string_lossy();
    if !is_real_dir(&root_str) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{root_str} is not a real directory"),
        ));
    }
    let mut current = root.to_path_buf();
    for component in rel_parent.components() {
        let std::path::Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains a non-normal component",
            ));
        };
        current.push(name);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_dir() => {}
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{} is not a real directory", current.to_string_lossy()),
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                std::fs::create_dir(&current)?;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Open a file for reading without following a final symlink.
pub fn open_nofollow(path: &str) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
}

/// Read a local sidecar with a hard byte cap (a corrupt/hostile sidecar must
/// not be able to exhaust PID 1's memory). A symlink is rejected.
pub fn read_capped(path: &str, max: u64) -> io::Result<String> {
    let mut file = open_nofollow(path)?;
    let mut out = Vec::new();
    Read::by_ref(&mut file)
        .take(max.saturating_add(1))
        .read_to_end(&mut out)?;
    if out.len() as u64 > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{path} exceeds the {max}-byte read cap"),
        ));
    }
    String::from_utf8(out)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("{path} is not UTF-8")))
}

/// Write `bytes` to `path` atomically:
/// - a per-write temp in the same real directory, created `create_new`;
/// - mode set exactly (not just masked by the umask);
/// - data fsynced, then `rename` over `path` (replaces a symlink, never
///   follows it);
/// - the directory fsynced so the rename is durable.
///
/// `path` must have a real parent directory; a symlinked parent is refused.
pub fn write_atomic(path: &str, bytes: &[u8], mode: u32) -> io::Result<()> {
    let path = Path::new(path);
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    let parent_str = parent.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "parent path is not valid UTF-8",
        )
    })?;
    if !is_real_dir(parent_str) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{parent_str} is not a real directory"),
        ));
    }

    static SEQ: AtomicU64 = AtomicU64::new(0);
    let mut last_exists = None;
    for _ in 0..8 {
        let tmp = parent.join(format!(
            ".tmp-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&tmp)
        {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                last_exists = Some(e);
                continue;
            }
            Err(e) => return Err(e),
        };

        let write = (|| -> io::Result<()> {
            file.write_all(bytes)?;
            // `mode` passed to open is masked by the umask; this makes the
            // final permissions exact.
            file.set_permissions(std::fs::Permissions::from_mode(mode))?;
            file.sync_all()
        })();
        if let Err(e) = write {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        drop(file);

        if let Err(e) = std::fs::rename(&tmp, path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        // The rename is atomic; fsync the directory so it survives a crash.
        if let Err(e) = File::open(parent).and_then(|dir| dir.sync_all()) {
            return Err(io::Error::new(
                e.kind(),
                format!("cannot fsync {}: {e}", parent_str),
            ));
        }
        return Ok(());
    }
    Err(last_exists.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "cannot allocate a temporary sidecar name",
        )
    }))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("vw-sup-fs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn file_ends_up_owner_only() {
        let dir = scratch("private");
        let path = dir.join("secret");
        std::fs::write(&path, b"x").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        make_private(path.to_str().unwrap()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn symlinks_are_never_followed() {
        let dir = scratch("symlink");
        let target = dir.join("target");
        std::fs::write(&target, b"old").unwrap();
        let link = dir.join("sidecar");
        symlink(&target, &link).unwrap();

        assert!(!is_real_file(link.to_str().unwrap()));
        assert!(read_capped(link.to_str().unwrap(), 64).is_err());

        write_atomic(link.to_str().unwrap(), b"new", 0o600).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"old", "target untouched");
        assert_eq!(std::fs::read(&link).unwrap(), b"new");
        let meta = std::fs::symlink_metadata(&link).unwrap();
        assert!(meta.file_type().is_file(), "the symlink was replaced");
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mountinfo_detects_a_tmpfs_mount() {
        let text = "1 0 0:1 / / rw - overlay overlay rw\n\
                    2 1 0:26 / /data rw,nosuid - tmpfs tmpfs rw\n\
                    3 1 0:27 / /state rw - ext4 /dev/root rw\n";
        assert!(mountinfo_is_tmpfs(text, "/data"));
        assert!(!mountinfo_is_tmpfs(text, "/state"));
        assert!(!mountinfo_is_tmpfs(text, "/missing"));
    }

    #[test]
    fn directory_creation_refuses_symlink_components() {
        let dir = scratch("dirs");
        let outside = dir.join("outside");
        std::fs::create_dir(&outside).unwrap();
        let link = dir.join("link");
        symlink(&outside, &link).unwrap();
        let err = create_real_dirs(&dir, Path::new("link/sub")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(!outside.join("sub").exists());

        create_real_dirs(&dir, Path::new("a/b")).unwrap();
        assert!(dir.join("a/b").is_dir());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_symlinked_parent_is_refused() {
        let dir = scratch("parent-link");
        let real = dir.join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.join("link");
        symlink(&real, &link).unwrap();
        let path = link.join("sidecar");
        let err = write_atomic(path.to_str().unwrap(), b"x", 0o600).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(!real.join("sidecar").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn local_reads_are_capped() {
        let dir = scratch("cap");
        let path = dir.join("file");
        std::fs::write(&path, b"abcdef").unwrap();
        assert_eq!(read_capped(path.to_str().unwrap(), 6).unwrap(), "abcdef");
        assert!(read_capped(path.to_str().unwrap(), 5).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
