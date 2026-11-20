//! File-permission and safe-local-I/O policy: the owner-only mode the
//! supervisor applies everywhere it writes secrets or vault data, plus the
//! no-follow, descriptor-anchored helpers used by the sync/backup sidecars.
//!
//! The vaultwarden child can write `/data`. Local files and sidecars are
//! therefore treated as untrusted path entries: a symlink is never followed
//! for a sidecar or a sync source, and atomic writes publish by rename over
//! the final name (which replaces a symlink instead of writing through it).

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};

use nix::fcntl::{OFlag, openat};
use nix::sys::stat::Mode;

/// The supervisor-only state volume root.
pub const STATE_ROOT: &str = "/state";

/// Open `path` read-only without following a symlink and prove it is a regular
/// file. `O_NONBLOCK` refuses a crafted FIFO instead of blocking the open;
/// a consumer that reopens the path (SQLite) can still race a writer.
pub(crate) fn open_regular(path: &str) -> std::io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    Ok(file)
}

/// Whether `path` is an absolute path under `root` with no `..` or other
/// non-normal component (and no control character in `value`). The one
/// helper behind every `/state` containment check.
pub(crate) fn under_root(root: &Path, value: &str) -> bool {
    if value.chars().any(char::is_control) {
        return false;
    }
    let path = Path::new(value);
    path.is_absolute()
        && path.starts_with(root)
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

/// Suffix for supervisor partial downloads. User files may legitimately
/// end in `.part`, so the supervisor uses a distinct name.
pub const PART_SUFFIX: &str = ".vw-part";

/// Whether `name` is a supervisor partial-download temp.
pub fn is_partial_name(name: &str) -> bool {
    name.ends_with(PART_SUFFIX)
}

/// Set `path` to owner-only mode 0600, exactly, regardless of the umask.
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
pub(crate) fn is_real_dir(path: &str) -> bool {
    std::fs::symlink_metadata(path)
        .map(|meta| meta.file_type().is_dir())
        .unwrap_or(false)
}

/// Whether the mountinfo `text` records `path` itself as a tmpfs mount (a PaaS
/// ephemeral `/data` is often one). The mount point must match exactly; the
/// fields after `-` carry the filesystem type.
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

/// Open `root/rel` with every component anchored to its parent descriptor and
/// `O_NOFOLLOW`: the upload-side counterpart of [`create_real_dirs`]. A vault
/// directory swapped for a symlink after enumeration cannot redirect the open.
pub fn open_under(root: &Path, rel: &str) -> io::Result<File> {
    /// The root must itself be a real directory with no final-link follow.
    const ROOT_FLAGS: i32 = nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC;
    let mut current = OpenOptions::new()
        .read(true)
        .custom_flags(ROOT_FLAGS)
        .open(root)?;
    let mut parts = Path::new(rel).components().peekable();
    if parts.peek().is_none() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty path"));
    }
    while let Some(part) = parts.next() {
        let Component::Normal(name) = part else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains a non-normal component",
            ));
        };
        let mut flags = OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        if parts.peek().is_some() {
            flags |= OFlag::O_DIRECTORY;
        } else {
            // A race may replace a file with a FIFO; do not block in open.
            flags |= OFlag::O_NONBLOCK;
        }
        let fd = openat(&current, Path::new(name), flags, Mode::empty())?;
        current = File::from(fd);
    }
    Ok(current)
}

/// Open a real directory without following a final symlink.
pub(crate) fn open_dir(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
}

/// Open `root/rel` as a real directory without following a symlink in any
/// component. The descriptor chain pins the parent even if a concurrent
/// writer renames or replaces the path entries after the check.
pub fn open_dir_under(root: &Path, rel: &Path) -> io::Result<File> {
    let mut current = open_dir(root)?;
    for component in rel.components() {
        let Component::Normal(name) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains a non-normal component",
            ));
        };
        let fd = openat(
            &current,
            Path::new(name),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?;
        current = File::from(fd);
    }
    Ok(current)
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
    let out = read_capped_bytes(path, max)?;
    String::from_utf8(out)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("{path} is not UTF-8")))
}

/// [`read_capped`] for binary files (the tailscaled identity is not
/// guaranteed to be UTF-8).
pub fn read_capped_bytes(path: &str, max: u64) -> io::Result<Vec<u8>> {
    let mut file = open_regular(path)?;
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
    Ok(out)
}

/// Write `bytes` to `path` atomically: a `create_new` temp in the real parent,
/// exact `mode`, fsynced file and directory, then `rename` over `path`, which
/// replaces a symlink. A symlinked parent is refused.
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

    /// Distinguishes per-write temp names within this process.
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
    //! Policy tests: owner-only modes, symlink refusal, read caps, and the
    //! component-anchored open.

    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;

    /// A clean per-test directory under the temp dir.
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
        assert_eq!(
            read_capped_bytes(path.to_str().unwrap(), 6).unwrap(),
            b"abcdef"
        );
        assert!(read_capped_bytes(path.to_str().unwrap(), 5).is_err());
        // Binary data (a tailscaled state file need not be UTF-8).
        std::fs::write(&path, [0xff, 0x00]).unwrap();
        assert_eq!(
            read_capped_bytes(path.to_str().unwrap(), 2).unwrap(),
            [0xff, 0x00]
        );
        assert!(read_capped(path.to_str().unwrap(), 2).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A FIFO at a sidecar path is a crafted open-block, not a readable
    /// file: the cap reader must refuse it without waiting for a writer.
    #[test]
    fn a_fifo_is_refused_without_blocking() {
        let dir = scratch("fifo");
        let path = dir.join("sidecar");
        nix::unistd::mkfifo(
            path.as_path(),
            nix::sys::stat::Mode::from_bits_truncate(0o600),
        )
        .unwrap();
        let start = std::time::Instant::now();
        assert!(read_capped(path.to_str().unwrap(), 64).is_err());
        assert!(
            start.elapsed() < std::time::Duration::from_secs(2),
            "a FIFO must not block the reader"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The upload open is component-anchored: a symlinked root, parent, or
    /// final file is refused, so a vault directory swap cannot redirect the
    /// supervisor onto `/state` or `/proc`.
    #[test]
    fn open_under_refuses_every_symlink_component() {
        use std::io::Read;

        let dir = scratch("open-under");
        std::fs::create_dir_all(dir.join("real/sub")).unwrap();
        std::fs::write(dir.join("real/sub/file"), b"data").unwrap();
        let mut opened = open_under(&dir, "real/sub/file").unwrap();
        let mut out = String::new();
        opened.read_to_string(&mut out).unwrap();
        assert_eq!(out, "data");

        let outside = dir.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("secret"), b"secret").unwrap();
        symlink(&outside, dir.join("parent-link")).unwrap();
        assert!(open_under(&dir, "parent-link/secret").is_err());
        symlink(outside.join("secret"), dir.join("final-link")).unwrap();
        assert!(open_under(&dir, "final-link").is_err());
        assert!(open_under(&dir, "../outside/secret").is_err());
        let linked_root = dir.join("root-link");
        symlink(&outside, &linked_root).unwrap();
        assert!(open_under(&linked_root, "secret").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
