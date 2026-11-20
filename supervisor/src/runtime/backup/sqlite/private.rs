//! A private, same-filesystem view of a live SQLite database, pinned by
//! directory descriptors.
//!
//! SQLite opens a database by path and derives `-wal`, `-shm`, and
//! `-journal` siblings from it. The vault controls the database's parent
//! directory, so a check-then-open sequence could be raced with a symlink
//! or FIFO. Open the database and its sidecars once with `O_NOFOLLOW` and
//! hard-link those exact inodes into a supervisor-owned 0700 directory;
//! SQLite then opens `/proc/self/fd/<dirfd>/db`, and every sibling path is
//! one of the pinned links. A path swap after the open cannot redirect the
//! read.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use nix::fcntl::{AT_FDCWD, AtFlags, OFlag, openat};
use nix::sys::stat::{Mode, fstat, mkdirat};
use nix::unistd::{UnlinkatFlags, geteuid, linkat, unlinkat};

use crate::util::log;

/// Flags opening a directory descriptor without following a symlink.
const DIR_FLAGS: i32 = nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC;
/// Name prefix marking a supervisor-owned private directory.
const PRIVATE_PREFIX: &str = ".vw-sqlite-";
/// Link names created for the pinned database and its sidecars.
const LINK_NAMES: [&str; 4] = ["db", "db-wal", "db-shm", "db-journal"];

/// A database opened through a pinned private directory. Dropping it
/// removes the links and the directory; the original database is untouched.
pub(super) struct PrivateDb {
    /// The database's parent directory, held to sweep and unlink by descriptor.
    parent: File,
    /// The private directory's entry name under `parent`.
    name: String,
    /// Descriptor of the private directory.
    dir: File,
    /// `/proc/self/fd/<dirfd>/db`, the path handed to SQLite.
    path: String,
}

impl PrivateDb {
    /// Pin `db_path` and its existing SQLite sidecars.
    ///
    /// `NotFound` means the database itself is absent; callers treat that
    /// as an empty database. Any other failure is a real refusal: the point
    /// is to never open an unpinned path.
    pub(super) fn open(db_path: &str) -> std::io::Result<Self> {
        let parent = Path::new(db_path).parent().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "database path has no parent",
            )
        })?;
        let (parent_dir, dir, name) = create_private_dir(parent)?;
        let mut private = Self {
            parent: parent_dir,
            name,
            dir,
            path: String::new(),
        };
        let db = crate::util::fs::open_regular(db_path)?;
        link_in(&private.dir, &db, "db")?;
        for (suffix, name) in [
            ("-wal", "db-wal"),
            ("-shm", "db-shm"),
            ("-journal", "db-journal"),
        ] {
            let sidecar = format!("{db_path}{suffix}");
            match crate::util::fs::open_regular(&sidecar) {
                Ok(file) => link_in(&private.dir, &file, name)?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        private.path = format!("/proc/self/fd/{}/db", private.dir.as_raw_fd());
        Ok(private)
    }

    /// The path to hand to SQLite: the pinned `db` link through the dirfd.
    pub(super) fn path(&self) -> &str {
        &self.path
    }
}

impl Drop for PrivateDb {
    fn drop(&mut self) {
        for name in LINK_NAMES {
            let _ = unlinkat(&self.dir, name, UnlinkatFlags::NoRemoveDir);
        }
        // The vault can rename the directory entry; then this fails and a
        // 0700 empty directory with no data remains for the next sweep.
        let _ = unlinkat(&self.parent, self.name.as_str(), UnlinkatFlags::RemoveDir);
    }
}

/// Create a fresh 0700 directory in `parent` and return the parent and
/// directory descriptors plus the chosen name. Stale private dirs from a
/// crash are reclaimed first; the vault cannot enter or write a
/// supervisor-owned 0700 directory, so the sweep cannot delete vault data.
fn create_private_dir(parent: &Path) -> std::io::Result<(File, File, String)> {
    let parent_dir = OpenOptions::new()
        .read(true)
        .custom_flags(DIR_FLAGS)
        .open(parent)?;
    sweep_stale(&parent_dir);
    /// Distinguishes private directories created by this process.
    static SEQ: AtomicU64 = AtomicU64::new(0);
    for _ in 0..8 {
        let name = format!(
            "{PRIVATE_PREFIX}{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        match mkdirat(&parent_dir, name.as_str(), Mode::from_bits_truncate(0o700)) {
            Ok(()) => {
                let fd = openat(
                    &parent_dir,
                    name.as_str(),
                    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )?;
                return Ok((parent_dir, File::from(fd), name));
            }
            Err(nix::errno::Errno::EEXIST) => continue,
            Err(e) => {
                return Err(std::io::Error::from_raw_os_error(e as i32));
            }
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "cannot allocate a private SQLite directory",
    ))
}

/// Remove crash leftovers: supervisor-owned owner-only `.vw-sqlite-*`
/// directories directly under the database parent. Every entry is opened
/// relative to the pinned parent descriptor and re-checked on the opened
/// inode, so a path swap cannot widen the sweep.
fn sweep_stale(parent_dir: &File) {
    let proc_path = format!("/proc/self/fd/{}", parent_dir.as_raw_fd());
    let Ok(entries) = std::fs::read_dir(&proc_path) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(PRIVATE_PREFIX) {
            continue;
        }
        let Ok(dir) = openat(
            parent_dir,
            name,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        ) else {
            continue;
        };
        let dir = File::from(dir);
        let Ok(meta) = fstat(&dir) else {
            continue;
        };
        if meta.st_uid != geteuid().as_raw() || meta.st_mode & 0o077 != 0 {
            continue;
        }
        if let Ok(children) = std::fs::read_dir(proc_path_of(&dir)) {
            for child in children.flatten() {
                let Ok(child_name) = child.file_name().into_string() else {
                    continue;
                };
                let _ = unlinkat(&dir, child_name.as_str(), UnlinkatFlags::NoRemoveDir);
            }
        }
        if unlinkat(parent_dir, name, UnlinkatFlags::RemoveDir).is_ok() {
            log::info(&format!(
                "db backup: removed a stale private SQLite directory {}",
                log::sanitize(name)
            ));
        }
    }
}

/// The `/proc/self/fd` path for an open descriptor.
fn proc_path_of(dir: &File) -> String {
    format!("/proc/self/fd/{}", dir.as_raw_fd())
}

/// Hard-link an open file into the private directory through its
/// `/proc/self/fd` name. `AT_SYMLINK_FOLLOW` resolves that name to the
/// pinned inode with no path component from the vault in between; the
/// source and destination are on the same filesystem because the private
/// directory lives beside the database.
fn link_in(dir: &File, file: &File, name: &str) -> std::io::Result<()> {
    let source = proc_path_of(file);
    linkat(
        AT_FDCWD,
        source.as_str(),
        dir,
        name,
        AtFlags::AT_SYMLINK_FOLLOW,
    )
    .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
}

/// Pinning, stale-directory reclamation, and refusal of a missing source.
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;
    use std::path::PathBuf;

    /// Create a fresh scratch directory for one test.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vw-private-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_private_view_links_the_database_and_sidecars() {
        let dir = scratch("links");
        let db = dir.join("db.sqlite3");
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('x');",
        )
        .unwrap();
        let private = PrivateDb::open(db.to_str().unwrap()).expect("private view");
        assert!(private.path().starts_with("/proc/self/fd/"));
        let copy = rusqlite::Connection::open_with_flags(
            private.path(),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let value: String = copy
            .query_row("SELECT v FROM t LIMIT 1", [], |row| row.get(0))
            .unwrap();
        assert_eq!(value, "x");
        drop(copy);
        drop(private);
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_stale_private_directory_is_swept() {
        let dir = scratch("sweep");
        let stale = dir.join(format!("{PRIVATE_PREFIX}{}-0", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&stale)
            .unwrap();
        std::fs::write(stale.join("db"), b"old").unwrap();
        assert!(
            PrivateDb::open(dir.join("missing.sqlite3").to_str().unwrap()).is_err(),
            "a missing database is an error"
        );
        assert!(!stale.exists(), "the stale directory is gone");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
