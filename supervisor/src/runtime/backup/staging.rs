//! Staging-directory hygiene for DB dumps. The directory is opened with
//! `O_NOFOLLOW | O_DIRECTORY` and swept through that descriptor, so a
//! symlink swapped in at the path can never redirect the sweep into `/data`
//! (or anywhere else). Entries are deleted by name relative to the open
//! directory; a nested directory is refused rather than recursively
//! followed.

use std::os::fd::AsFd;

use nix::dir::{Dir, Type};
use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::sys::stat::{Mode, fchmod};
use nix::unistd::{UnlinkatFlags, mkdir, unlinkat};

use crate::util::log;

/// Open (or create) `dir` as an owner-only directory, then remove every
/// entry inside it. Returns false on any uncertainty; the caller skips the
/// backup rather than deleting blind.
pub(super) fn sweep_staging(dir: &str) -> bool {
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let mut handle = match Dir::open(dir, flags, Mode::empty()) {
        Ok(handle) => handle,
        Err(Errno::ENOENT) => {
            if let Err(e) = mkdir(dir, Mode::from_bits_truncate(0o700))
                && e != Errno::EEXIST
            {
                log::err(&format!("db backup: cannot create staging dir: {e}"));
                return false;
            }
            match Dir::open(dir, flags, Mode::empty()) {
                Ok(handle) => handle,
                Err(e) => {
                    log::err(&format!(
                        "db backup: cannot open staging dir after create: {e}"
                    ));
                    return false;
                }
            }
        }
        Err(e) => {
            log::err(&format!(
                "db backup: cannot open staging dir (a symlink is refused): {e}"
            ));
            return false;
        }
    };
    if let Err(e) = fchmod(handle.as_fd(), Mode::from_bits_truncate(0o700)) {
        log::err(&format!("db backup: cannot restrict staging dir: {e}"));
        return false;
    }
    // Collect names first: the iterator borrows the handle mutably, and the
    // unlink calls need to borrow its descriptor. Staging is bounded to a
    // handful of in-flight dumps; a huge directory is refused rather than
    // materialized.
    const MAX_STAGING_ENTRIES: usize = 4096;
    let mut entries: Vec<(std::ffi::CString, Type)> = Vec::new();
    for entry in handle.iter() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                log::err(&format!("db backup: cannot read a staging entry: {e}"));
                return false;
            }
        };
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        let Some(file_type) = entry.file_type() else {
            log::err("db backup: cannot classify a staging entry; refusing to sweep");
            return false;
        };
        if entries.len() >= MAX_STAGING_ENTRIES {
            log::err("db backup: too many staging entries; refusing to sweep");
            return false;
        }
        entries.push((name.to_owned(), file_type));
    }
    for (name, file_type) in entries {
        match file_type {
            // Staging holds files only. A directory is either a mistake or
            // an attempt to turn the sweep recursive; refuse it.
            Type::Directory => {
                log::err("db backup: unexpected directory in staging; refusing to sweep");
                return false;
            }
            _ => {
                if let Err(e) =
                    unlinkat(handle.as_fd(), name.as_c_str(), UnlinkatFlags::NoRemoveDir)
                {
                    log::err(&format!(
                        "db backup: cannot clear staging entry {}: {e}",
                        log::sanitize(&name.to_string_lossy())
                    ));
                    return false;
                }
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::super::support::next_staging;
    use super::*;

    #[test]
    fn staging_sweeps_leftovers() {
        let dir = next_staging();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(format!("{dir}/sqlite-stale"), "garbage").unwrap();
        assert!(sweep_staging(&dir));
        let entries: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
        assert!(entries.is_empty());
        let _ = std::fs::remove_dir(&dir);
    }

    /// The staging dir is owner-only regardless of umask: everything that
    /// lands in it is sensitive.
    #[test]
    fn staging_dir_is_0700() {
        let dir = next_staging();
        std::fs::create_dir_all(&dir).unwrap();
        // Simulate a permissive umask having created it wide.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(sweep_staging(&dir));
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        let _ = std::fs::remove_dir(&dir);
    }

    /// A symlink at the staging path is refused, and a symlink *inside* is
    /// removed without touching its target.
    #[test]
    fn staging_refuses_symlinked_dirs_and_never_follows_entries() {
        let root = std::path::PathBuf::from(next_staging());
        std::fs::create_dir_all(&root).unwrap();
        let outside = root.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let victim = outside.join("victim");
        std::fs::write(&victim, b"keep").unwrap();

        let link = root.join("staging");
        symlink(&outside, &link).unwrap();
        assert!(!sweep_staging(link.to_str().unwrap()));
        assert!(victim.exists(), "the target directory must survive");

        let real = root.join("real");
        std::fs::create_dir(&real).unwrap();
        let entry_link = real.join("entry-link");
        symlink(&victim, &entry_link).unwrap();
        assert!(sweep_staging(real.to_str().unwrap()));
        assert!(!entry_link.exists(), "the link itself is removed");
        assert!(victim.exists(), "the link target must survive");

        let _ = std::fs::remove_dir_all(&root);
    }
}
