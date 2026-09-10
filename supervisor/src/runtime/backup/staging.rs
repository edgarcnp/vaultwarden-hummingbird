//! Staging-directory hygiene and staged-file permissions for DB dumps.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::util::log;

/// Remove stale staging artifacts from `dir` (a previous run may have
/// been killed mid-dump) and ensure the directory exists. An uncleanable
/// directory aborts the run rather than risking a full volume. The
/// directory is owner-only (0700): everything staged is sensitive, and a
/// wider mode must not depend on the creating process's umask.
pub(super) fn sweep_staging(dir: &str) -> bool {
    let dir = Path::new(dir);
    if let Err(e) = std::fs::create_dir_all(dir) {
        log::err(&format!("db backup: cannot create staging dir: {e}"));
        return false;
    }
    if let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)) {
        log::err(&format!("db backup: cannot restrict staging dir: {e}"));
        return false;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            log::err(&format!("db backup: cannot read staging dir: {e}"));
            return false;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let rm = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        if let Err(e) = rm {
            log::err(&format!(
                "db backup: cannot clear staging entry {}: {e}",
                log::sanitize(&path.to_string_lossy())
            ));
            return false;
        }
    }
    true
}

/// Restrict a staged dump to owner-only before it leaves the volume.
pub(super) fn lock_down(path: &str) {
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

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
}
