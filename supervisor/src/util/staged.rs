//! Staged `/tmp` files: unique per call (pid + sequence), 0600,
//! container-private, never following a pre-existing path — and unlinked
//! when the handle drops, the normal exit path. The binary is
//! `panic = "abort"`, so a panic skips `Drop`; a leftover from an
//! ungraceful exit is reclaimed by name on the next start (a container
//! restart reuses the same pid and sequence), so a stale secret neither
//! lingers nor jams the boot. Consumers: secrets that must never ride
//! argv (the tailscale authkey) and captured child output.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::{AtomicU64, Ordering};

/// One staged file; the on-disk name dies with this handle.
pub struct StagedFile {
    /// The open handle to the staged file.
    file: File,
    /// The on-disk path, removed when the handle drops.
    path: String,
}

impl StagedFile {
    /// Create `/tmp/<prefix>-<pid>-<seq>` exclusively, never following a
    /// pre-existing path, at owner-only 0600 or narrower by umask. A leftover at
    /// that deterministic name is reclaimed, so no stale secret blocks boot.
    pub fn create(prefix: &str) -> std::io::Result<Self> {
        Self::create_in("/tmp", prefix)
    }

    /// [`Self::create`] in an explicit directory. Secrets that the vault
    /// must not interfere with use the supervisor-only state root.
    pub fn create_in(dir: &str, prefix: &str) -> std::io::Result<Self> {
        /// Distinguishes staged names within this process.
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let path = format!(
            "{dir}/{prefix}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let file = open_staged(&path)?;
        Ok(Self { file, path })
    }

    /// The staged path (safe to hand to a child while the handle lives).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The underlying handle (seek, read back, or duplicate for stdio).
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Write bytes and fsync; a partial write removes the file
    /// immediately (a sensitive half-written file must not linger).
    pub fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        if let Err(e) = self
            .file
            .write_all(bytes)
            .and_then(|_| self.file.sync_all())
        {
            let _ = std::fs::remove_file(&self.path);
            return Err(e);
        }
        Ok(())
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Open `path` exclusively, reclaiming a leftover from an ungraceful exit: a
/// stale file (possibly a secret or a symlink) is unlinked and the name reused.
/// `create_new` never follows it, and unlinking removes the link, not a target.
fn open_staged(path: &str) -> std::io::Result<File> {
    let options = || {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true).mode(0o600);
        options
    };
    match options().open(path) {
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(path)?;
            options().open(path)
        }
        other => other,
    }
}

#[cfg(test)]
impl StagedFile {
    /// Test constructor over an arbitrary handle (e.g. read-only, to
    /// force write failures deterministically).
    fn from_parts(file: File, path: String) -> Self {
        Self { file, path }
    }
}

#[cfg(test)]
mod tests {
    //! Staged-file lifecycle tests: mode, reclamation, cleanup.

    use std::os::unix::fs::PermissionsExt;

    use super::*;

    /// 0600 regardless of umask, verbatim content, and removed on drop.
    #[test]
    fn staged_file_is_0600_and_removed_on_drop() {
        let mut f = StagedFile::create("vw-staged-test").expect("created");
        assert!(f.path().starts_with("/tmp/vw-staged-test-"));
        let meta = std::fs::metadata(f.path()).expect("exists");
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        f.write_all(b"payload").expect("written");
        assert_eq!(std::fs::read_to_string(f.path()).unwrap(), "payload");
        let path = f.path().to_string();
        drop(f);
        assert!(!std::path::Path::new(&path).exists(), "removed on drop");
    }

    /// A failed write removes the file immediately (no partial sensitive
    /// leftovers): the handle is read-only, so the write errors.
    #[test]
    fn failed_write_removes_the_file() {
        let path = std::env::temp_dir()
            .join(format!("vw-staged-ro-{}.sql", std::process::id()))
            .to_string_lossy()
            .into_owned();
        std::fs::write(&path, b"").unwrap();
        let ro = File::open(&path).unwrap();
        let mut f = StagedFile::from_parts(ro, path.clone());
        assert!(f.write_all(b"payload").is_err());
        assert!(
            !std::path::Path::new(&path).exists(),
            "removed after failed write"
        );
    }

    /// A leftover from an ungraceful exit (same pid, same sequence) is
    /// reclaimed instead of jamming the next start, and the stale bytes
    /// (possibly a secret) are gone.
    #[test]
    fn a_stale_leftover_is_reclaimed() {
        let path = format!("/tmp/vw-staged-stale-{}-0", std::process::id());
        std::fs::write(&path, b"stale secret").unwrap();
        let file = open_staged(&path).expect("reclaims the name");
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            0,
            "a fresh file, not the stale one"
        );
        drop(file);
        let _ = std::fs::remove_file(&path);
    }
}
