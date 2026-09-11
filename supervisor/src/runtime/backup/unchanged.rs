//! Unchanged-dump suppression: skip the upload when a fresh dump is
//! byte-identical to the newest backup already in the bucket. A quiet
//! vault would otherwise mint a redundant object every cycle. The
//! comparison is exact bytes (`VACUUM INTO` is deterministic for an
//! unchanged database) against the previous dump, kept next to the
//! lineage sidecar — not in staging, which is swept before every run.
//! Any doubt (missing or unreadable previous dump) is a normal push:
//! this can only save an upload, never lose one. Skipping itself is only
//! sound while the lineage owns the bucket's newest object — verified by
//! the caller — so an externally deleted newest dump is healed by a push
//! instead of skipped over.

use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::util::log;

/// 64 KiB comparison chunks: bounded memory, few syscalls per MiB.
const CHUNK: usize = 64 * 1024;

/// Where the newest pushed dump's bytes live: next to the lineage
/// sidecar, so both die with the same volume.
fn last_path(db_path: &str) -> String {
    match Path::new(db_path).parent() {
        Some(dir) => dir.join("db-backups.last").to_string_lossy().into_owned(),
        None => "db-backups.last".to_string(),
    }
}

/// Whether `staged` is byte-identical to the remembered previous dump.
pub(super) fn is_repeat(staged: &str, db_path: &str) -> bool {
    same_bytes(staged, &last_path(db_path)).unwrap_or(false)
}

/// Full-file byte comparison in bounded chunks. Err covers any I/O
/// trouble; the caller treats it as "not a repeat" and pushes.
fn same_bytes(a: &str, b: &str) -> std::io::Result<bool> {
    let mut fa = std::fs::File::open(a)?;
    let mut fb = std::fs::File::open(b)?;
    let mut buf_a = vec![0u8; CHUNK];
    let mut buf_b = vec![0u8; CHUNK];
    loop {
        let na = read_full(&mut fa, &mut buf_a)?;
        let nb = read_full(&mut fb, &mut buf_b)?;
        if na != nb {
            return Ok(false);
        }
        if na == 0 {
            return Ok(true);
        }
        if buf_a[..na] != buf_b[..nb] {
            return Ok(false);
        }
    }
}

/// Read up to `buf.len()` bytes; short only at EOF.
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// Remember `staged` as the newest dump's bytes (a rename — both paths
/// sit on the data volume by construction). Best-effort: a failure only
/// costs one redundant push next cycle. The kept copy is owner-only; it
/// is a full database.
pub(super) fn retain(staged: &str, db_path: &str) {
    let last = last_path(db_path);
    match std::fs::rename(staged, &last) {
        Ok(()) => {
            let _ = std::fs::set_permissions(&last, std::fs::Permissions::from_mode(0o600));
        }
        Err(e) => {
            let _ = std::fs::remove_file(staged);
            log::err(&format!(
                "db backup: cannot remember the pushed dump {}: {e}",
                log::sanitize(&last)
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> (String, String) {
        let dir = std::env::temp_dir().join(format!("vw-sup-unch-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("db.sqlite3").to_string_lossy().into_owned();
        (dir.to_string_lossy().into_owned(), db)
    }

    #[test]
    fn fresh_dump_is_never_a_repeat() {
        let (dir, db) = scratch("fresh");
        let staged = format!("{dir}/dump.sqlite3");
        std::fs::write(&staged, b"payload").unwrap();
        assert!(!is_repeat(&staged, &db));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn identical_dump_is_a_repeat() {
        let (dir, db) = scratch("same");
        let first = format!("{dir}/first.sqlite3");
        std::fs::write(&first, b"payload").unwrap();
        retain(&first, &db);
        let staged = format!("{dir}/second.sqlite3");
        std::fs::write(&staged, b"payload").unwrap();
        assert!(is_repeat(&staged, &db));
        // is_repeat never consumes the staged dump; the caller decides.
        assert!(std::path::Path::new(&staged).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn changed_dump_is_not_a_repeat() {
        let (dir, db) = scratch("changed");
        let first = format!("{dir}/first.sqlite3");
        std::fs::write(&first, b"payload").unwrap();
        retain(&first, &db);
        let staged = format!("{dir}/second.sqlite3");
        std::fs::write(&staged, b"changed payload").unwrap();
        assert!(!is_repeat(&staged, &db));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn same_size_different_bytes_is_not_a_repeat() {
        let (dir, db) = scratch("samesize");
        let first = format!("{dir}/first.sqlite3");
        std::fs::write(&first, b"aaaaaaa").unwrap();
        retain(&first, &db);
        let staged = format!("{dir}/second.sqlite3");
        std::fs::write(&staged, b"aaaaaab").unwrap();
        assert!(!is_repeat(&staged, &db));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retain_replaces_the_previous_copy() {
        let (dir, db) = scratch("retain");
        let first = format!("{dir}/first.sqlite3");
        std::fs::write(&first, b"one").unwrap();
        retain(&first, &db);
        let second = format!("{dir}/second.sqlite3");
        std::fs::write(&second, b"two").unwrap();
        retain(&second, &db);
        assert_eq!(std::fs::read(last_path(&db)).unwrap(), b"two");
        // The retained copy is owner-only; it is a full database.
        let mode = std::fs::metadata(last_path(&db))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
