//! SQLite restore: emptiness gate (absent, or a valid database with no
//! user tables) and import (integrity check on the staged copy, then a
//! no-replace link into place). In-process via bundled rusqlite — no
//! external tool.
//!
//! The staged dump lives on the supervisor-only state volume while the
//! live DB is on the vault's data volume, so they are different
//! filesystems. Publication copies the verified bytes to a same-directory
//! temp on the data volume, then `link(2)`s it into place: still atomic,
//! still never replacing existing data, and no cross-device rename.

use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::util::log;
use crate::util::make_private;

/// The live DB is shared with the vault through the data group: the vault
/// runs a different uid and must be able to write its own database.
const LIVE_MODE: u32 = 0o660;

/// Emptiness per the never-overwrite invariant: the live file is absent,
/// or a readable SQLite database with zero user tables (a freshly created
/// or truncated file). Corrupt or unreadable files are ambiguous (Err) —
/// never silently treated as empty, never silently kept.
pub(crate) fn is_empty(path: &str) -> anyhow::Result<bool> {
    match Path::new(path).try_exists() {
        Ok(false) => return Ok(true),
        Ok(true) => {}
        Err(e) => return Err(anyhow::anyhow!("cannot inspect existing db: {e}")),
    }
    let conn = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|e| anyhow::anyhow!("cannot open existing db: {e}"))?;
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master \
             WHERE type = 'table' AND lower(name) NOT GLOB 'sqlite_*'",
            [],
            |r| r.get(0),
        )
        .map_err(|e| anyhow::anyhow!("cannot inspect existing db: {e}"))?;
    Ok(count == 0)
}

/// Why an import failed. The caller distinguishes a candidate that is
/// proven unusable (an older backup may be tried) from a local failure
/// (no fallback can fix it; the boot must refuse).
#[derive(Debug)]
pub(crate) enum ImportError {
    /// The staged copy is not a usable SQLite database.
    Invalid,
    /// Publication failed locally (I/O, permissions, or the live path).
    Local,
    /// A stop request interrupted the integrity check.
    Aborted,
}

/// Integrity pre-check (`PRAGMA integrity_check` on the staged copy),
/// then import via atomic no-replace publication. The verified bytes are
/// copied to a temp beside the live path (same filesystem for the link),
/// then `link(2)` fails with `AlreadyExists` if anything created the live
/// path meanwhile — unlike `rename(2)`, which would silently replace it —
/// so the never-overwrite invariant is enforced by the kernel, not by a
/// check. A live path that exists but is *provably empty* (the same
/// predicate [`is_empty`] uses) is cleared first: it holds no data, and
/// the no-replace link cannot publish over it. The live file is 0660 so
/// the vault's uid can write it through the shared data group.
pub(crate) fn import(
    staged: &str,
    path: &str,
    abort: &(impl Fn() -> bool + Sync),
) -> Result<(), ImportError> {
    if abort() {
        return Err(ImportError::Aborted);
    }
    let check = match rusqlite::Connection::open_with_flags(
        staged,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    ) {
        Ok(conn) => {
            let interrupt = conn.get_interrupt_handle();
            let done = AtomicBool::new(false);
            let check: Result<String, String> = std::thread::scope(|scope| {
                if let Err(e) = std::thread::Builder::new()
                    .name("sqlite-restore-abort".into())
                    .spawn_scoped(scope, || {
                        while !done.load(Ordering::Relaxed) {
                            if abort() {
                                interrupt.interrupt();
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(50));
                        }
                    })
                {
                    return Err(format!("cannot start the sqlite abort watcher: {e}"));
                }
                let check = conn
                    .query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
                    .unwrap_or_else(|e| format!("check failed: {e}"));
                done.store(true, Ordering::Relaxed);
                Ok(check)
            });
            let check = match check {
                Ok(check) => check,
                Err(e) => {
                    log::err(&format!("db restore: {e}; refusing the import"));
                    return Err(ImportError::Local);
                }
            };
            if abort() {
                return Err(ImportError::Aborted);
            }
            check
        }
        Err(e) => format!("cannot open: {e}"),
    };
    if check != "ok" {
        log::err(&format!(
            "db restore: staged dump failed integrity check ({check})"
        ));
        return Err(ImportError::Invalid);
    }
    if let Err(e) = make_private(staged) {
        log::err(&format!("db restore: cannot secure staged dump: {e}"));
        return Err(ImportError::Local);
    }
    // A tableless live file would fail the link with EEXIST and jam the
    // boot in a retry loop; it is provably empty (no user tables), so
    // clearing it loses nothing. If this dies in between, the next boot
    // sees an absent database and retries; a non-empty file is never
    // touched.
    match Path::new(path).try_exists() {
        Ok(true) => match is_empty(path) {
            Ok(true) => {
                if let Err(e) = std::fs::remove_file(path) {
                    log::err(&format!("db restore: cannot clear the empty live DB: {e}"));
                    return Err(ImportError::Local);
                }
            }
            Ok(false) => {
                log::err("db restore: live DB is not empty; not overwriting");
                return Err(ImportError::Local);
            }
            Err(e) => {
                log::err(&format!(
                    "db restore: cannot verify the live DB is empty ({e}); not overwriting"
                ));
                return Err(ImportError::Local);
            }
        },
        Ok(false) => {}
        Err(e) => {
            log::err(&format!(
                "db restore: cannot inspect the live DB path ({e}); not overwriting"
            ));
            return Err(ImportError::Local);
        }
    }
    let tmp = match copy_beside(staged, path) {
        Ok(tmp) => tmp,
        Err(e) => {
            log::err(&format!("db restore: cannot stage the dump on /data: {e}"));
            return Err(ImportError::Local);
        }
    };
    let published = std::fs::hard_link(&tmp, path);
    let _ = std::fs::remove_file(&tmp);
    match published {
        Ok(()) => {
            // Unlink the staging name; failure only leaves a stale copy
            // for the next staging sweep, never a wrong live file.
            let _ = std::fs::remove_file(staged);
            // The published DB must not inherit the replaced file's sidecars:
            // a stale `<db>-wal`/`-journal` from the old inode must not be
            // picked up by the next opener. Nothing else has the DB open at
            // boot time, so removing them is safe.
            let _ = std::fs::remove_file(format!("{path}-wal"));
            let _ = std::fs::remove_file(format!("{path}-shm"));
            let _ = std::fs::remove_file(format!("{path}-journal"));
            // Make the publication durable before the vault starts. A
            // failure here is reported but does not unpublish the file.
            if let Err(e) = std::fs::File::open(path).and_then(|file| file.sync_all()) {
                log::err(&format!("db restore: cannot fsync the live DB: {e}"));
            }
            if let Some(parent) = Path::new(path).parent()
                && let Err(e) = std::fs::File::open(parent).and_then(|dir| dir.sync_all())
            {
                log::err(&format!("db restore: cannot fsync the DB directory: {e}"));
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            log::err("db restore: live DB appeared mid-restore; not overwriting");
            Err(ImportError::Local)
        }
        Err(e) => {
            log::err(&format!("db restore: cannot move dump into place: {e}"));
            Err(ImportError::Local)
        }
    }
}

/// Copy the verified staged dump to a fresh temp beside `path` (the live
/// DB's filesystem), fsync it, and return the temp name. Publication by
/// `link` then has no torn-copy window. A stale temp (a crash before the
/// unlink) is removed, never followed.
fn copy_beside(staged: &str, path: &str) -> std::io::Result<String> {
    let tmp = format!("{path}.restore");
    let _ = std::fs::remove_file(&tmp);
    let mut input = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(staged)?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(LIVE_MODE)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&tmp)?;
    let copied = (|| -> std::io::Result<()> {
        std::io::copy(&mut input, &mut output)?;
        // The open mask is umask-dependent; make the exact mode explicit.
        output.set_permissions(std::fs::Permissions::from_mode(LIVE_MODE))?;
        output.sync_all()
    })();
    drop(output);
    if let Err(e) = copied {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(tmp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("vw-sup-sqle-{}-{}", name, std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("db.sqlite3").to_string_lossy().into_owned()
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
    }

    /// A missing file is empty (nothing to lose).
    #[test]
    fn missing_file_is_empty() {
        let path = scratch("missing");
        cleanup(&path);
        assert!(is_empty(&path).unwrap());
    }

    /// A valid database with no user tables (fresh/truncated file) is
    /// empty: vaultwarden has never written to it.
    #[test]
    fn valid_db_without_user_tables_is_empty() {
        let path = scratch("fresh");
        cleanup(&path);
        let conn = rusqlite::Connection::open(&path).unwrap();
        drop(conn);
        assert!(is_empty(&path).unwrap());
        cleanup(&path);
    }

    /// Any user table means data: never eligible for automatic restore.
    #[test]
    fn db_with_user_tables_is_not_empty() {
        let path = scratch("data");
        cleanup(&path);
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('x');")
            .unwrap();
        drop(conn);
        assert!(!is_empty(&path).unwrap());
        cleanup(&path);
    }

    /// `LIKE 'sqlite_%'` treats `_` as a wildcard; a user table that merely
    /// starts with `sqlite` (no underscore) is still user data.
    #[test]
    fn a_user_table_starting_with_sqlite_is_not_empty() {
        let path = scratch("sqlite-prefix");
        cleanup(&path);
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE sqliteX (v TEXT);")
            .unwrap();
        drop(conn);
        assert!(!is_empty(&path).unwrap());
        cleanup(&path);
    }

    /// The live DB path is vault-writable; a symlink is never followed.
    #[test]
    fn a_symlinked_db_is_refused() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!("vw-sup-sqllink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let real = dir.join("real.sqlite3");
        let conn = rusqlite::Connection::open(&real).unwrap();
        conn.execute_batch("CREATE TABLE t (v TEXT);").unwrap();
        drop(conn);
        let link = dir.join("link.sqlite3");
        symlink(&real, &link).unwrap();
        assert!(is_empty(link.to_str().unwrap()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Internal sqlite tables (e.g. a leftover sqlite_sequence from a
    /// dropped autoincrement table) don't count as user data.
    #[test]
    fn internal_tables_still_count_as_empty() {
        let path = scratch("internal");
        cleanup(&path);
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT, v TEXT);
             INSERT INTO t (v) VALUES ('x');
             DROP TABLE t;",
        )
        .unwrap();
        drop(conn);
        assert!(is_empty(&path).unwrap());
        cleanup(&path);
    }

    /// A corrupt file is ambiguous: Err, fail closed (never "empty", never
    /// silently kept).
    #[test]
    fn corrupt_file_is_ambiguous_not_empty() {
        let path = scratch("corrupt");
        std::fs::write(&path, b"not a database at all").unwrap();
        assert!(is_empty(&path).is_err());
        cleanup(&path);
    }

    /// Publication is no-replace: a live DB that appears between the
    /// emptiness gate and the import must win — the kernel refuses the
    /// link, the existing file keeps its inode, and the staged dump is
    /// left for the next sweep.
    #[test]
    fn import_never_replaces_an_existing_live_db() {
        let dir = std::env::temp_dir().join(format!("vw-sup-sqli-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let staged = dir.join("staged.sqlite3");
        let live = dir.join("live.sqlite3");

        // A valid staged dump...
        let conn = rusqlite::Connection::open(&staged).unwrap();
        conn.execute_batch("CREATE TABLE restored (v TEXT); INSERT INTO restored VALUES ('new');")
            .unwrap();
        drop(conn);
        // ...and an existing live DB with different content.
        let conn = rusqlite::Connection::open(&live).unwrap();
        conn.execute_batch("CREATE TABLE existing (v TEXT); INSERT INTO existing VALUES ('old');")
            .unwrap();
        drop(conn);
        let before = std::fs::metadata(&live).unwrap().ino();

        assert!(import(staged.to_str().unwrap(), live.to_str().unwrap(), &|| false).is_err());

        // The live file is untouched (same inode, same data).
        use std::os::unix::fs::MetadataExt;
        assert_eq!(std::fs::metadata(&live).unwrap().ino(), before);
        let conn = rusqlite::Connection::open_with_flags(
            &live,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let v: String = conn
            .query_row("SELECT v FROM existing LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, "old");
        drop(conn);

        // Happy path for contrast: publication into an absent path works
        // and lands group-writable (the vault's uid is in the data group).
        let target = dir.join("fresh.sqlite3");
        assert!(
            import(staged.to_str().unwrap(), target.to_str().unwrap(), &|| {
                false
            })
            .is_ok()
        );
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660);
        assert!(!staged.exists(), "staging name is unlinked after publish");
        assert!(
            !dir.join("fresh.sqlite3.restore").exists(),
            "no publication temp remains"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A live DB that is provably empty (tableless, the state the restore
    /// gate accepted) is replaced: it holds no data, and refusing would
    /// jam boot in an EEXIST retry loop.
    #[test]
    fn import_replaces_a_provably_empty_live_db() {
        let dir = std::env::temp_dir().join(format!("vw-sup-sqle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let staged = dir.join("staged.sqlite3");
        let conn = rusqlite::Connection::open(&staged).unwrap();
        conn.execute_batch("CREATE TABLE restored (v TEXT); INSERT INTO restored VALUES ('new');")
            .unwrap();
        drop(conn);
        let live = dir.join("live.sqlite3");
        rusqlite::Connection::open(&live).unwrap(); // tableless, no user data

        assert!(import(staged.to_str().unwrap(), live.to_str().unwrap(), &|| false).is_ok());

        let conn = rusqlite::Connection::open_with_flags(
            &live,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let v: String = conn
            .query_row("SELECT v FROM restored LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, "new");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A published DB must not inherit the replaced file's WAL siblings:
    /// stale `-wal`/`-shm` files are removed on import (a stale WAL from
    /// the old inode must never be picked up by the next opener).
    #[test]
    fn import_removes_stale_wal_siblings() {
        let dir = std::env::temp_dir().join(format!("vw-sup-sqlw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let staged = dir.join("staged.sqlite3");
        let conn = rusqlite::Connection::open(&staged).unwrap();
        conn.execute_batch("CREATE TABLE restored (v TEXT);")
            .unwrap();
        drop(conn);
        let live = dir.join("live.sqlite3");
        let wal = dir.join("live.sqlite3-wal");
        let shm = dir.join("live.sqlite3-shm");
        let journal = dir.join("live.sqlite3-journal");
        std::fs::write(&wal, b"stale").unwrap();
        std::fs::write(&shm, b"stale").unwrap();
        std::fs::write(&journal, b"stale").unwrap();

        assert!(import(staged.to_str().unwrap(), live.to_str().unwrap(), &|| false).is_ok());

        assert!(!wal.exists(), "stale -wal must be removed");
        assert!(!shm.exists(), "stale -shm must be removed");
        assert!(!journal.exists(), "stale -journal must be removed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A staged copy that is not a database at all is classified Invalid
    /// (the caller may try an older candidate), unlike a local failure.
    #[test]
    fn import_honours_an_immediate_abort() {
        let dir = std::env::temp_dir().join(format!("vw-sup-sqlab-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let staged = dir.join("staged.sqlite3");
        std::fs::write(&staged, b"x").unwrap();
        let live = dir.join("live.sqlite3");
        let err = import(staged.to_str().unwrap(), live.to_str().unwrap(), &|| true)
            .expect_err("abort must not publish");
        assert!(matches!(err, ImportError::Aborted), "got {err:?}");
        assert!(!live.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn import_marks_a_non_database_staged_copy_invalid() {
        let dir = std::env::temp_dir().join(format!("vw-sup-sqlinv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let staged = dir.join("staged.sqlite3");
        std::fs::write(&staged, b"not a database").unwrap();
        let live = dir.join("live.sqlite3");
        let err = import(staged.to_str().unwrap(), live.to_str().unwrap(), &|| false)
            .expect_err("garbage must not import");
        assert!(matches!(err, ImportError::Invalid), "got {err:?}");
        assert!(!live.exists(), "a rejected candidate must not publish");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
