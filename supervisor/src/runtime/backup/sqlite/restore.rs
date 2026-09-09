//! SQLite restore: emptiness gate (absent, or a valid database with no
//! user tables) and import (integrity check on the staged copy, then
//! atomic rename into place). In-process via bundled rusqlite — no
//! external tool. Same filesystem (data volume), so the rename has no
//! torn-copy window.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::util::log;

/// Emptiness per the never-overwrite invariant: the live file is absent,
/// or a readable SQLite database with zero user tables (a freshly created
/// or truncated file). Corrupt or unreadable files are ambiguous (Err) —
/// never silently treated as empty, never silently kept.
pub(crate) fn is_empty(path: &str) -> Result<bool, String> {
    if !Path::new(path).exists() {
        return Ok(true);
    }
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| format!("cannot open existing db: {e}"))?;
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master \
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            [],
            |r| r.get(0),
        )
        .map_err(|e| format!("cannot inspect existing db: {e}"))?;
    Ok(count == 0)
}

/// Integrity pre-check (`PRAGMA integrity_check` on the staged copy),
/// then import via atomic no-replace publication. `link(2)` fails with
/// `AlreadyExists` if anything created the live path meanwhile — unlike
/// `rename(2)`, which would silently replace it — so the never-overwrite
/// invariant is enforced by the kernel, not by a check. The 0600 mode is
/// applied to the staged inode before linking, so the live path never
/// exists with wider permissions. Both paths sit on the same data volume,
/// so the hard link is always possible (same constraint `rename` had).
pub(crate) fn import(staged: &str, path: &str) -> bool {
    let check = match rusqlite::Connection::open_with_flags(
        staged,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) {
        Ok(c) => c
            .query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
            .unwrap_or_else(|e| format!("check failed: {e}")),
        Err(e) => format!("cannot open: {e}"),
    };
    if check != "ok" {
        log::err(&format!(
            "db restore: staged dump failed integrity check ({check})"
        ));
        return false;
    }
    if let Err(e) = std::fs::set_permissions(staged, std::fs::Permissions::from_mode(0o600)) {
        log::err(&format!("db restore: cannot secure staged dump: {e}"));
        return false;
    }
    match std::fs::hard_link(staged, path) {
        Ok(()) => {
            // Unlink the staging name; failure only leaves a stale copy
            // for the next staging sweep, never a wrong live file.
            let _ = std::fs::remove_file(staged);
            true
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            log::err("db restore: live DB appeared mid-restore; not overwriting");
            false
        }
        Err(e) => {
            log::err(&format!("db restore: cannot move dump into place: {e}"));
            false
        }
    }
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

        assert!(!import(staged.to_str().unwrap(), live.to_str().unwrap()));

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
        // and lands 0600.
        let target = dir.join("fresh.sqlite3");
        assert!(import(staged.to_str().unwrap(), target.to_str().unwrap()));
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(!staged.exists(), "staging name is unlinked after publish");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
