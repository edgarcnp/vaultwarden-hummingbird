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
/// then import (atomic rename). The live path was verified absent
/// immediately before; a re-check here keeps the invariant absolute.
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
    if Path::new(path).exists() {
        log::err("db restore: live DB appeared mid-restore; not overwriting");
        return false;
    }
    match std::fs::rename(staged, path) {
        Ok(()) => {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            true
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
}
