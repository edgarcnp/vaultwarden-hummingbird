//! SQLite dump: `VACUUM INTO` a fresh consistent copy, in-process
//! (bundled rusqlite — no external tool). The source may be in WAL use by
//! the vault; a busy DB fails the run cleanly (bounded busy timeout,
//! never blocks the vault).

use std::time::Duration;

use crate::config::DbSpec;
use crate::util::log;

/// `VACUUM INTO` a fresh consistent copy into `staged`.
pub(crate) fn dump(db: &DbSpec, staged: &str) -> bool {
    let DbSpec::Sqlite { path } = db else {
        return false;
    };
    let conn = match rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) {
        Ok(c) => c,
        Err(e) => {
            log::err(&format!("db backup: cannot open sqlite db: {e}"));
            return false;
        }
    };
    // VACUUM INTO does not modify the source; read-only is enough and
    // guarantees it.
    if let Err(e) = conn.busy_timeout(Duration::from_secs(30)) {
        log::err(&format!("db backup: sqlite busy_timeout failed: {e}"));
        return false;
    }
    match conn.execute_batch(&format!("VACUUM INTO '{}'", staged.replace('\'', "''"))) {
        Ok(()) => true,
        Err(e) => {
            log::err(&format!("db backup: sqlite VACUUM INTO failed: {e}"));
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_dump_from_readonly_handle_is_valid() {
        let dir = std::env::temp_dir().join(format!("vw-sup-bk-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.sqlite3");
        {
            let conn = rusqlite::Connection::open(&src).unwrap();
            conn.execute_batch(
                "PRAGMA journal_mode=WAL; CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('x');",
            )
            .unwrap();
        }
        let staged = dir.join("dumped.sqlite3");
        let db = DbSpec::Sqlite {
            path: src.to_string_lossy().into_owned(),
        };
        assert!(dump(&db, staged.to_str().unwrap()));
        let copy = rusqlite::Connection::open_with_flags(
            &staged,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let v: String = copy
            .query_row("SELECT v FROM t LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, "x");
        let ok: String = copy
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap();
        assert_eq!(ok, "ok");
        drop(copy);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
