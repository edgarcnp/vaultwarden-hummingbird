//! SQLite dump: `VACUUM INTO` a fresh consistent copy, in-process
//! (bundled rusqlite — no external tool). The source may be in WAL use by
//! the vault; a busy DB fails the run cleanly (bounded busy timeout,
//! never blocks the vault).

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::util::log;

/// `VACUUM INTO` a fresh consistent copy of the sqlite DB at `path` into
/// `staged`. `abort` is honoured through `sqlite3_interrupt`, so a shutdown
/// budget cannot be overrun by a large database dump.
pub(crate) fn dump(path: &str, staged: &str, abort: &(impl Fn() -> bool + Sync)) -> bool {
    if abort() {
        return false;
    }
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
    let interrupt = conn.get_interrupt_handle();
    let done = AtomicBool::new(false);
    let result = std::thread::scope(|scope| {
        scope.spawn(|| {
            while !done.load(Ordering::Relaxed) {
                if abort() {
                    interrupt.interrupt();
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        let result = conn.execute("VACUUM INTO ?1", [staged]).map(|_| ());
        done.store(true, Ordering::Relaxed);
        result
    });
    match result {
        Ok(()) => true,
        Err(e) => {
            // VACUUM INTO can leave a partial output before failing: a
            // sensitive half-dump must never linger in staging (the next
            // sweep would clear it, but why keep it hours).
            let _ = std::fs::remove_file(staged);
            log::err(&format!("db backup: sqlite VACUUM INTO failed: {e}"));
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_dump_failure_removes_the_partial_staged_file() {
        let dir = std::env::temp_dir().join(format!("vw-sup-bkfail-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // A garbage "source" makes VACUUM INTO fail after creating output.
        let src = dir.join("garbage.sqlite3");
        std::fs::write(&src, b"not a database").unwrap();
        let staged = dir.join("dump.sqlite3");
        std::fs::write(&staged, b"pre-existing sentinel").unwrap();
        assert!(!dump(
            src.to_str().unwrap(),
            staged.to_str().unwrap(),
            &|| false
        ));
        assert!(
            !staged.exists(),
            "failed dump must not leave partial output"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dump_honours_an_immediate_abort() {
        let dir = std::env::temp_dir().join(format!("vw-sup-bkabort-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let staged = dir.join("never.sqlite3");
        assert!(!dump(
            "/nonexistent/source.sqlite3",
            staged.to_str().unwrap(),
            &|| true
        ));
        assert!(!staged.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

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
        assert!(dump(
            src.to_str().unwrap(),
            staged.to_str().unwrap(),
            &|| false
        ));
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
