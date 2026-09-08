//! The periodic backup cycle (sweep -> dump -> push -> prune) and the
//! per-backend dump commands.

use std::time::Duration;

use crate::config::{BACKUP_TIMEOUT, DbBackupConfig, DbSpec, MARIADB_DUMP, PG_DUMP};
use crate::proc::run_bounded_env;
use crate::util::log;

use super::dbenv::{defaults_file, mysql_env, pg_env};
use super::prune::prune;
use super::staging::{lock_down, sweep_staging};
use super::timestamp::timestamp;
use super::tools::{rclone, tool};

/// One periodic backup cycle: sweep staging, dump, push, prune. Runs on
/// the watch loop's spawned backup thread; never fatal, aborting early on
/// a stop request.
pub fn tick(cfg: &DbBackupConfig, abort: impl Fn() -> bool) {
    if abort() {
        return;
    }
    let ts = timestamp();
    let staged = format!("{}/{}-{ts}.{}", cfg.staging, cfg.db.label(), cfg.db.ext());
    let object = format!("{}/{}-{ts}.{}", cfg.prefix(), cfg.db.label(), cfg.db.ext());

    if !sweep_staging(&cfg.staging) {
        return;
    }
    let dumped = match &cfg.db {
        DbSpec::Postgres { .. } => dump_postgres(cfg, &staged, &abort),
        DbSpec::Mysql { .. } => dump_mysql(cfg, &staged, &abort),
        DbSpec::Sqlite { .. } => dump_sqlite(&cfg.db, &staged),
    };
    if !dumped {
        log::err("db backup: dump failed; continuing (bucket unchanged)");
        return;
    }
    lock_down(&staged);
    let size = std::fs::metadata(&staged).map(|m| m.len()).unwrap_or(0);
    if !rclone(cfg, &["copyto", &staged, &object], &abort) {
        log::err("db backup: push failed; continuing (previous backups intact)");
        let _ = std::fs::remove_file(&staged);
        return;
    }
    let _ = std::fs::remove_file(&staged);
    log::info(&format!("db backup: pushed {object} ({size} bytes)"));
    prune(cfg, &abort);
}

/// pg_dump (custom format, MVCC-consistent). Connection config rides env
/// (libpq PG* vars) — never argv.
fn dump_postgres(cfg: &DbBackupConfig, staged: &str, abort: &impl Fn() -> bool) -> bool {
    let env = pg_env(&cfg.db);
    let args = [
        "--format=custom",
        "--no-owner",
        "--no-privileges",
        "--file",
        staged,
    ];
    tool("pg_dump", PG_DUMP, &args, &env, staged, abort)
}

/// mariadb-dump (`--single-transaction` InnoDB snapshot). Credentials ride
/// a 0600 defaults-file — mariadb tools have no password env var and argv
/// is world-readable in /proc.
fn dump_mysql(cfg: &DbBackupConfig, staged: &str, abort: &impl Fn() -> bool) -> bool {
    let DbSpec::Mysql {
        host,
        port,
        user,
        password,
        db,
    } = &cfg.db
    else {
        return false;
    };
    let Some(cnf) = defaults_file(user.as_deref(), password.as_deref(), host.as_deref(), *port)
    else {
        log::err("db backup: cannot stage mariadb defaults file");
        return false;
    };
    let mut args: Vec<String> = vec![
        format!("--defaults-extra-file={cnf}"),
        "--single-transaction".into(),
        "--quick".into(),
        format!("--result-file={staged}"),
    ];
    args.extend(db.iter().cloned());
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let ok = run_bounded_env(BACKUP_TIMEOUT, MARIADB_DUMP, &argv, &mysql_env(), || {
        abort()
    });
    let _ = std::fs::remove_file(&cnf);
    if ok {
        true
    } else {
        log::err("db backup: mariadb-dump failed or timed out");
        false
    }
}

/// `VACUUM INTO` a fresh consistent copy, in-process (bundled sqlite).
/// The source may be in WAL use by the vault; a busy DB fails the run
/// cleanly (bounded busy timeout, never blocks the vault).
fn dump_sqlite(db: &DbSpec, staged: &str) -> bool {
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
    use super::super::support;
    use super::*;

    /// A backup run against a nonexistent sqlite source: dump fails
    /// cleanly, nothing staged, nothing uploaded.
    #[test]
    fn tick_fails_cleanly_on_missing_source() {
        let cfg = support::cfg("sqlite:///nonexistent/db.sqlite3");
        tick(&cfg, || false);
        // staging dir exists (created by sweep) but is empty again
        let entries: Vec<_> = std::fs::read_dir(&cfg.staging)
            .expect("staging dir created")
            .collect();
        assert!(entries.is_empty());
        let _ = std::fs::remove_dir(&cfg.staging);
    }

    /// A sqlite dump round-trips through VACUUM INTO from a read-only
    /// connection: this is the load-bearing consistency claim for the
    /// sqlite backend.
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
        assert!(dump_sqlite(&db, staged.to_str().unwrap()));
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
