//! S3 DB backup (opt-in via SUPERVISOR_DB_BACKUP*): periodic consistent
//! dumps of the vault's database pushed to `<state remote>/db`, pruned to
//! keep-N per backend — plus an opt-in boot-time restore into an empty DB.
//!
//! Consistency per backend: postgres via `pg_dump` (MVCC snapshot, no
//! downtime); mysql via `mariadb-dump --single-transaction` (InnoDB
//! snapshot); sqlite via `VACUUM INTO` (consistent copy under WAL).
//! Every phase is bounded and non-fatal: a failed backup logs and
//! continues; the vault never waits on it.
//!
//! Safety model (miss-never-corrupt): dumps stage on the data volume and
//! are pushed to a NEW timestamped object (S3 objects are atomic — a
//! partial upload never materializes); pruning runs strictly after a
//! successful push. A kill at any point costs at most a missed backup,
//! never a corrupt one. Nothing here writes to the live DB except the
//! opt-in restore, which only ever touches a verifiably empty database.
//! Secrets ride env / a 0600 defaults-file — never argv.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use crate::config::{
    DbBackupConfig, DbSpec, BACKUP_TIMEOUT, DB_TOOL_LIB, MARIADB, MARIADB_DUMP, PG_DUMP,
    PG_RESTORE, RCLONE, SYNC_TIMEOUT,
};
use crate::proc::{pg, run_bounded_capture, run_bounded_env};
use crate::util::log;

/// Timestamp for object names: UTC, `YYYYMMDDTHHMMSSZ` (sortable).
fn timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let days = now.as_secs() / 86_400;
    let secs_of_day = now.as_secs() % 86_400;
    let (y, m, d) = civil_from_days(days as i64);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        secs_of_day / 3600,
        secs_of_day % 3600 / 60,
        secs_of_day % 60
    )
}

/// Days-since-epoch to (year, month, day) — Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

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

/// Remove stale staging artifacts from `dir` (a previous run may have
/// been killed mid-dump) and ensure the directory exists. An uncleanable
/// directory aborts the run rather than risking a full volume.
fn sweep_staging(dir: &str) -> bool {
    let dir = Path::new(dir);
    if let Err(e) = std::fs::create_dir_all(dir) {
        log::err(&format!("db backup: cannot create staging dir: {e}"));
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

/// Run one dump/import tool, bounded; logs (secret-free) on failure.
fn tool(
    name: &str,
    prog: &str,
    args: &[&str],
    env: &[(String, String)],
    staged: &str,
    abort: &impl Fn() -> bool,
) -> bool {
    if run_bounded_env(BACKUP_TIMEOUT, prog, args, env, abort) {
        true
    } else {
        let _ = std::fs::remove_file(staged);
        log::err(&format!("db backup: {name} failed or timed out"));
        false
    }
}

/// libpq env vars for the dump/restore tools (secrets ride env, never
/// argv — /proc cmdline is world-readable).
fn pg_env(db: &DbSpec) -> Vec<(String, String)> {
    let DbSpec::Postgres {
        host,
        port,
        user,
        password,
        db,
        sslmode,
    } = db
    else {
        return Vec::new();
    };
    let mut env = vec![("LD_LIBRARY_PATH".to_string(), DB_TOOL_LIB.to_string())];
    if let Some(h) = host {
        env.push(("PGHOST".to_string(), h.clone()));
    }
    env.push(("PGPORT".to_string(), port.to_string()));
    if let Some(u) = user {
        env.push(("PGUSER".to_string(), u.clone()));
    }
    if let Some(p) = password {
        env.push(("PGPASSWORD".to_string(), p.clone()));
    }
    if let Some(d) = db {
        env.push(("PGDATABASE".to_string(), d.clone()));
    }
    if let Some(s) = sslmode {
        env.push(("PGSSLMODE".to_string(), s.clone()));
    }
    env
}

/// Shared-lib dir for the mariadb tools, extracted by the image build.
fn mysql_env() -> Vec<(String, String)> {
    vec![("LD_LIBRARY_PATH".to_string(), DB_TOOL_LIB.to_string())]
}

/// 0600 defaults file for mariadb tools; under /tmp (tmpfs,
/// container-private); removed by the caller after the run.
fn defaults_file(
    user: Option<&str>,
    password: Option<&str>,
    host: Option<&str>,
    port: u16,
) -> Option<String> {
    let path = format!("/tmp/.my-{}", std::process::id());
    let mut content = String::from("[client]\n");
    if let Some(u) = user {
        content.push_str(&format!("user={u}\n"));
    }
    if let Some(p) = password {
        // my.cnf quoting: embedded quotes/backslashes are escaped with '\'
        content.push_str(&format!(
            "password=\"{}\"\n",
            p.replace('\\', "\\\\").replace('"', "\\\"")
        ));
    }
    if let Some(h) = host {
        content.push_str(&format!("host={h}\n"));
    }
    content.push_str(&format!("port={port}\n"));
    std::fs::write(&path, content).ok()?;
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    Some(path)
}

/// Restrict a staged dump to owner-only before it leaves the volume.
fn lock_down(path: &str) {
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

/// One bounded rclone invocation with the shared backend env.
fn rclone(cfg: &DbBackupConfig, args: &[&str], abort: &impl Fn() -> bool) -> bool {
    run_bounded_env(SYNC_TIMEOUT, RCLONE, args, &cfg.sync.env, abort)
}

/// Delete the oldest per-backend dumps beyond keep-N. Listing failure
/// skips pruning entirely — never delete blind. Sort by name == sort by
/// timestamp (fixed-width sortable names).
fn prune(cfg: &DbBackupConfig, abort: &impl Fn() -> bool) {
    let prefix = cfg.prefix();
    let listing = format!("{}/{}-*", prefix, cfg.db.label());
    let args = ["lsf", &listing, "--files-only"];
    let Some(out) = run_bounded_capture(SYNC_TIMEOUT, RCLONE, &args, &cfg.sync.env, abort) else {
        log::err("db backup: prune skipped (listing failed)");
        return;
    };
    let mut names: Vec<&str> = out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    names.sort();
    if names.len() <= cfg.keep {
        return;
    }
    for name in names[..names.len() - cfg.keep].iter() {
        let object = format!("{prefix}/{name}");
        if rclone(cfg, &["deletefile", &object], abort) {
            log::info(&format!("db backup: pruned {object}"));
        } else {
            log::err("db backup: prune delete failed; continuing");
        }
    }
}

/// Boot-time restore (opt-in via SUPERVISOR_DB_BACKUP_RESTORE): runs
/// before vaultwarden spawns. Acts ONLY on an unambiguously empty DB;
/// ambiguity (unreachable, malformed) fails closed — never overwrites
/// existing data.
pub fn restore_if_empty(cfg: &DbBackupConfig, abort: impl Fn() -> bool) {
    if !cfg.restore {
        return;
    }
    match is_empty(cfg, &abort) {
        Err(e) => log::err(&format!(
            "db restore: cannot verify the DB is empty ({e}); not restoring (fail-closed)"
        )),
        Ok(false) => log::info("db restore: database is not empty; skipped"),
        Ok(true) => {
            log::info("db restore: database is empty; looking for the newest backup");
            let Some(object) = newest_object(cfg, &abort) else {
                log::err("db restore: empty DB but no backup found in the bucket");
                return;
            };
            if abort() {
                return;
            }
            log::info(&format!("db restore: importing {object}"));
            if restore_object(cfg, &object, &abort) {
                log::info("db restore: done");
            } else {
                log::err("db restore: import failed; vaultwarden will surface the DB state");
            }
        }
    }
}

/// Emptiness per backend: sqlite = file absent; postgres = `users` table
/// verifiably missing; mysql = information_schema count via the mariadb
/// client. Anything uncertain is Err -> fail closed.
fn is_empty(cfg: &DbBackupConfig, abort: &impl Fn() -> bool) -> Result<bool, String> {
    match &cfg.db {
        DbSpec::Sqlite { path } => Ok(!Path::new(path).exists()),
        DbSpec::Postgres { .. } => pg_users_missing(&cfg.url),
        DbSpec::Mysql { db, .. } => mysql_table_count(cfg, abort).map(|count| {
            match db {
                // no database name in the URL = nothing to restore into
                None => false,
                Some(_) => count == 0,
            }
        }),
    }
}

/// True iff the `users` table is verifiably absent. Connection/query
/// failures are Err (ambiguous), never "empty".
fn pg_users_missing(url: &str) -> Result<bool, String> {
    let mut client = pg::connect(url, crate::config::DB_PING_TIMEOUT)
        .ok_or_else(|| "postgres unreachable".to_string())?;
    let rows = client
        .query(
            "SELECT 1 FROM information_schema.tables \
             WHERE table_schema = 'public' AND table_name = 'users'",
            &[],
        )
        .map_err(|e| format!("query failed: {e}"))?;
    Ok(rows.is_empty())
}

/// Table count in the vault's mysql database, via the mariadb client with
/// captured stdout. Any failure is Err (ambiguous).
fn mysql_table_count(cfg: &DbBackupConfig, abort: &impl Fn() -> bool) -> Result<u64, String> {
    let DbSpec::Mysql {
        host,
        port,
        user,
        password,
        ..
    } = &cfg.db
    else {
        return Err("not a mysql URL".to_string());
    };
    let Some(cnf) = defaults_file(user.as_deref(), password.as_deref(), host.as_deref(), *port)
    else {
        return Err("cannot stage defaults file".to_string());
    };
    let args = [
        &format!("--defaults-extra-file={cnf}"),
        "--skip-column-names",
        "--execute=SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()",
    ];
    let out = run_bounded_capture(BACKUP_TIMEOUT, MARIADB, &args, &mysql_env(), abort);
    let _ = std::fs::remove_file(&cnf);
    let Some(out) = out else {
        return Err("mariadb empty-check failed or timed out".to_string());
    };
    out.trim()
        .parse::<u64>()
        .map_err(|_| "unexpected mariadb output".to_string())
}

/// The newest dump object for this backend (name order == time order).
fn newest_object(cfg: &DbBackupConfig, abort: &impl Fn() -> bool) -> Option<String> {
    let prefix = cfg.prefix();
    let listing = format!("{prefix}/{}-*", cfg.db.label());
    let args = ["lsf", &listing, "--files-only"];
    let out = run_bounded_capture(SYNC_TIMEOUT, RCLONE, &args, &cfg.sync.env, abort)?;
    let mut names: Vec<&str> = out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    names.sort();
    names.last().map(|name| format!("{prefix}/{name}"))
}

/// Download the object into staging, verify integrity, import, clean up.
fn restore_object(cfg: &DbBackupConfig, object: &str, abort: &impl Fn() -> bool) -> bool {
    if !sweep_staging(&cfg.staging) {
        return false;
    }
    let staged = format!("{}/restore-{}", cfg.staging, cfg.db.label());
    if !rclone(cfg, &["copyto", object, &staged], abort) {
        log::err("db restore: download failed");
        let _ = std::fs::remove_file(&staged);
        return false;
    }
    let ok = import(cfg, &staged, abort);
    let _ = std::fs::remove_file(&staged);
    ok
}

/// Integrity pre-check + import per backend. Never touches the live DB
/// until the staged dump has been validated.
fn import(cfg: &DbBackupConfig, staged: &str, abort: &impl Fn() -> bool) -> bool {
    match &cfg.db {
        DbSpec::Postgres { .. } => {
            let env = pg_env(&cfg.db);
            // integrity: the custom format must parse; --list reads only
            // the archive, no connection needed.
            let check = ["--list", staged];
            if !tool("pg_restore --list", PG_RESTORE, &check, &env, staged, abort) {
                return false;
            }
            let args = ["--no-owner", "--no-privileges", staged];
            tool("pg_restore", PG_RESTORE, &args, &env, staged, abort)
        }
        DbSpec::Mysql { db, .. } => {
            let DbSpec::Mysql {
                host,
                port,
                user,
                password,
                ..
            } = &cfg.db
            else {
                return false;
            };
            // integrity: header + non-empty (a truncated dump loses the
            // trailing dump-complete footer; the header alone is a weak
            // check, so verify the mysql client import exit code instead)
            if !mysql_dump_header_ok(staged) {
                log::err("db restore: staged dump failed header check");
                return false;
            }
            let Some(db) = db else {
                log::err("db restore: DATABASE_URL has no database name");
                return false;
            };
            let Some(cnf) =
                defaults_file(user.as_deref(), password.as_deref(), host.as_deref(), *port)
            else {
                log::err("db restore: cannot stage defaults file");
                return false;
            };
            let args = [
                format!("--defaults-extra-file={cnf}"),
                format!("--database={db}"),
                // `source` streams the dump through the client; batch mode
                // stops on the first error and exits non-zero.
                format!("--execute=source {staged}"),
            ];
            let argv: Vec<&str> = args.iter().map(String::as_str).collect();
            let ok = run_bounded_env(BACKUP_TIMEOUT, MARIADB, &argv, &mysql_env(), abort);
            let _ = std::fs::remove_file(&cnf);
            if !ok {
                let _ = std::fs::remove_file(staged);
                log::err("db restore: mariadb import failed");
            }
            ok
        }
        DbSpec::Sqlite { path } => {
            // integrity: pragma check on the staged copy first
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
            // Same filesystem (data volume): atomic rename, no torn copy.
            // The live path was verified absent immediately before; a
            // re-check here keeps the never-overwrite invariant absolute.
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
    }
}

/// mysql dumps start with a `-- MariaDB dump`/`-- MySQL dump` header line.
fn mysql_dump_header_ok(path: &str) -> bool {
    use std::io::Read;
    let mut buf = [0u8; 64];
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let n = f.read(&mut buf).unwrap_or(0);
    let head = &buf[..n];
    n > 0 && (head.starts_with(b"-- MariaDB dump") || head.starts_with(b"-- MySQL dump"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Unique-ish staging dir per test invocation (tests run concurrently
    /// on one process).
    fn next_staging() -> String {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("vw-sup-stage-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.to_string_lossy().into_owned()
    }

    fn cfg(url: &str) -> DbBackupConfig {
        DbBackupConfig {
            sync: crate::config::SyncConfig::new(
                "r2:vw".into(),
                "id".into(),
                "secret".into(),
                String::new(),
                Duration::from_secs(60),
            ),
            url: url.to_string(),
            db: DbSpec::Sqlite {
                path: "/nonexistent/db.sqlite3".into(),
            },
            periodic: true,
            interval: Duration::from_secs(43_200),
            keep: 3,
            restore: false,
            staging: next_staging(),
        }
    }

    #[test]
    fn timestamp_is_sortable_utc() {
        let ts = timestamp();
        assert_eq!(ts.len(), 16);
        assert!(ts.ends_with('Z'));
        assert!(ts.chars().take(15).all(|c| c.is_ascii_digit() || c == 'T'));
    }

    #[test]
    fn civil_epoch_and_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // verified: 2026-09-08 - 1970-01-01 = 20704 days
        assert_eq!(civil_from_days(20_704), (2026, 9, 8));
        // leap-day inclusive: 2000-02-29 is day 11016
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
    }

    /// A backup run against a nonexistent sqlite source: dump fails
    /// cleanly, nothing staged, nothing uploaded.
    #[test]
    fn tick_fails_cleanly_on_missing_source() {
        let cfg = cfg("sqlite:///nonexistent/db.sqlite3");
        tick(&cfg, || false);
        // staging dir exists (created by sweep) but is empty again
        let entries: Vec<_> = std::fs::read_dir(&cfg.staging)
            .expect("staging dir created")
            .collect();
        assert!(entries.is_empty());
        let _ = std::fs::remove_dir(&cfg.staging);
    }

    #[test]
    fn staging_sweeps_leftovers() {
        let cfg = cfg("sqlite:///nonexistent/db.sqlite3");
        std::fs::create_dir_all(&cfg.staging).unwrap();
        std::fs::write(format!("{}/postgres-stale", cfg.staging), "garbage").unwrap();
        assert!(sweep_staging(&cfg.staging));
        let entries: Vec<_> = std::fs::read_dir(&cfg.staging).unwrap().collect();
        assert!(entries.is_empty());
        let _ = std::fs::remove_dir(&cfg.staging);
    }

    /// restore_if_empty with restore disabled is a no-op (no network, no
    /// staging, no logs of consequence).
    #[test]
    fn restore_noop_when_disabled() {
        restore_if_empty(&cfg("sqlite:///nonexistent/db.sqlite3"), || false);
    }

    #[test]
    fn pg_env_carries_connection_config() {
        let db = DbSpec::Postgres {
            host: Some("h".into()),
            port: 6543,
            user: Some("u".into()),
            password: Some("p@".into()),
            db: Some("vault".into()),
            sslmode: Some("require".into()),
        };
        let env = pg_env(&db);
        assert!(env.contains(&("PGHOST".to_string(), "h".to_string())));
        assert!(env.contains(&("PGPORT".to_string(), "6543".to_string())));
        assert!(env.contains(&("PGUSER".to_string(), "u".to_string())));
        assert!(env.contains(&("PGPASSWORD".to_string(), "p@".to_string())));
        assert!(env.contains(&("PGDATABASE".to_string(), "vault".to_string())));
        assert!(env.contains(&("PGSSLMODE".to_string(), "require".to_string())));
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

    #[test]
    fn mysql_dump_header_check() {
        let dir = std::env::temp_dir().join(format!("vw-sup-hdr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("d.sql");
        std::fs::write(&p, "-- MariaDB dump 10.19\n\nCREATE TABLE ...;\n").unwrap();
        assert!(mysql_dump_header_ok(p.to_str().unwrap()));
        std::fs::write(&p, "garbage").unwrap();
        assert!(!mysql_dump_header_ok(p.to_str().unwrap()));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
