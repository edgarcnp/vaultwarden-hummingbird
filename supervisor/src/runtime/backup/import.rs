//! The boot-time restore path: download the newest backup, verify it,
//! import it — only ever into a verifiably empty database.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::config::{BACKUP_TIMEOUT, DbBackupConfig, DbSpec, MARIADB, PG_RESTORE};
use crate::runtime::run_bounded_env;
use crate::util::log;

use super::check::is_empty;
use super::super::db::tools::{defaults_file, mysql_env, pg_env};
use super::staging::sweep_staging;
use super::tools::{list_objects, rclone, tool};

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

/// The newest dump object for this backend (name order == time order).
fn newest_object(cfg: &DbBackupConfig, abort: &impl Fn() -> bool) -> Option<String> {
    let prefix = cfg.prefix();
    let pattern = format!("{prefix}/{}-*", cfg.db.label());
    let mut names = list_objects(cfg, &pattern, abort)?;
    names.pop().map(|name| format!("{prefix}/{name}"))
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
