//! MariaDB/MySQL restore: emptiness gate (information_schema table count
//! via the `mariadb` client) and import (`source` streamed through the
//! client; batch mode stops on the first error and exits non-zero).
//! Credentials ride a 0600 defaults-file — never argv. TLS 1.3 only
//! (pinned in `db::tools::defaults_file`).

use crate::config::{BACKUP_TIMEOUT, DbBackupConfig, DbSpec, MARIADB};
use crate::runtime::{run_bounded_capture, run_bounded_env};
use crate::util::log;

use crate::runtime::db::tools::{defaults_file, mysql_env};

/// Table count in the vault's mysql database, via the mariadb client with
/// captured stdout. Any failure is Err (ambiguous). The count runs with
/// `--database` selected: without it `DATABASE()` is NULL and the query
/// returns 0 for ANY database — a fail-open emptiness gate.
pub(crate) fn table_count(cfg: &DbBackupConfig, abort: &impl Fn() -> bool) -> Result<u64, String> {
    let DbSpec::Mysql {
        host,
        port,
        user,
        password,
        db,
    } = &cfg.db
    else {
        return Err("not a mysql URL".to_string());
    };
    let Some(cnf) = defaults_file(user.as_deref(), password.as_deref(), host.as_deref(), *port)
    else {
        return Err("cannot stage defaults file".to_string());
    };
    let mut args: Vec<String> = vec![
        format!("--defaults-extra-file={cnf}"),
        "--skip-column-names".into(),
        "--execute=SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()"
            .into(),
    ];
    if let Some(db) = db {
        args.push(format!("--database={db}"));
    }
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = run_bounded_capture(BACKUP_TIMEOUT, MARIADB, &argv, &mysql_env(), abort);
    let _ = std::fs::remove_file(&cnf);
    let Some(out) = out else {
        return Err("mariadb empty-check failed or timed out".to_string());
    };
    out.trim()
        .parse::<u64>()
        .map_err(|_| "unexpected mariadb output".to_string())
}

/// Integrity pre-check (dump header) + import. Never touches the live DB
/// until the staged dump has been validated.
pub(crate) fn import(cfg: &DbBackupConfig, staged: &str, abort: &impl Fn() -> bool) -> bool {
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
    // integrity: header + non-empty (a truncated dump loses the trailing
    // dump-complete footer; the header alone is a weak check, so verify
    // the mysql client import exit code instead)
    if !dump_header_ok(staged) {
        log::err("db restore: staged dump failed header check");
        return false;
    }
    let Some(db) = db else {
        log::err("db restore: VAULTWARDEN_DATABASE_URL has no database name");
        return false;
    };
    let Some(cnf) = defaults_file(user.as_deref(), password.as_deref(), host.as_deref(), *port)
    else {
        log::err("db restore: cannot stage defaults file");
        return false;
    };
    let args = [
        format!("--defaults-extra-file={cnf}"),
        format!("--database={db}"),
        // `source` streams the dump through the client; batch mode stops
        // on the first error and exits non-zero.
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

/// mysql dumps start with a `-- MariaDB dump`/`-- MySQL dump` header line.
fn dump_header_ok(path: &str) -> bool {
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
        assert!(dump_header_ok(p.to_str().unwrap()));
        std::fs::write(&p, "garbage").unwrap();
        assert!(!dump_header_ok(p.to_str().unwrap()));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
