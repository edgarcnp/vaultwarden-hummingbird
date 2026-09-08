//! Emptiness verification for the boot-time restore: the gate that makes
//! restore miss-never-corrupt. Anything uncertain is Err (ambiguous),
//! never "empty" — callers fail closed.

use crate::config::{DbBackupConfig, DbSpec, BACKUP_TIMEOUT, DB_PING_TIMEOUT, MARIADB};
use crate::runtime::db::pg;
use crate::runtime::run_bounded_capture;

use super::dbenv::{defaults_file, mysql_env};

/// Emptiness per backend: sqlite = file absent; postgres = `users` table
/// verifiably missing; mysql = information_schema count via the mariadb
/// client. Anything uncertain is Err -> fail closed.
pub(super) fn is_empty(cfg: &DbBackupConfig, abort: &impl Fn() -> bool) -> Result<bool, String> {
    match &cfg.db {
        DbSpec::Sqlite { path } => Ok(!std::path::Path::new(path).exists()),
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
    let mut client =
        pg::connect(url, DB_PING_TIMEOUT).ok_or_else(|| "postgres unreachable".to_string())?;
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
