//! Postgres restore: emptiness gate (no application relations anywhere
//! outside system/extension schemas, via the native client) and import
//! (`pg_restore` in one transaction after a `--list` parse check).
//! Connection config rides env (libpq PG* vars) — never argv. TLS 1.3
//! only (env pinned in `db::tools::pg_env`).

use crate::config::{DbBackupConfig, DbSpec, DB_PING_TIMEOUT, PG_RESTORE};
use crate::runtime::db::pg;
use crate::util::log;

use super::super::tools::tool;
use crate::runtime::db::tools::pg_env;

/// True iff the database holds no application relations: no user tables in
/// any schema outside `pg_catalog`/`information_schema` and the schemas
/// owned by extensions. A lone sentinel table is not enough — a database
/// with other deployments' tables, migration artifacts, or user objects
/// must never qualify for automatic restore. Connection/query failures are
/// Err (ambiguous), never "empty".
pub(crate) fn is_empty(url: &str) -> Result<bool, String> {
    let mut client =
        pg::connect(url, DB_PING_TIMEOUT).ok_or_else(|| "postgres unreachable".to_string())?;
    let rows = client
        .query(
            "SELECT 1 FROM pg_catalog.pg_tables \
             WHERE schemaname NOT IN ('pg_catalog', 'information_schema') \
             AND schemaname NOT IN (SELECT nspname FROM pg_catalog.pg_namespace \
             WHERE oid IN (SELECT extnamespace FROM pg_catalog.pg_extension)) \
             LIMIT 1",
            &[],
        )
        .map_err(|e| format!("query failed: {e}"))?;
    Ok(rows.is_empty())
}

/// Integrity pre-check (`--list` parses the custom-format archive; reads
/// only the archive, no connection) + import. Never touches the live DB
/// until the staged dump has been validated. `--dbname` is required:
/// without it pg_restore writes the SQL script to stdout and exits 0 —
/// a silent no-op restore. A URL without a database name fails closed.
/// `--single-transaction` makes the import atomic: a failing statement
/// rolls the whole restore back, so the (verified-empty) database stays
/// empty and the next boot can retry cleanly instead of finding a
/// half-restored state.
pub(crate) fn import(cfg: &DbBackupConfig, staged: &str, abort: &impl Fn() -> bool) -> bool {
    let DbSpec::Postgres { db: Some(db), .. } = &cfg.db else {
        log::err("db restore: VAULTWARDEN_DATABASE_URL has no database name");
        return false;
    };
    let env = pg_env(&cfg.db);
    let check = ["--list", staged];
    if !tool("pg_restore --list", PG_RESTORE, &check, &env, staged, abort) {
        return false;
    }
    let args = restore_args(db, staged);
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    tool("pg_restore", PG_RESTORE, &argv, &env, staged, abort)
}

/// pg_restore import arguments (pure, unit-tested).
fn restore_args(db: &str, staged: &str) -> Vec<String> {
    vec![
        "--single-transaction".to_string(),
        "--dbname".to_string(),
        db.to_string(),
        "--no-owner".to_string(),
        "--no-privileges".to_string(),
        staged.to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restore_args_are_single_transaction() {
        let args = restore_args("vault", "/data/db-backups/restore-postgres");
        assert_eq!(
            args,
            vec![
                "--single-transaction".to_string(),
                "--dbname".to_string(),
                "vault".to_string(),
                "--no-owner".to_string(),
                "--no-privileges".to_string(),
                "/data/db-backups/restore-postgres".to_string(),
            ]
        );
    }
}
