//! Emptiness verification for the boot-time restore (backend dispatch +
//! the fail-closed contract): the gate that makes restore
//! miss-never-corrupt. Anything uncertain is Err (ambiguous), never
//! "empty" — callers fail closed. Per-backend checks live in the
//! `pg_restore`/`mariadb_restore`/`sqlite_restore` modules.

use crate::config::{DbBackupConfig, DbSpec};

/// Emptiness per backend: sqlite = file absent; postgres = `users` table
/// verifiably missing; mysql = information_schema count via the mariadb
/// client. Anything uncertain is Err -> fail closed.
pub(super) fn is_empty(cfg: &DbBackupConfig, abort: &impl Fn() -> bool) -> Result<bool, String> {
    match &cfg.db {
        DbSpec::Sqlite { path } => super::sqlite::is_empty(path),
        DbSpec::Postgres { .. } => super::postgres::is_empty(&cfg.url),
        DbSpec::Mysql { db, .. } => super::mariadb::table_count(cfg, abort).map(|count| {
            match db {
                // no database name in the URL = nothing to restore into
                None => false,
                Some(_) => count == 0,
            }
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::super::support;
    use super::*;

    /// The is_empty dispatch is only reachable with matching backend
    /// specs; a malformed pair must never claim emptiness.
    #[test]
    fn sqlite_spec_dispatches_on_path_presence() {
        // Sqlite spec: file absent -> empty (no side effects).
        let cfg = support::cfg("sqlite:///nonexistent/db.sqlite3");
        let no_abort = || false;
        assert!(is_empty(&cfg, &no_abort).unwrap());
    }
}
