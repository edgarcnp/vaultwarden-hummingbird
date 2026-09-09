//! Emptiness verification for the boot-time restore: the gate that makes
//! restore miss-never-corrupt. Anything uncertain is Err (ambiguous),
//! never "empty" — callers fail closed.

use crate::config::{DbBackupConfig, DbSpec};

/// Emptiness per backend: sqlite = file absent; postgres = `users` table
/// verifiably missing; mysql = information_schema count via the mariadb
/// client.
pub(super) fn is_empty(cfg: &DbBackupConfig, abort: &impl Fn() -> bool) -> Result<bool, String> {
    match &cfg.db {
        DbSpec::Sqlite { path } => super::sqlite::is_empty(path),
        DbSpec::Postgres { .. } => super::postgres::is_empty(&cfg.url),
        DbSpec::Mysql { db, .. } => super::mariadb::table_count(cfg, abort).map(|count| match db {
            None => false,
            Some(_) => count == 0,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::super::support;
    use super::*;

    #[test]
    fn sqlite_spec_dispatches_on_path_presence() {
        let cfg = support::cfg("sqlite:///nonexistent/db.sqlite3");
        let no_abort = || false;
        assert!(is_empty(&cfg, &no_abort).unwrap());
    }
}
