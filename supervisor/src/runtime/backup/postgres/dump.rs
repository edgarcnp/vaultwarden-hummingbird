//! Postgres dump: `pg_dump` in custom format (MVCC snapshot, no
//! downtime). Connection config rides env (libpq PG* vars) — never argv.

use crate::config::{DbBackupConfig, PG_DUMP};

use super::super::tools::tool;
use crate::runtime::db::tools::pg_env;

/// pg_dump (custom format, MVCC-consistent) into `staged`.
pub(crate) fn dump(cfg: &DbBackupConfig, staged: &str, abort: &impl Fn() -> bool) -> bool {
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
