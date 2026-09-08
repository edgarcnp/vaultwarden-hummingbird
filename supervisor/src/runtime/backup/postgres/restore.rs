//! Postgres restore: emptiness gate (the `users` table verifiably
//! missing, via the native client) and import (`pg_restore` after a
//! `--list` parse check). Connection config rides env (libpq PG* vars)
//! — never argv. TLS 1.3 only (env pinned in `db::tools::pg_env`).

use crate::config::{DB_PING_TIMEOUT, DbBackupConfig, PG_RESTORE};
use crate::runtime::db::pg;

use super::super::tools::tool;
use crate::runtime::db::tools::pg_env;

/// True iff the `users` table is verifiably absent. Connection/query
/// failures are Err (ambiguous), never "empty".
pub(crate) fn is_empty(url: &str) -> Result<bool, String> {
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

/// Integrity pre-check (`--list` parses the custom-format archive; reads
/// only the archive, no connection) + import. Never touches the live DB
/// until the staged dump has been validated.
pub(crate) fn import(cfg: &DbBackupConfig, staged: &str, abort: &impl Fn() -> bool) -> bool {
    let env = pg_env(&cfg.db);
    let check = ["--list", staged];
    if !tool("pg_restore --list", PG_RESTORE, &check, &env, staged, abort) {
        return false;
    }
    let args = ["--no-owner", "--no-privileges", staged];
    tool("pg_restore", PG_RESTORE, &args, &env, staged, abort)
}
