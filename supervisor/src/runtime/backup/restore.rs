//! The boot-time restore path: verify emptiness (fail closed), pull the
//! newest backup, dispatch to the per-backend import. A failed import is
//! fatal: starting the vault on a half-restored database would surface
//! partial state as the vault's truth — the container exits and the
//! orchestrator retries instead.

use crate::config::{DbBackupConfig, DbSpec};
use crate::util::log;

use super::check::is_empty;
use super::staging::sweep_staging;
use super::tools::rclone;

/// Boot-time restore (opt-in via SUPERVISOR_DB_BACKUP_RESTORE): runs
/// before vaultwarden spawns. Acts ONLY on an unambiguously empty DB;
/// ambiguity (unreachable, malformed) fails closed — never overwrites
/// existing data. Returns false only when a restore was attempted and
/// failed: the caller must not start the vault. "No backup found" is not
/// a failure (a fresh deployment legitimately boots on an empty DB).
pub fn restore_if_empty(cfg: &DbBackupConfig, abort: impl Fn() -> bool) -> bool {
    if !cfg.restore {
        return true;
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
                return true;
            };
            if abort() {
                return true;
            }
            log::info(&format!("db restore: importing {object}"));
            if restore_object(cfg, &object, &abort) {
                log::info("db restore: done");
            } else {
                log::err(
                    "db restore: import failed; refusing to start the vault on a \
                     partially restored database",
                );
                return false;
            }
        }
    }
    true
}

/// The newest dump object for this backend (name order == time order).
fn newest_object(cfg: &DbBackupConfig, abort: &impl Fn() -> bool) -> Option<String> {
    let prefix = cfg.prefix();
    let pattern = format!("{prefix}/{}-*", cfg.db.label());
    let mut names = super::tools::list_objects(cfg, &pattern, abort)?;
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
    let ok = match &cfg.db {
        DbSpec::Postgres { .. } => super::postgres::import(cfg, &staged, abort),
        DbSpec::Mysql { .. } => super::mariadb::import(cfg, &staged, abort),
        DbSpec::Sqlite { path } => super::sqlite::import(&staged, path),
    };
    let _ = std::fs::remove_file(&staged);
    ok
}

#[cfg(test)]
mod tests {
    use super::super::support;
    use super::*;

    #[test]
    fn restore_noop_when_disabled() {
        assert!(restore_if_empty(&support::cfg(), || false));
    }

    /// No backup in the bucket is not a failure: a fresh deployment
    /// legitimately boots on an empty DB.
    #[test]
    fn restore_with_no_backup_found_is_not_fatal() {
        let mut cfg = support::cfg();
        cfg.restore = true;
        assert!(restore_if_empty(&cfg, || false));
    }
}
