//! The boot-time restore path: verify emptiness (fail closed), pull the
//! newest backup, import it. A failed import is fatal: starting the vault
//! on a half-restored database would surface partial state as the vault's
//! truth — the container exits and the orchestrator retries instead.

use crate::config::DbBackupConfig;
use crate::util::log;

use super::check::is_empty;
use super::lineage;
use super::staging::sweep_staging;
use super::tools::{list_objects, rclone};

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
    match is_empty(cfg) {
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

/// The newest dump object (name order == time order).
fn newest_object(cfg: &DbBackupConfig, abort: &impl Fn() -> bool) -> Option<String> {
    let mut names = super::tools::list_objects(cfg, abort)?;
    names.pop().map(|name| format!("{}/{name}", cfg.prefix()))
}

/// Boot-time lineage adoption (SUPERVISOR_DB_BACKUP_RESTORE=true): the
/// flag declares the bucket authoritative for this data volume, so a
/// non-empty database with no recorded lineage — an upgrade from before
/// the guard existed, or a volume the operator knows matches the bucket —
/// adopts the bucket's newest dump as its lineage and periodic pushes
/// continue. Without the flag the tick refuses, loudly, and nothing is
/// guessed. An empty DB needs nothing here (the import path records
/// lineage); a listing failure needs nothing here (the tick skips loudly).
pub fn adopt_lineage(cfg: &DbBackupConfig, abort: impl Fn() -> bool) {
    if !cfg.restore || lineage::read(&cfg.db_path).is_some() {
        return;
    }
    if is_empty(cfg) != Ok(false) {
        return;
    }
    let Some(newest) = list_objects(cfg, &abort).and_then(|mut n| n.pop()) else {
        return;
    };
    lineage::write(&cfg.db_path, &newest);
    log::info(&format!(
        "db backup: adopted {newest} as this database's lineage"
    ));
}

/// Download the object into staging, verify integrity, import, clean up.
/// A successful import adopts the dump's lineage: the sidecar records it,
/// so the restored database may push without refusing.
fn restore_object(cfg: &DbBackupConfig, object: &str, abort: &impl Fn() -> bool) -> bool {
    if !sweep_staging(&cfg.staging) {
        return false;
    }
    let staged = format!("{}/restore-{}", cfg.staging, cfg.db_label());
    if !rclone(cfg, &["copyto", object, &staged], abort) {
        log::err("db restore: download failed");
        let _ = std::fs::remove_file(&staged);
        return false;
    }
    let ok = super::sqlite::import(&staged, &cfg.db_path);
    let _ = std::fs::remove_file(&staged);
    if ok {
        super::lineage::write(&cfg.db_path, object.rsplit('/').next().unwrap_or(object));
    }
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

    /// Adoption with a non-empty, unproven DB and an unreachable bucket
    /// records nothing (no lineage is guessed) and never panics — the
    /// first tick will refuse loudly instead.
    #[test]
    fn adoption_needs_a_listable_bucket() {
        let dir = std::env::temp_dir().join(format!("vw-sup-adpt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("db.sqlite3").to_string_lossy().into_owned();
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY)", [])
            .unwrap();
        drop(conn);
        let mut cfg = support::cfg();
        cfg.restore = true;
        cfg.db_path = db_path;
        adopt_lineage(&cfg, || false);
        assert!(lineage::read(&cfg.db_path).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
