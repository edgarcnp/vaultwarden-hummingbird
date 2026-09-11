//! The periodic backup cycle (sweep -> dump -> push -> prune).

use crate::config::DbBackupConfig;
use crate::util::log;

use super::lineage;
use super::prune::prune;
use super::staging::{lock_down, sweep_staging};
use super::timestamp::timestamp;
use super::tools::{list_objects, rclone};

/// One periodic backup cycle: sweep staging, dump, push, prune. Runs on
/// a detached maintenance thread; never fatal, aborting early on a stop
/// request.
///
/// Two guards run before anything is staged: an empty database has
/// nothing to lose (and backing one up would let a wiped /data poison
/// the bucket), and a database that cannot prove it owns the bucket's
/// newest dump is refused (a stale or foreign DB must not shadow good
/// backups). A bucket-listing failure also skips the run: pushing without
/// the lineage check would be guessing.
pub fn tick(cfg: &DbBackupConfig, abort: impl Fn() -> bool) {
    if abort() {
        return;
    }
    match super::check::is_empty(cfg) {
        Ok(true) => {
            log::info("db backup: database is empty; nothing to back up");
            return;
        }
        Err(e) => {
            log::err(&format!(
                "db backup: cannot verify the database is non-empty ({e}); \
                 skipping (fail-closed)"
            ));
            return;
        }
        Ok(false) => {}
    }
    let Some(mut names) = list_objects(cfg, &abort) else {
        log::err("db backup: skipped (cannot list the bucket; refusing to guess lineage)");
        return;
    };
    if matches!(
        lineage::verdict(
            lineage::read(&cfg.db_path).as_deref(),
            names.last().map(String::as_str)
        ),
        lineage::Verdict::Refuse
    ) {
        log::err(
            "db backup: the bucket holds a newer backup than this database's lineage; \
             refusing to shadow it — boot with SUPERVISOR_DB_BACKUP_RESTORE=true to \
             adopt it, or clear the bucket to start a new generation",
        );
        return;
    }
    let ts = timestamp();
    let staged = format!("{}/{}-{ts}.{}", cfg.staging, cfg.db_label(), cfg.db_ext());
    let object = format!("{}/{}-{ts}.{}", cfg.prefix(), cfg.db_label(), cfg.db_ext());

    if !sweep_staging(&cfg.staging) {
        return;
    }
    if !super::sqlite::dump(&cfg.db_path, &staged) {
        log::err("db backup: dump failed; continuing (bucket unchanged)");
        return;
    }
    lock_down(&staged);
    let size = std::fs::metadata(&staged).map(|m| m.len()).unwrap_or(0);
    if !rclone(cfg, &["copyto", &staged, &object], &abort) {
        log::err("db backup: push failed; continuing (previous backups intact)");
        let _ = std::fs::remove_file(&staged);
        return;
    }
    let _ = std::fs::remove_file(&staged);
    let object_name = object.rsplit('/').next().unwrap_or(&object);
    lineage::write(&cfg.db_path, object_name);
    log::info(&format!("db backup: pushed {object} ({size} bytes)"));
    // The listing predates the push: add the new object so keep-N counts it.
    names.push(object_name.to_string());
    prune(cfg, names, &abort);
}

#[cfg(test)]
mod tests {
    use super::super::support;
    use super::*;

    /// A missing database is empty: the tick skips before anything is
    /// staged (and before any bucket listing — nothing to back up).
    #[test]
    fn tick_skips_a_missing_database() {
        let cfg = support::cfg();
        tick(&cfg, || false);
        assert!(
            !std::path::Path::new(&cfg.staging).exists(),
            "the empty-DB guard must run before staging is created"
        );
    }

    /// A fresh, tableless sqlite file is empty per the same predicate the
    /// restore gate uses: skipped too, though the file exists.
    #[test]
    fn tick_skips_a_tableless_database() {
        let dir = std::env::temp_dir().join(format!("vw-sup-dump-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("db.sqlite3").to_string_lossy().into_owned();
        rusqlite::Connection::open(&db_path).unwrap();
        let mut cfg = support::cfg();
        cfg.db_path = db_path.clone();
        tick(&cfg, || false);
        assert!(!std::path::Path::new(&cfg.staging).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
