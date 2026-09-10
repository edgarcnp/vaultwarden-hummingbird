//! The periodic backup cycle (sweep -> dump -> push -> prune).

use crate::config::DbBackupConfig;
use crate::util::log;

use super::prune::prune;
use super::staging::{lock_down, sweep_staging};
use super::timestamp::timestamp;
use super::tools::rclone;

/// One periodic backup cycle: sweep staging, dump, push, prune. Runs on
/// the watch loop's spawned backup thread; never fatal, aborting early on
/// a stop request.
pub fn tick(cfg: &DbBackupConfig, abort: impl Fn() -> bool) {
    if abort() {
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
    log::info(&format!("db backup: pushed {object} ({size} bytes)"));
    prune(cfg, &abort);
}

#[cfg(test)]
mod tests {
    use super::super::support;
    use super::*;

    /// A backup run against a nonexistent sqlite source: dump fails
    /// cleanly, nothing staged, nothing uploaded.
    #[test]
    fn tick_fails_cleanly_on_missing_source() {
        let cfg = support::cfg();
        tick(&cfg, || false);
        let entries: Vec<_> = std::fs::read_dir(&cfg.staging)
            .expect("staging dir created")
            .collect();
        assert!(entries.is_empty());
        let _ = std::fs::remove_dir(&cfg.staging);
    }
}
