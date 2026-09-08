//! Bounded invocations of the external backup tools (rclone and the
//! dump/restore binaries), with staged-file cleanup and object listing.

use crate::config::{BACKUP_TIMEOUT, DbBackupConfig, RCLONE, SYNC_TIMEOUT};
use crate::proc::{run_bounded_capture, run_bounded_env};
use crate::util::log;

/// One bounded rclone invocation with the shared backend env.
pub(super) fn rclone(cfg: &DbBackupConfig, args: &[&str], abort: &impl Fn() -> bool) -> bool {
    run_bounded_env(SYNC_TIMEOUT, RCLONE, args, &cfg.sync.env, abort)
}

/// Run one dump/import tool, bounded; logs (secret-free) on failure and
/// removes the staged artifact it would have produced.
pub(super) fn tool(
    name: &str,
    prog: &str,
    args: &[&str],
    env: &[(String, String)],
    staged: &str,
    abort: &impl Fn() -> bool,
) -> bool {
    if run_bounded_env(BACKUP_TIMEOUT, prog, args, env, abort) {
        true
    } else {
        let _ = std::fs::remove_file(staged);
        log::err(&format!("db backup: {name} failed or timed out"));
        false
    }
}

/// Names of the objects under `pattern` (`rclone lsf`), sorted so name
/// order == creation order (fixed-width sortable timestamps). None =
/// listing failed — callers must never delete blind.
pub(super) fn list_objects(
    cfg: &DbBackupConfig,
    pattern: &str,
    abort: &impl Fn() -> bool,
) -> Option<Vec<String>> {
    let out = run_bounded_capture(
        SYNC_TIMEOUT,
        RCLONE,
        &["lsf", pattern, "--files-only"],
        &cfg.sync.env,
        abort,
    )?;
    let mut names: Vec<String> = out
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect();
    names.sort();
    Some(names)
}
