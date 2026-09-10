//! Bounded invocations of the external backup tool (rclone), with object
//! listing. The sqlite dump/restore itself is in-process (`sqlite/`).

use crate::config::{DbBackupConfig, RCLONE, SYNC_TIMEOUT};
use crate::runtime::run_bounded_capture;
use crate::runtime::run_bounded_env;

/// One bounded rclone invocation with the shared backend env.
pub(crate) fn rclone(cfg: &DbBackupConfig, args: &[&str], abort: &impl Fn() -> bool) -> bool {
    run_bounded_env(SYNC_TIMEOUT, RCLONE, args, &cfg.sync.env, abort)
}

/// Names of the objects under `pattern` (`rclone lsf`), sorted so name
/// order == creation order. None = listing failed — callers must never
/// delete blind.
pub(crate) fn list_objects(
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
