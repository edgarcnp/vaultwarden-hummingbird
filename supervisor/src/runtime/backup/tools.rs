//! Bounded invocations of the external backup tool (rclone), with object
//! listing. The sqlite dump/restore itself is in-process (`sqlite/`).

use crate::config::{DbBackupConfig, RCLONE, RCLONE_NO_CHECK_BUCKET, SYNC_TIMEOUT};
use crate::runtime::run_bounded_capture;
use crate::runtime::run_bounded_env;

/// One bounded rclone invocation with the shared backend env. Uploads skip
/// the bucket pre-check (see [`RCLONE_NO_CHECK_BUCKET`]); harmless on
/// download/delete paths.
pub(crate) fn rclone(cfg: &DbBackupConfig, args: &[&str], abort: &impl Fn() -> bool) -> bool {
    let mut full: Vec<&str> = Vec::with_capacity(args.len() + 1);
    full.push(args[0]);
    full.push(RCLONE_NO_CHECK_BUCKET);
    full.extend_from_slice(&args[1..]);
    run_bounded_env(SYNC_TIMEOUT, RCLONE, &full, &cfg.sync.env, abort)
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
