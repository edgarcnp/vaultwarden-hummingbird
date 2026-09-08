//! Keep-N pruning of the per-backend dumps in the bucket.

use crate::config::DbBackupConfig;

use super::tools::{list_objects, rclone};
use crate::util::log;

/// Delete the oldest per-backend dumps beyond keep-N. Listing failure
/// skips pruning entirely — never delete blind. Name order == time order
/// (fixed-width sortable names).
pub(super) fn prune(cfg: &DbBackupConfig, abort: &impl Fn() -> bool) {
    let prefix = cfg.prefix();
    let pattern = format!("{prefix}/{}-*", cfg.db.label());
    let Some(names) = list_objects(cfg, &pattern, abort) else {
        log::err("db backup: prune skipped (listing failed)");
        return;
    };
    if names.len() <= cfg.keep {
        return;
    }
    for name in &names[..names.len() - cfg.keep] {
        let object = format!("{prefix}/{name}");
        if rclone(cfg, &["deletefile", &object], abort) {
            log::info(&format!("db backup: pruned {object}"));
        } else {
            log::err("db backup: prune delete failed; continuing");
        }
    }
}
