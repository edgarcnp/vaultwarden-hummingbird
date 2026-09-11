//! Keep-N pruning of the per-backend dumps in the bucket.

use crate::config::DbBackupConfig;

use super::tools::rclone;
use crate::util::log;

/// Delete the oldest per-backend dumps beyond keep-N. The listing is the
/// caller's (tick already fetched it for the lineage guard); a stale view
/// here can only mean an extra kept object — never a wrong deletion,
/// since only strictly-oldest names are removed.
pub(super) fn prune(cfg: &DbBackupConfig, mut names: Vec<String>, abort: &impl Fn() -> bool) {
    let prefix = cfg.prefix();
    if names.len() <= cfg.keep {
        return;
    }
    names.sort();
    for name in &names[..names.len() - cfg.keep] {
        let object = format!("{prefix}/{name}");
        if rclone(cfg, &["deletefile", &object], abort) {
            log::info(&format!("db backup: pruned {object}"));
        } else {
            log::err("db backup: prune delete failed; continuing");
        }
    }
}
