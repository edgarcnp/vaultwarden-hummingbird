//! Keep-N pruning of the per-backend dumps in the bucket.

use crate::config::DbBackupConfig;
use crate::s3::Client;
use crate::util::log;

/// Delete the oldest per-backend dumps beyond keep-N. The listing is the
/// caller's (tick already fetched it for the lineage guard); a stale view
/// here can only mean an extra kept object — never a wrong deletion,
/// since only strictly-oldest names are removed.
pub(super) fn prune(
    client: &Client,
    cfg: &DbBackupConfig,
    mut names: Vec<String>,
    abort: &impl Fn() -> bool,
) {
    let prefix = cfg.prefix();
    if names.len() <= cfg.keep {
        return;
    }
    names.sort();
    for name in &names[..names.len() - cfg.keep] {
        let key = format!("{prefix}{name}");
        match client.delete(&key, abort) {
            Ok(()) => log::info(&format!("db backup: pruned {key}")),
            Err(e) => log::err(&format!("db backup: prune delete failed ({e}); continuing")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::support;
    use super::super::tools;
    use super::*;

    /// Pruning below keep-N is a no-op and never touches the client.
    #[test]
    fn prune_noop_at_or_below_keep() {
        let cfg = support::cfg();
        let s3 = tools::client(&cfg).expect("test client builds");
        prune(
            &s3,
            &cfg,
            vec!["sqlite-1.sqlite3".into(), "sqlite-2.sqlite3".into()],
            &|| false,
        );
        // nothing to assert beyond "no panic": deletes only fire above keep
    }
}
