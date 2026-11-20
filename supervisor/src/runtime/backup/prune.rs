//! Generation pruning: delete the objects of the manifest entries evicted
//! beyond keep-N. Runs after the manifest write that dropped them, so a
//! crash can only leave unreferenced objects — never a manifest pointing
//! at a deleted one.

use crate::config::DbBackupConfig;
use crate::s3::Client;
use crate::util::log;

use super::manifest::Entry;

pub(super) fn prune(
    client: &Client,
    cfg: &DbBackupConfig,
    evicted: &[Entry],
    abort: &impl Fn() -> bool,
) {
    if evicted.is_empty() {
        return;
    }
    let keys: Vec<String> = evicted
        .iter()
        .map(|entry| format!("{}{}", cfg.prefix(), entry.name))
        .collect();
    match client.delete_many(&keys, abort) {
        Ok(()) => log::info(&format!("db backup: pruned {} object(s)", keys.len())),
        Err(e) => log::err(&format!(
            "db backup: batch prune failed ({e}); the bucket may keep extra backups \
             (check that the access key may delete)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::super::support;
    use super::super::tools;
    use super::*;

    /// No evicted entries means no deletes and no panics.
    #[test]
    fn prune_noop_without_evictions() {
        let cfg = support::cfg();
        let s3 = tools::client(&cfg).expect("test client builds");
        prune(&s3, &cfg, &[], &|| false);
    }
}
