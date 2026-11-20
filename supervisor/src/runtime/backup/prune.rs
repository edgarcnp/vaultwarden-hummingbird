//! Generation pruning and orphan cleanup: delete the objects of the
//! manifest entries evicted beyond keep-N, and dump objects that were
//! uploaded but never referenced by a manifest (a kill between the object
//! PUT and the manifest write). Both run only after the manifest write
//! that supersedes them, so a crash can only leave unreferenced objects —
//! never a manifest pointing at a deleted one.

use std::collections::BTreeSet;
use std::time::Duration;

use crate::config::DbBackupConfig;
use crate::s3::Client;
use crate::util::log;

use super::manifest::Entry;
use super::tools;

/// A crash orphan must be old enough that no in-flight push can own it.
/// The one-container-per-bucket contract is the other half of the safety
/// argument; a concurrent writer's fresh object is inside this window.
const ORPHAN_GRACE: Duration = Duration::from_secs(24 * 60 * 60);

/// Bounded orphan deletions per tick; the next tick continues.
const MAX_ORPHAN_DELETES: usize = 1000;

/// Delete the evicted objects; call only after the manifest that dropped
/// them is published, so a crash never leaves a reference to a deleted one.
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

/// Delete dump objects the manifest does not reference. This covers a kill
/// between the object PUT and the manifest write, which otherwise leaks one
/// object per crash. The evicted entries from this tick are left to
/// [`prune`], and a fresh object is left alone until [`ORPHAN_GRACE`].
pub(super) fn gc_orphans(
    client: &Client,
    cfg: &DbBackupConfig,
    manifest: &super::manifest::Manifest,
    evicted: &[Entry],
    abort: &impl Fn() -> bool,
) {
    let listed = match tools::list_objects_with_time(client, cfg, abort) {
        Ok(listed) => listed,
        Err(e) => {
            log::info(&format!(
                "db backup: orphan cleanup skipped ({e}); the next tick retries"
            ));
            return;
        }
    };
    if listed.is_empty() {
        return;
    }
    let evicted_names: BTreeSet<&str> = evicted.iter().map(|entry| entry.name.as_str()).collect();
    let now = jiff::Timestamp::now().as_second();
    let mut keys = Vec::new();
    for (name, _, _) in &listed {
        if manifest.find_name(name).is_some() || evicted_names.contains(name.as_str()) {
            continue;
        }
        if !old_enough(name, cfg.db_label(), now) {
            continue;
        }
        keys.push(format!("{}{name}", cfg.prefix()));
        if keys.len() >= MAX_ORPHAN_DELETES {
            log::info(&format!(
                "db backup: orphan cleanup hit its {MAX_ORPHAN_DELETES}-delete cap; \
                 the next tick continues"
            ));
            break;
        }
    }
    if keys.is_empty() {
        return;
    }
    match client.delete_many(&keys, abort) {
        Ok(()) => log::info(&format!(
            "db backup: removed {} unreferenced dump(s)",
            keys.len()
        )),
        Err(e) => log::err(&format!(
            "db backup: orphan cleanup failed ({e}); the next tick retries"
        )),
    }
}

/// Whether a dump name's timestamp is older than [`ORPHAN_GRACE`]. A name
/// this process cannot parse is left alone rather than guessed at.
fn old_enough(name: &str, label: &str, now: i64) -> bool {
    let Some(rest) = name
        .strip_prefix(label)
        .and_then(|rest| rest.strip_prefix('-'))
    else {
        return false;
    };
    let Some(stamp) = rest.get(..15) else {
        return false;
    };
    let Ok(datetime) = jiff::civil::DateTime::strptime("%Y%m%dT%H%M%S", stamp) else {
        return false;
    };
    let Ok(zoned) = datetime.to_zoned_datetime(jiff::tz::TimeZone::UTC) else {
        return false;
    };
    now.saturating_sub(zoned.timestamp().as_second()) >= ORPHAN_GRACE.as_secs() as i64
}

/// Prune with no evictions: no deletes, no panic.
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
