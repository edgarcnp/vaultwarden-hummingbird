//! Backup lineage continuity: the stale-DB shadow guard. "Newest wins"
//! restore is only sound if every push comes from the lineage that owns the
//! bucket's newest generation. A sidecar next to the live database records
//! that ownership as the manifest generation this volume last pushed or
//! imported; pushes from a DB that cannot prove continuity are refused
//! instead of silently shadowing good backups. An explicit adoption
//! (`SUPERVISOR_DB_BACKUP_RESTORE=true`) overwrites a stale or missing
//! sidecar: the remedy must work, or a crash between the manifest write
//! and the sidecar write would jam backups forever.

use std::path::Path;

use crate::util::fs::{is_real_file, read_capped, write_atomic};
use crate::util::log;

/// On the supervisor-only state volume (not the vault-writable data
/// volume): the sidecar records the newest manifest generation this
/// lineage has produced (after a push) or adopted (after a restore). Keyed
/// by the database and remote, so changing either starts a new identity.
pub(super) fn sidecar_path(state_dir: &str, key: &str) -> String {
    Path::new(state_dir)
        .join(format!("db-backups-{key}.state"))
        .to_string_lossy()
        .into_owned()
}

/// The pre-keying sidecar (one database, one remote); read once so an
/// existing deployment keeps its lineage, then superseded by the keyed
/// file on the next write.
fn legacy_path(state_dir: &str) -> String {
    Path::new(state_dir)
        .join("db-backups.state")
        .to_string_lossy()
        .into_owned()
}

/// What the sidecar records.
pub(super) enum Known {
    /// Current format: the generation of the newest dump this lineage owns.
    Generation(u64),
    /// Pre-manifest format: a bare object name, resolved against the
    /// manifest or listing by the caller. Rewritten as a generation once
    /// a push persists a manifest.
    LegacyName(String),
}

/// The recorded lineage, if any.
pub(super) fn read(state_dir: &str, key: &str) -> Option<Known> {
    // The sidecar is a generation or a legacy object name; 1 KiB is ample.
    // A symlink or an oversized/corrupt file is "no usable lineage". A
    // corrupt keyed file must not silently fall back to a stale legacy
    // record.
    let path = sidecar_path(state_dir, key);
    let path = if is_real_file(&path) {
        path
    } else {
        legacy_path(state_dir)
    };
    let text = read_capped(&path, 1024).ok()?;
    let value = text.trim();
    if value.is_empty() {
        return None;
    }
    match value.parse::<u64>() {
        Ok(generation) => Some(Known::Generation(generation)),
        Err(_) => Some(Known::LegacyName(value.to_string())),
    }
}

/// Record the newest generation for this lineage. Best-effort: a failed
/// write is logged loudly — the next push refuses (missing continuity)
/// rather than guess, and RESTORE=true adoption can re-establish it.
pub(super) fn write(state_dir: &str, key: &str, generation: u64) {
    write_text(state_dir, key, &format!("{generation}\n"));
}

/// Record a legacy object name (pre-manifest bucket): resolved against
/// the listing on the next tick.
pub(super) fn write_name(state_dir: &str, key: &str, name: &str) {
    write_text(state_dir, key, &format!("{name}\n"));
}

fn write_text(state_dir: &str, key: &str, text: &str) {
    let path = sidecar_path(state_dir, key);
    // Atomic replace: a symlink at the sidecar path is replaced, never
    // followed, and the 0600 mode is exact.
    if let Err(e) = write_atomic(&path, text.as_bytes(), 0o600) {
        log::err(&format!(
            "db backup: cannot record lineage state {}: {e}",
            log::sanitize(&path)
        ));
    }
}

/// Whether this database may push its next dump into the bucket.
pub(super) enum Verdict {
    /// The push may go ahead (and will extend this lineage's ownership).
    Proceed,
    /// The bucket holds a newer backup than this lineage can prove;
    /// pushing would shadow it. Remediation is logged by the caller.
    Refuse,
}

/// Compare the lineage's known generation against the bucket's latest
/// (`0` = empty bucket). `known == None` with a non-empty bucket is a
/// foreign or unproven database (refuse — the upgrade path and any
/// swapped-in /data land here, loudly); an empty bucket is a fresh
/// generation (proceed).
pub(super) fn verdict(known: Option<u64>, bucket_latest: u64) -> Verdict {
    if bucket_latest == 0 {
        return Verdict::Proceed;
    }
    match known {
        Some(known) if known >= bucket_latest => Verdict::Proceed,
        _ => Verdict::Refuse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("vw-sup-lin-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.to_string_lossy().into_owned()
    }

    #[test]
    fn verdict_matrix() {
        // empty bucket: any database may start a generation
        assert!(matches!(verdict(None, 0), Verdict::Proceed));
        assert!(matches!(verdict(Some(7), 0), Verdict::Proceed));
        // unproven database against a non-empty bucket: refuse
        assert!(matches!(verdict(None, 3), Verdict::Refuse));
        // behind the bucket: refuse
        assert!(matches!(verdict(Some(2), 3), Verdict::Refuse));
        // at or ahead of the bucket: proceed
        assert!(matches!(verdict(Some(3), 3), Verdict::Proceed));
        assert!(matches!(verdict(Some(4), 3), Verdict::Proceed));
    }

    #[test]
    fn sidecar_round_trips_generations_and_legacy_names() {
        let dir = scratch("roundtrip");
        assert!(read(&dir, "aabb").is_none(), "no sidecar yet");
        write(&dir, "aabb", 12);
        assert!(matches!(read(&dir, "aabb"), Some(Known::Generation(12))));
        write(&dir, "aabb", 13);
        assert!(matches!(read(&dir, "aabb"), Some(Known::Generation(13))));

        // A pre-manifest sidecar (a bare object name) still parses; the
        // caller resolves it against the manifest.
        write_name(&dir, "aabb", "sqlite-20260901T000000Z-aabbccdd.sqlite3");
        match read(&dir, "aabb") {
            Some(Known::LegacyName(name)) => {
                assert_eq!(name, "sqlite-20260901T000000Z-aabbccdd.sqlite3");
            }
            _ => panic!("expected a legacy name"),
        }
        // A different identity starts clean rather than inheriting it.
        assert!(read(&dir, "ccdd").is_none(), "sidecars are per identity");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The pre-keying sidecar is read once, so an upgraded deployment keeps
    /// its lineage; the next write uses the keyed name.
    #[test]
    fn the_legacy_sidecar_is_adopted_once() {
        let dir = scratch("legacy");
        std::fs::write(legacy_path(&dir), b"9\n").unwrap();
        assert!(matches!(read(&dir, "aabb"), Some(Known::Generation(9))));
        write(&dir, "aabb", 10);
        assert!(matches!(read(&dir, "aabb"), Some(Known::Generation(10))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_failure_is_loud_but_nonfatal() {
        // parent dir does not exist: write logs, read stays None
        let dir = "/nonexistent-vw-sup-lin";
        write(dir, "aabb", 1);
        write_name(dir, "aabb", "sqlite-20260901T000000Z-aabbccdd.sqlite3");
        assert!(read(dir, "aabb").is_none());
    }
}
