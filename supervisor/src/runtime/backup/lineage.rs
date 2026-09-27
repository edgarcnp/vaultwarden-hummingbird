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

use crate::util::log;
use crate::util::make_private;

/// Sidecar next to the live database holding the newest manifest
/// generation this lineage has produced (after a push) or adopted (after
/// a restore import).
pub(super) fn sidecar_path(db_path: &str) -> String {
    match Path::new(db_path).parent() {
        Some(dir) => dir.join("db-backups.state").to_string_lossy().into_owned(),
        None => "db-backups.state".to_string(),
    }
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
pub(super) fn read(db_path: &str) -> Option<Known> {
    let text = std::fs::read_to_string(sidecar_path(db_path)).ok()?;
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
pub(super) fn write(db_path: &str, generation: u64) {
    write_text(db_path, &format!("{generation}\n"));
}

/// Record a legacy object name (pre-manifest bucket): resolved against
/// the listing on the next tick.
pub(super) fn write_name(db_path: &str, name: &str) {
    write_text(db_path, &format!("{name}\n"));
}

fn write_text(db_path: &str, text: &str) {
    let path = sidecar_path(db_path);
    if let Err(e) = std::fs::write(&path, text) {
        log::err(&format!(
            "db backup: cannot record lineage state {}: {e}",
            log::sanitize(&path)
        ));
        return;
    }
    if let Err(e) = make_private(&path) {
        log::err(&format!(
            "db backup: cannot restrict the lineage sidecar {} ({e})",
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
        dir.join("db.sqlite3").to_string_lossy().into_owned()
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
        let db = scratch("roundtrip");
        assert!(read(&db).is_none(), "no sidecar yet");
        write(&db, 12);
        assert!(matches!(read(&db), Some(Known::Generation(12))));
        write(&db, 13);
        assert!(matches!(read(&db), Some(Known::Generation(13))));

        // A pre-manifest sidecar (a bare object name) still parses; the
        // caller resolves it against the manifest.
        write_name(&db, "sqlite-20260901T000000Z-aabbccdd.sqlite3");
        match read(&db) {
            Some(Known::LegacyName(name)) => {
                assert_eq!(name, "sqlite-20260901T000000Z-aabbccdd.sqlite3");
            }
            _ => panic!("expected a legacy name"),
        }
        let _ = std::fs::remove_dir_all(Path::new(&db).parent().unwrap());
    }

    #[test]
    fn write_failure_is_loud_but_nonfatal() {
        // parent dir does not exist: write logs, read stays None
        let db = "/nonexistent-vw-sup-lin/db.sqlite3";
        write(db, 1);
        write_name(db, "sqlite-20260901T000000Z-aabbccdd.sqlite3");
        assert!(read(db).is_none());
    }
}
