//! Backup lineage continuity: the stale-DB shadow guard. "Newest wins"
//! restore is only sound if every push comes from the lineage that owns
//! the bucket's newest dump. A sidecar next to the live database records
//! that ownership; pushes from a DB that cannot prove continuity are
//! refused instead of silently shadowing good backups.

use std::path::Path;

use crate::util::log;
use crate::util::make_private;

/// Sidecar next to the live database holding the newest dump object name
/// this lineage has produced (after a push) or adopted (after a restore
/// import). Dump names sort by creation time (see `timestamp`), so names
/// compare directly.
fn sidecar_path(db_path: &str) -> String {
    match Path::new(db_path).parent() {
        Some(dir) => dir.join("db-backups.state").to_string_lossy().into_owned(),
        None => "db-backups.state".to_string(),
    }
}

/// The newest dump object name this lineage knows, if any.
pub(super) fn read(db_path: &str) -> Option<String> {
    let text = std::fs::read_to_string(sidecar_path(db_path)).ok()?;
    let name = text.trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

/// Record the newest dump object name for this lineage. Best-effort: a
/// failed write is logged loudly — the next push will refuse (missing
/// continuity) rather than guess, which is the safe direction.
pub(super) fn write(db_path: &str, object_name: &str) {
    let path = sidecar_path(db_path);
    if let Err(e) = std::fs::write(&path, format!("{object_name}\n")) {
        log::err(&format!(
            "db backup: cannot record lineage state {}: {e}",
            log::sanitize(&path)
        ));
        return;
    }
    let _ = make_private(&path);
}

/// Whether this database may push its next dump into the bucket.
pub(super) enum Verdict {
    /// The push may go ahead (and will extend this lineage's ownership).
    Proceed,
    /// The bucket holds a newer backup than this lineage can prove;
    /// pushing would shadow it. Remediation is logged by the caller.
    Refuse,
}

/// Compare the sidecar's known newest dump against the bucket's newest.
/// `known == None` with an empty bucket is a fresh generation (proceed);
/// with a non-empty bucket it is a foreign or unproven database (refuse —
/// the upgrade path and any swapped-in /data both land here, loudly).
pub(super) fn verdict(known: Option<&str>, bucket_newest: Option<&str>) -> Verdict {
    let Some(bucket_newest) = bucket_newest else {
        return Verdict::Proceed;
    };
    match known {
        Some(known) if known >= bucket_newest => Verdict::Proceed,
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
        let old = "sqlite-20260911T100000Z-aaaaaaaa.sqlite3";
        let new = "sqlite-20260911T110000Z-bbbbbbbb.sqlite3";
        // empty bucket: any database may start a generation
        assert!(matches!(verdict(None, None), Verdict::Proceed));
        assert!(matches!(verdict(Some(old), None), Verdict::Proceed));
        // unproven database against a non-empty bucket: refuse
        assert!(matches!(verdict(None, Some(new)), Verdict::Refuse));
        // behind the bucket: refuse
        assert!(matches!(verdict(Some(old), Some(new)), Verdict::Refuse));
        // at or ahead of the bucket: proceed
        assert!(matches!(verdict(Some(new), Some(new)), Verdict::Proceed));
        assert!(matches!(verdict(Some(new), Some(old)), Verdict::Proceed));
    }

    #[test]
    fn sidecar_round_trips_and_survives_trim() {
        let db = scratch("roundtrip");
        assert!(read(&db).is_none(), "no sidecar yet");
        write(&db, "sqlite-20260911T100000Z-aaaaaaaa.sqlite3");
        assert_eq!(
            read(&db).as_deref(),
            Some("sqlite-20260911T100000Z-aaaaaaaa.sqlite3")
        );
        write(&db, "sqlite-20260911T110000Z-bbbbbbbb.sqlite3");
        assert_eq!(
            read(&db).as_deref(),
            Some("sqlite-20260911T110000Z-bbbbbbbb.sqlite3")
        );
        let _ = std::fs::remove_dir_all(Path::new(&db).parent().unwrap());
    }

    #[test]
    fn write_failure_is_loud_but_nonfatal() {
        // parent dir does not exist: write logs, read stays None
        let db = "/nonexistent-vw-sup-lin/db.sqlite3";
        write(db, "sqlite-20260911T100000Z-aaaaaaaa.sqlite3");
        assert!(read(db).is_none());
    }
}
