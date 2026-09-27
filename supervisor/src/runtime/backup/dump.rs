//! The periodic backup cycle (sweep -> dump -> push -> manifest -> prune).

use crate::config::DbBackupConfig;
use crate::util::log;
use crate::util::make_private;

use super::lineage::{self, Known, Verdict};
use super::manifest::{Entry, Manifest};
use super::prune::prune;
use super::staging::sweep_staging;
use super::timestamp::timestamp;
use super::tools::{client, list_objects, load_manifest, store_manifest};
use super::unchanged;

/// One periodic backup cycle: sweep staging, dump, push, publish the
/// manifest, prune. Runs on the maintenance reactor thread; never fatal,
/// aborting early on a stop request.
///
/// Ordering: the dump object is PUT before the manifest that names it, so
/// a crash leaves at most an unreferenced object — never a manifest
/// pointing at a missing one; and evicted objects are deleted only after
/// the manifest that dropped them is published.
///
/// Guards run before anything is staged: an empty database has nothing to
/// lose (and backing one up would let a wiped /data poison the bucket),
/// and a database that cannot prove it owns the bucket's newest
/// generation is refused (a stale or foreign DB must not shadow good
/// backups). An absent manifest means the legacy layout: the name listing
/// is converted into an equivalent in-memory manifest, and the first
/// successful push persists it. A dump byte-identical to the newest
/// backup is not re-uploaded (`unchanged`), so a quiet vault mints no
/// redundant objects.
pub fn tick(cfg: &DbBackupConfig, abort: impl Fn() -> bool) {
    if abort() {
        return;
    }
    match super::check::is_empty(cfg) {
        Ok(true) => {
            log::info("db backup: database is empty; nothing to back up");
            return;
        }
        Err(e) => {
            log::err(&format!(
                "db backup: skipped: cannot verify the database is non-empty ({e}); \
                 refusing to back up on a guess — the next tick retries"
            ));
            return;
        }
        Ok(false) => {}
    }
    let s3 = match client(cfg) {
        Ok(s3) => s3,
        Err(e) => {
            log::err(&format!(
                "db backup: skipped: unusable S3 configuration ({e}); \
                 check the SUPERVISOR_S3_* settings and endpoint"
            ));
            return;
        }
    };
    let mut manifest = match load_manifest(&s3, cfg, &abort) {
        Ok(Some(manifest)) => manifest,
        Ok(None) => match list_objects(&s3, cfg, &abort) {
            Ok(listed) => Manifest::from_listing(&listed),
            Err(e) => {
                log::err(&format!(
                    "db backup: skipped: cannot list the bucket ({e}); refusing to back up \
                     without knowing the bucket's newest backup — check credentials and \
                     network; the next tick retries"
                ));
                return;
            }
        },
        Err(e) => {
            log::err(&format!(
                "db backup: skipped: cannot read the manifest ({e}); refusing to push \
                 without knowing the bucket's history — check credentials and that the \
                 manifest object is readable; the next tick retries"
            ));
            return;
        }
    };
    // The local lineage: current sidecars hold a generation; a pre-manifest
    // sidecar holds an object name, resolved against the manifest now.
    let known = resolve_known(lineage::read(&cfg.db_path), &manifest);
    if matches!(lineage::verdict(known, manifest.latest()), Verdict::Refuse) {
        log::err(&format!(
            "db backup: the bucket holds a newer backup than this database's lineage; \
             refusing to shadow it — boot with SUPERVISOR_DB_BACKUP_RESTORE=true to \
             adopt generation {}, or clear the bucket to start a new generation",
            manifest.latest(),
        ));
        return;
    }
    let ts = timestamp();
    let staged = format!("{}/{}-{ts}.{}", cfg.staging, cfg.db_label(), cfg.db_ext());
    let name = object_name(cfg, &ts);

    // Allocate before anything is staged: a saturated generation space
    // must refuse the push, never wrap the manifest back to generation 0.
    let Some(generation) = manifest.next_generation() else {
        log::err(
            "db backup: generation space is exhausted; refusing to push — clear the \
             bucket to start a new generation",
        );
        return;
    };

    if !sweep_staging(&cfg.staging) {
        return;
    }
    if !super::sqlite::dump(&cfg.db_path, &staged) {
        log::err(
            "db backup: dump failed; nothing was uploaded or deleted, the next tick \
             retries (if it repeats, check free space on /data)",
        );
        return;
    }
    // Owner-only before the staged dump leaves the volume: a dump that
    // could not be restricted must not be pushed (or retained).
    if let Err(e) = make_private(&staged) {
        log::err(&format!(
            "db backup: cannot restrict the staged dump ({e}); nothing was uploaded, \
             the next tick retries"
        ));
        let _ = std::fs::remove_file(&staged);
        return;
    }
    let size = std::fs::metadata(&staged).map(|m| m.len()).unwrap_or(0);
    // Skip a redundant upload only while this lineage still owns the
    // newest generation: a stale or unproven lineage must push, so a gap
    // is never skipped over. (An externally deleted newest object is not
    // detected while the dump stays byte-identical; the next changed dump
    // replaces it, and restore falls back to the next older entry until
    // then.)
    if upload_is_redundant(
        known,
        manifest.latest(),
        unchanged::is_repeat(&staged, &cfg.db_path),
    ) {
        let _ = std::fs::remove_file(&staged);
        log::info("db backup: dump is identical to the newest backup; upload skipped");
        return;
    }
    let key = format!("{}{name}", cfg.prefix());
    if let Err(e) = s3.put(&key, &staged, &abort) {
        log::err(&format!(
            "db backup: push failed ({e}); previous backups are intact, the next tick \
             retries (if it repeats, check the bucket credentials and network)"
        ));
        let _ = std::fs::remove_file(&staged);
        return;
    }
    manifest.push(Entry {
        generation,
        name: name.clone(),
        size,
    });
    let evicted = manifest.retain(cfg.keep);
    match store_manifest(&s3, cfg, &manifest, &abort) {
        Ok(()) => {
            lineage::write(&cfg.db_path, generation);
            unchanged::retain(&staged, &cfg.db_path);
            log::info(&format!(
                "db backup: pushed {key} ({size} bytes, generation {generation})"
            ));
            prune(&s3, cfg, &evicted, &abort);
        }
        Err(e) => {
            // The dump we just pushed is now unreferenced: remove it so a
            // manifest-write outage cannot accumulate orphans, and leave
            // the lineage where it was so the next tick retries.
            log::err(&format!(
                "db backup: pushed {key} but cannot publish the manifest ({e}); removing \
                 the unreferenced dump and retrying next tick — check that the access \
                 key may write the manifest object"
            ));
            let _ = std::fs::remove_file(&staged);
            if let Err(d) = s3.delete(&key, &abort) {
                log::err(&format!(
                    "db backup: cannot remove the unreferenced dump {key} ({d}); restore \
                     and prune ignore it"
                ));
            }
        }
    }
}

/// The dump's bare object name (`sqlite-<timestamp>.sqlite3`).
fn object_name(cfg: &DbBackupConfig, ts: &str) -> String {
    format!("{}-{ts}.{}", cfg.db_label(), cfg.db_ext())
}

/// The lineage's known generation: a legacy name resolves through the
/// manifest; a name that is not there (foreign, or pruned) stays unproven.
fn resolve_known(recorded: Option<Known>, manifest: &Manifest) -> Option<u64> {
    match recorded {
        Some(Known::Generation(generation)) => Some(generation),
        Some(Known::LegacyName(name)) => manifest.find_name(&name).map(|entry| entry.generation),
        None => None,
    }
}

/// Whether the fresh dump may skip its upload: only while this lineage
/// owns the newest generation and the bytes are unchanged. A stale
/// lineage, an unproven one, or an externally deleted newest object all
/// force a push, so continuity heals instead of skipping over a gap.
fn upload_is_redundant(known: Option<u64>, latest: u64, dump_unchanged: bool) -> bool {
    latest > 0 && known == Some(latest) && dump_unchanged
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::config::SyncConfig;

    use super::super::support;
    use super::*;

    /// A missing database is empty: the tick skips before anything is
    /// staged (and before any bucket call — nothing to back up).
    #[test]
    fn tick_skips_a_missing_database() {
        let cfg = support::cfg();
        tick(&cfg, || false);
        assert!(
            !std::path::Path::new(&cfg.staging).exists(),
            "the empty-DB guard must run before staging is created"
        );
    }

    /// A fresh, tableless sqlite file is empty per the same predicate the
    /// restore gate uses: skipped too, though the file exists.
    #[test]
    fn tick_skips_a_tableless_database() {
        let dir = std::env::temp_dir().join(format!("vw-sup-dump-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("db.sqlite3").to_string_lossy().into_owned();
        rusqlite::Connection::open(&db_path).unwrap();
        let mut cfg = support::cfg();
        cfg.db_path = db_path.clone();
        tick(&cfg, || false);
        assert!(!std::path::Path::new(&cfg.staging).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The full object key never doubles the separator between the backup
    /// prefix and the dump name.
    #[test]
    fn object_key_never_doubles_the_slash() {
        for remote in ["r2:bucket", "r2:bucket/sub"] {
            let sync = SyncConfig::new(
                remote.into(),
                "id".into(),
                "secret".into(),
                "http://127.0.0.1:1".into(),
                Duration::from_secs(60),
            )
            .expect("valid test remote");
            let cfg = support::cfg_with_sync(sync);
            let key = format!("{}{}", cfg.prefix(), object_name(&cfg, "20260911T182850Z"));
            assert_eq!(
                key,
                format!("{}sqlite-20260911T182850Z.sqlite3", cfg.prefix())
            );
            assert!(!key.contains("//"), "no doubled separator allowed: {key}");
        }
    }

    /// Skip decisions: only a lineage that owns the newest generation and
    /// byte-identical dump bytes skips. A stale or unproven lineage, or an
    /// empty bucket, always pushes (healing continuity).
    #[test]
    fn skip_requires_current_lineage_and_identical_bytes() {
        assert!(upload_is_redundant(Some(3), 3, true));
        assert!(
            !upload_is_redundant(Some(3), 3, false),
            "changed bytes push"
        );
        assert!(
            !upload_is_redundant(Some(2), 3, true),
            "a stale lineage must push, not skip over a newer backup"
        );
        assert!(
            !upload_is_redundant(None, 3, true),
            "unproven lineage pushes"
        );
        assert!(
            !upload_is_redundant(Some(0), 0, true),
            "an empty bucket needs its first push"
        );
    }

    /// A pre-manifest sidecar name resolves through the manifest; a name
    /// that is not there stays unproven (never guessed).
    #[test]
    fn legacy_names_resolve_through_the_manifest() {
        let manifest = Manifest::from_listing(&[
            ("sqlite-1.sqlite3".to_string(), 1),
            ("sqlite-2.sqlite3".to_string(), 2),
        ]);
        assert_eq!(
            resolve_known(Some(Known::Generation(7)), &manifest),
            Some(7)
        );
        assert_eq!(
            resolve_known(
                Some(Known::LegacyName("sqlite-2.sqlite3".into())),
                &manifest
            ),
            Some(2)
        );
        assert_eq!(
            resolve_known(Some(Known::LegacyName("foreign.sqlite3".into())), &manifest),
            None
        );
        assert_eq!(resolve_known(None, &manifest), None);
    }
}
