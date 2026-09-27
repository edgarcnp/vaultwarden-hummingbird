//! The boot-time restore path: verify emptiness (fail closed), pull the
//! newest restorable backup, import it. A failed import is fatal: starting
//! the vault on a half-restored database would surface partial state as the
//! vault's truth — the container exits and the orchestrator retries instead.
//!
//! Candidates come from the manifest, newest generation first, so one
//! corrupt object falls through to the next older one instead of blocking
//! boot. Without a manifest (legacy bucket) the name listing is used, and
//! an unreadable manifest falls back to that listing loudly as recovery.

use crate::config::DbBackupConfig;
use crate::s3::MAX_DB_OBJECT_BYTES;
use crate::util::log;

use super::check::is_empty;
use super::lineage;
use super::staging::sweep_staging;
use super::tools::{Client, client, list_objects, load_manifest};

/// One restore candidate: object key, its listed size, and (when it came
/// from the manifest) the generation to record as lineage on success.
struct Candidate {
    key: String,
    size: u64,
    generation: Option<u64>,
}

/// Boot-time restore (opt-in via `SUPERVISOR_DB_BACKUP_RESTORE`): runs
/// before vaultwarden spawns. Acts ONLY on an unambiguously empty DB;
/// ambiguity (unreachable, malformed) fails closed — never overwrites
/// existing data. Returns false only when a restore was attempted and
/// failed: the caller must not start the vault. "No backup found" is not a
/// failure (a fresh deployment legitimately boots on an empty DB), but a
/// bucket that cannot be listed is: an empty database against an unknown
/// bucket is exactly the ambiguity this function exists to refuse.
pub fn restore_if_empty(cfg: &DbBackupConfig, abort: impl Fn() -> bool) -> bool {
    if !cfg.restore {
        return true;
    }
    match is_empty(cfg) {
        Err(e) => log::err(&format!(
            "db restore: cannot verify the DB is empty ({e}); not restoring (fail-closed)"
        )),
        Ok(false) => log::info("db restore: database is not empty; skipped"),
        Ok(true) => {
            log::info("db restore: database is empty; looking for the newest backup");
            let s3 = match client(cfg) {
                Ok(s3) => s3,
                Err(e) => {
                    log::err(&format!(
                        "db restore: skipped: unusable S3 configuration ({e}); \
                         check the SUPERVISOR_S3_* settings and endpoint (a fresh DB \
                         will boot)"
                    ));
                    return true;
                }
            };
            let candidates = match candidates(&s3, cfg, &abort) {
                Ok(candidates) => candidates,
                Err(e) => {
                    log::err(&format!(
                        "db restore: cannot list the bucket ({e}); an empty database \
                         against an unreachable bucket is ambiguous, so refusing to \
                         start the vault — the orchestrator will retry"
                    ));
                    return false;
                }
            };
            if candidates.is_empty() {
                log::info(
                    "db restore: empty DB and no backup found in the bucket; \
                     booting fresh",
                );
                return true;
            }
            for candidate in candidates {
                if abort() {
                    return true;
                }
                log::info(&format!("db restore: importing {}", candidate.key));
                if restore_object(&s3, cfg, &candidate, &abort) {
                    log::info("db restore: done");
                    return true;
                }
                log::err(&format!(
                    "db restore: {} did not restore; trying the next older backup",
                    candidate.key
                ));
            }
            log::err(
                "db restore: no restorable backup found (every candidate failed); \
                 refusing to start the vault on a partial restore",
            );
            return false;
        }
    }
    true
}

/// Candidate backups, newest first: the manifest's generations when it
/// exists, the legacy name listing otherwise — and as recovery when the
/// manifest is unreadable. The import's integrity check still decides what
/// is restorable; this only orders the attempts.
fn candidates(
    s3: &Client,
    cfg: &DbBackupConfig,
    abort: &impl Fn() -> bool,
) -> anyhow::Result<Vec<Candidate>> {
    match load_manifest(s3, cfg, abort) {
        // A manifest, even an empty one, is authoritative: only its
        // entries are restorable candidates. An absent manifest is the
        // legacy layout; an unreadable one falls back to the listing as
        // recovery, with the integrity check still deciding.
        Ok(Some(manifest)) => Ok(manifest
            .newest_first()
            .map(|entry| Candidate {
                key: format!("{}{}", cfg.prefix(), entry.name),
                size: entry.size,
                generation: Some(entry.generation),
            })
            .collect()),
        Ok(None) => legacy_candidates(s3, cfg, abort),
        Err(e) => {
            log::err(&format!(
                "db restore: cannot read the manifest ({e}); falling back to the \
                 name listing"
            ));
            legacy_candidates(s3, cfg, abort)
        }
    }
}

/// The pre-manifest view: listed names newest-first, sizes from the
/// listing, lineage recorded as a name (rewritten as a generation once a
/// push persists a manifest).
fn legacy_candidates(
    s3: &Client,
    cfg: &DbBackupConfig,
    abort: &impl Fn() -> bool,
) -> anyhow::Result<Vec<Candidate>> {
    let listed = list_objects(s3, cfg, abort)?;
    Ok(listed
        .into_iter()
        .rev()
        .map(|(name, size)| Candidate {
            key: format!("{}{name}", cfg.prefix()),
            size,
            generation: None,
        })
        .collect())
}

/// Boot-time lineage adoption (`SUPERVISOR_DB_BACKUP_RESTORE=true`): the
/// flag declares the bucket authoritative for this data volume, so a
/// non-empty database adopts the bucket's newest generation — an upgrade
/// from before the guard existed, a volume the operator knows matches the
/// bucket, or a stale sidecar after a crash (the remedy the refusal
/// message names; it must work even when a stale sidecar is present).
/// Without the flag the tick refuses, loudly, and nothing is guessed.
pub fn adopt_lineage(cfg: &DbBackupConfig, abort: impl Fn() -> bool) {
    if !cfg.restore {
        return;
    }
    if !matches!(is_empty(cfg), Ok(false)) {
        return;
    }
    let Ok(s3) = client(cfg) else {
        return;
    };
    match load_manifest(&s3, cfg, &abort) {
        Ok(Some(manifest)) if !manifest.is_empty() => {
            let generation = manifest.latest();
            lineage::write(&cfg.db_path, generation);
            log::info(&format!(
                "db backup: adopted generation {generation} as this database's lineage"
            ));
        }
        Ok(_) => {
            // Legacy bucket: adopt the newest listed name; the next push
            // persists a manifest and rewrites this as a generation.
            if let Ok(mut listed) = list_objects(&s3, cfg, &abort)
                && let Some((name, _)) = listed.pop()
            {
                lineage::write_name(&cfg.db_path, &name);
                log::info(&format!(
                    "db backup: adopted {name} as this database's lineage"
                ));
            }
        }
        Err(e) => log::err(&format!(
            "db backup: cannot read the manifest ({e}); not adopting — the first \
             tick refuses and names the remedy"
        )),
    }
}

/// Download one candidate into staging, verify integrity, import; on a
/// successful import record its lineage. Any failure returns false with
/// the live DB untouched (the download is atomic and the import links).
fn restore_object(
    s3: &Client,
    cfg: &DbBackupConfig,
    candidate: &Candidate,
    abort: &impl Fn() -> bool,
) -> bool {
    if !sweep_staging(&cfg.staging) {
        return false;
    }
    let staged = format!("{}/restore-{}", cfg.staging, cfg.db_label());
    if let Err(e) = s3.get(
        &candidate.key,
        &staged,
        Some(candidate.size),
        MAX_DB_OBJECT_BYTES,
        abort,
    ) {
        log::err(&format!("db restore: download failed ({e})"));
        return false;
    }
    let ok = super::sqlite::import(&staged, &cfg.db_path);
    let _ = std::fs::remove_file(&staged);
    if ok {
        match candidate.generation {
            Some(generation) => lineage::write(&cfg.db_path, generation),
            None => {
                let name = candidate.key.rsplit('/').next().unwrap_or(&candidate.key);
                lineage::write_name(&cfg.db_path, name);
            }
        }
    }
    ok
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use crate::config::SyncConfig;
    use std::time::Duration;

    use super::super::support;
    use super::*;

    #[test]
    fn restore_noop_when_disabled() {
        assert!(restore_if_empty(&support::cfg(), || false));
    }

    /// An S3 endpoint that answers `GET .../manifest` with 404 (no
    /// manifest yet) and ListObjectsV2 with an empty bucket. Handles
    /// every request in order — the restore path asks for the manifest
    /// first. Local stub, no credentials needed (the client signs, the
    /// stub ignores it).
    fn serve_empty_bucket() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut sock) = stream else {
                    continue;
                };
                let mut buf = [0u8; 4096];
                let n = sock.read(&mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);
                let (status, body) = if request.contains("manifest") {
                    ("404 Not Found", String::new())
                } else {
                    (
                        "200 OK",
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                         <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                         <Name>stub</Name><Prefix></Prefix>\
                         <KeyCount>0</KeyCount><MaxKeys>1000</MaxKeys>\
                         <IsTruncated>false</IsTruncated></ListBucketResult>"
                            .to_string(),
                    )
                };
                let head = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/xml\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes());
                let _ = sock.write_all(body.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    /// A genuinely empty, listable bucket is not a failure: a fresh
    /// deployment legitimately boots on an empty DB.
    #[test]
    fn restore_with_no_backup_found_is_not_fatal() {
        let endpoint = serve_empty_bucket();
        let sync = SyncConfig::new(
            "r2:vw-restore-stub".into(),
            "id".into(),
            "secret".into(),
            endpoint,
            Duration::from_secs(60),
        )
        .expect("valid test remote");
        let mut cfg = support::cfg_with_sync(sync);
        cfg.restore = true;
        let dir = std::env::temp_dir().join(format!("vw-sup-rstub-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        cfg.db_path = dir.join("db.sqlite3").to_string_lossy().into_owned();
        rusqlite::Connection::open(&cfg.db_path).unwrap();
        assert!(restore_if_empty(&cfg, || false));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An unreachable bucket against an empty database is ambiguous:
    /// refusing is fatal, and the orchestrator retries the boot.
    #[test]
    fn restore_refuses_an_unlistable_bucket() {
        let sync = SyncConfig::new(
            "r2:vw-restore-dead".into(),
            "id".into(),
            "secret".into(),
            "http://127.0.0.1:1".into(),
            Duration::from_secs(60),
        )
        .expect("valid test remote");
        let mut cfg = support::cfg_with_sync(sync);
        cfg.restore = true;
        let dir = std::env::temp_dir().join(format!("vw-sup-rdead-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        cfg.db_path = dir.join("db.sqlite3").to_string_lossy().into_owned();
        rusqlite::Connection::open(&cfg.db_path).unwrap();
        assert!(!restore_if_empty(&cfg, || false));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Adoption with a non-empty, unproven DB and an unreachable bucket
    /// records nothing (no lineage is guessed) and never panics — the
    /// first tick will refuse loudly instead.
    #[test]
    fn adoption_needs_a_listable_bucket() {
        let dir = std::env::temp_dir().join(format!("vw-sup-adpt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("db.sqlite3").to_string_lossy().into_owned();
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY)", [])
            .unwrap();
        drop(conn);
        let mut cfg = support::cfg();
        cfg.restore = true;
        cfg.db_path = db_path;
        adopt_lineage(&cfg, || false);
        assert!(lineage::read(&cfg.db_path).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
