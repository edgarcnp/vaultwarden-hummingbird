//! The boot-time restore path: verify emptiness (fail closed), pull the
//! newest backup, import it. A failed import is fatal: starting the vault
//! on a half-restored database would surface partial state as the vault's
//! truth — the container exits and the orchestrator retries instead.

use crate::config::DbBackupConfig;
use crate::util::log;

use super::check::is_empty;
use super::lineage;
use super::staging::sweep_staging;
use super::tools::{Client, client, list_objects};

/// Boot-time restore (opt-in via SUPERVISOR_DB_BACKUP_RESTORE): runs
/// before vaultwarden spawns. Acts ONLY on an unambiguously empty DB;
/// ambiguity (unreachable, malformed) fails closed — never overwrites
/// existing data. Returns false only when a restore was attempted and
/// failed: the caller must not start the vault. "No backup found" is not
/// a failure (a fresh deployment legitimately boots on an empty DB), but
/// a bucket that cannot be listed is: an empty database against an
/// unknown bucket is exactly the ambiguity this function exists to
/// refuse.
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
            match newest_object(&s3, cfg, &abort) {
                Ok(Some(object)) => {
                    if abort() {
                        return true;
                    }
                    log::info(&format!("db restore: importing {object}"));
                    if restore_object(&s3, cfg, &object, &abort) {
                        log::info("db restore: done");
                    } else {
                        log::err(
                            "db restore: import failed; refusing to start the vault on a \
                             partially restored database",
                        );
                        return false;
                    }
                }
                Ok(None) => {
                    log::info(
                        "db restore: empty DB and no backup found in the bucket; \
                         booting fresh",
                    );
                }
                Err(e) => {
                    log::err(&format!(
                        "db restore: cannot list the bucket ({e}); an empty database \
                         against an unreachable bucket is ambiguous, so refusing to \
                         start the vault — the orchestrator will retry"
                    ));
                    return false;
                }
            }
        }
    }
    true
}

/// The newest dump object's full key (name order == time order). `None`
/// means the bucket lists fine but holds no dumps; `Err` means the
/// listing itself failed — the caller refuses (fail-closed) instead of
/// booting an empty vault against an unknown bucket.
fn newest_object(
    s3: &Client,
    cfg: &DbBackupConfig,
    abort: &impl Fn() -> bool,
) -> anyhow::Result<Option<String>> {
    let mut names = list_objects(s3, cfg, abort)?;
    Ok(names.pop().map(|name| format!("{}{name}", cfg.prefix())))
}

/// Boot-time lineage adoption (SUPERVISOR_DB_BACKUP_RESTORE=true): the
/// flag declares the bucket authoritative for this data volume, so a
/// non-empty database with no recorded lineage — an upgrade from before
/// the guard existed, or a volume the operator knows matches the bucket —
/// adopts the bucket's newest dump as its lineage and periodic pushes
/// continue. Without the flag the tick refuses, loudly, and nothing is
/// guessed. An empty DB needs nothing here (the import path records
/// lineage); a listing failure needs nothing here (the tick skips loudly).
pub fn adopt_lineage(cfg: &DbBackupConfig, abort: impl Fn() -> bool) {
    if !cfg.restore || lineage::read(&cfg.db_path).is_some() {
        return;
    }
    if !matches!(is_empty(cfg), Ok(false)) {
        return;
    }
    let newest = client(cfg)
        .and_then(|s3| list_objects(&s3, cfg, &abort))
        .ok()
        .and_then(|mut n| n.pop());
    let Some(newest) = newest else {
        return;
    };
    lineage::write(&cfg.db_path, &newest);
    log::info(&format!(
        "db backup: adopted {newest} as this database's lineage"
    ));
}

/// Download the object into staging, verify integrity, import, clean up.
/// A successful import adopts the dump's lineage: the sidecar records it,
/// so the restored database may push without refusing.
fn restore_object(
    s3: &Client,
    cfg: &DbBackupConfig,
    object: &str,
    abort: &impl Fn() -> bool,
) -> bool {
    if !sweep_staging(&cfg.staging) {
        return false;
    }
    let staged = format!("{}/restore-{}", cfg.staging, cfg.db_label());
    if let Err(e) = s3.get(object, &staged, abort) {
        log::err(&format!("db restore: download failed ({e})"));
        let _ = std::fs::remove_file(&staged);
        return false;
    }
    let ok = super::sqlite::import(&staged, &cfg.db_path);
    let _ = std::fs::remove_file(&staged);
    if ok {
        super::lineage::write(&cfg.db_path, object.rsplit('/').next().unwrap_or(object));
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

    /// An S3 endpoint that answers ListObjectsV2 with an empty bucket:
    /// local stub, no credentials needed (the client signs, the stub
    /// ignores it).
    fn serve_empty_bucket() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf);
            let body = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                <Name>stub</Name><Prefix></Prefix>\
                <KeyCount>0</KeyCount><MaxKeys>1000</MaxKeys>\
                <IsTruncated>false</IsTruncated></ListBucketResult>";
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(head.as_bytes());
            let _ = sock.write_all(body.as_bytes());
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
