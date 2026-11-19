//! Unchanged-dump suppression: skip the upload when a fresh dump is
//! byte-identical to the newest backup already in the bucket. A quiet
//! vault would otherwise mint a redundant object every cycle. The
//! comparison uses a tiny sidecar holding the SHA-256 of the last pushed
//! dump — never a second full database copy: the staged dump is hashed
//! once, the sidecar compares 64 bytes, and the dump is discarded.
//!
//! Sidecars are keyed by the database and remote, so switching either
//! starts clean. Any doubt (missing, unreadable, or old-format sidecar) is
//! a normal push: this can only save an upload, never lose one. Skipping
//! itself is only sound while the lineage owns the bucket's newest object
//! — verified by the caller — so an externally deleted newest dump is
//! healed by a push instead of skipped over.

use std::path::Path;

use crate::util::fs::{is_real_file, read_capped, write_atomic};
use crate::util::hash::sha256_file;
use crate::util::log;

/// Where the newest pushed dump's SHA-256 lives: on the supervisor-only
/// state volume, beside the lineage sidecar, keyed by database + remote.
fn last_path(state_dir: &str, key: &str) -> String {
    Path::new(state_dir)
        .join(format!("db-backups-{key}.last"))
        .to_string_lossy()
        .into_owned()
}

/// The pre-keying sidecar held a full dump (an unchanged comparison by
/// bytes); it is obsolete and may be database-sized. Remove it when the
/// first hash sidecar is written.
fn legacy_path(state_dir: &str) -> String {
    Path::new(state_dir)
        .join("db-backups.last")
        .to_string_lossy()
        .into_owned()
}

/// The SHA-256 of a staged dump, or `None` when it cannot be read (the
/// upload proceeds; only the skip optimization is lost).
pub(super) fn fingerprint(staged: &str) -> Option<String> {
    match sha256_file(staged) {
        Ok(hash) => Some(hash),
        Err(e) => {
            log::err(&format!(
                "db backup: cannot hash the staged dump ({e}); uploading it"
            ));
            None
        }
    }
}

/// Whether `fingerprint` matches the last pushed dump for this identity.
pub(super) fn is_repeat(state_dir: &str, key: &str, fingerprint: &str) -> bool {
    let path = last_path(state_dir, key);
    if !is_real_file(&path) {
        return false;
    }
    read_capped(&path, 128)
        .map(|text| text.trim() == fingerprint)
        .unwrap_or(false)
}

/// Remember the uploaded dump's hash, then discard the staged dump (the
/// bucket now holds it). Best-effort: a failed sidecar write only costs
/// one redundant push next cycle.
pub(super) fn retain(staged: &str, state_dir: &str, key: &str, fingerprint: &str) {
    let path = last_path(state_dir, key);
    if let Err(e) = write_atomic(&path, format!("{fingerprint}\n").as_bytes(), 0o600) {
        log::err(&format!(
            "db backup: cannot remember the pushed dump hash {}: {e} — the next \
             cycle may re-upload it",
            log::sanitize(&path)
        ));
    }
    if let Err(e) = std::fs::remove_file(staged) {
        log::err(&format!(
            "db backup: cannot remove the staged dump after upload: {e}"
        ));
    }
    // The full-copy sidecar from the previous layout is not a hash; once
    // this identity has a hash sidecar it is dead weight (often gigabytes).
    let _ = std::fs::remove_file(legacy_path(state_dir));
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn scratch(name: &str) -> String {
        let dir = std::env::temp_dir().join(format!("vw-sup-unch-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.to_string_lossy().into_owned()
    }

    #[test]
    fn fresh_dump_is_never_a_repeat() {
        let dir = scratch("fresh");
        let staged = format!("{dir}/dump.sqlite3");
        std::fs::write(&staged, b"payload").unwrap();
        let hash = fingerprint(&staged).expect("hashable");
        assert!(!is_repeat(&dir, "aabb", &hash));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn identical_dump_is_a_repeat() {
        let dir = scratch("same");
        let first = format!("{dir}/first.sqlite3");
        std::fs::write(&first, b"payload").unwrap();
        let hash = fingerprint(&first).expect("hashable");
        retain(&first, &dir, "aabb", &hash);
        assert!(
            !std::path::Path::new(&first).exists(),
            "staged dump removed"
        );

        let staged = format!("{dir}/second.sqlite3");
        std::fs::write(&staged, b"payload").unwrap();
        let hash = fingerprint(&staged).expect("hashable");
        assert!(is_repeat(&dir, "aabb", &hash));
        assert!(std::path::Path::new(&staged).exists(), "caller decides");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn changed_dump_is_not_a_repeat() {
        let dir = scratch("changed");
        let first = format!("{dir}/first.sqlite3");
        std::fs::write(&first, b"payload").unwrap();
        retain(&first, &dir, "aabb", &fingerprint(&first).unwrap());
        let staged = format!("{dir}/second.sqlite3");
        std::fs::write(&staged, b"changed payload").unwrap();
        assert!(!is_repeat(&dir, "aabb", &fingerprint(&staged).unwrap()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sidecars_are_per_identity_and_owner_only() {
        let dir = scratch("identity");
        let first = format!("{dir}/first.sqlite3");
        std::fs::write(&first, b"payload").unwrap();
        let hash = fingerprint(&first).unwrap();
        retain(&first, &dir, "aabb", &hash);
        assert!(is_repeat(&dir, "aabb", &hash));
        assert!(
            !is_repeat(&dir, "ccdd", &hash),
            "another remote/db starts clean"
        );
        let path = last_path(&dir, "aabb");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), hash);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_legacy_full_dump_sidecar_is_removed() {
        let dir = scratch("legacy");
        let legacy = legacy_path(&dir);
        std::fs::write(&legacy, vec![0u8; 4096]).unwrap();
        let staged = format!("{dir}/staged.sqlite3");
        std::fs::write(&staged, b"payload").unwrap();
        let hash = fingerprint(&staged).unwrap();
        assert!(!is_repeat(&dir, "aabb", &hash), "not a hash sidecar");
        retain(&staged, &dir, "aabb", &hash);
        assert!(!std::path::Path::new(&legacy).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
