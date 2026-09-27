//! The durable /data set: which files sync to and from the bucket. It
//! covers the machine's identity (`tailscaled.state`, `rsa_key*`,
//! `certs/**`) plus the vault's user content that cannot be regenerated
//! (`attachments/**`, and `sends/**` when Bitwarden Send is enabled).
//! Pure policy, no I/O against the bucket — both sync directions filter
//! through it (what push may upload is exactly what pull may write), so
//! the set lives in one auditable place.
//!
//! The bucket holds secrets and user data: whatever passes here is what
//! a bucket writer could plant on the data volume, so keep the set to
//! files that are safe to restore wholesale.

use std::path::Path;

/// The recursive directory trees in the set, as (absolute, bucket-
/// relative) pairs. Each is walked whole; a missing directory is a no-op.
const TREES: [(&str, &str); 3] = [
    ("/data/certs", "certs"),
    ("/data/attachments", "attachments"),
    ("/data/sends", "sends"),
];

/// Whether a bucket-relative path is inside the durable set. Traversal
/// and absolute paths never pass, in any position; neither does a `.part`
/// staging file left by an interrupted download (excluded from both
/// directions, so junk can neither be uploaded nor planted). The
/// configured state file (a /data-relative name) is always inside the set;
/// the default `tailscaled.state` spelling stays accepted even when a
/// custom path is configured, so an identity synced by an earlier
/// deployment remains restorable.
pub(super) fn is_synced_file(rel: &str, state_file: Option<&str>) -> bool {
    if rel.contains("..") || rel.starts_with('/') || rel.ends_with(".part") {
        return false;
    }
    if rel == "tailscaled.state"
        || state_file == Some(rel)
        || (rel.starts_with("rsa_key") && !rel.contains('/'))
    {
        return true;
    }
    match rel.split_once('/') {
        Some((dir, _)) => TREES.iter().any(|(_, tree)| *tree == dir),
        None => false,
    }
}

/// The /data files in the durable set, as bucket-relative paths.
pub(super) fn local_synced_files(state_file: Option<&str>) -> Vec<String> {
    let mut files = Vec::new();
    if Path::new("/data/tailscaled.state").is_file() {
        files.push("tailscaled.state".to_string());
    }
    if let Some(state) = state_file
        && state != "tailscaled.state"
        && Path::new("/data").join(state).is_file()
    {
        files.push(state.to_string());
    }
    if let Ok(entries) = std::fs::read_dir("/data") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue; // non-UTF-8 names never enter the set
            };
            if name.starts_with("rsa_key") && entry.path().is_file() {
                files.push(name.to_string());
            }
        }
    }
    for (abs, rel) in TREES {
        walk_dir(Path::new(abs), rel, state_file, &mut |path| {
            files.push(path)
        });
    }
    // The invariant both directions share: what push may upload is exactly
    // what pull may write.
    files.retain(|file| is_synced_file(file, state_file));
    files.sort();
    files
}

/// Recursively collect files under `dir`, as paths relative to /data that
/// pass the durable-set predicate.
fn walk_dir(dir: &Path, rel: &str, state_file: Option<&str>, out: &mut impl FnMut(String)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let path_rel = format!("{rel}/{name}");
        if entry.path().is_dir() {
            walk_dir(&entry.path(), &path_rel, state_file, out);
        } else if is_synced_file(&path_rel, state_file) {
            out(path_rel);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synced_set_is_enforced_in_both_directions() {
        let synced = |rel: &str| is_synced_file(rel, None);
        assert!(synced("tailscaled.state"));
        assert!(synced("rsa_key"));
        assert!(synced("rsa_key.foo.bar"));
        assert!(synced("certs/key.crt"));
        assert!(synced("certs/sub/key.crt"));
        assert!(synced("attachments/8f14e45f-uuid"));
        assert!(synced("attachments/sub/uuid"));
        assert!(synced("sends/uuid"));
        assert!(synced("sends/sub/uuid"));
        // `.part` staging leftovers are never part of the set
        assert!(!synced("attachments/8f14e45f-uuid.part"));
        assert!(!synced("certs/key.crt.part"));
        assert!(!synced("sends/uuid.part"));
        // everything else is outside the set
        assert!(!synced("db.sqlite3"));
        assert!(!synced("certs"));
        assert!(!synced("attachments"));
        assert!(!synced("sends"));
        assert!(!synced("icon_cache/x"));
        assert!(!synced("db-backups/x"));
        assert!(!synced("tailscaled.state.bak"));
        // traversal and absolute paths never pass, in any position
        assert!(!synced("../tailscaled.state"));
        assert!(!synced("certs/../../etc/passwd"));
        assert!(!synced("attachments/../../etc/passwd"));
        assert!(!synced("/etc/passwd"));
        // a custom configured state file is inside the set (and only then)
        assert!(is_synced_file("node.state", Some("node.state")));
        assert!(is_synced_file("sub/x.state", Some("sub/x.state")));
        assert!(!is_synced_file("node.state", None));
        assert!(!is_synced_file("other.state", Some("node.state")));
    }

    /// The push filter only treats regular files as synced files; a
    /// directory named `rsa_key` in /data would not be uploaded.
    #[test]
    fn local_enumeration_walks_files_and_skips_directories() {
        let dir = std::env::temp_dir().join(format!("vw-sup-sync-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("certs/sub")).unwrap();
        std::fs::create_dir_all(dir.join("attachments")).unwrap();
        std::fs::create_dir_all(dir.join("sends/sub")).unwrap();
        std::fs::write(dir.join("tailscaled.state"), b"x").unwrap();
        std::fs::create_dir(dir.join("rsa_key")).unwrap(); // a directory!
        std::fs::write(dir.join("certs/example.com.crt"), b"x").unwrap();
        std::fs::write(dir.join("certs/sub/deep.crt"), b"x").unwrap();
        std::fs::write(dir.join("attachments/uuid-1"), b"x").unwrap();
        std::fs::write(dir.join("attachments/uuid-1.part"), b"x").unwrap();
        std::fs::write(dir.join("sends/sub/uuid-2"), b"x").unwrap();
        std::fs::write(dir.join("db.sqlite3"), b"x").unwrap();
        // temp dir stands in for /data via the walker's inputs is not
        // possible (paths are pinned to /data); exercise walk_dir + the
        // top-level predicate instead.
        let mut found = Vec::new();
        for name in ["certs", "attachments", "sends"] {
            walk_dir(&dir.join(name), name, None, &mut |path| found.push(path));
        }
        found.sort();
        assert_eq!(
            found,
            vec![
                "attachments/uuid-1",
                "certs/example.com.crt",
                "certs/sub/deep.crt",
                "sends/sub/uuid-2",
            ]
        );
        assert!(found.iter().all(|f| is_synced_file(f, None)));
        assert!(!is_synced_file("db.sqlite3", None));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
