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
/// and absolute paths never pass, in any position.
pub(super) fn is_synced_file(rel: &str) -> bool {
    if rel.contains("..") || rel.starts_with('/') {
        return false;
    }
    if rel == "tailscaled.state" || (rel.starts_with("rsa_key") && !rel.contains('/')) {
        return true;
    }
    match rel.split_once('/') {
        Some((dir, _)) => TREES.iter().any(|(_, tree)| *tree == dir),
        None => false,
    }
}

/// The /data files in the durable set, as bucket-relative paths.
pub(super) fn local_synced_files() -> Vec<String> {
    let mut files = Vec::new();
    if Path::new("/data/tailscaled.state").is_file() {
        files.push("tailscaled.state".to_string());
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
        walk_dir(Path::new(abs), rel, &mut |path| files.push(path));
    }
    files.sort();
    files
}

/// Recursively collect files under `dir`, as paths relative to /data.
fn walk_dir(dir: &Path, rel: &str, out: &mut impl FnMut(String)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let path_rel = format!("{rel}/{name}");
        if entry.path().is_dir() {
            walk_dir(&entry.path(), &path_rel, out);
        } else {
            out(path_rel);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synced_set_is_enforced_in_both_directions() {
        assert!(is_synced_file("tailscaled.state"));
        assert!(is_synced_file("rsa_key"));
        assert!(is_synced_file("rsa_key.foo.bar"));
        assert!(is_synced_file("certs/key.crt"));
        assert!(is_synced_file("certs/sub/key.crt"));
        assert!(is_synced_file("attachments/8f14e45f-uuid"));
        assert!(is_synced_file("attachments/sub/uuid"));
        assert!(is_synced_file("sends/uuid"));
        assert!(is_synced_file("sends/sub/uuid"));
        // everything else is outside the set
        assert!(!is_synced_file("db.sqlite3"));
        assert!(!is_synced_file("certs"));
        assert!(!is_synced_file("attachments"));
        assert!(!is_synced_file("sends"));
        assert!(!is_synced_file("icon_cache/x"));
        assert!(!is_synced_file("db-backups/x"));
        assert!(!is_synced_file("tailscaled.state.bak"));
        // traversal and absolute paths never pass, in any position
        assert!(!is_synced_file("../tailscaled.state"));
        assert!(!is_synced_file("certs/../../etc/passwd"));
        assert!(!is_synced_file("attachments/../../etc/passwd"));
        assert!(!is_synced_file("/etc/passwd"));
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
        std::fs::write(dir.join("sends/sub/uuid-2"), b"x").unwrap();
        std::fs::write(dir.join("db.sqlite3"), b"x").unwrap();
        // temp dir stands in for /data via the walker's inputs is not
        // possible (paths are pinned to /data); exercise walk_dir + the
        // top-level predicate instead.
        let mut found = Vec::new();
        for name in ["certs", "attachments", "sends"] {
            walk_dir(&dir.join(name), name, &mut |path| found.push(path));
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
        assert!(found.iter().all(|f| is_synced_file(f)));
        assert!(!is_synced_file("db.sqlite3"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
