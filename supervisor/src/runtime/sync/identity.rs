//! The /data identity set: which files count as the machine's tailnet
//! identity. Pure policy, no I/O against the bucket — both sync
//! directions filter through it (what push may upload is exactly what
//! pull may write), so the set lives in one auditable place.

use std::path::Path;

/// Whether a bucket-relative path is inside the identity set. Traversal
/// and absolute paths never pass, in any position.
pub(super) fn is_identity_file(rel: &str) -> bool {
    if rel.contains("..") || rel.starts_with('/') {
        return false;
    }
    rel == "tailscaled.state"
        || (rel.starts_with("rsa_key") && !rel.contains('/'))
        || rel.starts_with("certs/")
}

/// The /data files in the identity set, as bucket-relative paths.
pub(super) fn local_identity_files() -> Vec<String> {
    let mut files = Vec::new();
    if Path::new("/data/tailscaled.state").is_file() {
        files.push("tailscaled.state".to_string());
    }
    if let Ok(entries) = std::fs::read_dir("/data") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue; // non-UTF-8 names never enter the identity set
            };
            if name.starts_with("rsa_key") && entry.path().is_file() {
                files.push(name.to_string());
            }
        }
    }
    let mut push_dir = |rel: String| files.push(rel);
    walk_certs(Path::new("/data/certs"), "certs", &mut push_dir);
    files.sort();
    files
}

/// Recursively collect files under `dir` (the tailscale cert store).
fn walk_certs(dir: &Path, rel: &str, out: &mut impl FnMut(String)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let path_rel = format!("{rel}/{name}");
        if entry.path().is_dir() {
            walk_certs(&entry.path(), &path_rel, out);
        } else {
            out(path_rel);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_set_is_enforced_in_both_directions() {
        assert!(is_identity_file("tailscaled.state"));
        assert!(is_identity_file("rsa_key"));
        assert!(is_identity_file("rsa_key.foo.bar"));
        assert!(is_identity_file("certs/key.crt"));
        assert!(is_identity_file("certs/sub/key.crt"));
        // everything else is outside the set
        assert!(!is_identity_file("db.sqlite3"));
        assert!(!is_identity_file("certs"));
        assert!(!is_identity_file("tailscaled.state.bak"));
        // traversal and absolute paths never pass, in any position
        assert!(!is_identity_file("../tailscaled.state"));
        assert!(!is_identity_file("certs/../../etc/passwd"));
        assert!(!is_identity_file("/etc/passwd"));
    }

    /// The push filter only treats regular files as identity files; a
    /// directory named `rsa_key` in /data would not be uploaded.
    #[test]
    fn local_enumeration_skips_directories() {
        let dir = std::env::temp_dir().join(format!("vw-sup-sync-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("certs/sub")).unwrap();
        std::fs::write(dir.join("tailscaled.state"), b"x").unwrap();
        std::fs::create_dir(dir.join("rsa_key")).unwrap(); // a directory!
        std::fs::write(dir.join("certs/example.com.crt"), b"x").unwrap();
        std::fs::write(dir.join("certs/sub/deep.crt"), b"x").unwrap();
        std::fs::write(dir.join("db.sqlite3"), b"x").unwrap();
        // temp dir stands in for /data via the walker's inputs is not
        // possible (paths are pinned to /data); exercise walk_certs + the
        // top-level predicate instead.
        let mut found = Vec::new();
        walk_certs(&dir.join("certs"), "certs", &mut |rel| found.push(rel));
        found.sort();
        assert_eq!(found, vec!["certs/example.com.crt", "certs/sub/deep.crt"]);
        assert!(found.iter().all(|f| is_identity_file(f)));
        assert!(!is_identity_file("db.sqlite3"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
