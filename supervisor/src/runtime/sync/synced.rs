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

use crate::util::fs::is_real_file;
use crate::util::log;

/// The recursive directory trees in the set, relative to the data root.
const TREES: [&str; 3] = ["certs", "attachments", "sends"];

/// Whether a bucket-relative path is inside the durable set. Traversal
/// and absolute paths never pass, in any position; neither does a `.part`
/// staging file left by an interrupted download (excluded from both
/// directions, so junk can neither be uploaded nor planted). The
/// configured state file (a /data-relative name) is always inside the set;
/// the default `tailscaled.state` spelling stays accepted even when a
/// custom path is configured, so an identity synced by an earlier
/// deployment remains restorable.
pub(super) fn is_synced_file(rel: &str, state_file: Option<&str>) -> bool {
    if rel.contains("..")
        || rel.starts_with('/')
        || rel.ends_with(".part")
        || rel.ends_with('/')
        || rel.chars().any(char::is_control)
    {
        return false;
    }
    if rel == "tailscaled.state"
        || rel == "config.json"
        || state_file == Some(rel)
        || (rel.starts_with("rsa_key") && !rel.contains('/'))
    {
        return true;
    }
    match rel.split_once('/') {
        Some((dir, _)) => TREES.contains(&dir),
        None => false,
    }
}

/// The files in the durable set, as bucket-relative paths, under `root`
/// (production passes `/data`; tests pass a scratch directory).
pub(super) fn local_synced_files(root: &Path, state_file: Option<&str>) -> Vec<String> {
    let mut files = Vec::new();
    if is_real_file(&root.join("tailscaled.state").to_string_lossy()) {
        files.push("tailscaled.state".to_string());
    }
    if is_real_file(&root.join("config.json").to_string_lossy()) {
        files.push("config.json".to_string());
    }
    if let Some(state) = state_file
        && state != "tailscaled.state"
        && is_real_file(&root.join(state).to_string_lossy())
    {
        files.push(state.to_string());
    }
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue; // non-UTF-8 names never enter the set
            };
            // `file_type()` does not follow symlinks; a symlink is never a
            // local sync source (a confused-deputy upload otherwise).
            if name.starts_with("rsa_key")
                && entry.file_type().is_ok_and(|file_type| file_type.is_file())
            {
                files.push(name.to_string());
            }
        }
    }
    for tree in TREES {
        walk_dir(&root.join(tree), tree, state_file, &mut |path| {
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
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            log::err(&format!(
                "state sync: cannot read {}: {e}; its files are not synced this run",
                log::sanitize(&dir.to_string_lossy())
            ));
            return;
        }
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let path_rel = format!("{rel}/{name}");
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };
        if file_type.is_dir() {
            walk_dir(&entry.path(), &path_rel, state_file, out);
        } else if file_type.is_file() && is_synced_file(&path_rel, state_file) {
            out(path_rel);
        }
    }
}

/// Remove `.part` staging leftovers under the data root (flat) and inside
/// the synced trees (recursively); returns how many were removed. A
/// transfer that died mid-pull leaves one, and it must never be resumed
/// against different content, so each boot starts clean. Staging
/// directories outside the synced trees (backup dumps) are not touched.
pub(super) fn clear_partials(root: &Path, state_file: Option<&str>) -> usize {
    let mut removed = 0;
    clear_flat(root, &mut removed);
    for tree in TREES {
        clear_recursive(&root.join(tree), &mut removed);
    }
    // A custom state file may live in a non-tree subdirectory; its parent
    // can still contain a `.part` from a dead transfer.
    if let Some(state) = state_file
        && let Some(parent) = Path::new(state).parent()
        && !parent.as_os_str().is_empty()
    {
        clear_recursive(&root.join(parent), &mut removed);
    }
    removed
}

fn is_partial(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".part"))
}

fn clear_flat(dir: &Path, removed: &mut usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // `file_type()` does not follow symlinks; removing a symlink removes
        // the link, never its target.
        let removable = entry
            .file_type()
            .is_ok_and(|file_type| file_type.is_file() || file_type.is_symlink());
        if removable && is_partial(&path) && std::fs::remove_file(&path).is_ok() {
            *removed += 1;
        }
    }
}

fn clear_recursive(dir: &Path, removed: &mut usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };
        if file_type.is_dir() {
            clear_recursive(&path, removed);
        } else if (file_type.is_file() || file_type.is_symlink())
            && is_partial(&path)
            && std::fs::remove_file(&path).is_ok()
        {
            *removed += 1;
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
        assert!(synced("config.json"));
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
        // control characters would corrupt the line-oriented manifest/cache
        assert!(!synced("attachments/bad\nname"));
        assert!(!synced("attachments/bad\tname"));
        // a directory-shaped key is not a file
        assert!(!synced("attachments/"));
        assert!(!synced("certs/"));
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
        // The walker is exercised directly on the scratch dir; the full
        // enumeration over a root is covered by the test below.
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

    /// The push enumeration is rooted at the data directory (tests use a
    /// scratch dir): identity files, rsa_key*, and the trees; `.part`
    /// leftovers are excluded.
    #[test]
    fn local_enumeration_covers_identity_keys_and_trees() {
        let root = std::env::temp_dir().join(format!("vw-sup-syncroot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("certs")).unwrap();
        std::fs::create_dir_all(root.join("attachments")).unwrap();
        std::fs::write(root.join("tailscaled.state"), b"x").unwrap();
        std::fs::write(root.join("config.json"), b"{}").unwrap();
        std::fs::write(root.join("rsa_key.pem"), b"x").unwrap();
        std::fs::write(root.join("rsa_key.pub.pem"), b"x").unwrap();
        std::fs::write(root.join("certs/c.crt"), b"x").unwrap();
        std::fs::write(root.join("attachments/u1"), b"x").unwrap();
        std::fs::write(root.join("attachments/u1.part"), b"x").unwrap();
        std::fs::write(root.join("db.sqlite3"), b"x").unwrap();
        assert_eq!(
            local_synced_files(&root, None),
            vec![
                "attachments/u1",
                "certs/c.crt",
                "config.json",
                "rsa_key.pem",
                "rsa_key.pub.pem",
                "tailscaled.state",
            ]
        );
        // a configured custom state file rides along
        std::fs::write(root.join("node.state"), b"x").unwrap();
        let files = local_synced_files(&root, Some("node.state"));
        assert!(files.contains(&"node.state".to_string()), "{files:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Stale `.part` leftovers are removed at boot, flat at the root and
    /// recursively under every tree; real files survive.
    #[test]
    fn stale_partials_are_cleared() {
        let root = std::env::temp_dir().join(format!("vw-sup-parts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("attachments/sub")).unwrap();
        std::fs::create_dir_all(root.join("certs")).unwrap();
        std::fs::write(root.join("rsa_key.part"), b"x").unwrap();
        std::fs::write(root.join("attachments/u.part"), b"x").unwrap();
        std::fs::write(root.join("attachments/sub/v.part"), b"x").unwrap();
        std::fs::write(root.join("certs/keep.crt"), b"x").unwrap();
        assert_eq!(clear_partials(&root, None), 3);
        assert!(!root.join("rsa_key.part").exists());
        assert!(!root.join("attachments/u.part").exists());
        assert!(!root.join("attachments/sub/v.part").exists());
        assert!(root.join("certs/keep.crt").exists());
        assert_eq!(clear_partials(&root, None), 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A symlink is not a sync source and is never walked. Removing a
    /// `.part` symlink removes the link, not the file it points at.
    #[test]
    fn symlinks_are_skipped_and_partial_links_do_not_touch_their_target() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!("vw-sup-symlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("attachments")).unwrap();
        let outside = root.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let secret = outside.join("secret");
        std::fs::write(&secret, b"do-not-touch").unwrap();

        symlink(&secret, root.join("attachments/alias")).unwrap();
        symlink(&outside, root.join("attachments/alias-dir")).unwrap();
        symlink(&secret, root.join("attachments/stale.part")).unwrap();

        let files = local_synced_files(&root, None);
        assert!(files.is_empty(), "symlinks are not synced: {files:?}");
        assert!(clear_partials(&root, None) >= 1);
        assert_eq!(std::fs::read(&secret).unwrap(), b"do-not-touch");
        assert!(!root.join("attachments/stale.part").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_custom_state_parent_is_cleaned() {
        let root = std::env::temp_dir().join(format!("vw-sup-statepart-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/node.state.part"), b"partial").unwrap();
        assert_eq!(clear_partials(&root, Some("sub/node.state")), 1);
        assert!(!root.join("sub/node.state.part").exists());
        let _ = std::fs::remove_dir_all(&root);
    }
}
