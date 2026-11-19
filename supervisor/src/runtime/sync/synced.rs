//! The durable set: which files sync to and from the bucket. It covers the
//! machine's identity (`tailscaled.state`, `certs/**`) on the
//! supervisor-only `/state` volume, plus the vault's own data (`rsa_key*`,
//! `config.json`, `attachments/**`, and `sends/**`) on `/data`. Bucket keys
//! are the historical names, independent of which local volume holds the
//! file, so an existing bucket restores into either layout unchanged.
//!
//! Pure policy, no I/O against the bucket — both sync directions filter
//! through it (what push may upload is exactly what pull may write), so
//! the set lives in one auditable place.
//!
//! The bucket holds secrets and user data: whatever passes here is what
//! a bucket writer could plant on a volume, so keep the set to files that
//! are safe to restore wholesale.

use std::path::{Path, PathBuf};

use crate::config::SUPERVISOR_STATE;
use crate::util::fs::is_real_file;
use crate::util::log;

/// Recursive trees on the vault data volume, as bucket-relative names.
const DATA_TREES: [&str; 2] = ["attachments", "sends"];
/// Recursive trees on the supervisor state volume. Tailscale's cert cache
/// lives under its `--statedir`, which is the state file's parent.
const STATE_TREES: [&str; 1] = ["certs"];

/// The two local volumes behind one bucket namespace. One is the vault's
/// writable data volume; the other is the supervisor-only state volume.
#[derive(Clone, Debug)]
pub(super) struct Roots {
    pub(super) data: PathBuf,
    pub(super) state: PathBuf,
}

impl Roots {
    pub(super) fn production() -> Self {
        Self {
            data: PathBuf::from("/data"),
            state: PathBuf::from(SUPERVISOR_STATE),
        }
    }

    /// A single scratch directory for both roles (tests).
    #[cfg(test)]
    pub(super) fn one(root: &Path) -> Self {
        Self {
            data: root.to_path_buf(),
            state: root.to_path_buf(),
        }
    }

    /// Which volume owns a bucket-relative path.
    fn owns_state(&self, rel: &str, state_file: Option<&str>) -> bool {
        state_file == Some(rel) || rel == "tailscaled.state" || rel.starts_with("certs/")
    }

    pub(super) fn root_of(&self, rel: &str, state_file: Option<&str>) -> &Path {
        if self.owns_state(rel, state_file) {
            &self.state
        } else {
            &self.data
        }
    }

    pub(super) fn local(&self, rel: &str, state_file: Option<&str>) -> PathBuf {
        self.root_of(rel, state_file).join(rel)
    }

    /// Exact mode for a downloaded file. Identity and cert material stays
    /// owner-only; vault data is group read/write for the other uid.
    pub(super) fn mode(&self, rel: &str, state_file: Option<&str>) -> u32 {
        if self.owns_state(rel, state_file) {
            0o600
        } else {
            0o660
        }
    }
}

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
        Some((dir, _)) => DATA_TREES.contains(&dir) || STATE_TREES.contains(&dir),
        None => false,
    }
}

/// The files in the durable set, as bucket-relative paths, across both
/// local volumes (production) or a single scratch directory (tests).
pub(super) fn local_synced_files(roots: &Roots, state_file: Option<&str>) -> Vec<String> {
    let mut files = Vec::new();
    if is_real_file(&roots.state.join("tailscaled.state").to_string_lossy()) {
        files.push("tailscaled.state".to_string());
    }
    if let Some(state) = state_file
        && state != "tailscaled.state"
        && is_real_file(&roots.state.join(state).to_string_lossy())
    {
        files.push(state.to_string());
    }
    for tree in STATE_TREES {
        walk_dir(&roots.state.join(tree), tree, state_file, &mut |path| {
            files.push(path)
        });
    }
    if is_real_file(&roots.data.join("config.json").to_string_lossy()) {
        files.push("config.json".to_string());
    }
    if let Ok(entries) = std::fs::read_dir(&roots.data) {
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
    for tree in DATA_TREES {
        walk_dir(&roots.data.join(tree), tree, state_file, &mut |path| {
            files.push(path)
        });
    }
    // The invariant both directions share: what push may upload is exactly
    // what pull may write.
    files.retain(|file| is_synced_file(file, state_file));
    files.sort();
    files
}

/// Recursively collect files under `dir`, as bucket-relative paths that
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

/// Remove `.part` staging leftovers at both roots and inside the synced
/// trees (recursively); returns how many were removed. A transfer that
/// died mid-pull leaves one, and it must never be resumed against
/// different content, so each boot starts clean. Staging directories
/// outside the synced trees (backup dumps) are not touched.
pub(super) fn clear_partials(roots: &Roots, state_file: Option<&str>) -> usize {
    let mut removed = 0;
    clear_flat(&roots.data, &mut removed);
    if roots.state != roots.data {
        clear_flat(&roots.state, &mut removed);
    }
    for tree in DATA_TREES {
        clear_recursive(&roots.data.join(tree), &mut removed);
    }
    for tree in STATE_TREES {
        clear_recursive(&roots.state.join(tree), &mut removed);
    }
    // A custom state file may live in a non-tree subdirectory; its parent
    // can still contain a `.part` from a dead transfer.
    if let Some(state) = state_file
        && let Some(parent) = Path::new(state).parent()
        && !parent.as_os_str().is_empty()
    {
        clear_recursive(&roots.state.join(parent), &mut removed);
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

    /// The push enumeration covers both volumes: identity files, rsa_key*,
    /// and the trees; `.part` leftovers are excluded.
    #[test]
    fn local_enumeration_covers_identity_keys_and_trees() {
        let base = std::env::temp_dir().join(format!("vw-sup-syncroot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let roots = Roots {
            data: base.join("data"),
            state: base.join("state"),
        };
        for root in [&roots.data, &roots.state] {
            std::fs::create_dir_all(root).unwrap();
        }
        std::fs::create_dir_all(roots.state.join("certs")).unwrap();
        std::fs::create_dir_all(roots.data.join("attachments")).unwrap();
        std::fs::write(roots.state.join("tailscaled.state"), b"x").unwrap();
        std::fs::write(roots.state.join("certs/c.crt"), b"x").unwrap();
        std::fs::write(roots.data.join("config.json"), b"{}").unwrap();
        std::fs::write(roots.data.join("rsa_key.pem"), b"x").unwrap();
        std::fs::write(roots.data.join("rsa_key.pub.pem"), b"x").unwrap();
        std::fs::write(roots.data.join("attachments/u1"), b"x").unwrap();
        std::fs::write(roots.data.join("attachments/u1.part"), b"x").unwrap();
        std::fs::write(roots.data.join("db.sqlite3"), b"x").unwrap();
        assert_eq!(
            local_synced_files(&roots, None),
            vec![
                "attachments/u1",
                "certs/c.crt",
                "config.json",
                "rsa_key.pem",
                "rsa_key.pub.pem",
                "tailscaled.state",
            ]
        );
        // a configured custom state file rides along from /state
        std::fs::write(roots.state.join("node.state"), b"x").unwrap();
        let files = local_synced_files(&roots, Some("node.state"));
        assert!(files.contains(&"node.state".to_string()), "{files:?}");
        // the vault's copy of the same name is not the identity
        std::fs::write(roots.data.join("node.state"), b"x").unwrap();
        let files = local_synced_files(&roots, Some("node.state"));
        assert_eq!(
            files.iter().filter(|f| *f == "node.state").count(),
            1,
            "{files:?}"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Identity and certs live on the state volume, so a download there is
    /// owner-only; vault data is shared with the vault's group.
    #[test]
    fn modes_follow_the_owning_volume() {
        let roots = Roots {
            data: PathBuf::from("/data"),
            state: PathBuf::from("/state"),
        };
        assert_eq!(roots.mode("tailscaled.state", None), 0o600);
        assert_eq!(roots.mode("certs/c.pem", None), 0o600);
        assert_eq!(roots.mode("node.state", Some("node.state")), 0o600);
        assert_eq!(roots.mode("rsa_key.pem", None), 0o660);
        assert_eq!(roots.mode("attachments/u", None), 0o660);
        assert_eq!(
            roots.local("certs/c.pem", None),
            PathBuf::from("/state/certs/c.pem")
        );
        assert_eq!(
            roots.local("attachments/u", None),
            PathBuf::from("/data/attachments/u")
        );
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
        let roots = Roots::one(&root);
        assert_eq!(clear_partials(&roots, None), 3);
        assert!(!root.join("rsa_key.part").exists());
        assert!(!root.join("attachments/u.part").exists());
        assert!(!root.join("attachments/sub/v.part").exists());
        assert!(root.join("certs/keep.crt").exists());
        assert_eq!(clear_partials(&roots, None), 0);
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

        let roots = Roots::one(&root);
        let files = local_synced_files(&roots, None);
        assert!(files.is_empty(), "symlinks are not synced: {files:?}");
        assert!(clear_partials(&roots, None) >= 1);
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
        assert_eq!(
            clear_partials(&Roots::one(&root), Some("sub/node.state")),
            1
        );
        assert!(!root.join("sub/node.state.part").exists());
        let _ = std::fs::remove_dir_all(&root);
    }
}
