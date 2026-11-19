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
//!
//! Enumeration and upload are descriptor-anchored (`openat` with
//! `O_NOFOLLOW` per component), so a vault-created symlink in the tree can
//! neither redirect the scan nor the upload. A scan that cannot prove the
//! complete set is a failed push: the deletion lifecycle never runs on a
//! partial view.

use std::path::{Path, PathBuf};

use nix::dir::{Dir, Type};
use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use nix::unistd::{UnlinkatFlags, unlinkat};

use crate::config::SUPERVISOR_STATE;
use crate::util::fs::is_real_dir;

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

/// Whether a synced path may be removed by the tombstone lifecycle. The
/// node identity and its certificates are never tombstoned: a transient
/// volume loss must not erase the machine's identity from the bucket, and
/// a user cannot delete them through the vault UI. Only user data and the
/// admin config can be intentionally deleted.
pub(super) fn is_deletable(rel: &str) -> bool {
    rel == "config.json" || rel.starts_with("attachments/") || rel.starts_with("sends/")
}

/// Whether a bucket-relative path is inside the durable set. Traversal
/// and absolute paths never pass, in any position; neither does a
/// supervisor `.vw-part` staging file left by an interrupted download. A
/// user file ending `.part` is ordinary user data and is synced. The
/// configured state file (a direct child of `/state`) is always inside the
/// set; the default `tailscaled.state` spelling stays accepted even when a
/// custom path is configured, so an identity synced by an earlier
/// deployment remains restorable.
pub(super) fn is_synced_file(rel: &str, state_file: Option<&str>) -> bool {
    if rel.is_empty()
        || rel.trim() != rel
        || rel.starts_with('/')
        || rel.ends_with('/')
        || rel
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || rel.chars().any(char::is_control)
        || crate::util::fs::is_partial_name(rel)
    {
        return false;
    }
    // Only normal components. A `..` inside a name (`foo..bar`) is a name;
    // a `..` component is traversal.
    if !std::path::Path::new(rel)
        .components()
        .all(|part| matches!(part, std::path::Component::Normal(_)))
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

/// Bound on the entries one scan may materialize. The manifest itself is
/// capped at 4 MiB (~40k paths); a larger local tree is refused rather than
/// letting a hostile or broken tree exhaust PID 1.
const MAX_SCAN_ENTRIES: usize = 50_000;

/// Bound on directory nesting. The tree is user-controlled; a depth this
/// large is already pathological and keeps recursion/FD use bounded.
const MAX_SCAN_DEPTH: usize = 32;

/// Why a scan could not prove the complete durable set. A push must refuse
/// rather than treat a partial scan as "these files were deleted".
#[derive(Debug)]
pub(super) enum ScanError {
    Aborted,
    MissingRoot(String),
    TooDeep(String),
    TooManyEntries,
    Io {
        path: String,
        source: std::io::Error,
    },
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aborted => f.write_str("aborted"),
            Self::MissingRoot(path) => write!(f, "{path} is not a real directory"),
            Self::TooDeep(path) => write!(f, "{path} is deeper than {MAX_SCAN_DEPTH} levels"),
            Self::TooManyEntries => {
                write!(f, "more than {MAX_SCAN_ENTRIES} entries")
            }
            Self::Io { path, source } => write!(f, "cannot scan {path}: {source}"),
        }
    }
}

fn scan_io(path: &Path, error: nix::errno::Errno) -> ScanError {
    ScanError::Io {
        path: path.to_string_lossy().into_owned(),
        source: std::io::Error::from_raw_os_error(error as i32),
    }
}

fn std_io(path: &Path, source: std::io::Error) -> ScanError {
    ScanError::Io {
        path: path.to_string_lossy().into_owned(),
        source,
    }
}

const DIR_FLAGS: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_DIRECTORY)
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC);

/// Open a tree root without following a final symlink. `Ok(None)` is a
/// missing tree (a fresh volume); every other failure is a failed scan.
fn open_root(path: &Path) -> Result<Option<Dir>, ScanError> {
    match Dir::open(path, DIR_FLAGS, Mode::empty()) {
        Ok(dir) => Ok(Some(dir)),
        Err(Errno::ENOENT) => Ok(None),
        Err(e) => Err(scan_io(path, e)),
    }
}

/// Open one child directory relative to an already-open descriptor. The
/// descriptor anchor plus O_NOFOLLOW is what makes a symlink swap fail
/// instead of redirecting the walk.
fn open_child(dir: &Dir, name: &std::ffi::CStr, path: &Path) -> Result<Dir, ScanError> {
    Dir::openat(dir, name, DIR_FLAGS, Mode::empty()).map_err(|e| scan_io(path, e))
}

/// A flat synced file: a regular file is a source, a missing path is not,
/// and other types are not followed. A permission/I/O error is a failed
/// scan, never "absent".
fn flat_file(path: &Path, rel: &str, files: &mut Vec<String>) -> Result<(), ScanError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => {
            files.push(rel.to_string());
            Ok(())
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(std_io(path, e)),
    }
}

/// Walk one tree through directory descriptors. Directory entries are
/// collected first (the iterator borrows the descriptor), then each child is
/// opened relative to it with O_NOFOLLOW.
fn scan_tree(
    dir: &mut Dir,
    rel: &str,
    state_file: Option<&str>,
    abort: &impl Fn() -> bool,
    depth: usize,
    entries: &mut usize,
    files: &mut Vec<String>,
) -> Result<(), ScanError> {
    if depth > MAX_SCAN_DEPTH {
        return Err(ScanError::TooDeep(rel.to_string()));
    }
    let mut listed: Vec<(std::ffi::CString, Type)> = Vec::new();
    for entry in dir.iter() {
        if abort() {
            return Err(ScanError::Aborted);
        }
        let entry = entry.map_err(|e| scan_io(Path::new(rel), e))?;
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        *entries += 1;
        if *entries > MAX_SCAN_ENTRIES {
            return Err(ScanError::TooManyEntries);
        }
        let Some(kind) = entry.file_type() else {
            return Err(ScanError::Io {
                path: rel.to_string(),
                source: std::io::Error::other("unknown directory entry type"),
            });
        };
        listed.push((name.to_owned(), kind));
    }
    for (name, kind) in listed {
        if abort() {
            return Err(ScanError::Aborted);
        }
        let Some(name_str) = name.to_str().ok() else {
            continue; // non-UTF-8 names never enter the durable set
        };
        let path_rel = format!("{rel}/{name_str}");
        match kind {
            Type::Directory => {
                let child_path = Path::new(&path_rel);
                let mut child = open_child(dir, name.as_c_str(), child_path)?;
                scan_tree(
                    &mut child,
                    &path_rel,
                    state_file,
                    abort,
                    depth + 1,
                    entries,
                    files,
                )?;
            }
            Type::File if is_synced_file(&path_rel, state_file) => {
                files.push(path_rel);
            }
            Type::File => {}
            // Never follow a symlink; special files are not sync sources.
            _ => {}
        }
    }
    Ok(())
}

fn scan_root(
    path: &Path,
    rel: &str,
    state_file: Option<&str>,
    abort: &impl Fn() -> bool,
    entries: &mut usize,
    files: &mut Vec<String>,
) -> Result<(), ScanError> {
    let Some(mut dir) = open_root(path)? else {
        return Ok(());
    };
    scan_tree(&mut dir, rel, state_file, abort, 0, entries, files)
}

/// The files in the durable set, as bucket-relative paths, across both
/// local volumes (production) or a single scratch directory (tests).
///
/// A failure is returned, not logged and skipped: the push must be able to
/// tell "the tree is empty" from "the scan could not finish", because only
/// the former may feed the deletion lifecycle.
pub(super) fn local_synced_files(
    roots: &Roots,
    state_file: Option<&str>,
    abort: &impl Fn() -> bool,
) -> Result<Vec<String>, ScanError> {
    for root in [&roots.data, &roots.state] {
        if !is_real_dir(&root.to_string_lossy()) {
            return Err(ScanError::MissingRoot(root.to_string_lossy().into_owned()));
        }
    }
    let mut files = Vec::new();
    let mut entries = 0usize;

    flat_file(
        &roots.state.join("tailscaled.state"),
        "tailscaled.state",
        &mut files,
    )?;
    if let Some(state) = state_file
        && state != "tailscaled.state"
    {
        flat_file(&roots.state.join(state), state, &mut files)?;
    }
    for tree in STATE_TREES {
        scan_root(
            &roots.state.join(tree),
            tree,
            state_file,
            abort,
            &mut entries,
            &mut files,
        )?;
    }

    flat_file(&roots.data.join("config.json"), "config.json", &mut files)?;
    // rsa_key* lives flat at the data root. Enumerate it through the same
    // anchored descriptor, so a directory swap cannot redirect the walk.
    let Some(mut data) = open_root(&roots.data)? else {
        return Err(ScanError::MissingRoot(
            roots.data.to_string_lossy().into_owned(),
        ));
    };
    for entry in data.iter() {
        if abort() {
            return Err(ScanError::Aborted);
        }
        let entry = entry.map_err(|e| scan_io(&roots.data, e))?;
        entries += 1;
        if entries > MAX_SCAN_ENTRIES {
            return Err(ScanError::TooManyEntries);
        }
        let Some(kind) = entry.file_type() else {
            return Err(ScanError::Io {
                path: roots.data.to_string_lossy().into_owned(),
                source: std::io::Error::other("unknown directory entry type"),
            });
        };
        if kind != Type::File {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str().ok() else {
            continue;
        };
        if name.starts_with("rsa_key") && is_synced_file(name, state_file) {
            files.push(name.to_string());
        }
    }
    for tree in DATA_TREES {
        scan_root(
            &roots.data.join(tree),
            tree,
            state_file,
            abort,
            &mut entries,
            &mut files,
        )?;
    }

    // The invariant both directions share: what push may upload is exactly
    // what pull may write.
    files.retain(|file| is_synced_file(file, state_file));
    files.sort();
    files.dedup();
    Ok(files)
}

/// Remove supervisor `.vw-part` staging leftovers at both roots and inside
/// the synced trees (recursively); returns how many were removed. A transfer
/// that died mid-pull leaves one, and it must never be resumed against
/// different content, so each boot starts clean. User files ending `.part`
/// are not touched. Staging directories outside the synced trees (backup
/// dumps) are not touched.
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
    // can still contain a `.vw-part` from a dead transfer.
    if let Some(state) = state_file
        && let Some(parent) = Path::new(state).parent()
        && !parent.as_os_str().is_empty()
    {
        clear_recursive(&roots.state.join(parent), &mut removed);
    }
    removed
}

fn open_cleanup_dir(path: &Path) -> Option<Dir> {
    match Dir::open(path, DIR_FLAGS, Mode::empty()) {
        Ok(dir) => Some(dir),
        Err(Errno::ENOENT) => None,
        Err(_) => None, // a symlinked/unreadable root is never followed
    }
}

fn clear_entries(dir: &mut Dir, removed: &mut usize, depth: usize) {
    if depth > MAX_SCAN_DEPTH {
        return;
    }
    let mut listed = Vec::new();
    for entry in dir.iter() {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name();
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        let Some(kind) = entry.file_type() else {
            continue;
        };
        if listed.len() >= MAX_SCAN_ENTRIES {
            return;
        }
        listed.push((name.to_owned(), kind));
    }
    for (name, kind) in listed {
        let Some(name_str) = name.to_str().ok() else {
            continue;
        };
        if name_str.ends_with(crate::util::fs::PART_SUFFIX) {
            if matches!(kind, Type::File | Type::Symlink)
                && unlinkat(&*dir, name.as_c_str(), UnlinkatFlags::NoRemoveDir).is_ok()
            {
                *removed += 1;
            }
        } else if kind == Type::Directory
            && let Ok(mut child) = open_child(dir, name.as_c_str(), Path::new(name_str))
        {
            clear_entries(&mut child, removed, depth + 1);
        }
    }
}

fn clear_flat(path: &Path, removed: &mut usize) {
    if let Some(mut dir) = open_cleanup_dir(path) {
        clear_entries(&mut dir, removed, 0);
    }
}

fn clear_recursive(path: &Path, removed: &mut usize) {
    if let Some(mut dir) = open_cleanup_dir(path) {
        clear_entries(&mut dir, removed, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_user_data_can_be_tombstoned() {
        use super::is_deletable;

        for rel in [
            "attachments/u",
            "attachments/sub/u",
            "sends/u",
            "config.json",
        ] {
            assert!(is_deletable(rel), "{rel} is user data");
        }
        for rel in [
            "tailscaled.state",
            "sub/node.state",
            "rsa_key",
            "rsa_key.pem",
            "certs/a.crt",
            "certs/sub/a.crt",
        ] {
            assert!(!is_deletable(rel), "{rel} is identity/cert material");
        }
    }

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
        // A user file ending `.part` is user data and must sync. Only the
        // supervisor's own temp suffix is excluded.
        assert!(synced("attachments/8f14e45f-uuid.part"));
        assert!(synced("certs/key.crt.part"));
        assert!(synced("sends/uuid.part"));
        assert!(!synced("attachments/8f14e45f-uuid.vw-part"));
        // A safe `..` inside a name is a name; traversal components are not.
        assert!(synced("attachments/foo..bar"));
        assert!(!synced("attachments/foo/../bar"));
        assert!(!synced("attachments/./bar"));
        assert!(!synced("attachments/bar/"));
        assert!(!synced("attachments/bar "));
        assert!(!synced(" attachments/bar"));
        assert!(!synced("attachments//bar"));
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
        // The anchored scan covers the same tree the push will use.
        let roots = Roots::one(&dir);
        let found = local_synced_files(&roots, None, &|| false).expect("scan");
        assert_eq!(
            found,
            vec![
                "attachments/uuid-1",
                "attachments/uuid-1.part",
                "certs/example.com.crt",
                "certs/sub/deep.crt",
                "sends/sub/uuid-2",
                "tailscaled.state",
            ]
        );
        assert!(found.iter().all(|f| is_synced_file(f, None)));
        assert!(!is_synced_file("db.sqlite3", None));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The push enumeration covers both volumes: identity files, rsa_key*,
    /// and the trees; user `.part` files are included, supervisor temps are not.
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
            local_synced_files(&roots, None, &|| false).expect("scan"),
            vec![
                "attachments/u1",
                "attachments/u1.part",
                "certs/c.crt",
                "config.json",
                "rsa_key.pem",
                "rsa_key.pub.pem",
                "tailscaled.state",
            ]
        );
        // a configured custom state file rides along from /state
        std::fs::write(roots.state.join("node.state"), b"x").unwrap();
        let files = local_synced_files(&roots, Some("node.state"), &|| false).expect("scan");
        assert!(files.contains(&"node.state".to_string()), "{files:?}");
        // the vault's copy of the same name is not the identity
        std::fs::write(roots.data.join("node.state"), b"x").unwrap();
        let files = local_synced_files(&roots, Some("node.state"), &|| false).expect("scan");
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

    /// Stale `.vw-part` leftovers are removed at boot, flat at the root and
    /// recursively under every tree; real files, including user `.part`
    /// files, survive.
    #[test]
    fn stale_partials_are_cleared() {
        let root = std::env::temp_dir().join(format!("vw-sup-parts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("attachments/sub")).unwrap();
        std::fs::write(root.join("attachments/user.part"), b"x").unwrap();
        std::fs::create_dir_all(root.join("certs")).unwrap();
        std::fs::write(root.join("rsa_key.vw-part"), b"x").unwrap();
        std::fs::write(root.join("attachments/u.vw-part"), b"x").unwrap();
        std::fs::write(root.join("attachments/sub/v.vw-part"), b"x").unwrap();
        std::fs::write(root.join("certs/keep.crt"), b"x").unwrap();
        let roots = Roots::one(&root);
        assert_eq!(clear_partials(&roots, None), 3);
        assert!(!root.join("rsa_key.vw-part").exists());
        assert!(root.join("attachments/user.part").exists());
        assert!(!root.join("attachments/u.vw-part").exists());
        assert!(!root.join("attachments/sub/v.vw-part").exists());
        assert!(root.join("certs/keep.crt").exists());
        assert_eq!(clear_partials(&roots, None), 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A symlink is not a sync source and is never walked. Removing a
    /// `.vw-part` symlink removes the link, not the file it points at.
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
        symlink(&secret, root.join("attachments/stale.vw-part")).unwrap();

        let roots = Roots::one(&root);
        let files = local_synced_files(&roots, None, &|| false).expect("scan");
        assert!(files.is_empty(), "symlinks are not synced: {files:?}");
        assert!(clear_partials(&roots, None) >= 1);
        assert_eq!(std::fs::read(&secret).unwrap(), b"do-not-touch");
        assert!(!root.join("attachments/stale.vw-part").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A symlinked tree root is a failed scan, not a walk into the target:
    /// the vault can replace `/data/attachments` with a link to `/state`, and
    /// its files must never be uploaded under the attachment namespace.
    #[test]
    fn a_symlinked_tree_root_is_a_failed_scan() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!("vw-sup-treelink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("outside")).unwrap();
        std::fs::write(root.join("outside/secret"), b"secret").unwrap();
        symlink(root.join("outside"), root.join("attachments")).unwrap();

        let roots = Roots::one(&root);
        let err = local_synced_files(&roots, None, &|| false)
            .expect_err("a symlinked tree root must fail the scan");
        assert!(matches!(err, ScanError::Io { .. }), "{err:?}");
        clear_partials(&roots, None);
        assert!(
            root.join("outside/secret").exists(),
            "the symlink target must survive cleanup"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A tree that exists but cannot be read is a failed scan. The push then
    /// refuses instead of treating the missing entries as deletions.
    #[test]
    fn an_unreadable_tree_is_a_failed_scan() {
        use std::os::unix::fs::PermissionsExt;

        if nix::unistd::geteuid().is_root() {
            return; // root ignores the permission bits
        }
        let root = std::env::temp_dir().join(format!("vw-sup-unreadable-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("attachments/locked")).unwrap();
        std::fs::write(root.join("attachments/locked/file"), b"x").unwrap();
        std::fs::set_permissions(
            root.join("attachments/locked"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();

        let roots = Roots::one(&root);
        let err = local_synced_files(&roots, None, &|| false)
            .expect_err("an unreadable tree must fail the scan");
        assert!(matches!(err, ScanError::Io { .. }), "{err:?}");
        std::fs::set_permissions(
            root.join("attachments/locked"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_aborted_scan_fails() {
        let root = std::env::temp_dir().join(format!("vw-sup-abortscan-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("attachments")).unwrap();
        std::fs::write(root.join("attachments/u"), b"x").unwrap();
        let roots = Roots::one(&root);
        let err =
            local_synced_files(&roots, None, &|| true).expect_err("an aborted scan must fail");
        assert!(matches!(err, ScanError::Aborted), "{err:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_tree_deeper_than_the_limit_is_a_failed_scan() {
        let root = std::env::temp_dir().join(format!("vw-sup-deep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut deep = root.join("attachments");
        for _ in 0..40 {
            deep.push("d");
        }
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("file"), b"x").unwrap();
        let err = local_synced_files(&Roots::one(&root), None, &|| false)
            .expect_err("a deeply nested tree must fail the scan");
        assert!(matches!(err, ScanError::TooDeep(_)), "{err:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_custom_state_parent_is_cleaned() {
        let root = std::env::temp_dir().join(format!("vw-sup-statepart-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("sub/node.state.vw-part"), b"partial").unwrap();
        assert_eq!(
            clear_partials(&Roots::one(&root), Some("sub/node.state")),
            1
        );
        assert!(!root.join("sub/node.state.vw-part").exists());
        let _ = std::fs::remove_dir_all(&root);
    }
}
