//! One-time migration from the pre-isolation layout, where the tailscaled
//! identity, cert cache, backup staging, and sync sidecars lived on the
//! vault-writable `/data` volume.
//!
//! The supervisor now keeps those under `/state` (2710, owner 65532, group
//! tailscale) and the identity/certs under `/state/tailscale` (2770). The
//! vault runs as 65533:65532 and can neither traverse that directory nor
//! read its files. `/data` stays the vault's volume: the supervisor only
//! reads it (0660/0770 for the shared group). In single-uid mode the group
//! is the supervisor's own gid and the vault shares that uid, so this
//! isolation does not apply; the layout is still prepared the same way.
//!
//! This runs before config resolution because the identity gate reads the
//! state file, and before the vault can run. Every source path is treated
//! as untrusted: symlinks are removed, never followed. Copies are atomic
//! and owner-only; a failed copy keeps the source and reports the error.
//! Bucket keys keep their old names (`tailscaled.state`, `certs/**`), so
//! an existing bucket restores into either layout unchanged.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use nix::unistd::{Gid, chown, geteuid};

use crate::config::{SUPERVISOR_GID, SUPERVISOR_STATE, SUPERVISOR_UID, TAILSCALE_GID};
use crate::util::fs::{is_real_file, write_atomic};
use crate::util::log;

/// Marks a completed `/data` -> `/state` migration.
const MARKER: &str = ".layout-v2";
/// Marks the tailscaled identity/certs move into `/state/tailscale`.
const TAILSCALE_MARKER: &str = ".layout-v3";
/// The identity, cert cache, and lineage sidecar are all small; the cap
/// only bounds a corrupt/hostile file.
const MAX_MIGRATED_BYTES: u64 = 16 * 1024 * 1024;
/// A recursive chmod is one-time; refuse a pathological tree rather than
/// spend an unbounded boot on it.
const MAX_ENTRIES: u64 = 2_000_000;
/// Bound on the recursive mode walks. The vault and tailscaled control the
/// trees; a depth this large is pathological and must not overflow the boot
/// stack.
const MAX_TREE_DEPTH: usize = 32;

/// Production entry: migrate `/data` into `/state` under the chosen
/// identity mode (`single_uid` keeps every file in the supervisor's group).
pub fn migrate_layout(single_uid: bool) -> bool {
    migrate_layout_at(Path::new(SUPERVISOR_STATE), Path::new("/data"), single_uid)
}

/// [`migrate_layout`] with explicit roots (tests use scratch directories).
pub(super) fn migrate_layout_at(state: &Path, data: &Path, single_uid: bool) -> bool {
    let group = tailscale_group(single_uid);
    if let Err(e) = ensure_state_dir(state, group) {
        log::err(&format!(
            "layout: cannot prepare the supervisor state volume {}: {e}",
            log::sanitize(&state.to_string_lossy())
        ));
        return false;
    }
    let marker = state.join(MARKER);
    let first_run = !is_real_file(&marker.to_string_lossy());
    let mut ok = true;

    if first_run {
        // The node identity and the tailscaled cert cache move together:
        // the daemon's `--statedir` is the state file's parent. Every
        // source must be supervisor-owned: after the split, the vault
        // cannot create such files, so a mismatched owner is a planted
        // identity and boot refuses rather than trust it.
        ok &= move_file(
            &data.join("tailscaled.state"),
            &state.join("tailscaled.state"),
        );
        ok &= move_tree(&data.join("certs"), &state.join("certs"));
        // Backup lineage is durable (it proves this volume owns the
        // bucket's newest generation). The retained dump, hash cache, and
        // repair list are optimizations/rebuildable and stay behind only
        // to be deleted.
        ok &= move_file(
            &data.join("db-backups.state"),
            &state.join("db-backups.state"),
        );
    } else {
        // A completed migration owns these names now. Anything that
        // reappears under them on the vault volume is not the identity;
        // remove it instead of copying it over a newer state volume.
        for stale in ["tailscaled.state", "db-backups.state"] {
            remove_file(&data.join(stale));
        }
        remove_tree(&data.join("certs"));
    }
    for stale in ["db-backups.last", ".sync-cache", ".sync-repair"] {
        remove_file(&data.join(stale));
    }
    remove_tree(&data.join("db-backups"));

    // Existing Vaultwarden files were created by the old same-UID layout
    // (0644/0755, group 0). The vault now reaches them through group
    // 65532, so make the shared modes explicit. A marker keeps this
    // one-time walk off every subsequent boot, and is written only after
    // both the moves and the walk succeeded.
    if !first_run {
        if let Err(e) = set_dir(data, 0o770) {
            log::err(&format!(
                "layout: cannot set the data root mode {}: {e}",
                log::sanitize(&data.to_string_lossy())
            ));
            ok = false;
        }
        if let Ok(meta) = fs::symlink_metadata(data) {
            share_group(data, &meta);
        }
        return ok;
    }
    match fix_data_permissions(data) {
        Ok(()) if ok => {
            if let Err(e) = write_atomic(&marker.to_string_lossy(), b"2\n", 0o600) {
                log::err(&format!("layout: cannot write the migration marker: {e}"));
            }
            log::info("layout: migrated the pre-isolation /data layout to /state");
        }
        Ok(()) => {
            log::err(
                "layout: the /data to /state move is incomplete; refusing to mark it \
                 done (the next boot retries)",
            );
        }
        Err(e) => {
            log::err(&format!(
                "layout: cannot finish the /data permission migration ({e}); \
                 it is retried on the next boot"
            ));
            ok = false;
        }
    }
    ok && migrate_tailscale_layout(state, group)
}

/// The production state volume and the tests share one rule: in the image
/// the group is the fixed `tailscale` gid; in a developer test run the
/// current gid is the only one the user may assign. Single-uid mode always
/// uses the current gid: a foreign group needs CAP_CHOWN/CAP_SETGID.
fn tailscale_group_for(single_uid: bool, euid: u32, egid: u32) -> u32 {
    if single_uid || (euid != SUPERVISOR_UID && euid != 0) {
        egid
    } else {
        TAILSCALE_GID
    }
}

/// [`tailscale_group_for`] for the running process.
fn tailscale_group(single_uid: bool) -> u32 {
    tailscale_group_for(
        single_uid,
        geteuid().as_raw(),
        nix::unistd::getegid().as_raw(),
    )
}

/// Prepare `/state`: owner supervisor, the chosen group, mode 2710 (owner
/// rwx, group traverse, setgid for the subtree). The group is set first:
/// the setgid bit survives chmod only when the caller belongs to the group
/// (single-uid mode has no `CAP_FSETID`).
fn ensure_state_dir(dir: &Path, group: u32) -> std::io::Result<()> {
    ensure_private_dir(dir)?;
    set_group(dir, group)?;
    set_dir(dir, 0o2710)
}

/// Set `path`'s group, mapping the nix error into `std::io`.
fn set_group(path: &Path, group: u32) -> std::io::Result<()> {
    chown(path, None, Some(Gid::from_raw(group)))
        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
}

/// Move the identity and cert cache into `/state/tailscale`, make the subtree
/// group-writable for tailscaled, and mark the layout done. Bucket keys stay
/// `tailscaled.state` and `certs/**`; only local paths move.
fn migrate_tailscale_layout(state: &Path, group: u32) -> bool {
    let dir = state.join("tailscale");
    if let Err(e) = ensure_dir_group(&dir, group) {
        log::err(&format!(
            "layout: cannot prepare {}: {e}",
            log::sanitize(&dir.to_string_lossy())
        ));
        return false;
    }
    // The cert tree is created up front (setgid, group tailscale) so a
    // restored cert inherits the group tailscaled reads.
    if let Err(e) = ensure_dir_group(&dir.join("certs"), group) {
        log::err(&format!(
            "layout: cannot prepare {}: {e}",
            log::sanitize(&dir.join("certs").to_string_lossy())
        ));
        return false;
    }
    if !ensure_state_link(state) {
        return false;
    }
    let marker = state.join(TAILSCALE_MARKER);
    if is_real_file(&marker.to_string_lossy()) {
        // A completed move still needs its modes enforced after an image
        // or volume mode change. The walk is best-effort: tailscaled owns
        // some files and creates them 0600, and the supervisor must not
        // fail the boot over a mode it cannot change (it reads them through
        // CAP_DAC_READ_SEARCH).
        fix_tailscale_modes(&dir, group);
        return true;
    }
    let mut ok = true;
    ok &= move_file(
        &state.join("tailscaled.state"),
        &dir.join("tailscaled.state"),
    );
    ok &= move_tree(&state.join("certs"), &dir.join("certs"));
    if !ok {
        log::err("layout: tailscaled state move incomplete; refusing to mark it done");
        return false;
    }
    fix_tailscale_modes(&dir, group);
    if let Err(e) = write_atomic(&marker.to_string_lossy(), b"3\n", 0o600) {
        log::err(&format!("layout: cannot write the tailscale marker: {e}"));
        return false;
    }
    log::info("layout: moved tailscaled identity and certs into /state/tailscale");
    true
}

/// Create `dir` privately, then set the chosen group and mode 2770. Group
/// first: the setgid bit needs the caller to belong to the group.
fn ensure_dir_group(dir: &Path, group: u32) -> std::io::Result<()> {
    ensure_private_dir(dir)?;
    set_group(dir, group)?;
    set_dir(dir, 0o2770)
}

/// Ensure `/state/tailscale-state -> tailscale` exists and names that target.
/// tailscaled is given the link so it cannot chmod the real, supervisor-owned
/// tree to 0700 — it would fall back to an in-memory state store.
fn ensure_state_link(state: &Path) -> bool {
    let link = state.join("tailscale-state");
    let target = Path::new("tailscale");
    match fs::symlink_metadata(&link) {
        Ok(meta) if meta.file_type().is_symlink() => match fs::read_link(&link) {
            Ok(dest) if dest == target => true,
            Ok(dest) => {
                log::err(&format!(
                    "layout: {} points at {}, expected tailscale; refusing to use it",
                    log::sanitize(&link.to_string_lossy()),
                    log::sanitize(&dest.to_string_lossy())
                ));
                false
            }
            Err(e) => {
                log::err(&format!(
                    "layout: cannot read the state link {}: {e}",
                    log::sanitize(&link.to_string_lossy())
                ));
                false
            }
        },
        Ok(_) => {
            log::err(&format!(
                "layout: {} exists but is not a symlink; refusing to use it",
                log::sanitize(&link.to_string_lossy())
            ));
            false
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            match std::os::unix::fs::symlink(target, &link) {
                Ok(()) => true,
                Err(e) => {
                    log::err(&format!(
                        "layout: cannot create the state link {}: {e}",
                        log::sanitize(&link.to_string_lossy())
                    ));
                    false
                }
            }
        }
        Err(e) => {
            log::err(&format!(
                "layout: cannot inspect the state link {}: {e}",
                log::sanitize(&link.to_string_lossy())
            ));
            false
        }
    }
}

/// Enforce 2770/660 and the group on the tailscaled-writable tree, removing
/// symlinks rather than following them. Best-effort and bounded: a mode the
/// supervisor cannot change is not a boot failure.
fn fix_tailscale_modes(dir: &Path, group: u32) {
    let mut budget = MAX_ENTRIES;
    fix_tailscale_modes_at(dir, group, 0, &mut budget);
}

/// Walk one directory level, enforcing modes within the entry and depth budgets.
fn fix_tailscale_modes_at(dir: &Path, group: u32, depth: usize, budget: &mut u64) {
    if depth > MAX_TREE_DEPTH {
        log::err(&format!(
            "layout: {} is deeper than {MAX_TREE_DEPTH} levels; leaving its modes alone",
            log::sanitize(&dir.to_string_lossy())
        ));
        return;
    }
    fix_owned_path(dir, 0o2770, group);
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            log::err(&format!(
                "layout: cannot read {}: {e}",
                log::sanitize(&dir.to_string_lossy())
            ));
            return;
        }
    };
    for entry in entries.flatten() {
        if *budget == 0 {
            log::err(&format!(
                "layout: more than {MAX_ENTRIES} entries under {}; leaving the rest alone",
                log::sanitize(&dir.to_string_lossy())
            ));
            return;
        }
        *budget -= 1;
        let path = entry.path();
        let kind = match entry.file_type() {
            Ok(kind) => kind,
            Err(e) => {
                log::err(&format!(
                    "layout: cannot classify {}: {e}",
                    log::sanitize(&path.to_string_lossy())
                ));
                continue;
            }
        };
        if kind.is_symlink() {
            let _ = fs::remove_file(&path);
        } else if kind.is_dir() {
            fix_tailscale_modes_at(&path, group, depth + 1, budget);
        } else if kind.is_file() {
            fix_owned_path(&path, 0o660, group);
        }
    }
}

/// Set mode and group only on a path this process owns (or as root): tailscaled
/// creates its own files 0600 under its uid, and the supervisor must leave
/// those alone, reading them through `CAP_DAC_READ_SEARCH`.
fn fix_owned_path(path: &Path, mode: u32, group: u32) {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return;
    };
    let euid = geteuid();
    if !euid.is_root() && meta.uid() != euid.as_raw() {
        return;
    }
    if let Err(e) = set_group(path, group) {
        log::err(&format!(
            "layout: cannot set the group of {}: {e}",
            log::sanitize(&path.to_string_lossy())
        ));
        return;
    }
    if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(mode)) {
        log::err(&format!(
            "layout: cannot set the mode of {}: {e}",
            log::sanitize(&path.to_string_lossy())
        ));
    }
}

/// Create `dir` if missing and force 0700; an existing non-directory is an error.
fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.file_type().is_dir() => {}
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "not a real directory",
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => fs::create_dir_all(dir)?,
        Err(e) => return Err(e),
    }
    set_dir(dir, 0o700)
}

/// Set `dir`'s mode exactly.
fn set_dir(dir: &Path, mode: u32) -> std::io::Result<()> {
    fs::set_permissions(dir, fs::Permissions::from_mode(mode))
}

/// Whether `meta` belongs to the image's supervisor identity. Under the test
/// uid the check is not meaningful and passes; in the image a foreign owner is
/// a planted identity that boot refuses to adopt.
fn authentic_owner(meta: &fs::Metadata) -> bool {
    geteuid().as_raw() != SUPERVISOR_UID || meta.uid() == SUPERVISOR_UID
}

/// Move one small regular file into the state volume. A missing source is a
/// no-op; a symlink is removed without following it; an oversized,
/// foreign-owned, or unreadable source stays put and fails the migration.
fn move_file(src: &Path, dst: &Path) -> bool {
    if src == dst {
        return true;
    }
    let meta = match fs::symlink_metadata(src) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return true,
        Err(e) => {
            log::err(&format!(
                "layout: cannot inspect {}: {e}",
                log::sanitize(&src.to_string_lossy())
            ));
            return false;
        }
    };
    if meta.file_type().is_symlink() {
        let _ = fs::remove_file(src);
        log::err(&format!(
            "layout: removed the symlink {} instead of following it",
            log::sanitize(&src.to_string_lossy())
        ));
        return true;
    }
    if !meta.is_file() {
        log::err(&format!(
            "layout: {} is not a regular file; left in place",
            log::sanitize(&src.to_string_lossy())
        ));
        return false;
    }
    if !authentic_owner(&meta) {
        log::err(&format!(
            "layout: {} is not owned by the supervisor; refusing to adopt it",
            log::sanitize(&src.to_string_lossy())
        ));
        return false;
    }
    if !is_real_file(&dst.to_string_lossy()) {
        if meta.len() > MAX_MIGRATED_BYTES {
            log::err(&format!(
                "layout: {} is {} bytes, over the {MAX_MIGRATED_BYTES}-byte cap; \
                 left in place",
                log::sanitize(&src.to_string_lossy()),
                meta.len()
            ));
            return false;
        }
        let bytes =
            match crate::util::fs::read_capped_bytes(&src.to_string_lossy(), MAX_MIGRATED_BYTES) {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::err(&format!(
                        "layout: cannot read {}: {e}",
                        log::sanitize(&src.to_string_lossy())
                    ));
                    return false;
                }
            };
        if let Err(e) = write_atomic(&dst.to_string_lossy(), &bytes, 0o600) {
            log::err(&format!(
                "layout: cannot write {}: {e}",
                log::sanitize(&dst.to_string_lossy())
            ));
            return false;
        }
    }
    if let Err(e) = fs::remove_file(src) {
        log::err(&format!(
            "layout: copied {} but cannot remove the old file ({e})",
            log::sanitize(&src.to_string_lossy())
        ));
        return false;
    }
    true
}

/// Recursively move a directory tree, keeping files owner-only and removing
/// symlinks without following them. An existing destination wins as the newer
/// layout; depth is bounded so a pathological tree fails instead of the stack.
fn move_tree(src: &Path, dst: &Path) -> bool {
    move_tree_at(src, dst, 0)
}

/// One level of [`move_tree`], recursing under the depth budget.
fn move_tree_at(src: &Path, dst: &Path, depth: usize) -> bool {
    if depth > MAX_TREE_DEPTH {
        log::err(&format!(
            "layout: {} is deeper than {MAX_TREE_DEPTH} levels; refusing to migrate it",
            log::sanitize(&src.to_string_lossy())
        ));
        return false;
    }
    if src == dst {
        return true;
    }
    let meta = match fs::symlink_metadata(src) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return true,
        Err(e) => {
            log::err(&format!(
                "layout: cannot inspect {}: {e}",
                log::sanitize(&src.to_string_lossy())
            ));
            return false;
        }
    };
    if meta.file_type().is_symlink() {
        let _ = fs::remove_file(src);
        return true;
    }
    if !meta.is_dir() {
        log::err(&format!(
            "layout: {} is not a directory; left in place",
            log::sanitize(&src.to_string_lossy())
        ));
        return false;
    }
    if !authentic_owner(&meta) {
        log::err(&format!(
            "layout: {} is not owned by the supervisor; refusing to adopt it",
            log::sanitize(&src.to_string_lossy())
        ));
        return false;
    }
    if let Err(e) = ensure_private_dir(dst) {
        log::err(&format!(
            "layout: cannot create {}: {e}",
            log::sanitize(&dst.to_string_lossy())
        ));
        return false;
    }
    let mut ok = true;
    let entries = match fs::read_dir(src) {
        Ok(entries) => entries,
        Err(e) => {
            log::err(&format!(
                "layout: cannot read {}: {e}",
                log::sanitize(&src.to_string_lossy())
            ));
            return false;
        }
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let child_src = src.join(&name);
        let child_dst = dst.join(&name);
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(e) => {
                log::err(&format!(
                    "layout: cannot classify {}: {e}",
                    log::sanitize(&child_src.to_string_lossy())
                ));
                ok = false;
                continue;
            }
        };
        if file_type.is_symlink() {
            let _ = fs::remove_file(&child_src);
        } else if file_type.is_dir() {
            ok &= move_tree_at(&child_src, &child_dst, depth + 1);
        } else if file_type.is_file() {
            ok &= move_file(&child_src, &child_dst);
        }
    }
    if fs::read_dir(src).is_ok_and(|mut entries| entries.next().is_none()) {
        let _ = fs::remove_dir(src);
    }
    ok
}

/// Remove `path` when it is a regular file or symlink; errors are ignored.
fn remove_file(path: &Path) {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() || meta.file_type().is_symlink() => {
            let _ = fs::remove_file(path);
        }
        Ok(_) => {}
        Err(_) => {}
    }
}

/// Remove `dir` recursively within the entry and depth budgets.
fn remove_tree(dir: &Path) {
    let mut budget = MAX_ENTRIES;
    remove_tree_at(dir, 0, &mut budget);
}

/// One level of [`remove_tree`], decrementing the shared entry budget.
fn remove_tree_at(dir: &Path, depth: usize, budget: &mut u64) {
    if depth > MAX_TREE_DEPTH || *budget == 0 {
        log::err(&format!(
            "layout: {} is too large or deep to remove; leaving the rest",
            log::sanitize(&dir.to_string_lossy())
        ));
        return;
    }
    let Ok(meta) = fs::symlink_metadata(dir) else {
        return;
    };
    if meta.file_type().is_symlink() {
        let _ = fs::remove_file(dir);
        return;
    }
    if !meta.is_dir() {
        return;
    }
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if *budget == 0 {
                log::err(&format!(
                    "layout: more than {MAX_ENTRIES} entries under {}; leaving the rest",
                    log::sanitize(&dir.to_string_lossy())
                ));
                return;
            }
            *budget -= 1;
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if file_type.is_dir() {
                remove_tree_at(&path, depth + 1, budget);
            } else {
                let _ = fs::remove_file(&path);
            }
        }
    }
    let _ = fs::remove_dir(dir);
}

/// Give the vault's volume shared group modes — directories 0770, files 0660 —
/// and leave ownership alone. A file owned by another uid cannot be changed
/// without CAP_CHOWN; that is logged, not fatal.
fn fix_data_permissions(root: &Path) -> std::io::Result<()> {
    set_dir(root, 0o770)?;
    if let Ok(meta) = fs::symlink_metadata(root) {
        // The old image made /data 65532:0; the vault's gid is 65532, so
        // the group must change or the vault cannot create a file at the
        // root of its own volume.
        share_group(root, &meta);
    }
    let mut seen = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) => {
                log::err(&format!(
                    "layout: cannot read {}: {e}",
                    log::sanitize(&dir.to_string_lossy())
                ));
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let meta = match fs::symlink_metadata(&path) {
                Ok(meta) => meta,
                Err(_) => continue,
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                if let Err(e) = set_dir(&path, 0o770) {
                    log::err(&format!(
                        "layout: cannot set the mode of {}: {e}",
                        log::sanitize(&path.to_string_lossy())
                    ));
                }
                share_group(&path, &meta);
                stack.push(path);
            } else if meta.is_file() {
                if let Err(e) = fs::set_permissions(&path, fs::Permissions::from_mode(0o660)) {
                    log::err(&format!(
                        "layout: cannot set the mode of {}: {e}",
                        log::sanitize(&path.to_string_lossy())
                    ));
                }
                share_group(&path, &meta);
            }
            seen += 1;
            if seen > MAX_ENTRIES {
                return Err(std::io::Error::other(format!(
                    "more than {MAX_ENTRIES} entries"
                )));
            }
        }
    }
    Ok(())
}

/// Best-effort move of `path` into the shared data group. Files already there
/// need nothing; a foreign uid cannot be changed without CAP_CHOWN, which the
/// supervisor deliberately does not hold.
fn share_group(path: &Path, meta: &fs::Metadata) {
    if meta.gid() == SUPERVISOR_GID {
        return;
    }
    // Only the image's supervisor identity owns the old-layout files. A
    // unit test (or an unsupported run as another user) has no business
    // changing their group, and would only log EPERM noise.
    if geteuid().as_raw() != SUPERVISOR_UID {
        return;
    }
    if let Err(e) = std::os::unix::fs::chown(path, None, Some(SUPERVISOR_GID)) {
        log::err(&format!(
            "layout: cannot move {} into group {SUPERVISOR_GID} ({e}); \
             the vault may not be able to read it",
            log::sanitize(&path.to_string_lossy())
        ));
    }
}

#[cfg(test)]
mod tests {
    //! Layout-migration tests over scratch state and data roots.

    use std::path::PathBuf;

    use super::*;

    /// A clean `(state, data)` pair under the temp dir.
    fn scratch(name: &str) -> (PathBuf, PathBuf) {
        let base =
            std::env::temp_dir().join(format!("vw-sup-migrate-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let state = base.join("state");
        let data = base.join("data");
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(&data).unwrap();
        (state, data)
    }

    /// The permission bits of `path`.
    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// In single-uid mode the layout must use the supervisor's own group;
    /// a foreign group would require CAP_CHOWN/CAP_SETGID, which the mode
    /// does not have.
    #[test]
    fn single_uid_mode_uses_the_supervisor_group() {
        assert_eq!(
            tailscale_group_for(true, SUPERVISOR_UID, SUPERVISOR_GID),
            SUPERVISOR_GID
        );
        assert_eq!(
            tailscale_group_for(false, SUPERVISOR_UID, SUPERVISOR_GID),
            TAILSCALE_GID
        );
        assert_eq!(tailscale_group_for(false, 0, SUPERVISOR_GID), TAILSCALE_GID);
        // a developer run keeps the only group it may assign
        assert_eq!(tailscale_group_for(false, 1000, 1000), 1000);
    }

    #[test]
    fn moves_identity_certs_and_lineage_out_of_the_vault_volume() {
        let (state, data) = scratch("move");
        fs::write(data.join("tailscaled.state"), b"identity").unwrap();
        fs::create_dir_all(data.join("certs/sub")).unwrap();
        fs::write(data.join("certs/a.crt"), b"cert").unwrap();
        fs::write(data.join("certs/sub/b.key"), b"key").unwrap();
        fs::write(data.join("db-backups.state"), b"7\n").unwrap();
        fs::write(data.join("db-backups.last"), vec![0u8; 1024]).unwrap();
        fs::write(data.join(".sync-cache"), b"cache").unwrap();
        fs::create_dir_all(data.join("db-backups")).unwrap();
        fs::write(data.join("db-backups/partial"), b"dump").unwrap();
        fs::create_dir_all(data.join("attachments/u")).unwrap();
        fs::write(data.join("attachments/u/f"), b"file").unwrap();

        // The test process is not uid 65532, so the group change cannot be
        // exercised here; the mode walk still runs.
        assert!(migrate_layout_at(&state, &data, false));

        assert_eq!(
            fs::read(state.join("tailscale/tailscaled.state")).unwrap(),
            b"identity"
        );
        assert_eq!(mode(&state.join("tailscale/tailscaled.state")), 0o660);
        assert_eq!(
            fs::read(state.join("tailscale/certs/sub/b.key")).unwrap(),
            b"key"
        );
        assert_eq!(mode(&state.join("tailscale/certs/sub/b.key")), 0o660);
        assert_eq!(mode(&state.join("tailscale/certs")), 0o770);
        assert_eq!(mode(&state), 0o710);
        assert_eq!(fs::read(state.join("db-backups.state")).unwrap(), b"7\n");
        assert!(!data.join("tailscaled.state").exists());
        assert!(!data.join("certs").exists());
        assert!(!data.join("db-backups.state").exists());
        assert!(!data.join("db-backups.last").exists());
        assert!(!data.join(".sync-cache").exists());
        assert!(!data.join("db-backups").exists());
        // User data stays, group-readable for the supervisor.
        assert_eq!(fs::read(data.join("attachments/u/f")).unwrap(), b"file");
        assert_eq!(mode(&data.join("attachments/u/f")), 0o660);
        assert_eq!(mode(&data.join("attachments/u")), 0o770);
        assert!(state.join(MARKER).is_file());
        assert!(state.join(TAILSCALE_MARKER).is_file());
        assert_eq!(
            fs::read_link(state.join("tailscale-state")).unwrap(),
            PathBuf::from("tailscale")
        );
        let _ = fs::remove_dir_all(state.parent().unwrap());
    }

    #[test]
    fn a_symlinked_old_layout_is_removed_not_followed() {
        use std::os::unix::fs::symlink;

        let (state, data) = scratch("symlink");
        let victim = data.join("victim");
        fs::write(&victim, b"keep").unwrap();
        symlink(&victim, data.join("tailscaled.state")).unwrap();
        fs::create_dir_all(data.join("certs")).unwrap();
        symlink(&victim, data.join("certs/key")).unwrap();

        assert!(migrate_layout_at(&state, &data, false));
        assert!(!data.join("tailscaled.state").exists());
        assert!(!data.join("certs/key").exists());
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
        assert!(!state.join("tailscale/tailscaled.state").exists());
        let _ = fs::remove_dir_all(state.parent().unwrap());
    }

    /// After a completed migration, a state file that reappears on the
    /// vault volume is removed, not adopted over the real identity.
    #[test]
    fn a_completed_migration_never_re_adopts_a_vault_volume_copy() {
        let (state, data) = scratch("readopt");
        assert!(migrate_layout_at(&state, &data, false));
        assert!(state.join(MARKER).is_file());
        fs::write(state.join("tailscale/tailscaled.state"), b"real-identity").unwrap();
        fs::write(data.join("tailscaled.state"), b"planted").unwrap();
        assert!(migrate_layout_at(&state, &data, false));
        assert_eq!(
            fs::read(state.join("tailscale/tailscaled.state")).unwrap(),
            b"real-identity"
        );
        assert!(!data.join("tailscaled.state").exists());
        let _ = fs::remove_dir_all(state.parent().unwrap());
    }

    #[test]
    fn a_target_already_in_the_state_volume_wins() {
        let (state, data) = scratch("target");
        fs::create_dir_all(state.join("tailscale")).unwrap();
        fs::write(state.join("tailscale/tailscaled.state"), b"new").unwrap();
        fs::write(data.join("tailscaled.state"), b"old").unwrap();
        assert!(migrate_layout_at(&state, &data, false));
        assert_eq!(
            fs::read(state.join("tailscale/tailscaled.state")).unwrap(),
            b"new"
        );
        assert!(!data.join("tailscaled.state").exists());
        let _ = fs::remove_dir_all(state.parent().unwrap());
    }
}
