//! One-time migration from the pre-isolation layout, where the tailscaled
//! identity, cert cache, backup staging, and sync sidecars lived on the
//! vault-writable `/data` volume.
//!
//! The supervisor now keeps those under `/state` (0700, owner 65532). The
//! vault runs as 65533:65532 and can neither traverse that directory nor
//! read its files. `/data` stays the vault's volume: the supervisor only
//! reads it (0660/0770 for the shared group).
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

use nix::unistd::geteuid;

use crate::config::{SUPERVISOR_GID, SUPERVISOR_STATE, SUPERVISOR_UID};
use crate::util::fs::{is_real_file, write_atomic};
use crate::util::log;

/// Marks a completed migration (and the recursive `/data` mode fix).
const MARKER: &str = ".layout-v2";
/// The identity, cert cache, and lineage sidecar are all small; the cap
/// only bounds a corrupt/hostile file.
const MAX_MIGRATED_BYTES: u64 = 16 * 1024 * 1024;
/// A recursive chmod is one-time; refuse a pathological tree rather than
/// spend an unbounded boot on it.
const MAX_ENTRIES: u64 = 2_000_000;

/// Production entry: migrate `/data` into `/state`.
pub fn migrate_layout() -> bool {
    migrate_layout_at(Path::new(SUPERVISOR_STATE), Path::new("/data"))
}

/// [`migrate_layout`] with explicit roots (tests use scratch directories).
pub(super) fn migrate_layout_at(state: &Path, data: &Path) -> bool {
    if let Err(e) = ensure_private_dir(state) {
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
    ok
}

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

fn set_dir(dir: &Path, mode: u32) -> std::io::Result<()> {
    fs::set_permissions(dir, fs::Permissions::from_mode(mode))
}

/// Only the image's supervisor identity may migrate a file. Under that
/// uid the vault (65533) cannot create a supervisor-owned file, so a
/// mismatched owner after the split is a planted identity. Unit tests run
/// as the developer's uid, where the check is not meaningful.
fn authentic_owner(meta: &fs::Metadata) -> bool {
    geteuid().as_raw() != SUPERVISOR_UID || meta.uid() == SUPERVISOR_UID
}

/// Move one small regular file into the state volume. A missing source is
/// a no-op; a symlink is removed without following it; an oversized,
/// foreign-owned, or unreadable source is left in place and fails the
/// migration loudly.
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

/// Recursively move a directory tree into the state volume. Files keep
/// owner-only modes; symlinks are removed, never followed. A destination
/// that already exists wins (it is the newer layout), and the source copy
/// is removed.
fn move_tree(src: &Path, dst: &Path) -> bool {
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
            ok &= move_tree(&child_src, &child_dst);
        } else if file_type.is_file() {
            ok &= move_file(&child_src, &child_dst);
        }
    }
    if fs::read_dir(src).is_ok_and(|mut entries| entries.next().is_none()) {
        let _ = fs::remove_dir(src);
    }
    ok
}

fn remove_file(path: &Path) {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() || meta.file_type().is_symlink() => {
            let _ = fs::remove_file(path);
        }
        Ok(_) => {}
        Err(_) => {}
    }
}

fn remove_tree(dir: &Path) {
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
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if file_type.is_dir() {
                remove_tree(&path);
            } else {
                let _ = fs::remove_file(&path);
            }
        }
    }
    let _ = fs::remove_dir(dir);
}

/// Give the vault's volume the shared group modes: directories 0770,
/// files 0660. Ownership is left alone. A file the supervisor does not own
/// (vault-created after this layout, e.g. when a `/state` volume was
/// recreated) cannot be changed without CAP_CHOWN — that is not fatal: the
/// vault already has the access it needs, and the sync logs anything it
/// cannot read.
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

/// Best-effort group change to the shared data group. Files already in
/// that group (everything the vault created) need nothing; a file owned
/// by another uid cannot be changed without CAP_CHOWN, which the
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
    use std::path::PathBuf;

    use super::*;

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

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
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
        assert!(migrate_layout_at(&state, &data));

        assert_eq!(
            fs::read(state.join("tailscaled.state")).unwrap(),
            b"identity"
        );
        assert_eq!(mode(&state.join("tailscaled.state")), 0o600);
        assert_eq!(fs::read(state.join("certs/sub/b.key")).unwrap(), b"key");
        assert_eq!(mode(&state.join("certs/sub/b.key")), 0o600);
        assert_eq!(mode(&state.join("certs")), 0o700);
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

        assert!(migrate_layout_at(&state, &data));
        assert!(!data.join("tailscaled.state").exists());
        assert!(!data.join("certs/key").exists());
        assert_eq!(fs::read(&victim).unwrap(), b"keep");
        assert!(!state.join("tailscaled.state").exists());
        let _ = fs::remove_dir_all(state.parent().unwrap());
    }

    /// After a completed migration, a state file that reappears on the
    /// vault volume is removed, not adopted over the real identity.
    #[test]
    fn a_completed_migration_never_re_adopts_a_vault_volume_copy() {
        let (state, data) = scratch("readopt");
        assert!(migrate_layout_at(&state, &data));
        assert!(state.join(MARKER).is_file());
        fs::write(state.join("tailscaled.state"), b"real-identity").unwrap();
        fs::write(data.join("tailscaled.state"), b"planted").unwrap();
        assert!(migrate_layout_at(&state, &data));
        assert_eq!(
            fs::read(state.join("tailscaled.state")).unwrap(),
            b"real-identity"
        );
        assert!(!data.join("tailscaled.state").exists());
        let _ = fs::remove_dir_all(state.parent().unwrap());
    }

    #[test]
    fn a_target_already_in_the_state_volume_wins() {
        let (state, data) = scratch("target");
        fs::write(state.join("tailscaled.state"), b"new").unwrap();
        fs::write(data.join("tailscaled.state"), b"old").unwrap();
        assert!(migrate_layout_at(&state, &data));
        assert_eq!(fs::read(state.join("tailscaled.state")).unwrap(), b"new");
        assert!(!data.join("tailscaled.state").exists());
        let _ = fs::remove_dir_all(state.parent().unwrap());
    }
}
