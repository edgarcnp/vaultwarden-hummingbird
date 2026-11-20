//! The push side of state sync: content-addressed uploads, the deletion
//! lifecycle (tombstones and bounded object GC), the local repair list a
//! boot reconciliation fills, and the bounded wait for vaultwarden's
//! signing key before the first push. Hash and upload share one opened
//! descriptor; a file that changes during the transfer is never committed. [`super::state`] carries the shared
//! module doc: the durable set, the content-addressed layout, and the
//! failure posture both directions keep.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::config::{SYNC_RUN_BUDGET, SyncConfig};
use crate::s3::{Client, MAX_SYNC_OBJECT_BYTES};
use crate::util::hash::sha256_reader;
use crate::util::log;

use super::cache::Cache;
use super::manifest::{Entry, MANIFEST_NAME, Manifest};
use super::state::{
    build, load_manifest, load_tombstones, object_key, read_repair, remote_only_files,
    split_object_key, store_manifest, store_tombstones, write_repair,
};
use super::synced::{Roots, is_deletable, is_synced_file, local_synced_files};
use super::tombstone::{
    MAX_GC_DELETES, MAX_TOMBSTONES_PER_RUN, Missing, TOMBSTONES_NAME, Tombstones, now_unix,
};

/// Wait (bounded) for vaultwarden's signing key, so the first post-vault
/// push carries it. Returns false on timeout or a stop request; the caller
/// pushes anyway — a missing key is logged, never silently assumed.
pub fn wait_for_rsa_key(timeout: Duration, abort: impl Fn() -> bool) -> bool {
    wait_for_rsa_key_at(Path::new("/data"), timeout, abort)
}

pub(super) fn wait_for_rsa_key_at(
    root: &Path,
    timeout: Duration,
    abort: impl Fn() -> bool,
) -> bool {
    crate::util::wait_until(
        || {
            std::fs::read_dir(root).ok().and_then(|entries| {
                entries
                    .flatten()
                    .find(|entry| {
                        entry.file_name().to_string_lossy().starts_with("rsa_key")
                            && entry.file_type().is_ok_and(|kind| kind.is_file())
                    })
                    .map(|_| ())
            })
        },
        timeout,
        abort,
        Duration::from_millis(100),
    )
    .is_some()
}

/// Push synced files to the bucket. Called after `up` (fresh state),
/// shortly after the vault starts (the RSA key only exists once
/// vaultwarden has run), on the periodic cadence, and at shutdown.
/// Uploads only files whose content differs from the manifest (a hash,
/// not just a size), then rewrites the manifest. A file absent for the
/// deletion grace becomes a tombstone instead of being kept forever; the
/// mass guard keeps a lost volume from emptying the bucket.
pub fn sync_state(cfg: &SyncConfig, abort: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + SYNC_RUN_BUDGET;
    sync_state_at(&Roots::production(), cfg, || {
        abort() || Instant::now() >= deadline
    })
}

/// [`sync_state`] with explicit roots (tests use a scratch directory).
pub(super) fn sync_state_at(roots: &Roots, cfg: &SyncConfig, abort: impl Fn() -> bool) -> bool {
    let Some(client) = build(cfg) else {
        return false;
    };
    let files = match local_synced_files(roots, cfg.state_file.as_deref(), &abort) {
        Ok(files) => files,
        Err(e) => {
            log::err(&format!(
                "state sync: cannot enumerate the synced set ({e}); refusing this push \
                 so a partial scan cannot tombstone files"
            ));
            return false;
        }
    };
    let (bucket_manifest, manifest_loaded) = match load_manifest(&client, cfg, &abort) {
        Ok(Some(manifest)) => (manifest, true),
        Ok(None) => (Manifest::default(), false),
        Err(e) => {
            // The volume is authoritative: rebuild the manifest from local
            // content, but only after proving the bucket is complete below.
            log::err(&format!(
                "state sync: cannot read the manifest ({e}); rebuilding it from \
                 local content"
            ));
            (Manifest::default(), false)
        }
    };
    // A rebuilt manifest must cover everything already in the bucket, or
    // publishing it would orphan the files it omits. When the bucket holds
    // synced files missing locally, or the listing itself fails, the
    // supervisor cannot prove completeness. It must not write mutable
    // path keys in that state: a changed local file could overwrite a newer
    // bucket copy. Skip the push until a complete pull/manifest exists.
    let (mut tombstones, tombstones_trusted) = match load_tombstones(&client, cfg, &abort) {
        Ok(Some(tombstones)) => (tombstones, true),
        Ok(None) => (Tombstones::default(), true),
        Err(e) => {
            log::err(&format!(
                "state sync: cannot read the tombstone list ({e}); not writing it \
                 and not collecting deletions this run"
            ));
            (Tombstones::default(), false)
        }
    };
    if !manifest_loaded && tombstones_trusted {
        match remote_only_files(&client, cfg, roots, &tombstones, &abort) {
            Some(missing) if missing.is_empty() => {}
            Some(missing) => {
                log::err(&format!(
                    "state sync: the bucket holds {} file(s) not present locally; refusing \
                     to push until they are restored (a path-key write could overwrite a \
                     newer copy)",
                    missing.len()
                ));
                return false;
            }
            None => {
                log::err(
                    "state sync: cannot list the bucket to prove it is complete; refusing \
                     to push this run",
                );
                return false;
            }
        }
    }
    if !manifest_loaded && !tombstones_trusted {
        log::err(
            "state sync: no manifest and no readable tombstone list; refusing to \
             rebuild the bucket state on a guess",
        );
        return false;
    }
    let mut manifest = bucket_manifest;
    let mut manifest_dirty = false;
    let mut failed = false;
    let local: BTreeSet<String> = files.iter().cloned().collect();

    // Deletion lifecycle. A tombstone only follows a day of consistent
    // absence, and a batch that could be a lost volume is refused.
    if tombstones_trusted {
        // Heal a crash between the tombstone write and the manifest write:
        // a tombstoned path must not keep a manifest entry.
        let stale: Vec<String> = manifest
            .iter()
            .filter(|(rel, _)| {
                is_synced_file(rel, cfg.state_file.as_deref()) && tombstones.contains(rel)
            })
            .map(|(rel, _)| rel.clone())
            .collect();
        for rel in stale {
            manifest.remove(&rel);
            manifest_dirty = true;
        }
        let mut cleared = false;
        for rel in &local {
            if tombstones.remove(rel) {
                cleared = true;
            }
        }
        if cleared && let Err(e) = store_tombstones(&client, cfg, &tombstones, &abort) {
            log::err(&format!(
                "state sync: cannot clear a restored path's tombstone ({e}); it \
                 stays effective until the next push"
            ));
            failed = true;
        }
        let now = now_unix();
        // Every manifest file absent, including identity material, signals
        // a lost/unmounted volume; only user data is ever eligible for a
        // tombstone.
        let missing_all: BTreeSet<String> = manifest
            .iter()
            .filter(|(rel, _)| {
                is_synced_file(rel, cfg.state_file.as_deref())
                    && !local.contains(*rel)
                    && !tombstones.contains(rel)
            })
            .map(|(rel, _)| rel.clone())
            .collect();
        let missing: BTreeSet<String> = missing_all
            .iter()
            .filter(|rel| is_deletable(rel))
            .cloned()
            .collect();
        let mut tracker = Missing::load(&roots.state.to_string_lossy());
        tracker.observe(&missing, now);
        let expired: Vec<String> = tracker
            .expired(now)
            .into_iter()
            .filter(|rel| manifest.get(rel).is_some() && is_deletable(rel))
            .collect();
        if !expired.is_empty() {
            let total = manifest.len();
            // Every manifest file absent at once is a lost/unmounted
            // volume, never intent. The absolute cap covers small vaults;
            // the fraction guard catches a large partial loss. Below five
            // files a partial deletion is a legitimate user action.
            let all_missing = total > 0 && missing_all.len() == total;
            let mass = all_missing
                || expired.len() > MAX_TOMBSTONES_PER_RUN
                || (total > 4 && expired.len().saturating_mul(4) > total);
            if mass {
                log::err(&format!(
                    "state sync: {} manifest file(s) have been absent for the grace \
                     window; refusing to treat that as user intent (possible volume \
                     loss). Restore them, or delete in smaller batches",
                    expired.len()
                ));
            } else {
                let mut next = tombstones.clone();
                let mut next_manifest = manifest.clone();
                for rel in &expired {
                    next.insert(rel.clone());
                    next_manifest.remove(rel);
                }
                match store_tombstones(&client, cfg, &next, &abort) {
                    Ok(()) => {
                        for rel in &expired {
                            tracker.remove(rel);
                        }
                        tombstones = next;
                        manifest = next_manifest;
                        manifest_dirty = true;
                        log::info(&format!(
                            "state sync: recorded {} deletion(s) as tombstones",
                            expired.len()
                        ));
                    }
                    Err(e) => {
                        log::err(&format!(
                            "state sync: cannot publish the tombstone list ({e}); \
                             the deletion is retried next push"
                        ));
                        failed = true;
                    }
                }
            }
        }
        tracker.save(&roots.state.to_string_lossy());
    }

    let mut repair = read_repair(&roots.state);
    let mut cache = Cache::load(&roots.state);
    let mut pushed = 0usize;
    for rel in &files {
        if abort() {
            return false;
        }
        let root = roots.local_root(rel, cfg.state_file.as_deref());
        let mut file = match crate::util::fs::open_under(&root, rel) {
            Ok(file) => file,
            Err(e) => {
                log::err(&format!(
                    "state sync: cannot open {} for upload: {e}",
                    log::sanitize(rel)
                ));
                failed = true;
                continue;
            }
        };
        let meta = match file.metadata() {
            Ok(meta) if meta.is_file() => meta,
            Ok(_) => {
                log::err(&format!(
                    "state sync: {} is not a regular file; not uploaded",
                    log::sanitize(rel)
                ));
                failed = true;
                continue;
            }
            Err(e) => {
                log::err(&format!(
                    "state sync: cannot size {}: {e}",
                    log::sanitize(rel)
                ));
                failed = true;
                continue;
            }
        };
        let size = meta.len();
        // The restore path enforces this cap. Uploading a larger object
        // would create a manifest entry that can never be restored.
        if size > MAX_SYNC_OBJECT_BYTES {
            log::err(&format!(
                "state sync: {} is {size} bytes, over the {MAX_SYNC_OBJECT_BYTES}-byte \
                 restore cap; not uploaded",
                log::sanitize(rel)
            ));
            failed = true;
            continue;
        }
        let mtime = mtime_nanos(&meta);
        let ctime = ctime_nanos(&meta);
        // A file the boot pass found missing or changed on the bucket is
        // re-uploaded even if the manifest still matches locally.
        let must_repair = repair.contains(rel);
        // The cache may skip hashing only when its remembered hash still
        // matches the recorded state; it is a hint, never the identity.
        if !must_repair
            && cache.hash_of(rel, size, mtime, ctime).is_some_and(|hash| {
                manifest
                    .get(rel)
                    .is_some_and(|entry| entry.sha256 == hash && entry.size == size)
            })
        {
            continue; // unchanged; nothing to upload
        }
        // Hash the bytes actually on disk before recording them: a stale
        // cache entry must never become the recorded identity. The handle
        // stays open for the upload, so a path swap cannot change the inode.
        let hash = match sha256_reader(&mut file) {
            Ok(hash) => hash,
            Err(e) => {
                log::err(&format!(
                    "state sync: cannot hash {}: {e}",
                    log::sanitize(rel)
                ));
                failed = true;
                continue;
            }
        };
        if !must_repair
            && manifest
                .get(rel)
                .is_some_and(|entry| entry.sha256 == hash && entry.size == size)
        {
            cache.record(rel, size, mtime, ctime, hash);
            continue;
        }
        // Content-addressed and immutable: the previous copy keeps its own
        // key, so a failed manifest write can never destroy it.
        let key = format!("{}{}", cfg.prefix(), object_key(rel, &hash));
        match client.put_file(&key, &mut file, size, &abort) {
            Ok(()) => {
                // The handle was opened before the hash and is used for the
                // upload. If the file changed underneath, the object no
                // longer matches the hash being recorded: never commit it.
                let after = file.metadata();
                let unchanged = after.as_ref().is_ok_and(|after| {
                    after.len() == size
                        && mtime_nanos(after) == mtime
                        && ctime_nanos(after) == ctime
                });
                if !unchanged {
                    log::err(&format!(
                        "state sync: {} changed during upload; not committing it",
                        log::sanitize(rel)
                    ));
                    // Do not delete the key: it may be a valid object from
                    // an earlier push that the manifest still references.
                    failed = true;
                    continue;
                }
                manifest.insert(
                    rel.clone(),
                    Entry {
                        size,
                        sha256: hash.clone(),
                    },
                );
                cache.record(rel, size, mtime, ctime, hash);
                repair.remove(rel);
                pushed += 1;
            }
            Err(e) => {
                log::err(&format!(
                    "state sync: push failed ({e}); continuing (fresh node/re-login possible)"
                ));
                failed = true;
            }
        }
    }
    // Only a manifest known to be durable may drive GC: if a new object
    // was uploaded but the manifest write failed, the bucket still names
    // the previous object and deleting it would destroy the usable copy.
    let mut manifest_committed = manifest_loaded && pushed == 0 && !manifest_dirty;
    if pushed > 0 || manifest_dirty {
        match store_manifest(&client, cfg, &manifest, &abort) {
            Ok(()) => {
                manifest_committed = true;
                log::info(&format!(
                    "state sync: push ok ({}, {pushed} new/changed)",
                    cfg.remote
                ));
            }
            Err(e) => {
                log::err(&format!(
                    "state sync: pushed {pushed} object(s) but cannot publish the manifest \
                     ({e}); the objects stay unreferenced until a later run re-uploads \
                     them (a shutdown flush may exit first)"
                ));
                failed = true;
            }
        }
    }
    // Garbage collection needs a durable manifest: deleting a superseded
    // object whose replacement is not committed would destroy the only
    // copy. It is best-effort and never fails the push.
    if manifest_committed && tombstones_trusted && !failed {
        gc_objects(&client, cfg, &manifest, &mut tombstones, &abort);
    }
    // Forget repairs for files this volume no longer has (nothing to
    // re-upload) and record the rest for the next push.
    let present: BTreeSet<&String> = files.iter().collect();
    repair.retain(|rel| present.contains(rel));
    write_repair(&roots.state, &repair);
    cache.save(&roots.state);
    !failed
}

/// Bounded object GC. Only objects the durable manifest supersedes, and
/// objects belonging to a tombstone older than its grace, are deleted; an
/// object with no manifest entry is left until a later upload supersedes
/// it (it may be a crash's only copy). A legacy path key is removed only
/// for a grace-old tombstone.
fn gc_objects(
    client: &Client,
    cfg: &SyncConfig,
    manifest: &Manifest,
    tombstones: &mut Tombstones,
    abort: &impl Fn() -> bool,
) -> bool {
    let listed = match client.list(cfg.prefix(), abort) {
        Ok(listed) => listed,
        Err(e) => {
            log::info(&format!("state sync: garbage collection skipped ({e})"));
            return false;
        }
    };
    let (deletable, prunable) = tombstones.gc_candidates(now_unix());
    let deletable: BTreeSet<String> = deletable.into_iter().collect();
    let present: BTreeMap<&str, u64> = listed
        .iter()
        .map(|item| (item.key.as_str(), item.size))
        .collect();
    let mut deletes = 0usize;
    let mut failed = false;
    let mut capped = false;
    for item in &listed {
        if abort() {
            return false;
        }
        let key = &item.key;
        let delete = if let Some((rel, sha)) = split_object_key(key, cfg.prefix()) {
            if !is_synced_file(rel, cfg.state_file.as_deref()) {
                continue;
            }
            match manifest.get(rel) {
                Some(current) => {
                    // Never delete a fallback copy while the manifest's
                    // current object is absent or the wrong size: that
                    // copy may be the only restorable version.
                    let current_key =
                        format!("{}{}", cfg.prefix(), object_key(rel, &current.sha256));
                    let legacy_key = format!("{}{rel}", cfg.prefix());
                    let current_present = present
                        .get(current_key.as_str())
                        .is_some_and(|size| *size == current.size)
                        || present
                            .get(legacy_key.as_str())
                            .is_some_and(|size| *size == current.size);
                    (current.sha256 != sha && current_present) || deletable.contains(rel)
                }
                None => deletable.contains(rel),
            }
        } else if let Some(rel) = key.strip_prefix(cfg.prefix()) {
            if rel == MANIFEST_NAME
                || rel == TOMBSTONES_NAME
                || !is_synced_file(rel, cfg.state_file.as_deref())
            {
                continue;
            }
            deletable.contains(rel)
        } else {
            false
        };
        if !delete {
            continue;
        }
        if deletes >= MAX_GC_DELETES {
            log::info(&format!(
                "state sync: garbage collection hit its {MAX_GC_DELETES}-delete cap; \
                 the next push continues"
            ));
            capped = true;
            break;
        }
        match client.delete(key, abort) {
            Ok(()) => deletes += 1,
            Err(e) => {
                log::err(&format!(
                    "state sync: cannot delete {} ({e}); the next push retries",
                    log::sanitize(key)
                ));
                failed = true;
            }
        }
    }
    let mut pruned = false;
    if !failed && !capped {
        for rel in prunable {
            if tombstones.remove(&rel) {
                pruned = true;
            }
        }
    }
    if pruned && let Err(e) = store_tombstones(client, cfg, tombstones, abort) {
        log::err(&format!(
            "state sync: cannot prune the tombstone list ({e}); the next push retries"
        ));
        failed = true;
    }
    if deletes > 0 {
        log::info(&format!(
            "state sync: garbage-collected {deletes} object(s) ({})",
            cfg.remote
        ));
    }
    !failed
}

/// Nanoseconds since the epoch, 0 when unavailable (the cache treats 0 as
/// "always hash", so an unknown clock can never pin a stale hash).
fn mtime_nanos(meta: &std::fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// The inode change time in nanoseconds since the epoch, 0 when
/// unavailable (the cache treats 0 as "always hash"). Any content change
/// bumps ctime, even one that preserves size and mtime.
fn ctime_nanos(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    let (secs, nsec) = (meta.ctime(), meta.ctime_nsec());
    if secs < 0 || nsec < 0 {
        return 0;
    }
    (secs as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(nsec as u64)
}

#[cfg(test)]
mod tests;
