//! /data state sync (opt-in via SUPERVISOR_S3_*): pulls /data durable
//! files at boot, pushes shortly after the vault starts, on a cadence, and
//! at shutdown — so node identity, vaultwarden signing keys, and user
//! content survive ephemeral redeploys (also keeps distance from Let's
//! Encrypt's 5-certs-per-week limit). The bucket holds secrets: keep it
//! private, one container per bucket/path. Every failure is non-fatal;
//! worst case is a fresh node registration, one client re-login, or one
//! cert re-issuance.
//!
//! The scope is the durable set ([`super::synced`], `tailscaled.state`,
//! `rsa_key*`, `certs/**`, `attachments/**`, `sends/**`) — enforced on BOTH
//! directions: pushes upload exactly that set, pulls refuse any key outside
//! it (a bucket anyone can write to must not be able to plant arbitrary
//! files on the data volume).
//!
//! Content, not size: the bucket-side manifest ([`super::manifest`])
//! records each synced file's size and SHA-256, so a push uploads a file
//! only when its content actually changed and a pull verifies the hash
//! before the file is published. Objects are content-addressed
//! (`objects/<rel>/<sha256>`) and therefore immutable: a change uploads a
//! new key, so a failed or interrupted manifest write can never replace
//! the copy the previous manifest names (the next run re-uploads and
//! commits again). Entries a bucket inherited from before this layout are
//! still pulled from their old `<rel>` key on a miss. Without a manifest
//! (a pre-manifest bucket) the name listing is used, size-checked only,
//! until the first push writes one. Hashes are cached locally keyed by
//! (size, mtime, ctime) ([`super::cache`]) so a quiet push does not
//! re-hash gigabytes, and a cached hash is only ever used to *skip* —
//! every upload records a hash computed from the bytes on disk.
//!
//! A best-effort boot pass reconciles what the manifest does not name:
//! unreferenced objects (a crash between the PUT and the manifest write)
//! are pulled for files missing locally, and every referenced entry is
//! checked against the bucket listing — a file whose object is gone or
//! changed is written to a local repair list, so the next push re-uploads
//! it instead of trusting the stale manifest. The pass costs one listing
//! per boot.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::config::{SYNC_TIMEOUT, SyncConfig};
use crate::s3::{Client, Expect, Listed, MAX_SYNC_OBJECT_BYTES};
use crate::util::hash::sha256_file;
use crate::util::log;

use super::cache::Cache;
use super::manifest::{Entry, MANIFEST_NAME, MAX_MANIFEST_BYTES, Manifest};
use super::synced::{clear_partials, is_synced_file, local_synced_files};

/// Build the client for one sync run; a construction failure is a
/// failed run (logged, non-fatal).
fn build(cfg: &SyncConfig) -> Option<Client> {
    match Client::connect(&cfg.target, SYNC_TIMEOUT) {
        Ok(c) => Some(c),
        Err(e) => {
            log::err(&format!("state sync: {e}; continuing"));
            None
        }
    }
}

/// The manifest's bucket key (inside the sync prefix).
fn manifest_key(cfg: &SyncConfig) -> String {
    format!("{}{MANIFEST_NAME}", cfg.prefix())
}

/// Load the manifest; `Ok(None)` = none yet (legacy layout or first run).
fn load_manifest(
    client: &Client,
    cfg: &SyncConfig,
    abort: &impl Fn() -> bool,
) -> anyhow::Result<Option<Manifest>> {
    match client.get_optional_text(&manifest_key(cfg), MAX_MANIFEST_BYTES, abort)? {
        Some(text) => Manifest::parse(&text).map(Some),
        None => Ok(None),
    }
}

fn store_manifest(
    client: &Client,
    cfg: &SyncConfig,
    manifest: &Manifest,
    abort: &impl Fn() -> bool,
) -> anyhow::Result<()> {
    let rendered = manifest.render();
    // Never write a manifest the next pull could not read back (the read
    // path caps at MAX_MANIFEST_BYTES).
    anyhow::ensure!(
        rendered.len() as u64 <= MAX_MANIFEST_BYTES,
        "refusing to write a manifest over the {MAX_MANIFEST_BYTES}-byte read cap"
    );
    client.put_bytes(&manifest_key(cfg), rendered.as_bytes(), abort)
}

/// Whether a bucket key should be written locally: only when nothing is
/// there yet, so an existing local file is never overwritten by the bucket.
fn should_pull(target: &Path) -> bool {
    !target.exists()
}

/// The content-addressed bucket key for one synced file's current
/// content: `objects/<rel>/<sha256>`. Immutable by construction — a
/// changed file gets a new key, so an interrupted push can never
/// overwrite the copy the previous manifest references.
fn object_key(rel: &str, sha256: &str) -> String {
    format!("objects/{rel}/{sha256}")
}

/// Split a content-addressed key (`<prefix>objects/<rel>/<sha256>`) into
/// `(rel, sha256)`. Anything else — the manifest, legacy path keys, names
/// that are not content-addressed — is not a reconciliation candidate.
fn split_object_key<'a>(key: &'a str, prefix: &str) -> Option<(&'a str, &'a str)> {
    let rest = key.strip_prefix(prefix)?;
    let rest = rest.strip_prefix("objects/")?;
    let (rel, sha256) = rest.rsplit_once('/')?;
    let well_formed =
        sha256.len() == 64 && sha256.chars().all(|c| c.is_ascii_hexdigit()) && !rel.is_empty();
    well_formed.then_some((rel, sha256))
}

/// One version of a file found in the listing.
#[derive(Clone)]
struct Version {
    sha256: String,
    size: u64,
    last_modified: String,
}

/// Pick the newest version per file from a listing. A file with several
/// versions is only recovered when their timestamps order it
/// unambiguously: anything else (equal or missing timestamps) is skipped
/// rather than guessed.
fn choose_newest(versions: impl Iterator<Item = (String, Version)>) -> BTreeMap<String, Version> {
    let mut by_rel: BTreeMap<String, Vec<Version>> = BTreeMap::new();
    for (rel, version) in versions {
        by_rel.entry(rel).or_default().push(version);
    }
    let mut chosen = BTreeMap::new();
    for (rel, mut versions) in by_rel {
        if versions.len() == 1 {
            chosen.insert(rel, versions.remove(0));
            continue;
        }
        let mut stamps: Vec<&str> = versions
            .iter()
            .map(|version| version.last_modified.as_str())
            .collect();
        if stamps.iter().any(|stamp| stamp.is_empty()) {
            continue;
        }
        stamps.sort_unstable();
        if stamps.windows(2).any(|pair| pair[0] == pair[1]) {
            continue;
        }
        let newest = stamps.last().expect("non-empty").to_string();
        let version = versions
            .into_iter()
            .find(|version| version.last_modified == newest)
            .expect("newest found");
        chosen.insert(rel, version);
    }
    chosen
}

/// The local record of files the bucket no longer holds correctly: the
/// next push re-uploads them even though the manifest still matches.
fn repair_path(root: &Path) -> std::path::PathBuf {
    root.join(".sync-repair")
}

fn read_repair(root: &Path) -> BTreeSet<String> {
    std::fs::read_to_string(repair_path(root))
        .map(|text| text.lines().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Rewrite the repair list; an empty list removes the file. Best-effort:
/// a failed write only means the next boot re-computes it.
fn write_repair(root: &Path, rels: &BTreeSet<String>) {
    let path = repair_path(root);
    if rels.is_empty() {
        let _ = std::fs::remove_file(&path);
        return;
    }
    let mut text = String::new();
    for rel in rels {
        // A path cannot be represented in a line-oriented file if it
        // contains a newline; such a name is pathological and is skipped.
        if rel.contains('\n') {
            continue;
        }
        text.push_str(rel);
        text.push('\n');
    }
    if let Err(e) = std::fs::write(&path, text) {
        log::err(&format!("state sync: cannot record the repair list ({e})"));
    }
}

/// The local shadow of what this volume last uploaded while the bucket had
/// no usable manifest: keeps a degraded run from re-uploading the whole
/// set every tick. Never uploaded (a dotfile outside the synced set).
fn shadow_path(root: &Path) -> std::path::PathBuf {
    root.join(".sync-pending-manifest")
}

fn load_shadow(root: &Path) -> Option<Manifest> {
    Manifest::parse(&std::fs::read_to_string(shadow_path(root)).ok()?).ok()
}

fn store_shadow(root: &Path, manifest: &Manifest) {
    if let Err(e) = std::fs::write(shadow_path(root), manifest.render()) {
        log::err(&format!(
            "state sync: cannot record the pending manifest ({e})"
        ));
    }
}

fn remove_shadow(root: &Path) {
    let _ = std::fs::remove_file(shadow_path(root));
}

/// Bucket-relative synced files that are not present locally, over the
/// whole prefix (both layouts). `None` = the listing failed, which the
/// caller treats as "cannot prove completeness".
fn remote_only_files(
    client: &Client,
    cfg: &SyncConfig,
    root: &Path,
    abort: &impl Fn() -> bool,
) -> Option<Vec<String>> {
    let listed = client.list(cfg.prefix(), abort).ok()?;
    let mut missing = Vec::new();
    for item in &listed {
        let rel = match split_object_key(&item.key, cfg.prefix()) {
            Some((rel, _)) => rel,
            None => match item.key.strip_prefix(cfg.prefix()) {
                Some(rel) => rel,
                None => continue,
            },
        };
        if rel == MANIFEST_NAME || !is_synced_file(rel, cfg.state_file.as_deref()) {
            continue;
        }
        if !root.join(rel).exists() {
            missing.push(rel.to_string());
        }
    }
    missing.sort();
    missing.dedup();
    Some(missing)
}

/// Recover what the manifest does not name and note referenced objects the
/// bucket no longer holds. One best-effort listing powers both:
///
/// - unreferenced content-addressed objects (a crash between the object
///   PUT and the manifest write, or a manifest that cannot be read) are
///   pulled for files missing locally, newest version per path;
/// - every manifest entry is checked by presence and size; a file whose
///   object is gone or changed is written to the local repair list so the
///   next push re-uploads it.
///
/// Returns how many files were recovered. A failed listing only costs this
/// pass; it never fails the pull.
fn reconcile_objects(
    root: &Path,
    client: &Client,
    cfg: &SyncConfig,
    manifest: Option<&Manifest>,
    abort: &impl Fn() -> bool,
) -> usize {
    let listed = match client.list(cfg.prefix(), abort) {
        Ok(listed) => listed,
        Err(e) => {
            log::info(&format!("state sync: reconciliation skipped ({e})"));
            return 0;
        }
    };
    let mut present: BTreeMap<&str, u64> = BTreeMap::new();
    let mut candidates = Vec::new();
    for item in &listed {
        present.insert(item.key.as_str(), item.size);
        let Some((rel, sha256)) = split_object_key(&item.key, cfg.prefix()) else {
            continue;
        };
        if !is_synced_file(rel, cfg.state_file.as_deref()) {
            continue;
        }
        if manifest.is_some_and(|manifest| manifest.get(rel).is_some()) {
            continue;
        }
        candidates.push((
            rel.to_string(),
            Version {
                sha256: sha256.to_string(),
                size: item.size,
                last_modified: item.last_modified.clone(),
            },
        ));
    }

    let mut recovered = 0usize;
    for (rel, version) in choose_newest(candidates.into_iter()) {
        if abort() {
            break;
        }
        let local = root.join(&rel);
        if local.exists() {
            continue;
        }
        if let Some(parent) = local.parent()
            && std::fs::create_dir_all(parent).is_err()
        {
            continue;
        }
        let key = format!("{}{}", cfg.prefix(), object_key(&rel, &version.sha256));
        let expect = Expect {
            size: Some(version.size),
            sha256: Some(&version.sha256),
            max_bytes: MAX_SYNC_OBJECT_BYTES,
        };
        let local = local.to_string_lossy().into_owned();
        match client.get(&key, &local, expect, abort) {
            Ok(()) => {
                recovered += 1;
                log::info(&format!("state sync: recovered unreferenced {rel}"));
            }
            Err(e) => log::err(&format!("state sync: recovery of {rel} failed ({e})")),
        }
    }

    // Verify every referenced object against the listing (presence and
    // size; content is only checked when a pull downloads it).
    let mut repair = read_repair(root);
    if let Some(manifest) = manifest {
        for (rel, entry) in manifest.iter() {
            if abort() {
                break;
            }
            let object = format!("{}{}", cfg.prefix(), object_key(rel, &entry.sha256));
            let legacy = format!("{}{}", cfg.prefix(), rel);
            let held = present
                .get(object.as_str())
                .is_some_and(|size| *size == entry.size)
                || present
                    .get(legacy.as_str())
                    .is_some_and(|size| *size == entry.size);
            if held {
                repair.remove(rel);
                continue;
            }
            if root.join(rel).exists() {
                log::err(&format!(
                    "state sync: the bucket no longer holds the current copy of {rel}; \
                     re-uploading it on the next push"
                ));
                repair.insert(rel.clone());
            } else {
                log::err(&format!(
                    "state sync: the bucket no longer holds {rel} and no local copy exists"
                ));
            }
        }
    }
    write_repair(root, &repair);
    recovered
}

/// One pull candidate: its relative path, plus the manifest's expectations
/// when it came from the manifest.
struct Target {
    rel: String,
    size: Option<u64>,
    sha256: Option<String>,
}

/// Pull synced files from the bucket into /data. Called at boot, before
/// tailscaled is spawned, so a restored state file wins over nothing.
///
/// The pull only fills gaps: a bucket key whose local file already exists
/// is left untouched. On an ephemeral volume nothing is there, so the whole
/// set is restored; on a persistent volume the volume stays authoritative
/// and the bucket acts as a fill/DR source rather than clobbering newer
/// local files. Only keys inside the synced set are written, and every
/// manifest entry is hash-verified before it is published.
pub fn restore_state(cfg: &SyncConfig, abort: impl Fn() -> bool) -> bool {
    restore_state_at(Path::new("/data"), cfg, abort)
}

/// [`restore_state`] with an explicit data root (tests use a scratch dir).
fn restore_state_at(root: &Path, cfg: &SyncConfig, abort: impl Fn() -> bool) -> bool {
    let Some(client) = build(cfg) else {
        return false;
    };
    // A partial left by a dead transfer must not be resumed against
    // different content; every boot starts clean.
    let cleared = clear_partials(root);
    if cleared > 0 {
        log::info(&format!(
            "state sync: removed {cleared} stale partial download(s)"
        ));
    }
    // The manifest is the bucket's record (hashes included). Without one
    // (legacy layout) the listing is authoritative; an unreadable one falls
    // back to the listing loudly, with the size check still applying.
    let manifest = match load_manifest(&client, cfg, &abort) {
        Ok(manifest) => manifest,
        Err(e) => {
            log::err(&format!(
                "state sync: cannot read the manifest ({e}); falling back to the \
                 name listing"
            ));
            None
        }
    };
    let targets: Vec<Target> = match &manifest {
        Some(manifest) => manifest
            .iter()
            .map(|(rel, entry)| Target {
                rel: rel.clone(),
                size: Some(entry.size),
                sha256: Some(entry.sha256.clone()),
            })
            .collect(),
        None => {
            let listed = match client.list(cfg.prefix(), &abort) {
                Ok(l) => l,
                Err(e) => {
                    log::err(&format!("state sync: pull failed ({e}); continuing"));
                    return false;
                }
            };
            let mut targets = Vec::new();
            for Listed { key, size, .. } in &listed {
                let Some(rel) = key.strip_prefix(cfg.prefix()) else {
                    continue;
                };
                // The manifest object itself is not a synced file.
                if rel == MANIFEST_NAME {
                    continue;
                }
                // Content-addressed objects are restorable only through a
                // manifest (a bare listing cannot order versions); skip
                // them in the legacy view.
                if rel.starts_with("objects/") {
                    continue;
                }
                targets.push(Target {
                    rel: rel.to_string(),
                    size: Some(*size),
                    sha256: None,
                });
            }
            targets
        }
    };
    let mut ok = true;
    let mut pulled = 0usize;
    let mut kept = 0usize;
    for target in targets {
        if abort() {
            return true;
        }
        if !is_synced_file(&target.rel, cfg.state_file.as_deref()) {
            log::err(&format!(
                "state sync: pull ignored {} (outside the synced set)",
                log::sanitize(&target.rel)
            ));
            ok = false;
            continue;
        }
        let local = root.join(&target.rel).to_string_lossy().into_owned();
        if !should_pull(Path::new(&local)) {
            kept += 1;
            continue;
        }
        if let Some(parent) = Path::new(&local).parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            log::err(&format!(
                "state sync: cannot create {}: {e}",
                log::sanitize(&target.rel)
            ));
            ok = false;
            continue;
        }
        let expect = Expect {
            size: target.size,
            sha256: target.sha256.as_deref(),
            max_bytes: MAX_SYNC_OBJECT_BYTES,
        };
        // Manifest entries name content-addressed objects; an entry a
        // bucket inherited from before the layout still lives at the old
        // `<rel>` key, so a miss falls back to it. Listing-only targets
        // (no manifest) use the legacy key directly. Whichever key answers
        // must still pass the manifest's hash check.
        let legacy = format!("{}{}", cfg.prefix(), target.rel);
        let primary = match target.sha256.as_deref() {
            Some(sha256) => format!("{}{}", cfg.prefix(), object_key(&target.rel, sha256)),
            None => legacy.clone(),
        };
        let primary_result = client.get(&primary, &local, expect, &abort);
        let result = match primary_result {
            Ok(()) => Ok(()),
            Err(primary_err) if target.sha256.is_some() && primary != legacy => {
                // Legacy fallback for entries a bucket inherited from
                // before the layout change.
                client
                    .get(&legacy, &local, expect, &abort)
                    .map_err(|legacy_err| {
                        anyhow::anyhow!(
                            "content-addressed key failed ({primary_err}); the legacy key \
                             failed too ({legacy_err})"
                        )
                    })
            }
            Err(e) => Err(e),
        };
        match result {
            Ok(()) => {
                pulled += 1;
                log::info(&format!("state sync: pulled {}", target.rel));
            }
            Err(e) => {
                log::err(&format!("state sync: pull failed ({e}); continuing"));
                ok = false;
            }
        }
    }
    // Recover objects the manifest does not name (a crash between the PUT
    // and the manifest write, or an unreadable manifest), and note any
    // referenced object the bucket no longer holds.
    pulled += reconcile_objects(root, &client, cfg, manifest.as_ref(), &abort);
    if ok && pulled + kept > 0 {
        log::info(&format!(
            "state sync: pull ok ({}, {pulled} new, {kept} kept)",
            cfg.remote
        ));
    }
    ok
}

/// Push synced files from /data to the bucket. Called after `up` (fresh
/// state), shortly after the vault starts (the RSA key only exists once
/// vaultwarden has run), on the periodic cadence, and at shutdown.
/// Uploads only files whose content differs from the manifest (a hash,
/// not just a size), then rewrites the manifest; entries for files no
/// longer present locally are kept, so the bucket stays a complete
/// disaster-recovery source.
pub fn sync_state(cfg: &SyncConfig, abort: impl Fn() -> bool) -> bool {
    sync_state_at(Path::new("/data"), cfg, abort)
}

/// [`sync_state`] with an explicit data root (tests use a scratch dir).
fn sync_state_at(root: &Path, cfg: &SyncConfig, abort: impl Fn() -> bool) -> bool {
    let Some(client) = build(cfg) else {
        return false;
    };
    let files = local_synced_files(root, cfg.state_file.as_deref());
    if files.is_empty() {
        log::info("state sync: no synced files to push yet");
        return true;
    }
    let (bucket_manifest, manifest_loaded) = match load_manifest(&client, cfg, &abort) {
        Ok(Some(manifest)) => (manifest, true),
        Ok(None) => (Manifest::default(), false),
        Err(e) => {
            // The volume is authoritative: rebuild the manifest from local
            // content (or the local shadow, so a degraded run does not
            // re-upload everything every tick).
            log::err(&format!(
                "state sync: cannot read the manifest ({e}); rebuilding it from \
                 local content"
            ));
            (Manifest::default(), false)
        }
    };
    // A rebuilt manifest must cover everything already in the bucket, or
    // publishing it would orphan the files it omits. When the bucket holds
    // synced files missing locally, keep the legacy path-keyed layout
    // (which listing-based pulls can still restore) until a complete pull
    // succeeds. A failed listing counts as "cannot prove completeness".
    let publish = if manifest_loaded {
        true
    } else {
        match remote_only_files(&client, cfg, root, &abort) {
            Some(missing) if missing.is_empty() => true,
            Some(missing) => {
                log::err(&format!(
                    "state sync: the bucket holds {} file(s) not present locally; keeping \
                     the legacy layout this run — restore them before a manifest is \
                     published",
                    missing.len()
                ));
                false
            }
            None => {
                log::err(
                    "state sync: cannot list the bucket to rebuild the manifest safely; \
                     keeping the legacy layout this run",
                );
                false
            }
        }
    };
    // In the legacy window the local shadow (what this volume last
    // uploaded) drives the skip decisions; otherwise the bucket manifest.
    let mut manifest = if publish {
        bucket_manifest
    } else {
        load_shadow(root).unwrap_or_default()
    };
    let mut repair = read_repair(root);
    let mut cache = Cache::load();
    let mut pushed = 0usize;
    let mut failed = false;
    for rel in &files {
        if abort() {
            return false;
        }
        let path = root.join(rel).to_string_lossy().into_owned();
        let meta = match std::fs::metadata(&path) {
            Ok(meta) => meta,
            Err(e) => {
                log::err(&format!("state sync: cannot size {rel}: {e}"));
                failed = true;
                continue;
            }
        };
        let size = meta.len();
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
        // cache entry must never become the recorded identity.
        let hash = match sha256_file(&path) {
            Ok(hash) => hash,
            Err(e) => {
                log::err(&format!("state sync: cannot hash {rel}: {e}"));
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
        // key, so a failed manifest write can never destroy it. While the
        // legacy layout is kept, the path key keeps listing pulls working.
        let key = if publish {
            format!("{}{}", cfg.prefix(), object_key(rel, &hash))
        } else {
            format!("{}{rel}", cfg.prefix())
        };
        match client.put(&key, &path, &abort) {
            Ok(()) => {
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
    if pushed > 0 {
        if publish {
            match store_manifest(&client, cfg, &manifest, &abort) {
                Ok(()) => {
                    remove_shadow(root);
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
        } else {
            store_shadow(root, &manifest);
            log::info(&format!(
                "state sync: pushed {pushed} object(s) in the legacy layout ({})",
                cfg.remote
            ));
        }
    }
    // Forget repairs for files this volume no longer has (nothing to
    // re-upload) and record the rest for the next push.
    let present: BTreeSet<&String> = files.iter().collect();
    repair.retain(|rel| present.contains(rel));
    write_repair(root, &repair);
    cache.save();
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
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// The pull is fill-only: an existing local file is never overwritten,
    /// so a persistent data volume stays authoritative over the bucket.
    #[test]
    fn pull_only_fills_missing_files() {
        let dir = std::env::temp_dir().join(format!("vw-sup-fill-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let present = dir.join("rsa_key.pem");
        std::fs::write(&present, b"local").unwrap();
        assert!(!should_pull(&present), "an existing file must be kept");
        assert!(
            should_pull(&dir.join("rsa_key.pub.pem")),
            "a missing file must be pulled"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Objects are content-addressed under their synced path: a changed
    /// file gets a new key, so an interrupted push can never overwrite the
    /// copy the previous manifest names. Paths with spaces survive (the
    /// key is built, never parsed back).
    #[test]
    fn object_keys_are_content_addressed_under_the_synced_path() {
        let sha = "ab".repeat(32);
        assert_eq!(
            object_key("attachments/uuid-1", &sha),
            format!("objects/attachments/uuid-1/{sha}")
        );
        assert_eq!(
            object_key("certs/my cert.pem", &sha),
            format!("objects/certs/my cert.pem/{sha}")
        );
    }

    /// The request path of a logged request line, query string stripped.
    fn req_path(line: &str) -> &str {
        line.split_whitespace()
            .nth(1)
            .unwrap_or("")
            .split('?')
            .next()
            .unwrap_or("")
    }

    /// A minimal S3 stand-in: records every request line and answers from
    /// `route`. The client signs requests; the stub ignores signatures.
    fn fake_bucket(
        route: impl Fn(&str) -> (u16, Vec<u8>) + Send + 'static,
    ) -> (String, Arc<Mutex<Vec<String>>>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_worker = Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                let mut head_end = None;
                while head_end.is_none() {
                    let n = s.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    head_end = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4);
                }
                let Some(head_end) = head_end else { continue };
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let line = head.lines().next().unwrap_or("").to_string();
                seen_worker.lock().unwrap().push(line.clone());
                // Drain the declared body so the client can finish sending.
                let content_length = head
                    .lines()
                    .find_map(|l| {
                        let (name, value) = l.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                let mut left = content_length.saturating_sub(buf.len() - head_end);
                while left > 0 {
                    let n = s.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    left = left.saturating_sub(n);
                }
                let (status, body) = route(&line);
                let reason = match status {
                    200 => "OK",
                    404 => "Not Found",
                    500 => "Internal Server Error",
                    _ => "Status",
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(response.as_bytes());
                let _ = s.write_all(&body);
            }
        });
        (format!("http://{addr}"), seen)
    }

    fn sync_cfg(endpoint: &str) -> SyncConfig {
        use std::time::Duration;
        SyncConfig::new(
            "r2:vw".into(),
            "id".into(),
            "secret".into(),
            endpoint.to_string(),
            Duration::from_secs(3600),
        )
        .expect("valid test remote")
    }

    /// A push whose manifest write fails must not touch the legacy key:
    /// the new content lands at its content-addressed key, and the copy
    /// the previous manifest still names is left alone. (Regression: the
    /// push used to overwrite `<rel>` in place, so a failed commit
    /// destroyed the good remote copy.)
    #[test]
    fn failed_manifest_write_never_overwrites_the_previous_object() {
        let old_sha = "a".repeat(64);
        let (endpoint, seen) = fake_bucket(move |line| {
            let path = req_path(line);
            if line.starts_with("GET") && path.ends_with("/manifest") {
                (200, format!("v1\n{old_sha} 3 rsa_key\n").into_bytes())
            } else if line.starts_with("PUT") && path.ends_with("/manifest") {
                (500, Vec::new()) // the commit fails
            } else {
                (200, Vec::new())
            }
        });
        let root = std::env::temp_dir().join(format!("vw-sup-syncfail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("rsa_key"), b"new").unwrap();

        assert!(
            !sync_state_at(&root, &sync_cfg(&endpoint), || false),
            "a failed manifest write fails the run"
        );

        let seen = seen.lock().unwrap().clone();
        let object_puts: Vec<&String> = seen
            .iter()
            .filter(|l| l.starts_with("PUT") && req_path(l).contains("/objects/rsa_key/"))
            .collect();
        assert_eq!(
            object_puts.len(),
            1,
            "the changed file uploads once, content-addressed: {seen:?}"
        );
        assert!(
            !seen
                .iter()
                .any(|l| l.starts_with("PUT") && req_path(l) == "/vw/rsa_key"),
            "the legacy key must never be overwritten: {seen:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A manifest entry whose content-addressed object is missing (a file
    /// pushed before the layout change) is pulled from its legacy key,
    /// still verified against the manifest's hash.
    #[test]
    fn pull_falls_back_to_the_legacy_key_with_hash_verification() {
        let root = std::env::temp_dir().join(format!("vw-sup-syncpull-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let sha = {
            let probe = root.join("probe");
            std::fs::write(&probe, b"data").unwrap();
            let sha = sha256_file(probe.to_str().unwrap()).unwrap();
            std::fs::remove_file(&probe).unwrap();
            sha
        };
        let manifest_body = format!("v1\n{sha} 4 rsa_key\n");
        let (endpoint, seen) = fake_bucket(move |line| {
            let path = req_path(line);
            if line.starts_with("GET") && path.ends_with("/manifest") {
                (200, manifest_body.clone().into_bytes())
            } else if line.starts_with("GET") && path.contains("/objects/") {
                (404, Vec::new()) // pushed before the layout change
            } else if line.starts_with("GET") && path.ends_with("/rsa_key") {
                (200, b"data".to_vec())
            } else {
                (404, Vec::new())
            }
        });

        assert!(restore_state_at(&root, &sync_cfg(&endpoint), || false));
        assert_eq!(
            std::fs::read(root.join("rsa_key")).unwrap(),
            b"data",
            "the legacy key's content is published after verification"
        );
        let seen = seen.lock().unwrap().clone();
        assert!(
            seen.iter()
                .any(|l| l.starts_with("GET") && req_path(l).contains("/objects/rsa_key/")),
            "the content-addressed key is tried first: {seen:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn object_keys_split_back_into_rel_and_sha() {
        let sha = "ab".repeat(32);
        let key = format!("prefix/objects/attachments/u/{sha}");
        assert_eq!(
            split_object_key(&key, "prefix/"),
            Some(("attachments/u", sha.as_str()))
        );
        // not ours / not content-addressed / malformed
        assert_eq!(split_object_key(&key, "other/"), None);
        assert_eq!(split_object_key("prefix/manifest", "prefix/"), None);
        assert_eq!(split_object_key("prefix/rsa_key", "prefix/"), None);
        assert_eq!(split_object_key("prefix/objects/a/nothex", "prefix/"), None);
    }

    #[test]
    fn choose_newest_orders_versions_and_skips_ambiguity() {
        let version = |sha: &str, last_modified: &str| Version {
            sha256: sha.into(),
            size: 1,
            last_modified: last_modified.into(),
        };
        // a sole version is taken even without a timestamp
        let chosen = choose_newest([("a".to_string(), version("s1", ""))].into_iter());
        assert_eq!(chosen.get("a").unwrap().sha256, "s1");
        // the newest timestamp wins
        let chosen = choose_newest(
            [
                ("a".to_string(), version("old", "2026-01-01T00:00:00.000Z")),
                ("a".to_string(), version("new", "2026-02-01T00:00:00.000Z")),
            ]
            .into_iter(),
        );
        assert_eq!(chosen.get("a").unwrap().sha256, "new");
        // equal or missing timestamps are ambiguous: skipped
        for versions in [
            [
                ("a", "2026-01-01T00:00:00.000Z"),
                ("a", "2026-01-01T00:00:00.000Z"),
            ],
            [("a", ""), ("a", "2026-01-01T00:00:00.000Z")],
        ] {
            let chosen = choose_newest(
                versions
                    .into_iter()
                    .enumerate()
                    .map(|(i, (rel, stamp))| (rel.to_string(), version(&format!("s{i}"), stamp))),
            );
            assert!(!chosen.contains_key("a"), "ambiguous must be skipped");
        }
    }

    #[test]
    fn repair_list_round_trips_and_removes_empties() {
        let root = std::env::temp_dir().join(format!("vw-sup-rep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let repairs: BTreeSet<String> = ["rsa_key", "attachments/with space"]
            .map(String::from)
            .into_iter()
            .collect();
        write_repair(&root, &repairs);
        assert_eq!(read_repair(&root), repairs);
        write_repair(&root, &BTreeSet::new());
        assert!(read_repair(&root).is_empty());
        assert!(!repair_path(&root).exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn shadow_manifest_round_trips() {
        let root = std::env::temp_dir().join(format!("vw-sup-shadow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        assert!(load_shadow(&root).is_none());
        let mut manifest = Manifest::default();
        manifest.insert(
            "rsa_key".into(),
            Entry {
                size: 3,
                sha256: "c".repeat(64),
            },
        );
        store_shadow(&root, &manifest);
        assert_eq!(load_shadow(&root), Some(manifest));
        remove_shadow(&root);
        assert!(load_shadow(&root).is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// An empty ListObjectsV2 page, as a provider would answer it.
    fn empty_listing() -> Vec<u8> {
        b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
          <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
          <Name>vw</Name><Prefix></Prefix><KeyCount>0</KeyCount>\
          <MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>"
            .to_vec()
    }

    /// A complete object the manifest does not name (a crash between the
    /// object PUT and the manifest write) is recovered on the next boot.
    #[test]
    fn reconciliation_recovers_unreferenced_objects() {
        let root = std::env::temp_dir().join(format!("vw-sup-rec-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let content = b"data".to_vec();
        let sha = {
            let probe = root.join("probe");
            std::fs::write(&probe, &content).unwrap();
            let sha = sha256_file(probe.to_str().unwrap()).unwrap();
            std::fs::remove_file(&probe).unwrap();
            sha
        };
        let key = object_key("attachments/x", &sha);
        let listing = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Name>vw</Name><Prefix></Prefix><KeyCount>1</KeyCount><MaxKeys>1000</MaxKeys>\
             <IsTruncated>false</IsTruncated>\
             <Contents><Key>{key}</Key><LastModified>2026-09-28T00:00:00.000Z</LastModified>\
             <ETag>\"x\"</ETag><Size>4</Size><StorageClass>STANDARD</StorageClass></Contents>\
             </ListBucketResult>"
        );
        let body = content.clone();
        let (endpoint, seen) = fake_bucket(move |line| {
            let path = req_path(line);
            if line.starts_with("GET") && path.ends_with("/manifest") {
                (200, b"v1\n".to_vec())
            } else if line.starts_with("GET") && line.contains("list-type=2") {
                (200, listing.clone().into_bytes())
            } else if line.starts_with("GET") && path.contains("/objects/") {
                (200, body.clone())
            } else {
                (404, Vec::new())
            }
        });
        assert!(restore_state_at(&root, &sync_cfg(&endpoint), || false));
        assert_eq!(std::fs::read(root.join("attachments/x")).unwrap(), content);
        let seen = seen.lock().unwrap().clone();
        assert!(
            seen.iter().any(|l| l.contains("list-type=2")),
            "the reconciliation listing ran: {seen:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A referenced object the bucket no longer holds is noted at boot and
    /// re-uploaded by the next push even though the manifest still matches
    /// the local bytes.
    #[test]
    fn a_missing_bucket_object_is_repaired_by_the_next_push() {
        let root = std::env::temp_dir().join(format!("vw-sup-heal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("rsa_key"), b"key").unwrap();
        let sha = sha256_file(root.join("rsa_key").to_str().unwrap()).unwrap();
        let manifest_body = format!("v1\n{sha} 3 rsa_key\n");
        let (endpoint, seen) = fake_bucket(move |line| {
            let path = req_path(line);
            if line.starts_with("GET") && path.ends_with("/manifest") {
                (200, manifest_body.clone().into_bytes())
            } else if line.starts_with("GET") && line.contains("list-type=2") {
                (200, empty_listing())
            } else if line.starts_with("PUT") {
                (200, Vec::new())
            } else {
                (404, Vec::new())
            }
        });
        let cfg = sync_cfg(&endpoint);

        // Boot: the manifest names rsa_key; the bucket holds no such object.
        assert!(restore_state_at(&root, &cfg, || false));
        assert!(
            read_repair(&root).contains("rsa_key"),
            "a repairable file is recorded"
        );

        // Push: the repair bypasses the manifest match and re-uploads.
        assert!(sync_state_at(&root, &cfg, || false));
        assert!(read_repair(&root).is_empty(), "the repair is consumed");
        let seen = seen.lock().unwrap().clone();
        assert!(
            seen.iter()
                .any(|l| l.starts_with("PUT") && req_path(l).contains("/objects/rsa_key/")),
            "the file is re-uploaded content-addressed: {seen:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
