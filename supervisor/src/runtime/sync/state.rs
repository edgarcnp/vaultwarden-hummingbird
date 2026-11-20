//! State sync (opt-in via SUPERVISOR_S3_*): pulls durable files at boot,
//! pushes shortly after the vault starts, on a cadence, and at shutdown —
//! so node identity, vaultwarden signing keys, and user content survive
//! ephemeral redeploys (also keeps distance from Let's Encrypt's
//! 5-certs-per-week limit). The bucket holds secrets: keep it private, one
//! container per bucket/path. Every failure is non-fatal; worst case is a
//! fresh node registration, one client re-login, or one cert re-issuance.
//!
//! The scope is the durable set ([`super::synced`], `tailscaled.state`,
//! `rsa_key*`, `config.json`, `certs/**`, `attachments/**`, `sends/**`)
//! spread over two local volumes with historical bucket names. It is
//! enforced on BOTH directions: pushes upload exactly that set, pulls
//! refuse any key outside it (a bucket anyone can write to must not be able
//! to plant arbitrary files on either volume).
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
//!
//! Deletions are explicit and conservative ([`super::tombstone`]): a
//! manifest file absent for 24 hours, below a mass-deletion guard, becomes
//! a tombstone; pulls and reconciliation skip it so it cannot be
//! resurrected, and a bounded GC removes its objects after another day. A
//! file that reappears locally clears its tombstone on the next push.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Instant;

use crate::config::{BOOT_RESTORE_BUDGET, SYNC_TIMEOUT, SyncConfig};
use crate::s3::{Client, Expect, GetError, Listed, MAX_SYNC_OBJECT_BYTES};
use crate::util::fs::{create_real_dirs, read_capped, write_atomic};
use crate::util::log;

use super::manifest::{MANIFEST_NAME, MAX_MANIFEST_BYTES, Manifest};
use super::synced::{Roots, clear_partials, is_synced_file};
use super::tombstone::{MAX_TOMBSTONES_BYTES, TOMBSTONES_NAME, Tombstones};

/// Build the client for one sync run; a construction failure is a
/// failed run (logged, non-fatal).
pub(super) fn build(cfg: &SyncConfig) -> Option<Client> {
    match Client::connect(&cfg.target, SYNC_TIMEOUT) {
        Ok(c) => Some(c),
        Err(e) => {
            log::err(&format!("state sync: {e}; continuing"));
            None
        }
    }
}

/// The local record of files the bucket no longer holds correctly: the
/// next push re-uploads them even though the manifest still matches.
pub(super) fn repair_path(root: &Path) -> std::path::PathBuf {
    root.join(".sync-repair")
}

/// The repair list is a sidecar, not user input: cap and no-follow it.
const MAX_REPAIR_BYTES: u64 = 16 * 1024 * 1024;

pub(super) fn read_repair(root: &Path) -> BTreeSet<String> {
    read_capped(&repair_path(root).to_string_lossy(), MAX_REPAIR_BYTES)
        .map(|text| text.lines().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Rewrite the repair list; an empty list removes the file. Best-effort:
/// a failed write only means the next boot re-computes it. Atomic, so a
/// symlink at the sidecar path is replaced, never followed.
pub(super) fn write_repair(root: &Path, rels: &BTreeSet<String>) {
    let path = repair_path(root);
    if rels.is_empty() {
        let _ = std::fs::remove_file(&path);
        return;
    }
    let mut text = String::new();
    for rel in rels {
        // A path cannot be represented in a line-oriented file if it
        // contains a control character; such a name is pathological.
        if rel.chars().any(char::is_control) {
            continue;
        }
        text.push_str(rel);
        text.push('\n');
    }
    if let Err(e) = write_atomic(&path.to_string_lossy(), text.as_bytes(), 0o600) {
        log::err(&format!("state sync: cannot record the repair list ({e})"));
    }
}

/// The manifest's bucket key (inside the sync prefix).
fn manifest_key(cfg: &SyncConfig) -> String {
    format!("{}{MANIFEST_NAME}", cfg.prefix())
}

fn tombstones_key(cfg: &SyncConfig) -> String {
    format!("{}{TOMBSTONES_NAME}", cfg.prefix())
}

/// Load the deletion list. `Ok(None)` = never written (legacy bucket); an
/// `Err` means it exists but cannot be trusted — callers must not overwrite
/// it or resurrect its paths.
pub(super) fn load_tombstones(
    client: &Client,
    cfg: &SyncConfig,
    abort: &impl Fn() -> bool,
) -> anyhow::Result<Option<Tombstones>> {
    match client.get_optional_text(&tombstones_key(cfg), MAX_TOMBSTONES_BYTES, abort)? {
        Some(text) => Tombstones::parse(&text).map(Some),
        None => Ok(None),
    }
}

pub(super) fn store_tombstones(
    client: &Client,
    cfg: &SyncConfig,
    tombstones: &Tombstones,
    abort: &impl Fn() -> bool,
) -> anyhow::Result<()> {
    let rendered = tombstones.render();
    anyhow::ensure!(
        rendered.len() as u64 <= MAX_TOMBSTONES_BYTES,
        "refusing to write a tombstone list over the {MAX_TOMBSTONES_BYTES}-byte read cap"
    );
    client.put_bytes(&tombstones_key(cfg), rendered.as_bytes(), abort)
}

/// Load the manifest; `Ok(None)` = none yet (legacy layout or first run).
pub(super) fn load_manifest(
    client: &Client,
    cfg: &SyncConfig,
    abort: &impl Fn() -> bool,
) -> anyhow::Result<Option<Manifest>> {
    match client.get_optional_text(&manifest_key(cfg), MAX_MANIFEST_BYTES, abort)? {
        Some(text) => {
            let mut manifest = Manifest::parse(&text)?;
            let dropped = manifest.retain(|rel| is_synced_file(rel, cfg.state_file.as_deref()));
            if dropped > 0 {
                log::err(&format!(
                    "state sync: ignoring {dropped} manifest entries outside the durable set"
                ));
            }
            Ok(Some(manifest))
        }
        None => Ok(None),
    }
}

pub(super) fn store_manifest(
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

/// Whether a real file or directory occupies the local path. A symlink is
/// not a local copy: the pull may replace the link itself (the atomic
/// rename never writes through it), which keeps a vault-planted link from
/// permanently blocking a disaster-recovery pull.
fn local_present(target: &Path) -> bool {
    std::fs::symlink_metadata(target)
        .is_ok_and(|meta| meta.file_type().is_file() || meta.file_type().is_dir())
}

/// Whether a bucket key should be written locally: only when nothing real
/// is there yet, so an existing local file is never overwritten by the
/// bucket.
fn should_pull(target: &Path) -> bool {
    !local_present(target)
}

/// The content-addressed bucket key for one synced file's current
/// content: `objects/<rel>/<sha256>`. Immutable by construction — a
/// changed file gets a new key, so an interrupted push can never
/// overwrite the copy the previous manifest references.
pub(super) fn object_key(rel: &str, sha256: &str) -> String {
    format!("objects/{rel}/{sha256}")
}

/// Split a content-addressed key (`<prefix>objects/<rel>/<sha256>`) into
/// `(rel, sha256)`. Anything else — the manifest, legacy path keys, names
/// that are not content-addressed — is not a reconciliation candidate.
pub(super) fn split_object_key<'a>(key: &'a str, prefix: &str) -> Option<(&'a str, &'a str)> {
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

/// Bucket-relative synced files that are not present locally, over the
/// whole prefix (both layouts). `None` = the listing failed, which the
/// caller treats as "cannot prove completeness".
pub(super) fn remote_only_files(
    client: &Client,
    cfg: &SyncConfig,
    roots: &Roots,
    tombstones: &Tombstones,
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
        if rel == MANIFEST_NAME
            || rel == TOMBSTONES_NAME
            || tombstones.contains(rel)
            || !is_synced_file(rel, cfg.state_file.as_deref())
        {
            continue;
        }
        if !local_present(&roots.local(rel, cfg.state_file.as_deref())) {
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
    roots: &Roots,
    client: &Client,
    cfg: &SyncConfig,
    manifest: Option<&Manifest>,
    tombstones: &Tombstones,
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
        if tombstones.contains(rel) || !is_synced_file(rel, cfg.state_file.as_deref()) {
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
        let local = roots.local(&rel, cfg.state_file.as_deref());
        if local_present(&local) {
            continue;
        }
        let rel_parent = Path::new(&rel).parent().unwrap_or_else(|| Path::new(""));
        if create_real_dirs(roots.root_of(&rel, cfg.state_file.as_deref()), rel_parent).is_err() {
            continue;
        }
        let key = format!("{}{}", cfg.prefix(), object_key(&rel, &version.sha256));
        let expect = Expect {
            size: Some(version.size),
            sha256: Some(&version.sha256),
            max_bytes: MAX_SYNC_OBJECT_BYTES,
            mode: roots.mode(&rel, cfg.state_file.as_deref()),
        };
        let local = local.to_string_lossy().into_owned();
        match client.get(&key, &local, expect, abort) {
            Ok(()) => {
                recovered += 1;
                log::info(&format!(
                    "state sync: recovered unreferenced {}",
                    log::sanitize(&rel)
                ));
            }
            Err(e) => log::err(&format!(
                "state sync: recovery of {} failed ({e})",
                log::sanitize(&rel)
            )),
        }
    }

    // Verify every referenced object against the listing (presence and
    // size; content is only checked when a pull downloads it).
    let mut repair = read_repair(&roots.state);
    if let Some(manifest) = manifest {
        for (rel, entry) in manifest.iter() {
            if abort() {
                break;
            }
            if tombstones.contains(rel) {
                continue;
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
                // A repair entry may record a hash failure the listing
                // cannot see (same size); only a successful re-upload
                // clears it.
                continue;
            }
            if local_present(&roots.local(rel, cfg.state_file.as_deref())) {
                log::err(&format!(
                    "state sync: the bucket no longer holds the current copy of {}; \
                     re-uploading it on the next push",
                    log::sanitize(rel)
                ));
                repair.insert(rel.clone());
            } else {
                log::err(&format!(
                    "state sync: the bucket no longer holds {} and no local copy exists",
                    log::sanitize(rel)
                ));
            }
        }
    }
    write_repair(&roots.state, &repair);
    recovered
}

/// One pull candidate: its relative path, plus the manifest's expectations
/// when it came from the manifest.
struct Target {
    rel: String,
    size: Option<u64>,
    sha256: Option<String>,
}

/// Pull synced files from the bucket into their local volumes. Called at
/// boot, before tailscaled is spawned, so a restored state file wins over
/// nothing.
///
/// The pull only fills gaps: a bucket key whose local file already exists
/// is left untouched. On an ephemeral volume nothing is there, so the whole
/// set is restored; on a persistent volume the volume stays authoritative
/// and the bucket acts as a fill/DR source rather than clobbering newer
/// local files. Only keys inside the synced set are written, and every
/// manifest entry is hash-verified before it is published.
pub fn restore_state(cfg: &SyncConfig, abort: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + BOOT_RESTORE_BUDGET;
    restore_state_at(&Roots::production(), cfg, || {
        abort() || Instant::now() >= deadline
    })
}

/// [`restore_state`] with explicit roots (tests use a scratch directory).
fn restore_state_at(roots: &Roots, cfg: &SyncConfig, abort: impl Fn() -> bool) -> bool {
    let Some(client) = build(cfg) else {
        return false;
    };
    // A partial left by a dead transfer must not be resumed against
    // different content; every boot starts clean.
    let cleared = clear_partials(roots, cfg.state_file.as_deref());
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
    // Deletions are authoritative. An unreadable tombstone list could
    // resurrect a deleted path from a legacy key, so the pull fails closed
    // instead of guessing.
    let tombstones = match load_tombstones(&client, cfg, &abort) {
        Ok(Some(tombstones)) => tombstones,
        Ok(None) => Tombstones::default(),
        Err(e) => {
            log::err(&format!(
                "state sync: cannot read the tombstone list ({e}); refusing \
                 the state pull this run"
            ));
            return false;
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
                // The manifest and tombstone objects are metadata, not
                // synced files.
                if rel == MANIFEST_NAME || rel == TOMBSTONES_NAME {
                    continue;
                }
                // Content-addressed objects are restorable only through a
                // manifest (a bare listing cannot order versions); skip
                // them in the legacy view.
                if rel.starts_with("objects/") {
                    continue;
                }
                // The prefix is shared with DB backups and may contain
                // provider metadata; only the durable set is pulled.
                if !is_synced_file(rel, cfg.state_file.as_deref()) {
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
    let mut deleted = 0usize;
    let mut invalid_pulls: BTreeSet<String> = BTreeSet::new();
    for target in targets {
        if tombstones.contains(&target.rel) {
            deleted += 1;
            continue;
        }
        if abort() {
            // The pull is incomplete; false is the honest result (the boot
            // caller ignores it, but the contract is not "success").
            return false;
        }
        if !is_synced_file(&target.rel, cfg.state_file.as_deref()) {
            log::err(&format!(
                "state sync: pull ignored {} (outside the synced set)",
                log::sanitize(&target.rel)
            ));
            ok = false;
            continue;
        }
        let local_path = roots.local(&target.rel, cfg.state_file.as_deref());
        let local = local_path.to_string_lossy().into_owned();
        if !should_pull(Path::new(&local)) {
            kept += 1;
            continue;
        }
        // Reject a symlinked parent component: a bucket-controlled path must
        // never redirect a supervisor write outside its volume.
        let rel_parent = Path::new(&target.rel)
            .parent()
            .unwrap_or_else(|| Path::new(""));
        if let Err(e) = create_real_dirs(
            roots.root_of(&target.rel, cfg.state_file.as_deref()),
            rel_parent,
        ) {
            log::err(&format!(
                "state sync: cannot create the parent of {}: {e}",
                log::sanitize(&target.rel)
            ));
            ok = false;
            continue;
        }
        let expect = Expect {
            size: target.size,
            sha256: target.sha256.as_deref(),
            max_bytes: MAX_SYNC_OBJECT_BYTES,
            mode: roots.mode(&target.rel, cfg.state_file.as_deref()),
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
        let mut invalid = false;
        let result: Result<(), GetError> = match client.get(&primary, &local, expect, &abort) {
            Ok(()) => Ok(()),
            Err(primary_err) => {
                if matches!(primary_err, GetError::Invalid(_)) {
                    invalid = true;
                }
                if target.sha256.is_some() && primary != legacy {
                    // Legacy fallback for entries a bucket inherited from
                    // before the layout change.
                    match client.get(&legacy, &local, expect, &abort) {
                        Ok(()) => Ok(()),
                        Err(legacy_err) => {
                            if matches!(legacy_err, GetError::Invalid(_)) {
                                invalid = true;
                            }
                            Err(GetError::Transport(format!(
                                "content-addressed key failed ({primary_err}); the legacy \
                                 key failed too ({legacy_err})"
                            )))
                        }
                    }
                } else {
                    Err(primary_err)
                }
            }
        };
        match result {
            Ok(()) => {
                pulled += 1;
                log::info(&format!("state sync: pulled {}", target.rel));
            }
            Err(e) => {
                // A hash/size failure means the bucket copy is not the one
                // the manifest describes. Mark it for a forced re-upload;
                // a presence/size-only reconciliation must not clear that.
                if invalid {
                    invalid_pulls.insert(target.rel.clone());
                }
                log::err(&format!("state sync: pull failed ({e}); continuing"));
                ok = false;
            }
        }
    }
    if !invalid_pulls.is_empty() {
        let mut repair = read_repair(&roots.state);
        repair.extend(invalid_pulls);
        write_repair(&roots.state, &repair);
    }
    // Recover objects the manifest does not name (a crash between the PUT
    // and the manifest write, or an unreadable manifest), and note any
    // referenced object the bucket no longer holds.
    pulled += reconcile_objects(roots, &client, cfg, manifest.as_ref(), &tombstones, &abort);
    if deleted > 0 {
        log::info(&format!(
            "state sync: skipped {deleted} intentionally deleted path(s)"
        ));
    }
    if ok && pulled + kept + deleted > 0 {
        log::info(&format!(
            "state sync: pull ok ({}, {pulled} new, {kept} kept, {deleted} deleted)",
            cfg.remote
        ));
    }
    ok
}

#[cfg(test)]
mod tests;
