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
use std::time::{Duration, Instant};

use crate::config::{SYNC_TIMEOUT, SyncConfig};
use crate::s3::{Client, Expect, Listed, MAX_SYNC_OBJECT_BYTES};
use crate::util::fs::{create_real_dirs, read_capped, write_atomic};
use crate::util::hash::sha256_file;
use crate::util::log;

use super::cache::Cache;
use super::manifest::{Entry, MANIFEST_NAME, MAX_MANIFEST_BYTES, Manifest};
use super::synced::{Roots, clear_partials, is_deletable, is_synced_file, local_synced_files};
use super::tombstone::{
    MAX_GC_DELETES, MAX_TOMBSTONES_BYTES, MAX_TOMBSTONES_PER_RUN, Missing, TOMBSTONES_NAME,
    Tombstones, now_unix,
};

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

fn tombstones_key(cfg: &SyncConfig) -> String {
    format!("{}{TOMBSTONES_NAME}", cfg.prefix())
}

/// Load the deletion list. `Ok(None)` = never written (legacy bucket); an
/// `Err` means it exists but cannot be trusted — callers must not overwrite
/// it or resurrect its paths.
fn load_tombstones(
    client: &Client,
    cfg: &SyncConfig,
    abort: &impl Fn() -> bool,
) -> anyhow::Result<Option<Tombstones>> {
    match client.get_optional_text(&tombstones_key(cfg), MAX_TOMBSTONES_BYTES, abort)? {
        Some(text) => Tombstones::parse(&text).map(Some),
        None => Ok(None),
    }
}

fn store_tombstones(
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

/// The repair list is a sidecar, not user input: cap and no-follow it.
const MAX_REPAIR_BYTES: u64 = 16 * 1024 * 1024;

fn read_repair(root: &Path) -> BTreeSet<String> {
    read_capped(&repair_path(root).to_string_lossy(), MAX_REPAIR_BYTES)
        .map(|text| text.lines().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Rewrite the repair list; an empty list removes the file. Best-effort:
/// a failed write only means the next boot re-computes it. Atomic, so a
/// symlink at the sidecar path is replaced, never followed.
fn write_repair(root: &Path, rels: &BTreeSet<String>) {
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

/// Bucket-relative synced files that are not present locally, over the
/// whole prefix (both layouts). `None` = the listing failed, which the
/// caller treats as "cannot prove completeness".
fn remote_only_files(
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
                repair.remove(rel);
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
    restore_state_at(&Roots::production(), cfg, abort)
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
        let primary_result = client
            .get(&primary, &local, expect, &abort)
            .map_err(|e| anyhow::anyhow!("{e}"));
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

/// Wait (bounded) for vaultwarden's signing key, so the first post-vault
/// push carries it. Returns false on timeout or a stop request; the caller
/// pushes anyway — a missing key is logged, never silently assumed.
pub fn wait_for_rsa_key(timeout: Duration, abort: impl Fn() -> bool) -> bool {
    wait_for_rsa_key_at(Path::new("/data"), timeout, abort)
}

fn wait_for_rsa_key_at(root: &Path, timeout: Duration, abort: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if abort() {
            return false;
        }
        if let Ok(entries) = std::fs::read_dir(root)
            && entries.flatten().any(|entry| {
                entry.file_name().to_string_lossy().starts_with("rsa_key")
                    && entry.file_type().is_ok_and(|kind| kind.is_file())
            })
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Push synced files to the bucket. Called after `up` (fresh state),
/// shortly after the vault starts (the RSA key only exists once
/// vaultwarden has run), on the periodic cadence, and at shutdown.
/// Uploads only files whose content differs from the manifest (a hash,
/// not just a size), then rewrites the manifest. A file absent for the
/// deletion grace becomes a tombstone instead of being kept forever; the
/// mass guard keeps a lost volume from emptying the bucket.
pub fn sync_state(cfg: &SyncConfig, abort: impl Fn() -> bool) -> bool {
    sync_state_at(&Roots::production(), cfg, abort)
}

/// [`sync_state`] with explicit roots (tests use a scratch directory).
fn sync_state_at(roots: &Roots, cfg: &SyncConfig, abort: impl Fn() -> bool) -> bool {
    let Some(client) = build(cfg) else {
        return false;
    };
    let files = local_synced_files(roots, cfg.state_file.as_deref());
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
        let path = roots
            .local(rel, cfg.state_file.as_deref())
            .to_string_lossy()
            .into_owned();
        let meta = match std::fs::metadata(&path) {
            Ok(meta) => meta,
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
        // cache entry must never become the recorded identity.
        let hash = match sha256_file(&path) {
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
            if rel == MANIFEST_NAME || rel == TOMBSTONES_NAME {
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
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// The first push waits for the vault's signing key, but a stop request
    /// or a missing key must end the wait.
    #[test]
    fn the_first_push_waits_for_the_signing_key() {
        let root = std::env::temp_dir().join(format!("vw-sup-rsa-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        assert!(!wait_for_rsa_key_at(
            &root,
            Duration::from_millis(50),
            || false
        ));
        assert!(
            !wait_for_rsa_key_at(&root, Duration::from_secs(5), || true),
            "a stop request ends the wait"
        );
        std::fs::write(root.join("rsa_key.pem"), b"key").unwrap();
        assert!(wait_for_rsa_key_at(
            &root,
            Duration::from_millis(50),
            || false
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

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
        // A symlink is not a local copy: a pull may replace the link
        // (never writing through it) instead of being blocked forever.
        let link = dir.join("alias");
        std::os::unix::fs::symlink(&present, &link).unwrap();
        assert!(should_pull(&link));
        assert!(!local_present(&link));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Bucket keys are historical names, but the local write must go to
    /// the volume that owns the file: identity/certs on `/state` (0600),
    /// vault data on `/data` (0660, group-shared with the vault uid).
    #[test]
    fn a_pull_routes_each_key_to_its_volume() {
        let base = std::env::temp_dir().join(format!("vw-sup-roots-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let roots = Roots {
            data: base.join("data"),
            state: base.join("state"),
        };
        for root in [&roots.data, &roots.state] {
            std::fs::create_dir_all(root).unwrap();
        }
        let sha = |bytes: &[u8]| {
            let probe = base.join("probe");
            std::fs::write(&probe, bytes).unwrap();
            let sha = sha256_file(probe.to_str().unwrap()).unwrap();
            std::fs::remove_file(&probe).unwrap();
            sha
        };
        let state_sha = sha(b"state");
        let data_sha = sha(b"attach");
        let manifest = format!("v1\n{state_sha} 5 tailscaled.state\n{data_sha} 6 attachments/u\n");
        let state_key = format!("/vw/objects/tailscaled.state/{state_sha}");
        let data_key = format!("/vw/objects/attachments/u/{data_sha}");
        let (endpoint, _seen) = fake_bucket(move |line| {
            let path = req_path(line);
            if line.starts_with("GET") && path.ends_with("/manifest") {
                (200, manifest.clone().into_bytes())
            } else if line.starts_with("GET") && path == state_key {
                (200, b"state".to_vec())
            } else if line.starts_with("GET") && path == data_key {
                (200, b"attach".to_vec())
            } else {
                (404, Vec::new())
            }
        });

        assert!(restore_state_at(&roots, &sync_cfg(&endpoint), || false));

        assert_eq!(
            std::fs::read(roots.state.join("tailscaled.state")).unwrap(),
            b"state"
        );
        assert_eq!(
            std::fs::read(roots.data.join("attachments/u")).unwrap(),
            b"attach"
        );
        use std::os::unix::fs::PermissionsExt;
        let mode =
            |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&roots.state.join("tailscaled.state")), 0o600);
        assert_eq!(mode(&roots.data.join("attachments/u")), 0o660);
        let _ = std::fs::remove_dir_all(&base);
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

    /// A recorded request: its line and body, for asserting on writes.
    type Captured = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

    /// Like [`fake_bucket`], but also records each request body (the
    /// tombstone/manifest assertions need to inspect what was written).
    fn fake_bucket_capturing(
        route: impl Fn(&str) -> (u16, Vec<u8>) + Send + 'static,
    ) -> (String, Captured) {
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
                let content_length = head
                    .lines()
                    .find_map(|l| {
                        let (name, value) = l.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())?
                    })
                    .unwrap_or(0);
                let mut body = buf[head_end..].to_vec();
                while body.len() < content_length {
                    let n = s.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    body.extend_from_slice(&chunk[..n]);
                }
                body.truncate(content_length);
                seen_worker.lock().unwrap().push((line.clone(), body));
                let (status, body) = route(&line);
                let reason = match status {
                    200 => "OK",
                    404 => "Not Found",
                    500 => "Internal Server Error",
                    _ => "Status",
                };
                let head = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(head.as_bytes());
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
            } else if line.starts_with("GET") && path.ends_with("/tombstones") {
                (404, Vec::new()) // no deletions recorded
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
            !sync_state_at(&Roots::one(&root), &sync_cfg(&endpoint), || false),
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
        assert!(
            !seen.iter().any(|l| l.starts_with("DELETE")),
            "a failed manifest write must never trigger GC: {seen:?}"
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

        assert!(restore_state_at(
            &Roots::one(&root),
            &sync_cfg(&endpoint),
            || false
        ));
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

    /// A bucket that is not provably complete must not be written to: the
    /// old fallback wrote mutable path keys and could overwrite newer data.
    #[test]
    fn degraded_bucket_is_never_written_to() {
        let root = std::env::temp_dir().join(format!("vw-sup-degraded-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("rsa_key"), b"new-local").unwrap();

        let listing = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Name>vw</Name><Prefix></Prefix><KeyCount>1</KeyCount><MaxKeys>1000</MaxKeys>\
             <IsTruncated>false</IsTruncated>\
             <Contents><Key>attachments/remote-only</Key>\
             <LastModified>2026-09-28T00:00:00.000Z</LastModified>\
             <ETag>\"x\"</ETag><Size>3</Size><StorageClass>STANDARD</StorageClass></Contents>\
             </ListBucketResult>"
            .to_vec();
        let (endpoint, seen) = fake_bucket(move |line| {
            let path = req_path(line);
            if line.starts_with("GET") && path.ends_with("/manifest") {
                (404, Vec::new())
            } else if line.starts_with("GET") && line.contains("list-type=2") {
                (200, listing.clone())
            } else if line.starts_with("PUT") {
                (200, Vec::new())
            } else {
                (404, Vec::new())
            }
        });
        assert!(
            !sync_state_at(&Roots::one(&root), &sync_cfg(&endpoint), || false),
            "a degraded bucket must refuse the push"
        );
        let seen = seen.lock().unwrap().clone();
        assert!(
            !seen.iter().any(|line| line.starts_with("PUT")),
            "no upload may reach a bucket that is not provably complete: {seen:?}"
        );
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
        assert!(restore_state_at(
            &Roots::one(&root),
            &sync_cfg(&endpoint),
            || false
        ));
        assert_eq!(std::fs::read(root.join("attachments/x")).unwrap(), content);
        let seen = seen.lock().unwrap().clone();
        assert!(
            seen.iter().any(|l| l.contains("list-type=2")),
            "the reconciliation listing ran: {seen:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A file absent for the grace window becomes a tombstone: the
    /// manifest entry is removed and the tombstone object is published
    /// before the manifest write.
    #[test]
    fn a_deleted_file_becomes_a_tombstone_after_the_grace() {
        let root = std::env::temp_dir().join(format!("vw-sup-tomb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("rsa_key"), b"key").unwrap();
        let sha_key = sha256_file(root.join("rsa_key").to_str().unwrap()).unwrap();
        let gone = "a".repeat(64);
        let manifest = format!("v1\n{gone} 3 attachments/gone\n{sha_key} 3 rsa_key\n");
        std::fs::write(root.join(".sync-missing"), b"0 attachments/gone\n").unwrap();
        let (endpoint, reqs) = fake_bucket_capturing(move |line| {
            let path = req_path(line);
            if line.starts_with("GET") && path.ends_with("/manifest") {
                (200, manifest.clone().into_bytes())
            } else if line.starts_with("GET") && path.ends_with("/tombstones") {
                (404, Vec::new())
            } else if line.starts_with("GET") && line.contains("list-type=2") {
                (200, empty_listing())
            } else if line.starts_with("PUT") {
                (200, Vec::new())
            } else {
                (404, Vec::new())
            }
        });
        assert!(sync_state_at(
            &Roots::one(&root),
            &sync_cfg(&endpoint),
            || false
        ));
        let reqs = reqs.lock().unwrap().clone();
        let tombstone = reqs
            .iter()
            .find(|(line, _)| line.starts_with("PUT") && req_path(line).ends_with("/tombstones"))
            .expect("tombstone list written");
        assert!(
            String::from_utf8_lossy(&tombstone.1).contains("attachments/gone"),
            "the deleted path is recorded"
        );
        let manifest = reqs
            .iter()
            .find(|(line, _)| line.starts_with("PUT") && req_path(line).ends_with("/manifest"))
            .expect("manifest rewritten");
        assert!(
            !String::from_utf8_lossy(&manifest.1).contains("attachments/gone"),
            "the deleted path leaves the manifest"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A disappearance large enough to be a lost volume is never treated as
    /// user intent.
    #[test]
    fn a_mass_disappearance_is_not_a_deletion() {
        let root = std::env::temp_dir().join(format!("vw-sup-mass-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let mut manifest = String::from("v1\n");
        let mut missing = String::new();
        for i in 0..5 {
            manifest.push_str(&format!("{} 3 attachments/gone{i}\n", "a".repeat(64)));
            missing.push_str(&format!("0 attachments/gone{i}\n"));
        }
        std::fs::write(root.join(".sync-missing"), missing).unwrap();
        let (endpoint, seen) = fake_bucket(move |line| {
            let path = req_path(line);
            if line.starts_with("GET") && path.ends_with("/manifest") {
                (200, manifest.clone().into_bytes())
            } else if line.starts_with("GET") && path.ends_with("/tombstones") {
                (404, Vec::new())
            } else if line.starts_with("GET") && line.contains("list-type=2") {
                (200, empty_listing())
            } else if line.starts_with("PUT") {
                (200, Vec::new())
            } else {
                (404, Vec::new())
            }
        });
        assert!(sync_state_at(
            &Roots::one(&root),
            &sync_cfg(&endpoint),
            || false
        ));
        let seen = seen.lock().unwrap().clone();
        assert!(
            !seen
                .iter()
                .any(|l| l.starts_with("PUT") && req_path(l).ends_with("/tombstones")),
            "a mass disappearance must not publish tombstones: {seen:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Even a single-file manifest is not emptied just because its file is
    /// absent: an unmounted volume looks exactly like that.
    #[test]
    fn a_sole_missing_file_is_not_a_deletion() {
        let root = std::env::temp_dir().join(format!("vw-sup-sole-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(".sync-missing"), b"0 attachments/sole\n").unwrap();
        let (endpoint, seen) = fake_bucket(move |line| {
            let path = req_path(line);
            if line.starts_with("GET") && path.ends_with("/manifest") {
                (
                    200,
                    format!("v1\n{} 3 attachments/sole\n", "a".repeat(64)).into_bytes(),
                )
            } else if line.starts_with("GET") && path.ends_with("/tombstones") {
                (404, Vec::new())
            } else if line.starts_with("GET") && line.contains("list-type=2") {
                (200, empty_listing())
            } else if line.starts_with("PUT") {
                (200, Vec::new())
            } else {
                (404, Vec::new())
            }
        });
        assert!(sync_state_at(
            &Roots::one(&root),
            &sync_cfg(&endpoint),
            || false
        ));
        let seen = seen.lock().unwrap().clone();
        assert!(
            !seen
                .iter()
                .any(|l| l.starts_with("PUT") && req_path(l).ends_with("/tombstones")),
            "a sole missing file must not be tombstoned: {seen:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The node identity and certificates are never tombstoned, even after
    /// the grace: user intent cannot erase the machine's identity.
    #[test]
    fn identity_files_are_never_tombstoned() {
        let root = std::env::temp_dir().join(format!("vw-sup-identity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(".sync-missing"), b"0 tailscaled.state\n").unwrap();
        let (endpoint, seen) = fake_bucket(move |line| {
            let path = req_path(line);
            if line.starts_with("GET") && path.ends_with("/manifest") {
                (
                    200,
                    format!("v1\n{} 3 tailscaled.state\n", "a".repeat(64)).into_bytes(),
                )
            } else if line.starts_with("GET") && path.ends_with("/tombstones") {
                (404, Vec::new())
            } else if line.starts_with("GET") && line.contains("list-type=2") {
                (200, empty_listing())
            } else if line.starts_with("PUT") {
                (200, Vec::new())
            } else {
                (404, Vec::new())
            }
        });
        assert!(sync_state_at(
            &Roots::one(&root),
            &sync_cfg(&endpoint),
            || false
        ));
        let seen = seen.lock().unwrap().clone();
        assert!(
            !seen
                .iter()
                .any(|l| l.starts_with("PUT") && req_path(l).ends_with("/tombstones")),
            "the identity can never be tombstoned: {seen:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A legacy listing shares the prefix with DB backups; only the
    /// durable set is pulled.
    #[test]
    fn a_legacy_listing_ignores_backup_objects() {
        let root = std::env::temp_dir().join(format!("vw-sup-shared-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let listing = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Name>vw</Name><Prefix></Prefix><KeyCount>3</KeyCount><MaxKeys>1000</MaxKeys>\
             <IsTruncated>false</IsTruncated>\
             <Contents><Key>attachments/a</Key><LastModified>2026-01-01T00:00:00.000Z</LastModified><Size>1</Size></Contents>\
             <Contents><Key>db/manifest</Key><LastModified>2026-01-01T00:00:00.000Z</LastModified><Size>3</Size></Contents>\
             <Contents><Key>db/sqlite-1.sqlite3</Key><LastModified>2026-01-01T00:00:00.000Z</LastModified><Size>3</Size></Contents>\
             </ListBucketResult>"
            .to_vec();
        let (endpoint, _seen) = fake_bucket(move |line| {
            let path = req_path(line);
            if line.starts_with("GET")
                && (path.ends_with("/manifest") || path.ends_with("/tombstones"))
            {
                (404, Vec::new())
            } else if line.starts_with("GET") && line.contains("list-type=2") {
                (200, listing.clone())
            } else if line.starts_with("GET") && path.ends_with("/attachments/a") {
                (200, b"x".to_vec())
            } else {
                (404, Vec::new())
            }
        });
        assert!(restore_state_at(
            &Roots::one(&root),
            &sync_cfg(&endpoint),
            || false
        ));
        assert_eq!(std::fs::read(root.join("attachments/a")).unwrap(), b"x");
        assert!(!root.join("db").exists(), "backup keys are not pulled");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// An unreadable tombstone list refuses the pull: pulling on a guess
    /// could resurrect a deleted file from a legacy key.
    #[test]
    fn a_corrupt_tombstone_list_refuses_the_pull() {
        let root = std::env::temp_dir().join(format!("vw-sup-tbad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let sha = "e".repeat(64);
        let (endpoint, seen) = fake_bucket(move |line| {
            let path = req_path(line);
            if line.starts_with("GET") && path.ends_with("/manifest") {
                (200, format!("v1\n{sha} 4 rsa_key\n").into_bytes())
            } else if line.starts_with("GET") && path.ends_with("/tombstones") {
                (200, b"not a tombstone list".to_vec())
            } else {
                (404, Vec::new())
            }
        });
        assert!(!restore_state_at(
            &Roots::one(&root),
            &sync_cfg(&endpoint),
            || false
        ));
        assert!(!root.join("rsa_key").exists());
        let seen = seen.lock().unwrap().clone();
        assert!(
            !seen.iter().any(|l| l.contains("/objects/")),
            "no object may be fetched on an untrusted tombstone list: {seen:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A tombstoned path is never pulled, even when its old object or
    /// legacy key still exists.
    #[test]
    fn a_pull_skips_a_tombstoned_path() {
        let root = std::env::temp_dir().join(format!("vw-sup-tskip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let sha = "b".repeat(64);
        let key = object_key("attachments/gone", &sha);
        let manifest = format!("v1\n{sha} 4 attachments/gone\n");
        let (endpoint, seen) = fake_bucket(move |line| {
            let path = req_path(line);
            if line.starts_with("GET") && path.ends_with("/manifest") {
                (200, manifest.clone().into_bytes())
            } else if line.starts_with("GET") && path.ends_with("/tombstones") {
                (200, b"v1\n0 attachments/gone\n".to_vec())
            } else if line.starts_with("GET") && line.contains("list-type=2") {
                (200, empty_listing())
            } else if line.starts_with("GET") && path.contains(&key) {
                (200, b"data".to_vec())
            } else {
                (404, Vec::new())
            }
        });
        assert!(restore_state_at(
            &Roots::one(&root),
            &sync_cfg(&endpoint),
            || false
        ));
        assert!(!root.join("attachments/gone").exists());
        let seen = seen.lock().unwrap().clone();
        assert!(
            !seen.iter().any(|l| l.contains("/objects/")),
            "a tombstoned object must not be fetched: {seen:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A file that reappears locally clears its tombstone and is uploaded.
    #[test]
    fn a_restored_file_clears_its_tombstone() {
        let root = std::env::temp_dir().join(format!("vw-sup-trestore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("rsa_key"), b"key").unwrap();
        let (endpoint, reqs) = fake_bucket_capturing(move |line| {
            let path = req_path(line);
            if line.starts_with("GET") && path.ends_with("/manifest") {
                (200, b"v1\n".to_vec())
            } else if line.starts_with("GET") && path.ends_with("/tombstones") {
                (200, b"v1\n0 rsa_key\n".to_vec())
            } else if line.starts_with("GET") && line.contains("list-type=2") {
                (200, empty_listing())
            } else if line.starts_with("PUT") {
                (200, Vec::new())
            } else {
                (404, Vec::new())
            }
        });
        assert!(sync_state_at(
            &Roots::one(&root),
            &sync_cfg(&endpoint),
            || false
        ));
        let reqs = reqs.lock().unwrap().clone();
        let tombstone = reqs
            .iter()
            .find(|(line, _)| line.starts_with("PUT") && req_path(line).ends_with("/tombstones"))
            .expect("tombstone list rewritten");
        assert!(
            !String::from_utf8_lossy(&tombstone.1).contains("rsa_key"),
            "the restored path leaves the tombstone list"
        );
        assert!(
            reqs.iter()
                .any(|(line, _)| line.starts_with("PUT")
                    && req_path(line).contains("/objects/rsa_key/")),
            "the restored file is uploaded"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Superseded content-addressed objects are deleted once the manifest
    /// naming the replacement is durable; the current object and unknown
    /// paths are kept.
    #[test]
    fn gc_deletes_only_superseded_objects() {
        let root = std::env::temp_dir().join(format!("vw-sup-gc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("rsa_key"), b"key").unwrap();
        let sha = sha256_file(root.join("rsa_key").to_str().unwrap()).unwrap();
        let old = "c".repeat(64);
        let manifest = format!("v1\n{sha} 3 rsa_key\n");
        let listing = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Name>vw</Name><Prefix></Prefix><KeyCount>2</KeyCount><MaxKeys>1000</MaxKeys>\
             <IsTruncated>false</IsTruncated>\
             <Contents><Key>objects/rsa_key/{old}</Key><LastModified>2026-01-01T00:00:00.000Z</LastModified><Size>3</Size></Contents>\
             <Contents><Key>objects/rsa_key/{sha}</Key><LastModified>2026-01-02T00:00:00.000Z</LastModified><Size>3</Size></Contents>\
             </ListBucketResult>"
        );
        let (endpoint, seen) = fake_bucket(move |line| {
            let path = req_path(line);
            if line.starts_with("GET") && path.ends_with("/manifest") {
                (200, manifest.clone().into_bytes())
            } else if line.starts_with("GET") && path.ends_with("/tombstones") {
                (404, Vec::new())
            } else if line.starts_with("GET") && line.contains("list-type=2") {
                (200, listing.clone().into_bytes())
            } else {
                (200, Vec::new())
            }
        });
        assert!(sync_state_at(
            &Roots::one(&root),
            &sync_cfg(&endpoint),
            || false
        ));
        let seen = seen.lock().unwrap().clone();
        assert!(
            seen.iter()
                .any(|l| l.starts_with("DELETE") && l.contains(&old)),
            "the superseded object is deleted: {seen:?}"
        );
        assert!(
            !seen
                .iter()
                .any(|l| l.starts_with("DELETE") && l.contains(&sha)),
            "the current object is kept: {seen:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// If the manifest's current object is gone, the older object is the
    /// only restorable copy: GC must keep it.
    #[test]
    fn gc_keeps_a_fallback_when_the_current_object_is_gone() {
        let root = std::env::temp_dir().join(format!("vw-sup-gckeep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("rsa_key"), b"key").unwrap();
        let sha = sha256_file(root.join("rsa_key").to_str().unwrap()).unwrap();
        let old = "d".repeat(64);
        let manifest = format!("v1\n{sha} 3 rsa_key\n");
        let listing = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Name>vw</Name><Prefix></Prefix><KeyCount>1</KeyCount><MaxKeys>1000</MaxKeys>\
             <IsTruncated>false</IsTruncated>\
             <Contents><Key>objects/rsa_key/{old}</Key><LastModified>2026-01-01T00:00:00.000Z</LastModified><Size>3</Size></Contents>\
             </ListBucketResult>"
        );
        let (endpoint, seen) = fake_bucket(move |line| {
            let path = req_path(line);
            if line.starts_with("GET") && path.ends_with("/manifest") {
                (200, manifest.clone().into_bytes())
            } else if line.starts_with("GET") && path.ends_with("/tombstones") {
                (404, Vec::new())
            } else if line.starts_with("GET") && line.contains("list-type=2") {
                (200, listing.clone().into_bytes())
            } else {
                (200, Vec::new())
            }
        });
        assert!(sync_state_at(
            &Roots::one(&root),
            &sync_cfg(&endpoint),
            || false
        ));
        let seen = seen.lock().unwrap().clone();
        assert!(
            !seen.iter().any(|l| l.starts_with("DELETE")),
            "the only fallback copy must survive: {seen:?}"
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
        assert!(restore_state_at(&Roots::one(&root), &cfg, || false));
        assert!(
            read_repair(&root).contains("rsa_key"),
            "a repairable file is recorded"
        );

        // Push: the repair bypasses the manifest match and re-uploads.
        assert!(sync_state_at(&Roots::one(&root), &cfg, || false));
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
