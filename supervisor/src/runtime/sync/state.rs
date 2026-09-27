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
//! before the file is published. Without a manifest (a pre-manifest
//! bucket) the name listing is used, size-checked only, until the first
//! push writes one. Hashes are cached locally keyed by (size, mtime)
//! ([`super::cache`]) so a quiet push does not re-hash gigabytes.

use std::path::Path;

use crate::config::{SYNC_TIMEOUT, SyncConfig};
use crate::s3::{Client, Expect, Listed, MAX_SYNC_OBJECT_BYTES};
use crate::util::hash::sha256_file;
use crate::util::log;

use super::cache::Cache;
use super::manifest::{Entry, MANIFEST_NAME, MAX_MANIFEST_BYTES, Manifest};
use super::synced::{is_synced_file, local_synced_files};

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
    client.put_bytes(&manifest_key(cfg), manifest.render().as_bytes(), abort)
}

/// Whether a bucket key should be written locally: only when nothing is
/// there yet, so an existing local file is never overwritten by the bucket.
fn should_pull(target: &Path) -> bool {
    !target.exists()
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
    let Some(client) = build(cfg) else {
        return false;
    };
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
            for Listed { key, .. } in &listed {
                let Some(rel) = key.strip_prefix(cfg.prefix()) else {
                    continue;
                };
                // The manifest object itself is not a synced file.
                if rel == MANIFEST_NAME {
                    continue;
                }
                targets.push(Target {
                    rel: rel.to_string(),
                    size: None,
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
        if !is_synced_file(&target.rel) {
            log::err(&format!(
                "state sync: pull ignored {} (outside the synced set)",
                log::sanitize(&target.rel)
            ));
            ok = false;
            continue;
        }
        let local = format!("/data/{}", target.rel);
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
        match client.get(
            &format!("{}{}", cfg.prefix(), target.rel),
            &local,
            expect,
            &abort,
        ) {
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
    let Some(client) = build(cfg) else {
        return false;
    };
    let files = local_synced_files();
    if files.is_empty() {
        log::info("state sync: no synced files to push yet");
        return true;
    }
    let mut manifest = match load_manifest(&client, cfg, &abort) {
        Ok(Some(manifest)) => manifest,
        Ok(None) => Manifest::default(),
        Err(e) => {
            // The volume is authoritative: rebuild the manifest from local
            // content. PUTs are idempotent, so every file is re-uploaded
            // once and the manifest is rewritten.
            log::err(&format!(
                "state sync: cannot read the manifest ({e}); rebuilding it from \
                 local content"
            ));
            Manifest::default()
        }
    };
    let mut cache = Cache::load();
    let mut pushed = 0usize;
    let mut failed = false;
    for rel in &files {
        if abort() {
            return false;
        }
        let path = format!("/data/{rel}");
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
        let hash = match cache.hash_of(rel, size, mtime) {
            Some(hash) => hash.to_string(),
            None => match sha256_file(&path) {
                Ok(hash) => hash,
                Err(e) => {
                    log::err(&format!("state sync: cannot hash {rel}: {e}"));
                    failed = true;
                    continue;
                }
            },
        };
        cache.record(rel, size, mtime, hash.clone());
        if manifest
            .get(rel)
            .is_some_and(|entry| entry.sha256 == hash && entry.size == size)
        {
            continue; // unchanged in the bucket; nothing to upload
        }
        let key = format!("{}{rel}", cfg.prefix());
        match client.put(&key, &path, &abort) {
            Ok(()) => {
                manifest.insert(rel.clone(), Entry { size, sha256: hash });
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
        match store_manifest(&client, cfg, &manifest, &abort) {
            Ok(()) => log::info(&format!(
                "state sync: push ok ({}, {pushed} new/changed)",
                cfg.remote
            )),
            Err(e) => {
                log::err(&format!(
                    "state sync: pushed {pushed} object(s) but cannot publish the manifest \
                     ({e}); they will be re-uploaded next tick"
                ));
                failed = true;
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
