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
//! files on the data volume). Pushes upload only files whose size differs
//! from the bucket's, so a quiet node costs one listing, not a re-upload of
//! everything. Pulls only fill gaps: a key whose local file already exists
//! is skipped, so a persistent data volume stays authoritative and the
//! bucket never clobbers newer local files.

use std::path::Path;

use crate::config::{SYNC_TIMEOUT, SyncConfig};
use crate::s3::{Client, Listed};
use crate::util::log;

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

/// Pull synced files from the bucket into /data. Called at boot, before
/// tailscaled is spawned, so a restored state file wins over nothing.
///
/// The pull only fills gaps: a bucket key whose local file already exists
/// is left untouched. On an ephemeral volume nothing is there, so the whole
/// set is restored; on a persistent volume the volume stays authoritative
/// and the bucket acts as a fill/DR source rather than clobbering newer
/// local files. Only keys inside the synced set are written.
pub fn restore_state(cfg: &SyncConfig, abort: impl Fn() -> bool) -> bool {
    let Some(client) = build(cfg) else {
        return false;
    };
    let listed = match client.list(cfg.prefix(), &abort) {
        Ok(l) => l,
        Err(e) => {
            log::err(&format!("state sync: pull failed ({e}); continuing"));
            return false;
        }
    };
    let mut ok = true;
    let mut pulled = 0usize;
    let mut kept = 0usize;
    for Listed { key, .. } in &listed {
        let Some(rel) = key.strip_prefix(cfg.prefix()) else {
            continue;
        };
        if !is_synced_file(rel) {
            log::err(&format!(
                "state sync: pull ignored {} (outside the synced set)",
                log::sanitize(key)
            ));
            continue;
        }
        let target = format!("/data/{rel}");
        if !should_pull(Path::new(&target)) {
            kept += 1;
            continue;
        }
        if let Some(parent) = Path::new(&target).parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            log::err(&format!(
                "state sync: cannot create {}: {e}",
                log::sanitize(key)
            ));
            ok = false;
            continue;
        }
        match client.get(key, &target, &abort) {
            Ok(()) => {
                pulled += 1;
                log::info(&format!("state sync: pulled {key}"));
            }
            Err(e) => {
                log::err(&format!("state sync: pull failed ({e}); continuing"));
                ok = false;
            }
        }
    }
    if ok && !listed.is_empty() {
        log::info(&format!(
            "state sync: pull ok ({}, {pulled} new, {kept} kept)",
            cfg.remote
        ));
    }
    ok
}

/// Whether a bucket key should be written locally: only when nothing is
/// there yet, so an existing local file is never overwritten by the bucket.
fn should_pull(target: &Path) -> bool {
    !target.exists()
}

/// Push synced files from /data to the bucket. Called after `up` (fresh
/// state), shortly after the vault starts (the RSA key only exists once
/// vaultwarden has run), on the periodic cadence, and at shutdown.
/// Uploads only files missing from — or of a different size than — the
/// bucket.
pub fn sync_state(cfg: &SyncConfig, abort: impl Fn() -> bool) -> bool {
    let Some(client) = build(cfg) else {
        return false;
    };
    let files = local_synced_files();
    if files.is_empty() {
        log::info("state sync: no synced files to push yet");
        return true;
    }
    let listed = match client.list(cfg.prefix(), &abort) {
        Ok(l) => l,
        Err(e) => {
            log::err(&format!("state sync: push failed ({e}); continuing"));
            return false;
        }
    };
    let remote_sizes: std::collections::HashMap<&str, u64> = listed
        .iter()
        .map(|Listed { key, size }| (key.as_str(), *size))
        .collect();
    let mut pushed = 0usize;
    for rel in &files {
        if abort() {
            return false;
        }
        let key = format!("{}{rel}", cfg.prefix());
        let path = format!("/data/{rel}");
        let size = match std::fs::metadata(&path).map(|m| m.len()) {
            Ok(s) => s,
            Err(e) => {
                log::err(&format!("state sync: cannot size {rel}: {e}"));
                continue;
            }
        };
        if remote_sizes.get(key.as_str()) == Some(&size) {
            continue; // unchanged in the bucket; nothing to upload
        }
        match client.put(&key, &path, &abort) {
            Ok(()) => pushed += 1,
            Err(e) => log::err(&format!(
                "state sync: push failed ({e}); continuing (fresh node/re-login possible)"
            )),
        }
    }
    if pushed > 0 {
        log::info(&format!(
            "state sync: push ok ({}, {pushed} new/changed)",
            cfg.remote
        ));
    }
    true
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
