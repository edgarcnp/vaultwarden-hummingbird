//! /data state sync (opt-in via SUPERVISOR_S3_*): pulls /data identity
//! files at boot, pushes after `up`, on a cadence, and at shutdown — so
//! node identity and vaultwarden signing keys survive ephemeral redeploys
//! (also keeps distance from Let's Encrypt's 5-certs-per-week limit).
//! The bucket holds secrets: keep it private, one container per
//! bucket/path. Every failure is non-fatal; worst case is a fresh node
//! registration, one client re-login, or one cert re-issuance.
//!
//! The scope is the identity set ([`super::identity`], `tailscaled.state`,
//! `rsa_key*`, `certs/**`) — enforced on BOTH directions: pushes upload
//! exactly that set, pulls refuse any key outside it (a bucket anyone can
//! write to must not be able to plant arbitrary files on the data volume).
//! Pushes upload only files whose size differs from the bucket's, so a
//! quiet node costs one listing, not a re-upload of everything.

use std::path::Path;

use crate::config::{SYNC_TIMEOUT, SyncConfig};
use crate::s3::{Client, Listed};
use crate::util::log;

use super::identity::{is_identity_file, local_identity_files};

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

/// Pull identity files from the bucket into /data. Called at boot, before
/// tailscaled is spawned, so a restored state file wins over nothing.
/// Only keys inside the identity set are written — and only files: a key
/// that looks like a directory marker is ignored.
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
    for Listed { key, .. } in &listed {
        let Some(rel) = key.strip_prefix(cfg.prefix()) else {
            continue;
        };
        if !is_identity_file(rel) {
            log::err(&format!(
                "state sync: pull ignored {} (outside the identity set)",
                log::sanitize(key)
            ));
            continue;
        }
        let target = format!("/data/{rel}");
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
            Ok(()) => log::info(&format!("state sync: pulled {key}")),
            Err(e) => {
                log::err(&format!("state sync: pull failed ({e}); continuing"));
                ok = false;
            }
        }
    }
    if ok && !listed.is_empty() {
        log::info(&format!("state sync: pull ok ({})", cfg.remote));
    }
    ok
}

/// Push identity files from /data to the bucket. Called after `up` (fresh
/// state), on the periodic cadence, and at shutdown. Uploads only files
/// missing from — or of a different size than — the bucket.
pub fn sync_state(cfg: &SyncConfig, abort: impl Fn() -> bool) -> bool {
    let Some(client) = build(cfg) else {
        return false;
    };
    let files = local_identity_files();
    if files.is_empty() {
        log::info("state sync: no identity files to push yet");
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
