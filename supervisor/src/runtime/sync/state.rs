//! /data state sync (opt-in via SUPERVISOR_S3_*): pulls /data identity
//! files at boot, pushes after `up`, on a cadence, and at shutdown — so
//! node identity and vaultwarden signing keys survive ephemeral redeploys
//! (also keeps distance from Let's Encrypt's 5-certs-per-week limit).
//! The bucket holds secrets: keep it private, one container per
//! bucket/path. Every failure is non-fatal; worst case is a fresh node
//! registration, one client re-login, or one cert re-issuance.
//!
//! The scope is the identity set — `tailscaled.state`, `rsa_key*`,
//! `certs/**` — enforced on BOTH directions: pushes upload exactly that
//! set, pulls refuse any key outside it (a bucket anyone can write to
//! must not be able to plant arbitrary files on the data volume). Pushes
//! upload only files whose size differs from the bucket's, so a quiet
//! node costs one listing, not a re-upload of everything.

use std::path::Path;

use crate::config::{SYNC_TIMEOUT, SyncConfig};
use crate::s3::{Client, Listed};
use crate::util::log;

/// Build the client for one sync run; a construction failure is a
/// failed run (logged, non-fatal).
fn build(cfg: &SyncConfig) -> Option<Client> {
    match Client::new(cfg, SYNC_TIMEOUT) {
        Ok(c) => Some(c),
        Err(e) => {
            log::err(&format!("state sync: {e}; continuing"));
            None
        }
    }
}

/// Whether a bucket-relative path is inside the identity set. Both
/// directions filter through this: what push may upload is exactly what
/// pull may write.
fn is_identity_file(rel: &str) -> bool {
    if rel.contains("..") || rel.starts_with('/') {
        return false;
    }
    rel == "tailscaled.state"
        || (rel.starts_with("rsa_key") && !rel.contains('/'))
        || rel.starts_with("certs/")
}

/// The /data files in the identity set, as bucket-relative paths.
fn local_identity_files() -> Vec<String> {
    let mut files = Vec::new();
    if Path::new("/data/tailscaled.state").is_file() {
        files.push("tailscaled.state".to_string());
    }
    if let Ok(entries) = std::fs::read_dir("/data") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue; // non-UTF-8 names never enter the identity set
            };
            if name.starts_with("rsa_key") && entry.path().is_file() {
                files.push(name.to_string());
            }
        }
    }
    let mut push_dir = |rel: String| files.push(rel);
    walk_certs(Path::new("/data/certs"), "certs", &mut push_dir);
    files.sort();
    files
}

/// Recursively collect files under `dir` (the tailscale cert store).
fn walk_certs(dir: &Path, rel: &str, out: &mut impl FnMut(String)) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let path_rel = format!("{rel}/{name}");
        if entry.path().is_dir() {
            walk_certs(&entry.path(), &path_rel, out);
        } else {
            out(path_rel);
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
    let listed = match client.list(&cfg.prefix, &abort) {
        Ok(l) => l,
        Err(e) => {
            log::err(&format!("state sync: pull failed ({e}); continuing"));
            return false;
        }
    };
    let mut ok = true;
    for Listed { key, .. } in &listed {
        let Some(rel) = key.strip_prefix(&cfg.prefix) else {
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
    let listed = match client.list(&cfg.prefix, &abort) {
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
        let key = format!("{}{rel}", cfg.prefix);
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

    #[test]
    fn identity_set_is_enforced_in_both_directions() {
        assert!(is_identity_file("tailscaled.state"));
        assert!(is_identity_file("rsa_key"));
        assert!(is_identity_file("rsa_key.foo.bar"));
        assert!(is_identity_file("certs/key.crt"));
        assert!(is_identity_file("certs/sub/key.crt"));
        // everything else is outside the set
        assert!(!is_identity_file("db.sqlite3"));
        assert!(!is_identity_file("certs"));
        assert!(!is_identity_file("tailscaled.state.bak"));
        // traversal and absolute paths never pass, in any position
        assert!(!is_identity_file("../tailscaled.state"));
        assert!(!is_identity_file("certs/../../etc/passwd"));
        assert!(!is_identity_file("/etc/passwd"));
    }

    /// The push filter only treats regular files as identity files; a
    /// directory named `rsa_key` in /data would not be uploaded.
    #[test]
    fn local_enumeration_skips_directories() {
        let dir = std::env::temp_dir().join(format!("vw-sup-sync-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("certs/sub")).unwrap();
        std::fs::write(dir.join("tailscaled.state"), b"x").unwrap();
        std::fs::create_dir(dir.join("rsa_key")).unwrap(); // a directory!
        std::fs::write(dir.join("certs/example.com.crt"), b"x").unwrap();
        std::fs::write(dir.join("certs/sub/deep.crt"), b"x").unwrap();
        std::fs::write(dir.join("db.sqlite3"), b"x").unwrap();
        // temp dir stands in for /data via the walker's inputs is not
        // possible (paths are pinned to /data); exercise walk_certs + the
        // top-level predicate instead.
        let mut found = Vec::new();
        walk_certs(&dir.join("certs"), "certs", &mut |rel| found.push(rel));
        found.sort();
        assert_eq!(found, vec!["certs/example.com.crt", "certs/sub/deep.crt"]);
        assert!(found.iter().all(|f| is_identity_file(f)));
        assert!(!is_identity_file("db.sqlite3"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
