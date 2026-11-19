//! Tests for the state pull path and the helpers both directions share.
//! Push-path tests live here too: `sync_state_at` is reachable through
//! `super::push`, and the fake bucket is shared via `super::test_support`.

use std::collections::BTreeSet;
use std::time::Duration;

use super::super::push::{sync_state_at, wait_for_rsa_key_at};
use super::super::test_support::{
    empty_listing, fake_bucket, fake_bucket_capturing, req_path, sync_cfg,
};
use super::*;
use crate::util::hash::sha256_file;

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

/// Two of five files is still more than a quarter of the manifest; a lost
/// `/data` volume can look like this even when `/state` identity survives.
#[test]
fn the_fraction_guard_refuses_a_large_partial_deletion() {
    let root = std::env::temp_dir().join(format!("vw-sup-fraction-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("attachments")).unwrap();
    let mut manifest = String::from("v1\n");
    for i in 0..3 {
        let name = format!("attachments/keep{i}");
        let bytes = format!("keep{i}");
        std::fs::write(root.join(&name), bytes.as_bytes()).unwrap();
        manifest.push_str(&format!(
            "{} {} {name}\n",
            crate::util::hash::sha256_bytes(bytes.as_bytes()),
            bytes.len()
        ));
    }
    let mut missing = String::new();
    for i in 0..2 {
        manifest.push_str(&format!("{} 4 attachments/gone{i}\n", "a".repeat(64)));
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
        "two of five must be refused as probable volume loss: {seen:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

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

/// A same-size object with the wrong bytes is a hash failure. It must be
/// recorded for a forced re-upload; the later presence/size reconciliation
/// cannot see the difference and must not clear the repair.
#[test]
fn a_hash_mismatch_marks_the_path_for_repair() {
    let root = std::env::temp_dir().join(format!("vw-sup-repairhash-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let expected = crate::util::hash::sha256_bytes(b"AAAA");
    let manifest = format!("v1\n{expected} 4 attachments/u\n");
    let object_suffix = format!("objects/attachments/u/{expected}");
    let (endpoint, _seen) = fake_bucket(move |line| {
        let path = req_path(line);
        if line.starts_with("GET") && path.ends_with("/manifest") {
            (200, manifest.clone().into_bytes())
        } else if line.starts_with("GET") && path.ends_with("/tombstones") {
            (404, Vec::new())
        } else if line.starts_with("GET") && path.ends_with(&object_suffix) {
            (200, b"BBBB".to_vec())
        } else if line.starts_with("GET") && line.contains("list-type=2") {
            (200, empty_listing())
        } else {
            (404, Vec::new())
        }
    });
    let cfg = sync_cfg(&endpoint);
    assert!(
        !restore_state_at(&Roots::one(&root), &cfg, || false),
        "a hash mismatch must fail the pull"
    );
    let repair = read_repair(&root);
    assert!(
        repair.contains("attachments/u"),
        "the path must be queued for repair: {repair:?}"
    );
    assert!(!root.join("attachments/u").exists());
    let _ = std::fs::remove_dir_all(&root);
}

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
        if line.starts_with("GET") && (path.ends_with("/manifest") || path.ends_with("/tombstones"))
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
    std::fs::create_dir_all(root.join("attachments")).unwrap();
    std::fs::write(root.join("attachments/u"), b"key").unwrap();
    let (endpoint, reqs) = fake_bucket_capturing(move |line| {
        let path = req_path(line);
        if line.starts_with("GET") && path.ends_with("/manifest") {
            (200, b"v1\n".to_vec())
        } else if line.starts_with("GET") && path.ends_with("/tombstones") {
            (200, b"v1\n0 attachments/u\n".to_vec())
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
        !String::from_utf8_lossy(&tombstone.1).contains("attachments/u"),
        "the restored path leaves the tombstone list"
    );
    assert!(
        reqs.iter().any(|(line, _)| line.starts_with("PUT")
            && req_path(line).contains("/objects/attachments/u/")),
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
