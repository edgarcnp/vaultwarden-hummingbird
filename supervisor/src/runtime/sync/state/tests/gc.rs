//! GC regressions: superseded objects, fallback copies, and repair.

use super::super::{read_repair, restore_state_at};
use crate::runtime::sync::push::sync_state_at;
use crate::runtime::sync::synced::Roots;
use crate::runtime::sync::test_support::{empty_listing, fake_bucket, req_path, sync_cfg};
use crate::util::hash::sha256_file;

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
