//! Push-path tests that need a fake bucket: a file changed between the
//! hash and the upload must never be committed.

use super::super::synced::Roots;
use super::super::test_support::{empty_listing, fake_bucket, req_path, sync_cfg};
use super::sync_state_at;

/// A file changed while its upload is in flight must not be committed: the
/// object no longer matches the hash the manifest would record.
#[test]
fn a_file_changed_during_upload_is_not_committed() {
    let root = std::env::temp_dir().join(format!("vw-sup-changerace-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("attachments")).unwrap();
    let local = root.join("attachments/u");
    std::fs::write(&local, b"AAAA").unwrap();
    let local_path = local.to_string_lossy().into_owned();
    let (endpoint, seen) = fake_bucket(move |line| {
        let path = req_path(line);
        if line.starts_with("PUT") && path.contains("/objects/attachments/u/") {
            // Same size, different bytes, after the body was read.
            std::fs::write(&local_path, b"BBBB").unwrap();
            (200, Vec::new())
        } else if line.starts_with("GET")
            && (path.ends_with("/manifest") || path.ends_with("/tombstones"))
        {
            (404, Vec::new())
        } else if line.starts_with("GET") && line.contains("list-type=2") {
            (200, empty_listing())
        } else if line.starts_with("PUT") || line.starts_with("DELETE") {
            (200, Vec::new())
        } else {
            (404, Vec::new())
        }
    });
    assert!(
        !sync_state_at(&Roots::one(&root), &sync_cfg(&endpoint), || false),
        "a changed file must fail the push"
    );
    let seen = seen.lock().unwrap().clone();
    assert!(
        !seen
            .iter()
            .any(|l| l.starts_with("PUT") && req_path(l).ends_with("/manifest")),
        "no manifest may name the changed bytes: {seen:?}"
    );
    assert!(
        !seen.iter().any(|l| l.starts_with("DELETE")),
        "a content-addressed key must not be deleted blindly: {seen:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}
