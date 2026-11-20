//! S3 client and transport tests (split from `client.rs` to keep
//! every source file under the 1,000-line limit).

use super::super::transport::*;
mod delete_many;
mod fifo;
mod head;

use super::*;
use std::time::Duration;

/// The signing region comes from the endpoint: AWS's regional,
/// dualstack, and FIPS spellings embed it; every other S3-compatible
/// provider gets `auto`.
#[test]
fn region_follows_the_endpoint() {
    let region = |url: &str| region_for(&url.parse().expect("test url"));
    assert_eq!(
        region("https://s3.eu-central-1.amazonaws.com"),
        "eu-central-1"
    );
    assert_eq!(region("https://s3.amazonaws.com"), "us-east-1");
    assert_eq!(region("https://s3.us-east-1.amazonaws.com"), "us-east-1");
    assert_eq!(region("https://s3-us-west-2.amazonaws.com"), "us-west-2");
    assert_eq!(
        region("https://s3.dualstack.us-west-2.amazonaws.com"),
        "us-west-2"
    );
    assert_eq!(
        region("https://s3-fips.us-east-1.amazonaws.com"),
        "us-east-1"
    );
    assert_eq!(
        region("https://s3-fips.dualstack.us-east-1.amazonaws.com"),
        "us-east-1"
    );
    assert_eq!(region("https://s3-accelerate.amazonaws.com"), "us-east-1");
    assert_eq!(
        region("https://s3-accelerate.dualstack.amazonaws.com"),
        "us-east-1"
    );
    assert_eq!(
        region("https://s3.cn-north-1.amazonaws.com.cn"),
        "cn-north-1"
    );
    assert_eq!(
        region("https://s3.dualstack.cn-north-1.amazonaws.com.cn"),
        "cn-north-1"
    );
    assert_eq!(
        region("https://s3.eu-central-1.amazonaws.com"),
        region("https://s3.dualstack.eu-central-1.amazonaws.com"),
        "spellings must agree"
    );
    assert_eq!(region("https://acct.r2.cloudflarestorage.com"), AUTO_REGION);
    assert_eq!(region("http://127.0.0.1:9000"), AUTO_REGION);
    assert_eq!(region("https://notaws.example.com"), AUTO_REGION);
}

/// A path-prefixed endpoint keeps its prefix: rusty-s3 joins the
/// bucket onto the normalized URL, so an unnormalized `…/s3` would
/// silently become `…/<bucket>`.
#[test]
fn path_prefixes_survive_the_bucket_join() {
    let joined = |url: &str| {
        normalize_endpoint(url.parse().expect("test url"))
            .join("vw-state")
            .expect("bucket join")
            .to_string()
    };
    assert_eq!(joined("https://host/s3"), "https://host/s3/vw-state");
    assert_eq!(joined("https://host/s3/"), "https://host/s3/vw-state");
    assert_eq!(joined("https://host/"), "https://host/vw-state");
    assert_eq!(joined("https://host"), "https://host/vw-state");
}

fn spec(endpoint: &str) -> RemoteSpec {
    RemoteSpec {
        bucket: "vw-state".into(),
        prefix: String::new(),
        key_id: "id".into(),
        key_secret: "secret".into(),
        endpoint: endpoint.parse().expect("test endpoint"),
        allow_http: true,
        ca_file: None,
        region: None,
        style: BucketStyle::Path,
    }
}

/// Every spelled-out http(s) endpoint — AWS or S3-compatible — builds;
/// another scheme is a construction error, never a panic. Missing and
/// unparseable endpoints are refused earlier, at config resolution.
#[test]
fn client_builds_only_with_an_http_endpoint() {
    assert!(
        Client::connect(
            &spec("https://s3.eu-central-1.amazonaws.com"),
            Duration::from_secs(60)
        )
        .is_ok()
    );
    assert!(
        Client::connect(
            &spec("https://acct.r2.cloudflarestorage.com"),
            Duration::from_secs(60)
        )
        .is_ok()
    );
    assert!(Client::connect(&spec("ftp://example.invalid"), Duration::from_secs(60)).is_err());
}

/// Operations against a non-listening endpoint fail closed, bounded,
/// and without a valid credential in the message (no URL, no
/// signature).
#[test]
fn operations_fail_closed_on_unreachable_endpoint() {
    // Port 1 on localhost: connection refused immediately.
    let client = Client::connect(&spec("http://127.0.0.1:1"), Duration::from_secs(5))
        .expect("local endpoint parses");
    let abort = || false;
    // an existing local file, so the failure is the HTTP layer's
    let dir = std::env::temp_dir().join(format!("vw-s3-up-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("payload");
    std::fs::write(&file, b"payload").unwrap();
    let path = file.to_str().unwrap();
    let err = client.put("k", path, abort).expect_err("put fails");
    assert!(
        !err.to_string().contains("http://127.0.0.1:1"),
        "no endpoint in errors"
    );
    assert!(
        client
            .get(
                "k",
                "/tmp/vw-s3-should-not-exist",
                expect(None, 1024),
                abort
            )
            .is_err()
    );
    assert!(client.list("prefix/", abort).is_err());
    assert!(client.delete("k", abort).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The abort flag wins before any request is attempted.
#[test]
fn abort_beats_the_request() {
    let client = Client::connect(
        &spec("https://acct.r2.cloudflarestorage.com"),
        Duration::from_secs(5),
    )
    .expect("client");
    assert_eq!(
        client
            .put("k", "/tmp/unused", || true)
            .unwrap_err()
            .to_string(),
        "aborted"
    );
    assert_eq!(
        client.list("p/", || true).err().map(|e| e.to_string()),
        Some("aborted".to_string())
    );
    assert_eq!(
        client.delete("k", || true).unwrap_err().to_string(),
        "aborted"
    );
}

/// A canned HTTP endpoint serving every connection until the test
/// process exits: reads the request head (plus a declared body, so a
/// PUT can finish), then answers with the given status, extra headers,
/// and body. The presigned query string is ignored, as it would be by
/// any real endpoint.
fn fake_server(
    status: &'static str,
    extra_headers: &'static str,
    body: &'static [u8],
) -> std::net::SocketAddr {
    use std::io::{Read, Write};

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                continue;
            };
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                match stream.read(&mut byte) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => head.push(byte[0]),
                }
            }
            let text = String::from_utf8_lossy(&head).to_lowercase();
            if let Some(len) = text
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
            {
                let mut rest = vec![0u8; len];
                let _ = stream.read_exact(&mut rest);
            }
            let response = format!(
                "HTTP/1.1 {status}\r\n{extra_headers}Content-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(body);
        }
    });
    addr
}

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("vw-s3-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn local_client(addr: std::net::SocketAddr) -> Client {
    Client::connect(&spec(&format!("http://{addr}")), Duration::from_secs(5))
        .expect("local endpoint")
}

/// A download expectation with no hash (the listing/legacy case).
fn expect(size: Option<u64>, max: u64) -> Expect<'static> {
    Expect {
        size,
        sha256: None,
        max_bytes: max,
        mode: 0o600,
    }
}

/// A 404 is a structured "missing" (the restore path may try the next
/// older candidate), unlike a transport failure.
#[test]
fn get_reports_a_missing_object() {
    let client = local_client(fake_server("404 Not Found", "", b""));
    let dir = scratch("get-missing");
    let target = dir.join("db.sqlite3");
    let err = client
        .get(
            "db/sqlite-1.sqlite3",
            target.to_str().unwrap(),
            expect(Some(1), 1024),
            || false,
        )
        .unwrap_err();
    assert_eq!(err, GetError::Missing);
    assert!(!target.exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Vault data must be group read/write so the vault's separate uid can
/// use it; identity material stays owner-only.
#[test]
fn get_publishes_the_requested_mode() {
    let client = local_client(fake_server("200 OK", "", b"hello"));
    let dir = scratch("get-mode");
    let target = dir.join("attachment");
    client
        .get(
            "state/attachments/a",
            target.to_str().unwrap(),
            Expect {
                size: Some(5),
                sha256: None,
                max_bytes: 1024,
                mode: 0o660,
            },
            || false,
        )
        .expect("download publishes");
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o660);
    assert!(!dir.join("attachment.vw-part").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A `.vw-part` symlink is not followed: the download fails locally
/// instead of writing through the link.
#[test]
fn get_refuses_a_symlinked_part_file() {
    let client = local_client(fake_server("200 OK", "", b"hello"));
    let dir = scratch("get-part-link");
    let victim = dir.join("victim");
    std::fs::write(&victim, b"keep").unwrap();
    std::os::unix::fs::symlink(&victim, dir.join("target.vw-part")).unwrap();
    let err = client
        .get(
            "state/target",
            dir.join("target").to_str().unwrap(),
            expect(Some(5), 1024),
            || false,
        )
        .unwrap_err();
    assert!(matches!(err, GetError::Local(_)), "{err}");
    assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A complete download lands atomically with owner-only permissions
/// and leaves no temp file behind.
#[test]
fn get_publishes_complete_downloads_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let client = local_client(fake_server("200 OK", "", b"hello"));
    let dir = scratch("get-ok");
    let target = dir.join("rsa_key.pem");
    client
        .get(
            "state/rsa_key.pem",
            target.to_str().unwrap(),
            expect(Some(5), 1024),
            || false,
        )
        .expect("complete body publishes");
    assert_eq!(std::fs::read(&target).unwrap(), b"hello");
    let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "pulled secrets must be owner-only");
    assert!(
        !dir.join("rsa_key.pem.vw-part").exists(),
        "temp file must not linger"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A body shorter than the listing promised fails and leaves any
/// existing file untouched: a truncated pull can never become the
/// volume's authoritative copy (the F1 data-loss path).
#[test]
fn get_refuses_a_truncated_body_without_touching_the_target() {
    let client = local_client(fake_server("200 OK", "", b"hell"));
    let dir = scratch("get-short");
    let target = dir.join("rsa_key.pem");
    std::fs::write(&target, b"old").unwrap();
    let err = client
        .get(
            "state/rsa_key.pem",
            target.to_str().unwrap(),
            expect(Some(5), 1024),
            || false,
        )
        .unwrap_err();
    assert!(err.to_string().contains("expected 5"), "{err}");
    assert_eq!(std::fs::read(&target).unwrap(), b"old", "target untouched");
    assert!(!dir.join("rsa_key.pem.vw-part").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A listing carries each object's key, size, and timestamp: a
/// LastModified the provider omitted stays empty (the reconciliation
/// then refuses to order that version), and an object with no size is
/// refused rather than given an invented one — a pull could not check
/// it against the manifest.
#[test]
fn list_reads_sizes_and_refuses_a_sizeless_object() {
    const COMPLETE: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>vw-state</Name>
  <Prefix>db/</Prefix>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>db/sqlite-1.sqlite3</Key>
    <LastModified>2026-01-01T00:00:00.000Z</LastModified>
    <ETag>"etag"</ETag>
    <Size>11</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
  <Contents>
    <Key>db/sqlite-2.sqlite3</Key>
    <ETag>"etag"</ETag>
    <Size>0</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
</ListBucketResult>"#;
    let client = local_client(fake_server("200 OK", "", COMPLETE));
    let listed = client.list("db/", || false).expect("listing parses");
    let seen: Vec<(&str, u64, &str)> = listed
        .iter()
        .map(|l| (l.key.as_str(), l.size, l.last_modified.as_str()))
        .collect();
    assert_eq!(
        seen,
        vec![
            ("db/sqlite-1.sqlite3", 11, "2026-01-01T00:00:00.000Z"),
            ("db/sqlite-2.sqlite3", 0, ""),
        ]
    );

    const SIZELESS: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>vw-state</Name>
  <Prefix>db/</Prefix>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>db/sqlite-1.sqlite3</Key>
    <LastModified>2026-01-01T00:00:00.000Z</LastModified>
    <ETag>"etag"</ETag>
  </Contents>
</ListBucketResult>"#;
    let client = local_client(fake_server("200 OK", "", SIZELESS));
    let err = client
        .list("db/", || false)
        .err()
        .expect("a sizeless listing is refused")
        .to_string();
    assert!(err.contains("has no size"), "{err}");
}

/// An object over the size cap is refused before it can fill the data
/// volume, even when no listing size is available.
#[test]
fn get_refuses_an_object_over_the_cap() {
    let client = local_client(fake_server("200 OK", "", b"hello"));
    let dir = scratch("get-cap");
    let target = dir.join("db.sqlite3");
    let err = client
        .get(
            "db/dump.sqlite3",
            target.to_str().unwrap(),
            expect(None, 4),
            || false,
        )
        .unwrap_err();
    assert!(err.to_string().contains("cap"), "{err}");
    assert!(!target.exists(), "nothing published");
    assert!(!dir.join("db.sqlite3.vw-part").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A redirect is never a success: with re-signing disabled a 3xx means
/// the request did not reach the object, so uploads must fail loudly
/// instead of silently no-oping and downloads must not publish the
/// redirect body.
#[test]
fn redirects_are_rejected_not_treated_as_success() {
    let client = local_client(fake_server(
        "302 Found",
        "Location: http://elsewhere.invalid/\r\n",
        b"<html>",
    ));
    let dir = scratch("get-redirect");
    let target = dir.join("rsa_key.pem");
    let err = client
        .get(
            "state/rsa_key.pem",
            target.to_str().unwrap(),
            expect(None, 1024),
            || false,
        )
        .unwrap_err();
    assert!(err.to_string().contains("HTTP 302"), "{err}");
    assert!(!target.exists(), "the redirect body must not be published");

    let file = dir.join("payload");
    std::fs::write(&file, b"x").unwrap();
    let err = client
        .put("state/rsa_key.pem", file.to_str().unwrap(), || false)
        .unwrap_err();
    assert!(err.to_string().contains("HTTP 302"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A manifest hash mismatch fails the download and leaves the target
/// untouched: equal-size corruption cannot be published (F13).
#[test]
fn get_verifies_the_manifest_hash() {
    // sha256("hello")
    const HELLO: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    // Correct hash: published.
    let client = local_client(fake_server("200 OK", "", b"hello"));
    let dir = scratch("get-hash-ok");
    let target = dir.join("rsa_key.pem");
    client
        .get(
            "state/rsa_key.pem",
            target.to_str().unwrap(),
            Expect {
                size: Some(5),
                sha256: Some(HELLO),
                max_bytes: 1024,
                mode: 0o600,
            },
            || false,
        )
        .expect("matching hash publishes");
    assert_eq!(std::fs::read(&target).unwrap(), b"hello");
    let _ = std::fs::remove_dir_all(&dir);

    // Wrong hash: refused, target untouched, temp removed.
    let client = local_client(fake_server("200 OK", "", b"hello"));
    let dir = scratch("get-hash-bad");
    let target = dir.join("rsa_key.pem");
    std::fs::write(&target, b"old").unwrap();
    let err = client
        .get(
            "state/rsa_key.pem",
            target.to_str().unwrap(),
            Expect {
                size: Some(5),
                sha256: Some(&"0".repeat(64)),
                max_bytes: 1024,
                mode: 0o600,
            },
            || false,
        )
        .unwrap_err();
    assert!(err.to_string().contains("sha256 mismatch"), "{err}");
    assert_eq!(std::fs::read(&target).unwrap(), b"old", "target untouched");
    assert!(!dir.join("rsa_key.pem.vw-part").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A canned endpoint for the multipart flow: create -> UploadId, part
/// PUTs -> ETags, complete -> 200, abort -> 204. Records the part
/// numbers it saw and the aborts; `fail_part` makes that part fail so
/// the abort path can be exercised.
fn fake_multipart_server(
    parts_seen: std::sync::Arc<std::sync::Mutex<Vec<u16>>>,
    aborts_seen: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    fail_part: Option<u16>,
    complete_error: bool,
) -> std::net::SocketAddr {
    use std::io::{Read, Write};

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                continue;
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                match stream.read(&mut byte) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => head.push(byte[0]),
                }
            }
            let text = String::from_utf8_lossy(&head).to_string();
            let line = text.lines().next().unwrap_or_default().to_string();
            if let Some(len) = text
                .to_lowercase()
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
            {
                let mut rest = vec![0u8; len];
                let _ = stream.read_exact(&mut rest);
            }
            let (status, extra, body) = if line.contains("uploads") {
                (
                        "200 OK",
                        String::new(),
                        "<InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><UploadId>test-upload</UploadId></InitiateMultipartUploadResult>".to_string(),
                    )
            } else if line.starts_with("PUT") && line.contains("partNumber=") {
                let part = line
                    .split("partNumber=")
                    .nth(1)
                    .and_then(|rest| rest.split('&').next())
                    .and_then(|n| n.parse::<u16>().ok())
                    .unwrap_or(0);
                if Some(part) == fail_part {
                    ("500 Internal Server Error", String::new(), String::new())
                } else {
                    parts_seen.lock().unwrap().push(part);
                    (
                        "200 OK",
                        format!("ETag: \"etag-{part}\"\r\n"),
                        String::new(),
                    )
                }
            } else if line.starts_with("DELETE") {
                aborts_seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                ("204 No Content", String::new(), String::new())
            } else if line.starts_with("POST") && line.contains("uploadId=") {
                if complete_error {
                    (
                        "200 OK",
                        String::new(),
                        "<Error><Code>InternalError</Code></Error>".to_string(),
                    )
                } else {
                    (
                            "200 OK",
                            String::new(),
                            "<CompleteMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></CompleteMultipartUploadResult>".to_string(),
                        )
                }
            } else {
                ("400 Bad Request", String::new(), String::new())
            };
            let response = format!(
                "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(body.as_bytes());
        }
    });
    addr
}

/// Large files go multipart: parts are uploaded individually and the
/// upload is completed. A small part size keeps the test fast while
/// exercising the exact flow production uses.
#[test]
fn multipart_upload_sends_parts_and_completes() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    let parts = Arc::new(Mutex::new(Vec::new()));
    let aborts = Arc::new(AtomicUsize::new(0));
    let client = local_client(fake_multipart_server(
        Arc::clone(&parts),
        Arc::clone(&aborts),
        None,
        false,
    ));
    let dir = scratch("multipart");
    let file = dir.join("big.bin");
    std::fs::write(&file, vec![7u8; 20]).unwrap();
    let mut file = std::fs::File::open(&file).unwrap();
    client
        .put_multipart("state/big.bin", &mut file, 20, 8, || false)
        .expect("multipart upload completes");
    assert_eq!(*parts.lock().unwrap(), vec![1, 2, 3], "20 bytes at 8/part");
    assert_eq!(aborts.load(Ordering::SeqCst), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A failed part aborts the upload — no orphaned parts linger — and the
/// part number is named in the error.
#[test]
fn multipart_upload_aborts_on_a_failed_part() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    let parts = Arc::new(Mutex::new(Vec::new()));
    let aborts = Arc::new(AtomicUsize::new(0));
    let client = local_client(fake_multipart_server(
        Arc::clone(&parts),
        Arc::clone(&aborts),
        Some(2),
        false,
    ));
    let dir = scratch("multipart-fail");
    let file = dir.join("big.bin");
    std::fs::write(&file, vec![7u8; 20]).unwrap();
    let mut file = std::fs::File::open(&file).unwrap();
    let err = client
        .put_multipart("state/big.bin", &mut file, 20, 8, || false)
        .unwrap_err();
    assert!(err.to_string().contains("HTTP 500"), "{err}");
    assert_eq!(*parts.lock().unwrap(), vec![1], "part 2 failed");
    assert_eq!(aborts.load(Ordering::SeqCst), 1, "the upload was aborted");
    let _ = std::fs::remove_dir_all(&dir);
}

/// S3 can answer CompleteMultipartUpload with HTTP 200 and an <Error>
/// body; that must abort, not count as success.
#[test]
fn multipart_upload_aborts_on_a_200_error_body() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    let parts = Arc::new(Mutex::new(Vec::new()));
    let aborts = Arc::new(AtomicUsize::new(0));
    let client = local_client(fake_multipart_server(
        Arc::clone(&parts),
        Arc::clone(&aborts),
        None,
        true,
    ));
    let dir = scratch("multipart-200-error");
    let file = dir.join("big.bin");
    std::fs::write(&file, vec![7u8; 20]).unwrap();
    let mut file = std::fs::File::open(&file).unwrap();
    let err = client
        .put_multipart("state/big.bin", &mut file, 20, 8, || false)
        .unwrap_err();
    assert!(err.to_string().contains("error body"), "{err}");
    assert_eq!(aborts.load(Ordering::SeqCst), 1, "the upload was aborted");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A body over the caller's cap is an error, not a silently truncated
/// string (the old `.take` would return a prefix).
#[test]
fn get_optional_text_refuses_an_oversized_body() {
    const BIG: [u8; 2048] = [b'x'; 2048];
    let client = local_client(fake_server("200 OK", "", &BIG));
    let err = client
        .get_optional_text("state/text", 1024, || false)
        .expect_err("a 2 KiB body over a 1 KiB cap must fail");
    assert!(err.to_string().contains("limit"), "{err}");
}

/// Delete is idempotent: a 404 means the object is already gone.
#[test]
fn delete_treats_a_missing_object_as_success() {
    let client = local_client(fake_server("404 Not Found", "", b""));
    client
        .delete("state/gone", || false)
        .expect("a missing object is success");
}

/// Plaintext HTTP is refused for a remote endpoint unless explicitly
/// allowed; loopback endpoints (local MinIO) stay usable.
#[test]
fn connect_refuses_remote_plaintext_http() {
    let mut remote = spec("http://example.invalid");
    assert!(
        Client::connect(&remote, Duration::from_secs(5)).is_ok(),
        "the permissive test fixture is allowed"
    );
    remote.allow_http = false;
    let err = Client::connect(&remote, Duration::from_secs(5))
        .err()
        .expect("remote plaintext HTTP must be refused");
    assert!(err.to_string().contains("plaintext HTTP"), "{err}");

    let local = spec("http://127.0.0.1:1");
    let mut local = local;
    local.allow_http = false;
    assert!(
        Client::connect(&local, Duration::from_secs(5)).is_ok(),
        "loopback HTTP is allowed for local MinIO"
    );
}

#[test]
fn ca_file_must_live_under_state() {
    let err = validate_ca_file("/tmp/not-a-ca.pem").expect_err("outside /state is refused");
    assert!(err.to_string().contains("must live under"), "{err}");
}

/// The upload body reader aborts before the next chunk when the stop
/// flag is set.
#[test]
fn abort_reader_stops_before_a_chunk() {
    use std::io::Read;

    let mut reader = AbortReader {
        inner: &b"payload"[..],
        abort: &|| true,
    };
    let mut buf = [0u8; 4];
    let err = reader.read(&mut buf).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::Interrupted);
}

#[test]
fn retry_classification_is_transient_only() {
    let status = |code| ureq::Error::StatusCode(code);
    for code in [408, 429, 500, 502, 503, 504] {
        assert!(retryable(&status(code)), "HTTP {code} is transient");
    }
    for code in [400, 401, 403, 404, 409, 501, 505] {
        assert!(!retryable(&status(code)), "HTTP {code} is definitive");
    }
    let io = |kind| ureq::Error::Io(std::io::Error::new(kind, "test"));
    for kind in [
        std::io::ErrorKind::ConnectionRefused,
        std::io::ErrorKind::ConnectionReset,
        std::io::ErrorKind::TimedOut,
        std::io::ErrorKind::UnexpectedEof,
    ] {
        assert!(retryable(&io(kind)), "{kind:?} is transient");
    }
    for kind in [
        std::io::ErrorKind::InvalidData,
        std::io::ErrorKind::PermissionDenied,
        std::io::ErrorKind::NotFound,
    ] {
        assert!(!retryable(&io(kind)), "{kind:?} is definitive");
    }
    assert!(!retryable(&ureq::Error::HostNotFound));
}

/// A fake endpoint that serves a body short on the first (non-range)
/// request, simulating a connection that died mid-transfer. With
/// `serve_ranges`, a `Range: bytes=N-` retry gets 206 and the
/// remainder; without it, every request gets the same short body (the
/// endpoint ignores ranges). Records the Range headers it saw.
fn fake_resume_server(
    body: &'static [u8],
    first_bytes: usize,
    serve_ranges: bool,
    ranges_seen: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
) -> std::net::SocketAddr {
    use std::io::{Read, Write};

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut first = true;
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else {
                continue;
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                match stream.read(&mut byte) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => head.push(byte[0]),
                }
            }
            let text = String::from_utf8_lossy(&head).to_string();
            let range = text
                .lines()
                .find(|line| line.to_lowercase().starts_with("range:"))
                .and_then(|line| line.split(':').nth(1))
                .map(|value| value.trim().to_string());
            if let Some(range) = &range {
                ranges_seen.lock().unwrap().push(range.clone());
            }
            let start = range
                .as_deref()
                .and_then(|r| r.strip_prefix("bytes="))
                .and_then(|r| r.strip_suffix('-'))
                .and_then(|n| n.parse::<usize>().ok())
                .unwrap_or(0);
            let (status, declared, payload): (&str, usize, &[u8]) = if serve_ranges && start > 0 {
                ("206 Partial Content", body.len() - start, &body[start..])
            } else {
                let short = first_bytes.min(body.len());
                first = false;
                ("200 OK", body.len(), &body[..short])
            };
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {declared}\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(payload);
            let _ = first;
        }
    });
    addr
}

/// A body that dies mid-transfer resumes from the partial file with a
/// Range request instead of restarting: progress survives within the
/// attempt budget.
#[test]
fn get_resumes_an_interrupted_download() {
    use std::sync::{Arc, Mutex};

    let body = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let ranges = Arc::new(Mutex::new(Vec::new()));
    let client = local_client(fake_resume_server(body, 10, true, Arc::clone(&ranges)));
    let dir = scratch("get-resume");
    let target = dir.join("rsa_key.pem");
    client
        .get(
            "state/rsa_key.pem",
            target.to_str().unwrap(),
            expect(Some(36), 1024),
            || false,
        )
        .expect("resumed download completes");
    assert_eq!(std::fs::read(&target).unwrap(), body);
    assert_eq!(*ranges.lock().unwrap(), vec!["bytes=10-".to_string()]);
    assert!(!dir.join("rsa_key.pem.vw-part").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Retries are bounded: when every attempt dies early the download
/// fails and the partial is removed.
#[test]
fn get_gives_up_after_the_attempt_budget() {
    use std::sync::{Arc, Mutex};

    let body = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let ranges = Arc::new(Mutex::new(Vec::new()));
    let client = local_client(fake_resume_server(body, 10, false, Arc::clone(&ranges)));
    let dir = scratch("get-resume-fail");
    let target = dir.join("rsa_key.pem");
    let err = client
        .get(
            "state/rsa_key.pem",
            target.to_str().unwrap(),
            expect(Some(36), 1024),
            || false,
        )
        .unwrap_err();
    assert!(
        err.to_string().contains("download of state/rsa_key.pem"),
        "{err}"
    );
    assert!(!target.exists(), "nothing published");
    assert!(
        !dir.join("rsa_key.pem.vw-part").exists(),
        "partial cleaned up"
    );
    assert_eq!(
        ranges.lock().unwrap().len(),
        MAX_DOWNLOAD_ATTEMPTS as usize - 1,
        "each retry after the first is ranged"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Retryable statuses (429, 5xx) and transport errors get bounded
/// attempts; other statuses are returned immediately.
#[test]
fn retrying_is_bounded_and_status_aware() {
    use std::cell::Cell;

    for code in [429u16, 500, 503] {
        let attempts = Cell::new(0);
        let err = retrying(|| {
            attempts.set(attempts.get() + 1);
            Err::<(), _>(ureq::Error::StatusCode(code))
        })
        .expect_err("still failing");
        assert!(matches!(err, ureq::Error::StatusCode(returned) if returned == code));
        assert_eq!(
            attempts.get(),
            RETRY_ATTEMPTS,
            "status {code} must use every attempt"
        );
    }
    for code in [400u16, 403, 404] {
        let attempts = Cell::new(0);
        let _ = retrying(|| {
            attempts.set(attempts.get() + 1);
            Err::<(), _>(ureq::Error::StatusCode(code))
        });
        assert_eq!(attempts.get(), 1, "status {code} is definitive");
    }
    // success on the second attempt comes back with the value
    let attempts = Cell::new(0);
    let value = retrying(|| {
        let n = attempts.get() + 1;
        attempts.set(n);
        if n < 2 {
            Err(ureq::Error::StatusCode(500))
        } else {
            Ok(7)
        }
    })
    .expect("second attempt succeeds");
    assert_eq!(value, 7);
    assert_eq!(attempts.get(), 2);
}

/// The backoff grows with the attempt and stays within its jitter band.
#[test]
fn backoff_is_bounded_and_grows() {
    for attempt in 1..=3 {
        let delay = backoff(attempt);
        assert!(delay >= RETRY_BASE, "{delay:?}");
        let cap = RETRY_BASE * (1 << (attempt - 1).min(3)) + Duration::from_millis(100);
        assert!(delay <= cap, "{delay:?} exceeds {cap:?}");
    }
    assert!(backoff(2) >= backoff(1));
}
