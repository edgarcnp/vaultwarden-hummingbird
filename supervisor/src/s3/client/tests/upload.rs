//! Multipart upload tests: the part flow, abort on a failed part, and abort
//! on a 200 `<Error>` completion body.

use std::time::Duration;

use super::{local_client, scratch};

/// A canned multipart endpoint (create, part PUTs, complete, abort) that
/// records parts and aborts; `fail_part` fails that part and `complete_error`
/// answers the completion with a 200 `<Error>` body.
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
