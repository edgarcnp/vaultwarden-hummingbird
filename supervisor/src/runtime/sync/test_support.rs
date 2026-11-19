//! Shared fake S3 bucket helpers for the sync tests: a minimal HTTP
//! stand-in that answers the in-crate client's signed requests, records
//! the request lines, and optionally captures request bodies so the
//! manifest and tombstone assertions can inspect what was written.

use std::sync::{Arc, Mutex};

use crate::config::SyncConfig;

/// The request path of a logged request line, query string stripped.
pub(super) fn req_path(line: &str) -> &str {
    line.split_whitespace()
        .nth(1)
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("")
}

/// A minimal S3 stand-in: records every request line and answers from
/// `route`. The client signs requests; the stub ignores signatures.
pub(super) fn fake_bucket(
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
pub(super) type Captured = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// Like [`fake_bucket`], but also records each request body (the
/// tombstone/manifest assertions need to inspect what was written).
pub(super) fn fake_bucket_capturing(
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

pub(super) fn sync_cfg(endpoint: &str) -> SyncConfig {
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

/// An empty ListObjectsV2 page, as a provider would answer it.
pub(super) fn empty_listing() -> Vec<u8> {
    b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
      <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
      <Name>vw</Name><Prefix></Prefix><KeyCount>0</KeyCount>\
      <MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated></ListBucketResult>"
        .to_vec()
}
