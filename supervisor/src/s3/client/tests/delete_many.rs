//! Batch DeleteObjects: request shape, MD5 header, and per-key errors.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};

use super::local_client;

/// A one-endpoint HTTP stub capturing the request head and body.
fn serve(status: &'static str, response: &'static str) -> (SocketAddr, Arc<Mutex<String>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    let captured = Arc::new(Mutex::new(String::new()));
    let sink = Arc::clone(&captured);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut sock) = stream else { continue };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            let head_end = loop {
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
                let n = sock.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break 0;
                }
                buf.extend_from_slice(&chunk[..n]);
            };
            if head_end == 0 {
                continue;
            }
            let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
            let content_length = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            let mut body = buf[head_end..].to_vec();
            while body.len() < content_length {
                let n = sock.read(&mut chunk).unwrap_or(0);
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..n]);
            }
            body.truncate(content_length);
            *sink.lock().unwrap() = format!("{head}\n--body--\n{}", String::from_utf8_lossy(&body));
            let reply = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                response.len()
            );
            let _ = sock.write_all(reply.as_bytes());
        }
    });
    (addr, captured)
}

const OK: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<Deleted><Key>a</Key></Deleted><Deleted><Key>b</Key></Deleted></DeleteResult>"#;

#[test]
fn delete_many_sends_one_signed_post_with_md5_and_all_keys() {
    let (addr, captured) = serve("200 OK", OK);
    let client = local_client(addr);
    client
        .delete_many(&["a".to_string(), "b".to_string()], || false)
        .expect("batch delete");
    let request = captured.lock().unwrap().clone();
    assert!(request.starts_with("POST "), "{request}");
    assert!(request.contains("delete="), "{request}");
    assert!(
        request.to_ascii_lowercase().contains("content-md5:"),
        "{request}"
    );
    assert!(request.contains("<Key>a</Key>"), "{request}");
    assert!(request.contains("<Key>b</Key>"), "{request}");
}

#[test]
fn delete_many_reports_per_key_errors() {
    let error = r#"<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<Error><Key>b</Key><Code>AccessDenied</Code><Message>no</Message></Error></DeleteResult>"#;
    let (addr, _) = serve("200 OK", error);
    let err = local_client(addr)
        .delete_many(&["a".to_string(), "b".to_string()], || false)
        .expect_err("a per-key error is a failure");
    assert!(err.to_string().contains("AccessDenied"), "{err}");
    assert!(err.to_string().contains('b'), "{err}");
}

#[test]
fn delete_many_fails_on_an_http_error() {
    let (addr, _) = serve("500 Internal Server Error", "");
    assert!(
        local_client(addr)
            .delete_many(&["a".to_string()], || false)
            .is_err()
    );
}
