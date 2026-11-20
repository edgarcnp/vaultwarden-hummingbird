//! Shared test fixtures for the backup modules (config builders and
//! unique staging dirs; tests run concurrently on one process).

#![cfg(test)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::config::{DbBackupConfig, SyncConfig};

/// Unique-ish scratch base per test invocation; the sidecars live directly
/// in it and the staging dir below it.
fn next_base() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("vw-sup-stage-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Unique-ish staging dir per test invocation.
pub(super) fn next_staging() -> String {
    next_base().join("staging").to_string_lossy().into_owned()
}

/// A DbBackupConfig with a custom sync config and unique scratch paths.
pub(super) fn cfg_with_sync(sync: SyncConfig) -> DbBackupConfig {
    let base = next_base();
    DbBackupConfig {
        sync,
        db_path: "/nonexistent/db.sqlite3".into(),
        periodic: true,
        interval: Duration::from_secs(43_200),
        keep: 3,
        restore: false,
        staging: base.join("staging").to_string_lossy().into_owned(),
        state_dir: base.to_string_lossy().into_owned(),
    }
}

/// A DbBackupConfig over a nonexistent sqlite source with a unique
/// staging dir.
pub(super) fn cfg() -> DbBackupConfig {
    cfg_with_sync(
        SyncConfig::new(
            "r2:vw".into(),
            "id".into(),
            "secret".into(),
            // dead local port: connect must succeed, no request is valid
            "http://127.0.0.1:1".into(),
            Duration::from_secs(60),
        )
        .expect("valid test remote"),
    )
}

/// A ListObjectsV2 page for the stateful fake, including every stored key.
/// The real listing uses the request prefix; the fake ignores it and the
/// client's dump filter drops non-dump keys.
fn listing_xml(objects: &std::collections::BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let mut out = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Name>vw-state</Name><Prefix></Prefix><KeyCount>{}</KeyCount>\
         <MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>",
        objects.len()
    );
    for (key, value) in objects {
        out.push_str(&format!(
            "<Contents><Key>{key}</Key>\
             <LastModified>2026-01-01T00:00:00.000Z</LastModified>\
             <Size>{}</Size></Contents>",
            value.len()
        ));
    }
    out.push_str("</ListBucketResult>");
    out.into_bytes()
}

/// A minimal stateful S3 stand-in for the backup tick: objects are stored
/// by key, HEAD reports their size, and every request is logged. Enough to
/// exercise dump -> manifest -> prune without a real bucket.
pub(super) struct FakeBucket {
    pub(super) endpoint: String,
    pub(super) requests: Arc<Mutex<Vec<(String, String)>>>,
    pub(super) objects: Arc<Mutex<std::collections::BTreeMap<String, Vec<u8>>>>,
    /// Keys whose HEAD reports 404 while the object remains stored; used
    /// to exercise the external-deletion repair without losing the object
    /// that the following prune batch must delete.
    pub(super) head_missing: Arc<Mutex<std::collections::BTreeSet<String>>>,
}

impl FakeBucket {
    pub(super) fn object(&self, key: &str) -> Option<Vec<u8>> {
        self.objects.lock().unwrap().get(key).cloned()
    }

    pub(super) fn start(bucket: &'static str) -> Self {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let objects = Arc::new(Mutex::new(std::collections::BTreeMap::new()));
        let head_missing = Arc::new(Mutex::new(std::collections::BTreeSet::new()));
        let log = Arc::clone(&requests);
        let store = Arc::clone(&objects);
        let missing = Arc::clone(&head_missing);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                let head_end = loop {
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                    let n = s.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break 0;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                };
                if head_end == 0 {
                    continue;
                }
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let line = head.lines().next().unwrap_or("").to_string();
                let mut parts = line.split_whitespace();
                let method = parts.next().unwrap_or("").to_string();
                let target = parts.next().unwrap_or("");
                let path = target.split('?').next().unwrap_or("");
                let list = target.contains("list-type=2");
                let batch_delete = target.contains("delete=") && method == "POST";
                let bucket_prefix = format!("/{bucket}");
                let key = path
                    .strip_prefix(&bucket_prefix)
                    .unwrap_or(path)
                    .trim_start_matches('/')
                    .to_string();
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
                log.lock().unwrap().push((method.clone(), key.clone()));

                let mut head_length = 0usize;
                let (status, response) = match (method.as_str(), list) {
                    ("PUT", _) => {
                        store.lock().unwrap().insert(key, body);
                        (200, Vec::new())
                    }
                    ("GET", true) => {
                        let objects = store.lock().unwrap();
                        (200, listing_xml(&objects))
                    }
                    ("GET", false) => match store.lock().unwrap().get(&key).cloned() {
                        Some(value) => (200, value),
                        None => (404, Vec::new()),
                    },
                    ("HEAD", _) if missing.lock().unwrap().contains(&key) => (404, Vec::new()),
                    ("HEAD", _) => match store.lock().unwrap().get(&key) {
                        Some(value) => {
                            head_length = value.len();
                            (200, Vec::new())
                        }
                        None => (404, Vec::new()),
                    },
                    ("DELETE", _) => {
                        store.lock().unwrap().remove(&key);
                        (204, Vec::new())
                    }
                    _ if batch_delete => {
                        let mut deleted = String::new();
                        if let Ok(text) = std::str::from_utf8(&body) {
                            for part in text.split("<Key>").skip(1) {
                                let Some(name) = part.split("</Key>").next() else {
                                    continue;
                                };
                                if store.lock().unwrap().remove(name).is_some() {
                                    deleted
                                        .push_str(&format!("<Deleted><Key>{name}</Key></Deleted>"));
                                }
                            }
                        }
                        let result = format!(
                            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                             <DeleteResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                             {deleted}</DeleteResult>"
                        );
                        (200, result.into_bytes())
                    }
                    _ => (405, Vec::new()),
                };
                let reason = match status {
                    200 => "OK",
                    204 => "No Content",
                    404 => "Not Found",
                    405 => "Method Not Allowed",
                    _ => "Status",
                };
                let length = if method == "HEAD" {
                    head_length
                } else {
                    response.len()
                };
                let head = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {length}\r\n\
                     Connection: close\r\n\r\n"
                );
                let _ = s.write_all(head.as_bytes());
                if method != "HEAD" && status != 204 {
                    let _ = s.write_all(&response);
                }
            }
        });
        Self {
            endpoint,
            requests,
            objects,
            head_missing,
        }
    }
}
