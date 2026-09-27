//! Minimal S3 client: exactly the four verbs the supervisor needs — put,
//! get, list, delete — against one bucket. rusty-s3 signs (SigV4, presigned
//! URLs); ureq speaks HTTPS (rustls, webpki roots). Secrets ride the signed
//! request only: never argv, never env, never logs.
//!
//! Every request is bounded: control phases by the caller's timeout, and
//! transfer bodies by a larger fixed budget so large objects can sync.
//! `abort` is checked before each request and per download chunk, so a stop
//! request is honored promptly. Errors never carry the presigned URL (its
//! signature is a credential).

use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::time::Duration;

use anyhow::{anyhow, bail};
use rusty_s3::{Bucket, Credentials, S3Action, UrlStyle};
use url::Url;

use super::remote::RemoteSpec;

/// Presigned-URL lifetime; must comfortably exceed the per-request
/// timeout (the request is issued immediately after signing).
const SIGN_EXPIRE: Duration = Duration::from_secs(900);

/// Total body budget for one transfer (upload or download body). A single
/// end-to-end request timeout made large objects unsyncable whenever the
/// bucket was slow; per-phase budgets bound every hang while still giving
/// a body this whole window to make progress.
const BODY_TIMEOUT: Duration = Duration::from_secs(600);

/// Absolute download cap for one synced object. Upstream clients cap
/// Bitwarden attachments at 100 MB by default; 1 GiB leaves generous
/// headroom while a rogue bucket still cannot fill the data volume.
pub const MAX_SYNC_OBJECT_BYTES: u64 = 1024 * 1024 * 1024;

/// Absolute download cap for one DB dump. The import's integrity check
/// still decides validity; this only bounds a rogue endpoint.
pub const MAX_DB_OBJECT_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Listing bound: far beyond any real backup/state prefix, mirroring the
/// old capture cap's intent — a listing this size is treated as failure,
/// not memory pressure.
const MAX_LIST_KEYS: usize = 10_000;

/// Raw listing-body bound (16 MiB): a page of 1000 keys is a few MiB at
/// most; anything larger is hostile or broken, and the read stops before
/// memory grows.
const LIST_BODY_CAP: u64 = 16 * 1024 * 1024;

/// SigV4 signing region: derived from the endpoint for AWS S3 (its
/// signature is region-checked), `auto` for everything else — S3-
/// compatible providers (R2, B2, MinIO, ...) accept or ignore it.
const AUTO_REGION: &str = "auto";

/// The signing region for an endpoint: the region embedded in AWS S3's
/// regional hostnames, `auto` for every other S3-compatible provider.
fn region_for(endpoint: &Url) -> String {
    match endpoint.host_str() {
        Some("s3.amazonaws.com") => "us-east-1".into(),
        Some(host) if host.starts_with("s3.") && host.ends_with(".amazonaws.com") => {
            host["s3.".len()..host.len() - ".amazonaws.com".len()].to_string()
        }
        _ => AUTO_REGION.to_string(),
    }
}

/// One listed object: its full key and size. The size feeds the state
/// sync's unchanged-skip; backup consumers only need the key.
pub struct Listed {
    pub key: String,
    pub size: u64,
}

/// One S3 client over a bucket. Cheap to build per run (an endpoint parse
/// and an agent); every operation takes its own `abort`.
pub struct Client {
    bucket: Bucket,
    credentials: Credentials,
    agent: ureq::Agent,
}

impl Client {
    /// Connect to the remote. `timeout` bounds each control phase (DNS,
    /// connect, request, response headers); transfer bodies get
    /// [`BODY_TIMEOUT`]. `Err` = unusable configuration (missing or bad
    /// endpoint URL) — callers treat it as a failed operation, per each
    /// caller's own failure semantics.
    pub fn connect(spec: &RemoteSpec, timeout: Duration) -> anyhow::Result<Self> {
        if spec.endpoint.is_empty() {
            bail!(
                "SUPERVISOR_S3_ENDPOINT is required; every S3-compatible provider \
                 (AWS included) is configured by its endpoint"
            );
        }
        let endpoint: Url = spec
            .endpoint
            .parse()
            .map_err(|e| anyhow!("invalid S3 endpoint: {e}"))?;
        let bucket = Bucket::new(
            endpoint.clone(),
            UrlStyle::Path,
            spec.bucket.clone(),
            region_for(&endpoint),
        )
        .map_err(|e| anyhow!("invalid S3 bucket configuration: {e}"))?;
        let agent = ureq::Agent::config_builder()
            // Per-phase budgets instead of one end-to-end timeout: control
            // phases stay tight while a transfer body gets BODY_TIMEOUT.
            .timeout_resolve(Some(timeout))
            .timeout_connect(Some(timeout))
            .timeout_send_request(Some(timeout))
            .timeout_send_body(Some(BODY_TIMEOUT))
            .timeout_recv_response(Some(timeout))
            .timeout_recv_body(Some(BODY_TIMEOUT))
            .timeout_global(None)
            // A presigned URL must never be re-signed by a redirect; a 3xx
            // is then not an error, so every call site checks the status.
            .max_redirects(0)
            .build()
            .new_agent();
        Ok(Self {
            bucket,
            credentials: Credentials::new(&spec.key_id, &spec.key_secret),
            agent,
        })
    }

    /// Upload a file as `key`. Content-Length is set explicitly: S3
    /// rejects chunked PUT bodies.
    pub fn put(&self, key: &str, path: &str, abort: impl Fn() -> bool) -> anyhow::Result<()> {
        if abort() {
            bail!("aborted");
        }
        let file =
            std::fs::File::open(path).map_err(|e| anyhow!("cannot open {path} for upload: {e}"))?;
        let size = file
            .metadata()
            .map_err(|e| anyhow!("cannot size {path}: {e}"))?
            .len();
        let url = self
            .bucket
            .put_object(Some(&self.credentials), key)
            .sign(SIGN_EXPIRE);
        let response = self
            .agent
            .put(url.as_str())
            .header("Content-Length", size.to_string())
            .send(file)
            .map_err(|e| anyhow!("upload of {key} failed: {}", http_err(&e)))?;
        checked("upload", key, response)?;
        Ok(())
    }

    /// Upload a small in-memory object (the DB manifest): [`Self::put`]
    /// takes a file, but the manifest is text built in memory.
    pub fn put_bytes(
        &self,
        key: &str,
        bytes: &[u8],
        abort: impl Fn() -> bool,
    ) -> anyhow::Result<()> {
        if abort() {
            bail!("aborted");
        }
        let url = self
            .bucket
            .put_object(Some(&self.credentials), key)
            .sign(SIGN_EXPIRE);
        let response = self
            .agent
            .put(url.as_str())
            .header("Content-Length", bytes.len().to_string())
            .send(bytes)
            .map_err(|e| anyhow!("upload of {key} failed: {}", http_err(&e)))?;
        checked("upload", key, response)?;
        Ok(())
    }

    /// Fetch a small text object; `Ok(None)` when the key does not exist
    /// (404), so "absent" is distinguishable from a failed fetch. The
    /// body is size-capped like every other read.
    pub fn get_optional_text(
        &self,
        key: &str,
        max_bytes: u64,
        abort: impl Fn() -> bool,
    ) -> anyhow::Result<Option<String>> {
        if abort() {
            bail!("aborted");
        }
        let url = self
            .bucket
            .get_object(Some(&self.credentials), key)
            .sign(SIGN_EXPIRE);
        let response = match self.agent.get(url.as_str()).call() {
            Ok(response) => checked("download", key, response)?,
            Err(ureq::Error::StatusCode(404)) => return Ok(None),
            Err(e) => return Err(anyhow!("download of {key} failed: {}", http_err(&e))),
        };
        let mut text = String::new();
        response
            .into_body()
            .into_reader()
            .take(max_bytes + 1)
            .read_to_string(&mut text)
            .map_err(|e| anyhow!("download of {key}: {e}"))?;
        if text.len() as u64 > max_bytes {
            bail!("download of {key}: exceeds the {max_bytes}-byte cap");
        }
        Ok(Some(text))
    }

    /// Download `key` into `path` atomically. Bytes land in a sibling temp
    /// file (same filesystem) bounded by `max_bytes` and, when the listing
    /// provided one, checked against `expected_size`; only a complete
    /// transfer is renamed into place, so a failed or truncated download
    /// leaves `path` untouched and removes the temp. The published file is
    /// 0600: everything here is a secret (identity, keys, attachments).
    pub fn get(
        &self,
        key: &str,
        path: &str,
        expected_size: Option<u64>,
        max_bytes: u64,
        abort: impl Fn() -> bool,
    ) -> anyhow::Result<()> {
        if abort() {
            bail!("aborted");
        }
        let url = self
            .bucket
            .get_object(Some(&self.credentials), key)
            .sign(SIGN_EXPIRE);
        let response = checked(
            "download",
            key,
            self.agent
                .get(url.as_str())
                .call()
                .map_err(|e| anyhow!("download of {key} failed: {}", http_err(&e)))?,
        )?;
        let mut reader = response.into_body().into_reader();
        // The temp lives beside the target so the publish is one atomic
        // same-filesystem rename; a crash leaves the target untouched.
        let tmp = format!("{path}.part");
        let staged = (|| -> anyhow::Result<u64> {
            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| anyhow!("cannot create {tmp}: {e}"))?;
            let mut buf = [0u8; 64 * 1024];
            let mut total: u64 = 0;
            loop {
                if abort() {
                    bail!("aborted");
                }
                let n = reader
                    .read(&mut buf)
                    .map_err(|e| anyhow!("download of {key}: {e}"))?;
                if n == 0 {
                    break;
                }
                total += n as u64;
                if total > max_bytes {
                    bail!("download of {key}: exceeds the {max_bytes}-byte cap");
                }
                if let Some(expected) = expected_size
                    && total > expected
                {
                    bail!("download of {key}: larger than the {expected} bytes listed");
                }
                out.write_all(&buf[..n])
                    .map_err(|e| anyhow!("download of {key}: {e}"))?;
            }
            out.sync_all()
                .map_err(|e| anyhow!("download of {key}: {e}"))?;
            Ok(total)
        })();
        let result = staged.and_then(|total| {
            if let Some(expected) = expected_size
                && total != expected
            {
                bail!("download of {key}: got {total} bytes, expected {expected}");
            }
            std::fs::rename(&tmp, path).map_err(|e| anyhow!("cannot publish {path}: {e}"))
        });
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    /// All objects under `prefix`, sorted by key (name order ==
    /// creation order for timestamped names). Truncated pages are
    /// followed up to [`MAX_LIST_KEYS`]; beyond that the listing fails
    /// rather than growing unbounded.
    pub fn list(&self, prefix: &str, abort: impl Fn() -> bool) -> anyhow::Result<Vec<Listed>> {
        let mut names: Vec<Listed> = Vec::new();
        let mut token: Option<String> = None;
        loop {
            if abort() {
                bail!("aborted");
            }
            let mut action = self.bucket.list_objects_v2(Some(&self.credentials));
            action.with_prefix(prefix);
            action.with_max_keys(1000);
            if let Some(t) = &token {
                action.with_continuation_token(t);
            }
            let url = action.sign(SIGN_EXPIRE);
            // The listing body is capped: an endpoint gone rogue cannot
            // exhaust memory within the request timeout.
            let response = self
                .agent
                .get(url.as_str())
                .call()
                .map_err(|e| anyhow!("listing {prefix:?} failed: {}", http_err(&e)))?;
            let mut reader = checked("listing", &format!("{prefix:?}"), response)?
                .into_body()
                .into_reader()
                .take(LIST_BODY_CAP);
            let mut body = String::new();
            reader
                .read_to_string(&mut body)
                .map_err(|e| anyhow!("listing {prefix:?}: {e}"))?;
            // The XML error type belongs to a transitive crate; the
            // message adds nothing — a listing that does not parse is
            // "unparseable".
            let parsed = rusty_s3::actions::ListObjectsV2::parse_response(&body)
                .map_err(|_| anyhow!("listing {prefix:?}: unparseable response"))?;
            names.extend(parsed.contents.into_iter().map(|c| Listed {
                key: c.key,
                size: c.size,
            }));
            if names.len() > MAX_LIST_KEYS {
                bail!("listing {prefix:?}: exceeded {MAX_LIST_KEYS} keys");
            }
            token = parsed.next_continuation_token;
            if token.is_none() {
                break;
            }
        }
        names.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(names)
    }

    /// Delete one object. A missing object (404) is a failed delete: the
    /// only caller lists first, so an unexpected 404 is a real anomaly.
    pub fn delete(&self, key: &str, abort: impl Fn() -> bool) -> anyhow::Result<()> {
        if abort() {
            bail!("aborted");
        }
        let url = self
            .bucket
            .delete_object(Some(&self.credentials), key)
            .sign(SIGN_EXPIRE);
        let response = self
            .agent
            .delete(url.as_str())
            .call()
            .map_err(|e| anyhow!("delete of {key} failed: {}", http_err(&e)))?;
        checked("delete", key, response)?;
        Ok(())
    }
}

/// Reject a non-2xx response that ureq did not already turn into an error.
/// With redirects disabled a 3xx arrives as a "successful" response;
/// treating it as one would make uploads silent no-ops and downloads
/// foreign bodies.
fn checked(
    action: &str,
    subject: &str,
    response: ureq::http::Response<ureq::Body>,
) -> anyhow::Result<ureq::http::Response<ureq::Body>> {
    let status = response.status();
    if status.is_success() {
        Ok(response)
    } else {
        bail!("{action} of {subject} failed: HTTP {}", status.as_u16())
    }
}

/// Render a ureq error without ever exposing the presigned URL (its
/// signature is a credential).
fn http_err(e: &ureq::Error) -> String {
    match e {
        ureq::Error::StatusCode(code) => format!("HTTP {code}"),
        ureq::Error::Io(io) => format!("I/O error: {io}"),
        _ => "transport error".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// The signing region comes from the endpoint: AWS regional hosts
    /// embed it (the signature is region-checked there), every other
    /// S3-compatible provider gets `auto`.
    #[test]
    fn region_follows_the_endpoint() {
        let region = |url: &str| region_for(&url.parse().expect("test url"));
        assert_eq!(
            region("https://s3.eu-central-1.amazonaws.com"),
            "eu-central-1"
        );
        assert_eq!(region("https://s3.amazonaws.com"), "us-east-1");
        assert_eq!(region("https://s3.us-east-1.amazonaws.com"), "us-east-1");
        assert_eq!(region("https://acct.r2.cloudflarestorage.com"), AUTO_REGION);
        assert_eq!(region("http://127.0.0.1:9000"), AUTO_REGION);
    }

    fn spec(endpoint: &str) -> RemoteSpec {
        RemoteSpec {
            bucket: "vw-state".into(),
            prefix: String::new(),
            key_id: "id".into(),
            key_secret: "secret".into(),
            endpoint: endpoint.into(),
        }
    }

    /// No endpoint is a construction error (no provider is a default);
    /// every spelled-out endpoint — AWS or S3-compatible — builds.
    #[test]
    fn client_builds_only_with_an_endpoint() {
        assert!(Client::connect(&spec(""), Duration::from_secs(60)).is_err());
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
        // An unparseable endpoint is a construction error, never a panic.
        assert!(Client::connect(&spec("not a url"), Duration::from_secs(60)).is_err());
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
                .get("k", "/tmp/vw-s3-should-not-exist", None, 1024, abort)
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
                Some(5),
                1024,
                || false,
            )
            .expect("complete body publishes");
        assert_eq!(std::fs::read(&target).unwrap(), b"hello");
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "pulled secrets must be owner-only");
        assert!(
            !dir.join("rsa_key.pem.part").exists(),
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
                Some(5),
                1024,
                || false,
            )
            .unwrap_err();
        assert!(err.to_string().contains("expected 5"), "{err}");
        assert_eq!(std::fs::read(&target).unwrap(), b"old", "target untouched");
        assert!(!dir.join("rsa_key.pem.part").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An object over the size cap is refused before it can fill the data
    /// volume, even when no listing size is available.
    #[test]
    fn get_refuses_an_object_over_the_cap() {
        let client = local_client(fake_server("200 OK", "", b"hello"));
        let dir = scratch("get-cap");
        let target = dir.join("db.sqlite3");
        let err = client
            .get("db/dump.sqlite3", target.to_str().unwrap(), None, 4, || {
                false
            })
            .unwrap_err();
        assert!(err.to_string().contains("cap"), "{err}");
        assert!(!target.exists(), "nothing published");
        assert!(!dir.join("db.sqlite3.part").exists());
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
                None,
                1024,
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
}
