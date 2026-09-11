//! Minimal S3 client: exactly the four verbs the supervisor needs — put,
//! get, list, delete — against one bucket. rusty-s3 signs (SigV4, presigned
//! URLs); ureq speaks HTTPS (rustls, webpki roots). Secrets ride the signed
//! request only: never argv, never env, never logs.
//!
//! Every request is bounded by the caller's timeout; `abort` is checked
//! before each request and between listing pages, so a stop request is
//! honored at object granularity. Errors never carry the presigned URL
//! (its signature is a credential).

use std::io::Read;
use std::time::Duration;

use rusty_s3::{Bucket, Credentials, S3Action, UrlStyle};
use url::Url;

use super::remote::RemoteSpec;

/// Presigned-URL lifetime; must comfortably exceed the per-request
/// timeout (the request is issued immediately after signing).
const SIGN_EXPIRE: Duration = Duration::from_secs(900);

/// Listing bound: far beyond any real backup/state prefix, mirroring the
/// old capture cap's intent — a listing this size is treated as failure,
/// not memory pressure.
const MAX_LIST_KEYS: usize = 10_000;

/// Raw listing-body bound (16 MiB): a page of 1000 keys is a few MiB at
/// most; anything larger is hostile or broken, and the read stops before
/// memory grows.
const LIST_BODY_CAP: u64 = 16 * 1024 * 1024;

/// AWS default when the remote's endpoint is empty (rclone's old default
/// region too).
const AWS_ENDPOINT: &str = "https://s3.us-east-1.amazonaws.com";
const AWS_REGION: &str = "us-east-1";
/// Custom endpoints (R2 et al) accept/ignore the region; "auto" is R2's
/// conventional value.
const CUSTOM_REGION: &str = "auto";

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
    /// Connect to the remote. `Err` = unusable configuration (bad
    /// endpoint URL) — callers treat it as a failed operation, per each
    /// caller's own failure semantics.
    pub fn connect(spec: &RemoteSpec, timeout: Duration) -> Result<Self, String> {
        let endpoint: Url = if spec.endpoint.is_empty() {
            AWS_ENDPOINT
        } else {
            &spec.endpoint
        }
        .parse()
        .map_err(|e| format!("invalid S3 endpoint: {e}"))?;
        let region = if spec.endpoint.is_empty() {
            AWS_REGION
        } else {
            CUSTOM_REGION
        };
        let bucket = Bucket::new(
            endpoint,
            UrlStyle::Path,
            spec.bucket.clone(),
            region.to_string(),
        )
        .map_err(|e| format!("invalid S3 bucket configuration: {e}"))?;
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .max_redirects(0) // a presigned URL must never be re-signed by a redirect
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
    pub fn put(&self, key: &str, path: &str, abort: impl Fn() -> bool) -> Result<(), String> {
        if abort() {
            return Err("aborted".into());
        }
        let file =
            std::fs::File::open(path).map_err(|e| format!("cannot open {path} for upload: {e}"))?;
        let size = file
            .metadata()
            .map_err(|e| format!("cannot size {path}: {e}"))?
            .len();
        let url = self
            .bucket
            .put_object(Some(&self.credentials), key)
            .sign(SIGN_EXPIRE);
        self.agent
            .put(url.as_str())
            .header("Content-Length", size.to_string())
            .send(file)
            .map_err(|e| format!("upload of {key} failed: {}", http_err(&e)))?;
        Ok(())
    }

    /// Download `key` into a local file (created, truncated).
    pub fn get(&self, key: &str, path: &str, abort: impl Fn() -> bool) -> Result<(), String> {
        if abort() {
            return Err("aborted".into());
        }
        let url = self
            .bucket
            .get_object(Some(&self.credentials), key)
            .sign(SIGN_EXPIRE);
        let mut reader = self
            .agent
            .get(url.as_str())
            .call()
            .map_err(|e| format!("download of {key} failed: {}", http_err(&e)))?
            .into_body()
            .into_reader();
        let mut out =
            std::fs::File::create(path).map_err(|e| format!("cannot create {path}: {e}"))?;
        std::io::copy(&mut reader, &mut out).map_err(|e| format!("download of {key}: {e}"))?;
        Ok(())
    }

    /// All objects under `prefix`, sorted by key (name order ==
    /// creation order for timestamped names). Truncated pages are
    /// followed up to [`MAX_LIST_KEYS`]; beyond that the listing fails
    /// rather than growing unbounded.
    pub fn list(&self, prefix: &str, abort: impl Fn() -> bool) -> Result<Vec<Listed>, String> {
        let mut names: Vec<Listed> = Vec::new();
        let mut token: Option<String> = None;
        loop {
            if abort() {
                return Err("aborted".into());
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
            let mut reader = self
                .agent
                .get(url.as_str())
                .call()
                .map_err(|e| format!("listing {prefix:?} failed: {}", http_err(&e)))?
                .into_body()
                .into_reader()
                .take(LIST_BODY_CAP);
            let mut body = String::new();
            reader
                .read_to_string(&mut body)
                .map_err(|e| format!("listing {prefix:?}: {e}"))?;
            // The XML error type belongs to a transitive crate; the
            // message adds nothing — a listing that does not parse is
            // "unparseable".
            let parsed = rusty_s3::actions::ListObjectsV2::parse_response(&body)
                .map_err(|_| format!("listing {prefix:?}: unparseable response"))?;
            names.extend(parsed.contents.into_iter().map(|c| Listed {
                key: c.key,
                size: c.size,
            }));
            if names.len() > MAX_LIST_KEYS {
                return Err(format!("listing {prefix:?}: exceeded {MAX_LIST_KEYS} keys"));
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
    pub fn delete(&self, key: &str, abort: impl Fn() -> bool) -> Result<(), String> {
        if abort() {
            return Err("aborted".into());
        }
        let url = self
            .bucket
            .delete_object(Some(&self.credentials), key)
            .sign(SIGN_EXPIRE);
        self.agent
            .delete(url.as_str())
            .call()
            .map_err(|e| format!("delete of {key} failed: {}", http_err(&e)))?;
        Ok(())
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

    fn spec(endpoint: &str) -> RemoteSpec {
        RemoteSpec {
            bucket: "vw-state".into(),
            prefix: String::new(),
            key_id: "id".into(),
            key_secret: "secret".into(),
            endpoint: endpoint.into(),
        }
    }

    #[test]
    fn client_builds_for_aws_default_and_custom_endpoints() {
        assert!(Client::connect(&spec(""), Duration::from_secs(60)).is_ok());
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
        assert!(!err.contains("http://127.0.0.1:1"), "no endpoint in errors");
        assert!(
            client
                .get("k", "/tmp/vw-s3-should-not-exist", abort)
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
            client.put("k", "/tmp/unused", || true).unwrap_err(),
            "aborted"
        );
        assert_eq!(client.list("p/", || true).err().as_deref(), Some("aborted"));
        assert_eq!(client.delete("k", || true).unwrap_err(), "aborted");
    }
}
