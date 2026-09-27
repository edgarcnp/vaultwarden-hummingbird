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
use rusty_s3::actions::CreateMultipartUpload;
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

/// Files at or above this size upload in parts: the body budget is then
/// paid per part, so a large attachment is no longer unsyncable on a slow
/// link.
const MULTIPART_THRESHOLD: u64 = 16 * 1024 * 1024;

/// Part size: comfortably above S3's 5 MiB minimum for non-final parts,
/// and small enough that the in-memory part stays bounded (10k parts
/// ≈ 80 GiB maximum).
const PART_SIZE: u64 = 8 * 1024 * 1024;

/// The part-count ceiling S3 enforces.
const MAX_PARTS: usize = 10_000;

/// Response-body cap for the multipart create handshake.
const MULTIPART_XML_CAP: u64 = 64 * 1024;

/// Bounded download attempts; each gets the full body budget, and a
/// partial transfer resumes with a Range request instead of restarting.
const MAX_DOWNLOAD_ATTEMPTS: u32 = 3;

/// How many bytes of a previous attempt a download may resume from: the
/// `.part` size, unless it already reached the expected size (a stale or
/// foreign leftover must never be appended to).
fn resumed_offset(tmp: &str, expected: Option<u64>) -> u64 {
    let len = std::fs::metadata(tmp).map(|meta| meta.len()).unwrap_or(0);
    if expected.is_some_and(|expected| len >= expected) {
        0
    } else {
        len
    }
}

/// Whether a transport-level failure is worth another bounded attempt
/// (an HTTP status is definitive).
fn retryable(e: &ureq::Error) -> bool {
    !matches!(e, ureq::Error::StatusCode(_))
}

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
/// hostnames, `auto` for every other S3-compatible provider. Handles the
/// regional, dualstack, and FIPS spellings AWS serves:
/// `s3.<region>.amazonaws.com`, `s3-<region>.amazonaws.com`,
/// `s3.dualstack.<region>.amazonaws.com`, `s3-fips.<region>.amazonaws.com`,
/// and `s3-fips.dualstack.<region>.amazonaws.com`.
fn region_for(endpoint: &Url) -> String {
    let Some(host) = endpoint.host_str() else {
        return AUTO_REGION.to_string();
    };
    let Some(rest) = host.strip_suffix(".amazonaws.com") else {
        return AUTO_REGION.to_string();
    };
    if rest == "s3" {
        // The legacy global host (`s3.amazonaws.com`).
        return "us-east-1".to_string();
    }
    // The dot form (`s3.<...>`) or the hyphen form (`s3-<...>`).
    let rest = match rest.strip_prefix("s3.") {
        Some(rest) => rest,
        None => match rest.strip_prefix("s3-") {
            Some(rest) => rest,
            None => return AUTO_REGION.to_string(),
        },
    };
    let mut region = rest;
    loop {
        let stripped = region
            .strip_prefix("dualstack.")
            .or_else(|| region.strip_prefix("fips."))
            .or_else(|| region.strip_prefix("fips-"));
        match stripped {
            Some(next) => region = next,
            None => break,
        }
    }
    match region {
        // The legacy `s3-external-1` alias is us-east-1.
        "" | "external-1" => "us-east-1".to_string(),
        region => region.to_string(),
    }
}

/// A path-prefixed endpoint must keep its prefix when rusty-s3 joins the
/// bucket: `Url::join` replaces the last segment unless the path ends with
/// a separator, which would silently drop `https://host/s3` to
/// `https://host/<bucket>`. Normalize once, at connect.
fn normalize_endpoint(mut endpoint: Url) -> Url {
    if !endpoint.path().ends_with('/') {
        let mut path = endpoint.path().to_string();
        path.push('/');
        endpoint.set_path(&path);
    }
    endpoint
}

/// What a download must turn out to be: the caller's expectations, checked
/// before the temp file is published. Size and checksum together protect
/// against an object that was truncated, corrupted, or substituted.
#[derive(Clone, Copy)]
pub struct Expect<'a> {
    /// The exact size, when the listing or manifest provided one.
    pub size: Option<u64>,
    /// The exact lowercase-hex SHA-256, when the manifest provided one.
    pub sha256: Option<&'a str>,
    /// Absolute cap regardless of the expectations above.
    pub max_bytes: u64,
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
        let endpoint = normalize_endpoint(endpoint);
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
    /// rejects chunked PUT bodies. Files at or above
    /// [`MULTIPART_THRESHOLD`] go through the multipart path, so each part
    /// gets its own body budget.
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
        if size >= MULTIPART_THRESHOLD {
            return self.put_multipart(key, path, size, PART_SIZE, abort);
        }
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

    /// Multipart upload for large files: create, upload parts sequentially
    /// (each part with the full body budget), complete — or abort, so no
    /// half-uploaded object lingers consuming storage. The part size is a
    /// parameter so tests can exercise the flow without moving gigabytes.
    fn put_multipart(
        &self,
        key: &str,
        path: &str,
        size: u64,
        part_size: u64,
        abort: impl Fn() -> bool,
    ) -> anyhow::Result<()> {
        if abort() {
            bail!("aborted");
        }
        let url = self
            .bucket
            .create_multipart_upload(Some(&self.credentials), key)
            .sign(SIGN_EXPIRE);
        let response = self
            .agent
            .post(url.as_str())
            .send_empty()
            .map_err(|e| anyhow!("creating the upload of {key} failed: {}", http_err(&e)))?;
        let response = checked("create upload", key, response)?;
        let mut body = String::new();
        response
            .into_body()
            .into_reader()
            .take(MULTIPART_XML_CAP)
            .read_to_string(&mut body)
            .map_err(|e| anyhow!("creating the upload of {key}: {e}"))?;
        let upload_id = CreateMultipartUpload::parse_response(&body)
            .map_err(|_| anyhow!("creating the upload of {key}: unparseable response"))?
            .upload_id()
            .to_string();
        let etags = match self.put_parts(key, path, size, part_size, &upload_id, &abort) {
            Ok(etags) => etags,
            Err(e) => {
                self.abort_upload(key, &upload_id);
                return Err(e);
            }
        };
        let action = self.bucket.complete_multipart_upload(
            Some(&self.credentials),
            key,
            &upload_id,
            etags.iter().map(String::as_str),
        );
        let url = action.sign(SIGN_EXPIRE);
        let body = action.body();
        let response = self
            .agent
            .post(url.as_str())
            .header("Content-Type", "application/xml")
            .send(body)
            .map_err(|e| anyhow!("completing the upload of {key} failed: {}", http_err(&e)))?;
        if let Err(e) = checked("complete upload", key, response) {
            self.abort_upload(key, &upload_id);
            return Err(e);
        }
        Ok(())
    }

    /// Upload every part in order, collecting the ETags the completion
    /// needs. Parts are read one at a time (bounded memory) and each part
    /// request gets the full body budget.
    fn put_parts(
        &self,
        key: &str,
        path: &str,
        size: u64,
        part_size: u64,
        upload_id: &str,
        abort: &impl Fn() -> bool,
    ) -> anyhow::Result<Vec<String>> {
        let mut file =
            std::fs::File::open(path).map_err(|e| anyhow!("cannot open {path} for upload: {e}"))?;
        let mut etags: Vec<String> = Vec::new();
        let mut offset: u64 = 0;
        while offset < size {
            if abort() {
                bail!("aborted");
            }
            if etags.len() >= MAX_PARTS {
                bail!("upload of {key}: more than {MAX_PARTS} parts needed");
            }
            let part_number = etags.len() as u16 + 1;
            let this = (size - offset).min(part_size);
            let mut chunk = vec![0u8; this as usize];
            file.read_exact(&mut chunk)
                .map_err(|e| anyhow!("reading {path}: {e}"))?;
            let url = self
                .bucket
                .upload_part(Some(&self.credentials), key, part_number, upload_id)
                .sign(SIGN_EXPIRE);
            let response = self
                .agent
                .put(url.as_str())
                .header("Content-Length", chunk.len().to_string())
                .send(&chunk)
                .map_err(|e| {
                    anyhow!(
                        "upload part {part_number} of {key} failed: {}",
                        http_err(&e)
                    )
                })?;
            let response = checked("upload part", key, response)?;
            let etag = response
                .headers()
                .get("etag")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
                .ok_or_else(|| anyhow!("upload part {part_number} of {key}: no ETag returned"))?;
            etags.push(etag);
            offset += this;
        }
        Ok(etags)
    }

    /// Best-effort abort: the caller keeps the original failure, and S3
    /// stops billing for the parts.
    fn abort_upload(&self, key: &str, upload_id: &str) {
        let url = self
            .bucket
            .abort_multipart_upload(Some(&self.credentials), key, upload_id)
            .sign(SIGN_EXPIRE);
        let _ = self.agent.delete(url.as_str()).call();
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
    /// file (same filesystem) bounded by [`Expect`], and only a transfer
    /// that meets every expectation is renamed into place: a failed,
    /// truncated, or mismatched download leaves `path` untouched and
    /// removes the temp. The published file is 0600: everything here is a
    /// secret (identity, keys, attachments).
    pub fn get(
        &self,
        key: &str,
        path: &str,
        expect: Expect<'_>,
        abort: impl Fn() -> bool,
    ) -> anyhow::Result<()> {
        if abort() {
            bail!("aborted");
        }
        let url = self
            .bucket
            .get_object(Some(&self.credentials), key)
            .sign(SIGN_EXPIRE);
        // The temp lives beside the target so the publish is one atomic
        // same-filesystem rename; a crash leaves the target untouched. A
        // partial transfer is kept and resumed with a Range request, so a
        // slow link makes progress across bounded attempts instead of
        // restarting from zero every time.
        let tmp = format!("{path}.part");
        let mut offset = resumed_offset(&tmp, expect.size);
        let mut attempt = 0;
        let staged: anyhow::Result<u64> = loop {
            attempt += 1;
            if abort() {
                break Err(anyhow!("aborted"));
            }
            let mut request = self.agent.get(url.as_str());
            if offset > 0 {
                request = request.header("Range", &format!("bytes={offset}-"));
            }
            let response = match request.call() {
                Ok(response) => match checked("download", key, response) {
                    Ok(response) => response,
                    Err(e) => break Err(e),
                },
                Err(e) => {
                    if retryable(&e) && attempt < MAX_DOWNLOAD_ATTEMPTS {
                        continue;
                    }
                    break Err(anyhow!("download of {key} failed: {}", http_err(&e)));
                }
            };
            // A server that ignored the range (or an object that changed)
            // answers 200: restart rather than append a different body.
            if offset > 0 && response.status().as_u16() != 206 {
                offset = 0;
            }
            let declared = response
                .headers()
                .get("content-length")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok());
            let start = offset;
            let mut reader = response.into_body().into_reader();
            let streamed = (|| -> anyhow::Result<u64> {
                let mut out = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(start == 0)
                    .append(start > 0)
                    .mode(0o600)
                    .open(&tmp)
                    .map_err(|e| anyhow!("cannot create {tmp}: {e}"))?;
                let mut buf = [0u8; 64 * 1024];
                let mut total = start;
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
                    if total > expect.max_bytes {
                        bail!(
                            "download of {key}: exceeds the {}-byte cap",
                            expect.max_bytes
                        );
                    }
                    if let Some(expected) = expect.size
                        && total > expected
                    {
                        bail!("download of {key}: larger than the {expected} bytes listed");
                    }
                    out.write_all(&buf[..n])
                        .map_err(|e| anyhow!("download of {key}: {e}"))?;
                }
                // A connection that closed early is a failed attempt, not
                // a short object: the reader may report EOF either way, so
                // the declared length is checked explicitly.
                if let Some(declared) = declared
                    && total - start != declared
                {
                    bail!(
                        "download of {key}: body ended after {} of {declared} bytes",
                        total - start
                    );
                }
                out.sync_all()
                    .map_err(|e| anyhow!("download of {key}: {e}"))?;
                Ok(total)
            })();
            match streamed {
                Ok(total) => break Ok(total),
                Err(e) => {
                    // Keep the partial for the next attempt; past the
                    // budget (or on abort) the failure is final and the
                    // cleanup below removes it.
                    let done = std::fs::metadata(&tmp).map(|meta| meta.len()).unwrap_or(0);
                    if attempt < MAX_DOWNLOAD_ATTEMPTS
                        && !abort()
                        && done < expect.size.unwrap_or(u64::MAX)
                    {
                        offset = done;
                        continue;
                    }
                    break Err(e);
                }
            }
        };
        let result = staged.and_then(|total| {
            if let Some(expected) = expect.size
                && total != expected
            {
                bail!("download of {key}: got {total} bytes, expected {expected}");
            }
            if let Some(expected) = expect.sha256 {
                let actual = crate::util::hash::sha256_file(&tmp)
                    .map_err(|e| anyhow!("download of {key}: cannot hash the temp file: {e}"))?;
                if actual != expected {
                    bail!("download of {key}: sha256 mismatch (got {actual}, expected {expected})");
                }
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
        }
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
                expect(Some(5), 1024),
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
            .get(
                "db/dump.sqlite3",
                target.to_str().unwrap(),
                expect(None, 4),
                || false,
            )
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
                },
                || false,
            )
            .unwrap_err();
        assert!(err.to_string().contains("sha256 mismatch"), "{err}");
        assert_eq!(std::fs::read(&target).unwrap(), b"old", "target untouched");
        assert!(!dir.join("rsa_key.pem.part").exists());
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
                    (
                        "200 OK",
                        String::new(),
                        "<CompleteMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"></CompleteMultipartUploadResult>".to_string(),
                    )
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
        ));
        let dir = scratch("multipart");
        let file = dir.join("big.bin");
        std::fs::write(&file, vec![7u8; 20]).unwrap();
        client
            .put_multipart("state/big.bin", file.to_str().unwrap(), 20, 8, || false)
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
        ));
        let dir = scratch("multipart-fail");
        let file = dir.join("big.bin");
        std::fs::write(&file, vec![7u8; 20]).unwrap();
        let err = client
            .put_multipart("state/big.bin", file.to_str().unwrap(), 20, 8, || false)
            .unwrap_err();
        assert!(err.to_string().contains("HTTP 500"), "{err}");
        assert_eq!(*parts.lock().unwrap(), vec![1], "part 2 failed");
        assert_eq!(aborts.load(Ordering::SeqCst), 1, "the upload was aborted");
        let _ = std::fs::remove_dir_all(&dir);
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
                let (status, declared, payload): (&str, usize, &[u8]) = if serve_ranges && start > 0
                {
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
        assert!(!dir.join("rsa_key.pem.part").exists());
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
        assert!(!dir.join("rsa_key.pem.part").exists(), "partial cleaned up");
        assert_eq!(
            ranges.lock().unwrap().len(),
            MAX_DOWNLOAD_ATTEMPTS as usize - 1,
            "each retry after the first is ranged"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
