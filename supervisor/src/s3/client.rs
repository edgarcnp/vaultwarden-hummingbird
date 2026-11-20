//! Minimal S3 client: exactly the four verbs the supervisor needs — put,
//! get, list, delete — against one bucket. rusty-s3 signs (SigV4, presigned
//! URLs); ureq speaks HTTPS (rustls, webpki roots). Secrets ride the signed
//! request only: never argv, never env, never logs.
//!
//! Every request is bounded: control phases by the caller's timeout, and
//! transfer bodies by a larger fixed budget so large objects can sync.
//! `abort` is checked before each request and per download chunk, so a stop
//! request is honored promptly. Errors never carry the presigned URL (its
//! signature is a credential). Partial downloads use the supervisor-only
//! `.vw-part` suffix, leaving user files that happen to end in `.part`
//! untouched.

use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, bail};
use nix::fcntl::{AtFlags, OFlag, openat, renameat};
use nix::sys::stat::{Mode, fstatat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use rusty_s3::actions::{CreateMultipartUpload, DeleteObjectsResponse, ObjectIdentifier};
use rusty_s3::{Bucket, Credentials, S3Action, UrlStyle};

use super::remote::{BucketStyle, RemoteSpec};
use super::transport::{
    AbortReader, BODY_TIMEOUT, SIGN_EXPIRE, ca_certs, checked, http_err, loopback,
    normalize_endpoint, read_body_capped, region_for, retryable, retrying,
};

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

/// A download target anchored on the directory descriptor, so the temp
/// creation, hash, rename, and cleanup cannot be redirected by a path swap
/// in the parent after the check.
struct Download {
    dir: std::fs::File,
    name: String,
    display: String,
}

impl Download {
    fn path(path: &str) -> std::io::Result<Self> {
        let path = Path::new(path);
        let parent = path.parent().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent")
        })?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
            })?;
        Ok(Self {
            dir: crate::util::fs::open_dir(parent)?,
            name: name.to_string(),
            display: path.to_string_lossy().into_owned(),
        })
    }

    fn under(root: &Path, rel: &str) -> std::io::Result<Self> {
        let path = Path::new(rel);
        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
            })?;
        Ok(Self {
            dir: crate::util::fs::open_dir_under(root, parent)?,
            name: name.to_string(),
            display: root.join(path).to_string_lossy().into_owned(),
        })
    }

    fn temp(&self) -> String {
        format!("{}{}", self.name, crate::util::fs::PART_SUFFIX)
    }

    fn temp_len(&self, temp: &str, expected: Option<u64>) -> u64 {
        let len = fstatat(&self.dir, temp, AtFlags::AT_SYMLINK_NOFOLLOW)
            .ok()
            .and_then(|stat| u64::try_from(stat.st_size).ok())
            .unwrap_or(0);
        if expected.is_some_and(|expected| len >= expected) {
            0
        } else {
            len
        }
    }

    fn open_temp(&self, temp: &str, start: u64, mode: u32) -> std::io::Result<std::fs::File> {
        let mut flags = OFlag::O_WRONLY
            | OFlag::O_CREAT
            | OFlag::O_NOFOLLOW
            | OFlag::O_NONBLOCK
            | OFlag::O_CLOEXEC;
        if start == 0 {
            flags |= OFlag::O_TRUNC;
        } else {
            flags |= OFlag::O_APPEND;
        }
        let fd = openat(&self.dir, temp, flags, Mode::from_bits_truncate(mode))?;
        Ok(std::fs::File::from(fd))
    }

    fn hash_temp(&self, temp: &str) -> std::io::Result<String> {
        let fd = openat(
            &self.dir,
            temp,
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?;
        let mut file = std::fs::File::from(fd);
        crate::util::hash::sha256_reader(&mut file)
    }

    fn remove_temp(&self, temp: &str) {
        let _ = unlinkat(&self.dir, temp, UnlinkatFlags::NoRemoveDir);
    }
}

/// Absolute download cap for one synced object. Upstream clients cap
/// Bitwarden attachments at 100 MB by default; 1 GiB leaves generous
/// headroom while a rogue bucket still cannot fill the data volume.
pub const MAX_SYNC_OBJECT_BYTES: u64 = 1024 * 1024 * 1024;

/// Absolute download cap for one DB dump. The import's integrity check
/// still decides validity; this only bounds a rogue endpoint.
pub const MAX_DB_OBJECT_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// S3's DeleteObjects limit per request.
const MAX_DELETE_BATCH: usize = 1000;
/// The delete response is a small XML document; cap it like every parser.
const DELETE_RESPONSE_CAP: u64 = 1024 * 1024;

/// Listing bound. The manifest caps at ~40k files; three content-addressed
/// versions per file plus the legacy keys fit comfortably under 100k. A
/// larger prefix is treated as failure rather than materializing an
/// unbounded vector in PID 1.
const MAX_LIST_KEYS: usize = 100_000;

/// Page bound for one listing. At 1000 keys/page this covers the key cap
/// with headroom; the bound also stops a broken endpoint that keeps
/// announcing more pages without content.
const MAX_LIST_PAGES: usize = 256;

/// Raw listing-body bound (16 MiB): a page of 1000 keys is a few MiB at
/// most; anything larger is hostile or broken, and the read stops before
/// memory grows.
const LIST_BODY_CAP: u64 = 16 * 1024 * 1024;

/// Why a download failed. The restore path must distinguish a definitively
/// missing/invalid candidate (try the next older backup) from a transport or
/// local failure (never silently downgrade the volume).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetError {
    /// The object does not exist (HTTP 404).
    Missing,
    /// The object exists but violates the caller's expectations: too large,
    /// too short, wrong size, or a checksum mismatch.
    Invalid(String),
    /// The request failed in a way that may be transient (network, 5xx,
    /// redirect, permission).
    Transport(String),
    /// A local filesystem failure (`.vw-part` creation, write, fsync, rename).
    Local(String),
    /// A stop request interrupted the transfer.
    Aborted,
}

impl std::fmt::Display for GetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => f.write_str("object not found"),
            Self::Invalid(message) | Self::Transport(message) | Self::Local(message) => {
                f.write_str(message)
            }
            Self::Aborted => f.write_str("aborted"),
        }
    }
}

impl std::error::Error for GetError {}

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
    /// Exact mode of the published file. Supervisor-owned and
    /// group-writable (0660): the identity/cert tree is writable by
    /// tailscaled's group, vault data by the vault's group; the owning
    /// service reads through that group, never world access.
    pub mode: u32,
}

/// One listed object: its full key and size. The size feeds the state
/// sync's unchanged-skip; backup consumers only need the key.
pub struct Listed {
    pub key: String,
    pub size: u64,
    /// The object's last-modified stamp (ISO-8601 as the provider sent it).
    /// Used only to order multiple versions of the same file during the
    /// state sync's reconciliation; empty when the provider omitted it.
    pub last_modified: String,
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
        let endpoint = spec.endpoint.clone();
        if !matches!(endpoint.scheme(), "http" | "https") {
            bail!("invalid S3 endpoint scheme (want http or https)");
        }
        if endpoint.scheme() == "http" && !spec.allow_http && !loopback(&endpoint) {
            bail!(
                "SUPERVISOR_S3_ENDPOINT {} uses plaintext HTTP; SigV4 credentials \
                 would cross the network in clear text. Use https, or set \
                 SUPERVISOR_S3_ALLOW_HTTP=true only on a trusted network",
                crate::util::log::sanitize(&endpoint.origin().ascii_serialization())
            );
        }
        let endpoint = normalize_endpoint(endpoint);
        let style = match spec.style {
            BucketStyle::Path => UrlStyle::Path,
            BucketStyle::VirtualHosted => UrlStyle::VirtualHost,
        };
        let region = spec.region.clone().unwrap_or_else(|| region_for(&endpoint));
        let bucket = Bucket::new(endpoint.clone(), style, spec.bucket.clone(), region)
            .map_err(|e| anyhow!("invalid S3 bucket configuration: {e}"))?;
        let mut config = ureq::Agent::config_builder()
            // Per-phase budgets instead of one end-to-end timeout: control
            // phases stay tight while a transfer body gets BODY_TIMEOUT.
            .timeout_resolve(Some(timeout))
            .timeout_connect(Some(timeout))
            .timeout_send_request(Some(timeout))
            .timeout_send_body(Some(BODY_TIMEOUT))
            .timeout_recv_response(Some(timeout))
            .timeout_recv_body(Some(BODY_TIMEOUT))
            // A black-holed peer must not hold a body attempt for the whole
            // 600-second budget; a progressing transfer still gets it.
            .timeout_per_read(Some(timeout))
            .timeout_per_write(Some(timeout))
            .timeout_global(None)
            // A presigned URL must never be re-signed by a redirect; a 3xx
            // is then not an error, so every call site checks the status.
            .max_redirects(0);
        if let Some(path) = &spec.ca_file {
            let certs = ca_certs(path)?;
            config = config.tls_config(
                ureq::tls::TlsConfig::builder()
                    .root_certs(ureq::tls::RootCerts::new_with_certs(&certs))
                    .build(),
            );
        }
        let agent = config.build().new_agent();
        Ok(Self {
            bucket,
            credentials: Credentials::new(&spec.key_id, &spec.key_secret),
            agent,
        })
    }

    /// Upload a file as `key`. Content-Length is set explicitly: S3
    /// rejects chunked PUT bodies. Files at or above
    /// [`MULTIPART_THRESHOLD`] go through the multipart path, so each part
    /// gets its own body budget. The path is opened once, without following
    /// a final symlink; the same handle is hashed and uploaded by callers
    /// that need content identity.
    pub fn put(&self, key: &str, path: &str, abort: impl Fn() -> bool) -> anyhow::Result<()> {
        if abort() {
            bail!("aborted");
        }
        let mut file = crate::util::fs::open_nofollow(path)
            .map_err(|e| anyhow!("cannot open {path} for upload: {e}"))?;
        let size = file
            .metadata()
            .map_err(|e| anyhow!("cannot size {path}: {e}"))?
            .len();
        self.put_file(key, &mut file, size, abort)
    }

    /// Upload an already-open file. The caller owns the handle for hashing
    /// and for the post-upload stat check, so a path swap cannot change the
    /// inode between the two operations.
    pub fn put_file(
        &self,
        key: &str,
        file: &mut std::fs::File,
        size: u64,
        abort: impl Fn() -> bool,
    ) -> anyhow::Result<()> {
        if abort() {
            bail!("aborted");
        }
        if size >= MULTIPART_THRESHOLD {
            return self.put_multipart(key, file, size, PART_SIZE, abort);
        }
        let response = retrying(|| {
            if abort() {
                return Err(ureq::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "aborted",
                )));
            }
            file.seek(SeekFrom::Start(0)).map_err(ureq::Error::Io)?;
            let url = self
                .bucket
                .put_object(Some(&self.credentials), key)
                .sign(SIGN_EXPIRE);
            let mut body = AbortReader {
                inner: &mut *file,
                abort: &abort,
            };
            self.agent
                .put(url.as_str())
                .header("Content-Length", size.to_string())
                .send(ureq::SendBody::from_reader(&mut body))
        })
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
        file: &mut std::fs::File,
        size: u64,
        part_size: u64,
        abort: impl Fn() -> bool,
    ) -> anyhow::Result<()> {
        if abort() {
            bail!("aborted");
        }
        // CreateMultipartUpload is not idempotent: retrying after a lost
        // response would create a second upload ID whose first copy can
        // never be aborted. One attempt; the next whole put retries.
        let response = {
            let url = self
                .bucket
                .create_multipart_upload(Some(&self.credentials), key)
                .sign(SIGN_EXPIRE);
            self.agent.post(url.as_str()).send_empty()
        }
        .map_err(|e| anyhow!("creating the upload of {key} failed: {}", http_err(&e)))?;
        let response = checked("create upload", key, response)?;
        let body = response
            .into_body()
            .into_with_config()
            .limit(MULTIPART_XML_CAP)
            .read_to_string()
            .map_err(|e| anyhow!("creating the upload of {key}: {e}"))?;
        let upload_id = CreateMultipartUpload::parse_response(&body)
            .map_err(|_| anyhow!("creating the upload of {key}: unparseable response"))?
            .upload_id()
            .to_string();
        let etags = match self.put_parts(key, file, size, part_size, &upload_id, &abort) {
            Ok(etags) => etags,
            Err(e) => {
                self.abort_upload(key, &upload_id);
                return Err(e);
            }
        };
        let response = retrying(|| {
            let action = self.bucket.complete_multipart_upload(
                Some(&self.credentials),
                key,
                &upload_id,
                etags.iter().map(String::as_str),
            );
            let url = action.sign(SIGN_EXPIRE);
            let body = action.body();
            self.agent
                .post(url.as_str())
                .header("Content-Type", "application/xml")
                .send(body)
        })
        .map_err(|e| anyhow!("completing the upload of {key} failed: {}", http_err(&e)))?;
        let response = match checked("complete upload", key, response) {
            Ok(response) => response,
            Err(e) => {
                self.abort_upload(key, &upload_id);
                return Err(e);
            }
        };
        // S3 may answer CompleteMultipartUpload with HTTP 200 and an
        // <Error> document; the object then does not exist.
        let body = match response
            .into_body()
            .into_with_config()
            .limit(MULTIPART_XML_CAP)
            .read_to_string()
        {
            Ok(body) => body,
            Err(e) => {
                self.abort_upload(key, &upload_id);
                return Err(anyhow!("completing the upload of {key}: {e}"));
            }
        };
        if body.contains("<Error") {
            self.abort_upload(key, &upload_id);
            bail!("completing the upload of {key} failed: provider returned an error body");
        }
        Ok(())
    }

    /// Upload every part in order, collecting the ETags the completion
    /// needs. Parts are read one at a time (bounded memory) and each part
    /// request gets the full body budget.
    fn put_parts(
        &self,
        key: &str,
        file: &mut std::fs::File,
        size: u64,
        part_size: u64,
        upload_id: &str,
        abort: &impl Fn() -> bool,
    ) -> anyhow::Result<Vec<String>> {
        let mut etags: Vec<String> = Vec::new();
        let mut offset: u64 = 0;
        while offset < size {
            if abort() {
                bail!("aborted");
            }
            if etags.len() >= MAX_PARTS {
                bail!("upload of {key}: more than {MAX_PARTS} parts needed");
            }
            let part_number = u16::try_from(etags.len() + 1).expect("MAX_PARTS fits in u16");
            let this = (size - offset).min(part_size);
            let mut chunk = vec![0u8; usize::try_from(this).expect("PART_SIZE fits in usize")];
            file.seek(SeekFrom::Start(offset))
                .and_then(|_| file.read_exact(&mut chunk))
                .map_err(|e| anyhow!("reading {key}: {e}"))?;
            let response = retrying(|| {
                let url = self
                    .bucket
                    .upload_part(Some(&self.credentials), key, part_number, upload_id)
                    .sign(SIGN_EXPIRE);
                let mut body = AbortReader {
                    inner: &chunk[..],
                    abort,
                };
                self.agent
                    .put(url.as_str())
                    .header("Content-Length", chunk.len().to_string())
                    .send(ureq::SendBody::from_reader(&mut body))
            })
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
        let response = retrying(|| {
            if abort() {
                return Err(ureq::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "aborted",
                )));
            }
            let url = self
                .bucket
                .put_object(Some(&self.credentials), key)
                .sign(SIGN_EXPIRE);
            let mut body = AbortReader {
                inner: bytes,
                abort: &abort,
            };
            self.agent
                .put(url.as_str())
                .header("Content-Length", bytes.len().to_string())
                .send(ureq::SendBody::from_reader(&mut body))
        })
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
        let response = match retrying(|| {
            let url = self
                .bucket
                .get_object(Some(&self.credentials), key)
                .sign(SIGN_EXPIRE);
            self.agent.get(url.as_str()).call()
        }) {
            Ok(response) => checked("download", key, response)?,
            Err(ureq::Error::StatusCode(404)) => return Ok(None),
            Err(e) => return Err(anyhow!("download of {key} failed: {}", http_err(&e))),
        };
        let text = read_body_capped(response, max_bytes, &abort)
            .map_err(|e| anyhow!("download of {key}: {e}"))?;
        Ok(Some(text))
    }

    /// Object existence and size via `HEAD`; `Ok(None)` = 404. A response
    /// without a usable Content-Length is malformed, never a zero-byte
    /// object.
    pub fn head(&self, key: &str, abort: impl Fn() -> bool) -> anyhow::Result<Option<u64>> {
        if abort() {
            bail!("aborted");
        }
        let response = match retrying(|| {
            if abort() {
                return Err(ureq::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "aborted",
                )));
            }
            let url = self
                .bucket
                .head_object(Some(&self.credentials), key)
                .sign(SIGN_EXPIRE);
            self.agent.head(url.as_str()).call()
        }) {
            Ok(response) => checked("head", key, response)?,
            Err(ureq::Error::StatusCode(404)) => return Ok(None),
            Err(e) => return Err(anyhow!("head of {key} failed: {}", http_err(&e))),
        };
        let size = response
            .headers()
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| anyhow!("head of {key}: response has no usable Content-Length"))?;
        Ok(Some(size))
    }

    /// Download `key` into `path` atomically. Bytes land in a sibling temp
    /// file (same filesystem) bounded by [`Expect`], and only a transfer
    /// that meets every expectation is renamed into place: a failed,
    /// truncated, or mismatched download leaves `path` untouched and
    /// removes the temp. The published file takes [`Expect::mode`] (0660:
    /// group-writable for the owning service). The parent directory is
    /// opened once and every temp/hash/rename/cleanup operation is relative
    /// to that descriptor; [`Self::get_under`] additionally anchors each
    /// path component.
    pub fn get(
        &self,
        key: &str,
        path: &str,
        expect: Expect<'_>,
        abort: impl Fn() -> bool,
    ) -> Result<(), GetError> {
        let target = Download::path(path)
            .map_err(|e| GetError::Local(format!("cannot open the parent of {path}: {e}")))?;
        self.get_target(key, target, expect, abort)
    }

    /// [`Self::get`] for `rel` below `root`, opened with `openat` and
    /// `O_NOFOLLOW` per component. The directory descriptors pin the
    /// parent, so a symlink swapped in after the caller's
    /// `create_real_dirs` cannot redirect the temp, rename, or cleanup.
    pub fn get_under(
        &self,
        key: &str,
        root: &Path,
        rel: &str,
        expect: Expect<'_>,
        abort: impl Fn() -> bool,
    ) -> Result<(), GetError> {
        let target = Download::under(root, rel).map_err(|e| {
            GetError::Local(format!(
                "cannot open the parent of {}: {e}",
                root.join(rel).display()
            ))
        })?;
        self.get_target(key, target, expect, abort)
    }

    fn get_target(
        &self,
        key: &str,
        target: Download,
        expect: Expect<'_>,
        abort: impl Fn() -> bool,
    ) -> Result<(), GetError> {
        if abort() {
            return Err(GetError::Aborted);
        }
        // The temp lives in the anchored directory so the publish is one
        // atomic same-filesystem rename; a crash leaves the target
        // untouched. A partial transfer is kept and resumed with a Range
        // request, so a slow link makes progress across bounded attempts
        // instead of restarting from zero every time.
        let tmp = target.temp();
        let mut offset = target.temp_len(&tmp, expect.size);
        let mut attempt = 0;
        let staged: Result<u64, GetError> = loop {
            attempt += 1;
            if abort() {
                break Err(GetError::Aborted);
            }
            // Sign per attempt: a retry must not reuse a URL that may have
            // expired while the previous attempt consumed its body budget.
            let url = self
                .bucket
                .get_object(Some(&self.credentials), key)
                .sign(SIGN_EXPIRE);
            let mut request = self.agent.get(url.as_str());
            if offset > 0 {
                request = request.header("Range", &format!("bytes={offset}-"));
            }
            let response = match request.call() {
                Ok(response) => match checked("download", key, response) {
                    Ok(response) => response,
                    Err(e) => break Err(GetError::Transport(e.to_string())),
                },
                Err(ureq::Error::StatusCode(404)) => break Err(GetError::Missing),
                Err(e) => {
                    if retryable(&e) && attempt < MAX_DOWNLOAD_ATTEMPTS {
                        continue;
                    }
                    break Err(GetError::Transport(format!(
                        "download of {key} failed: {}",
                        http_err(&e)
                    )));
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
            let streamed = (|| -> Result<u64, GetError> {
                let mut out = target.open_temp(&tmp, start, expect.mode).map_err(|e| {
                    GetError::Local(format!("cannot create {}: {e}", target.display))
                })?;
                // A pre-created FIFO opens without O_NONBLOCK only when a
                // reader is present; never write into anything but a file.
                if !out
                    .metadata()
                    .map_err(|e| {
                        GetError::Local(format!("cannot inspect {}: {e}", target.display))
                    })?
                    .is_file()
                {
                    return Err(GetError::Local(format!(
                        "cannot create {}: not a regular file",
                        target.display
                    )));
                }
                let mut buf = [0u8; 64 * 1024];
                let mut total = start;
                loop {
                    if abort() {
                        return Err(GetError::Aborted);
                    }
                    let n = reader
                        .read(&mut buf)
                        .map_err(|e| GetError::Transport(format!("download of {key}: {e}")))?;
                    if n == 0 {
                        break;
                    }
                    total += n as u64;
                    if total > expect.max_bytes {
                        return Err(GetError::Invalid(format!(
                            "download of {key}: exceeds the {}-byte cap",
                            expect.max_bytes
                        )));
                    }
                    if let Some(expected) = expect.size
                        && total > expected
                    {
                        return Err(GetError::Invalid(format!(
                            "download of {key}: larger than the {expected} bytes listed"
                        )));
                    }
                    out.write_all(&buf[..n])
                        .map_err(|e| GetError::Local(format!("download of {key}: {e}")))?;
                }
                // A body that ends short of the declared length is an
                // interrupted transfer, not proof the object is invalid:
                // keep the partial and resume within the attempt budget. A
                // restore then refuses the boot instead of silently
                // downgrading to an older backup.
                if let Some(declared) = declared
                    && total - start != declared
                {
                    return Err(GetError::Transport(format!(
                        "download of {key}: body ended after {} of {declared} bytes",
                        total - start
                    )));
                }
                // The open mode is masked by the umask; the published file
                // must have exactly the caller's mode.
                out.set_permissions(std::fs::Permissions::from_mode(expect.mode))
                    .and_then(|()| out.sync_all())
                    .map_err(|e| GetError::Local(format!("download of {key}: {e}")))?;
                Ok(total)
            })();
            match streamed {
                Ok(total) => break Ok(total),
                Err(e) => {
                    // Only a transport failure is worth another attempt; a
                    // cap/size/hash/local failure is definitive.
                    let retry = matches!(e, GetError::Transport(_));
                    let done = target.temp_len(&tmp, None);
                    if retry
                        && attempt < MAX_DOWNLOAD_ATTEMPTS
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
                return Err(GetError::Invalid(format!(
                    "download of {key}: got {total} bytes, expected {expected}"
                )));
            }
            if let Some(expected) = expect.sha256 {
                let actual = target.hash_temp(&tmp).map_err(|e| {
                    GetError::Local(format!(
                        "download of {key}: cannot hash {}: {e}",
                        target.display
                    ))
                })?;
                if actual != expected {
                    return Err(GetError::Invalid(format!(
                        "download of {key}: sha256 mismatch (got {actual}, expected {expected})"
                    )));
                }
            }
            renameat(&target.dir, tmp.as_str(), &target.dir, target.name.as_str())
                .map_err(|e| GetError::Local(format!("cannot publish {}: {e}", target.display)))?;
            // The file is complete and published; make the name durable
            // too, or a crash can lose a successful pull.
            target
                .dir
                .sync_all()
                .map_err(|e| GetError::Local(format!("cannot fsync {}: {e}", target.display)))?;
            Ok(())
        });
        if result.is_err() {
            target.remove_temp(&tmp);
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
        let mut pages = 0usize;
        loop {
            if abort() {
                bail!("aborted");
            }
            pages += 1;
            if pages > MAX_LIST_PAGES {
                bail!("listing {prefix:?}: exceeded {MAX_LIST_PAGES} pages");
            }
            let mut action = self.bucket.list_objects_v2(Some(&self.credentials));
            action.with_prefix(prefix);
            action.with_max_keys(1000);
            if let Some(t) = &token {
                action.with_continuation_token(t);
            }
            // The listing body is capped: an endpoint gone rogue cannot
            // exhaust memory within the request timeout.
            let response = retrying(|| {
                let url = action.sign(SIGN_EXPIRE);
                self.agent.get(url.as_str()).call()
            })
            .map_err(|e| anyhow!("listing {prefix:?} failed: {}", http_err(&e)))?;
            let body = checked("listing", &format!("{prefix:?}"), response)
                .and_then(|response| read_body_capped(response, LIST_BODY_CAP, &abort))
                .map_err(|e| anyhow!("listing {prefix:?}: {e}"))?;
            // The XML error type belongs to a transitive crate; the
            // message adds nothing — a listing that does not parse is
            // "unparseable".
            let parsed = rusty_s3::actions::ListObjectsV2::parse_response(&body)
                .map_err(|_| anyhow!("listing {prefix:?}: unparseable response"))?;
            // rusty-s3 reports the size as optional; a listed object
            // without one cannot be size-checked on download nor
            // reconciled against the manifest, so the listing is refused
            // rather than given an invented size. A LastModified the
            // provider omitted stays empty, which the reconciliation
            // already treats as "cannot order this version".
            let mut contents = Vec::with_capacity(parsed.contents.len());
            for c in parsed.contents {
                let Some(size) = c.size else {
                    bail!("listing {prefix:?}: object {:?} has no size", c.key);
                };
                contents.push(Listed {
                    key: c.key,
                    size,
                    last_modified: c.last_modified.unwrap_or_default(),
                });
            }
            names.extend(contents);
            if names.len() > MAX_LIST_KEYS {
                bail!("listing {prefix:?}: exceeded {MAX_LIST_KEYS} keys");
            }
            let previous = token.take();
            token = parsed.next_continuation_token;
            let Some(next) = &token else { break };
            if Some(next) == previous.as_ref() {
                // Identical page forever: a broken endpoint must not keep
                // the maintenance thread in this loop.
                bail!("listing {prefix:?}: repeated continuation token");
            }
        }
        names.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(names)
    }

    /// Delete `keys` in batches of at most 1,000 (S3's DeleteObjects
    /// limit). A per-key error leaves the other deletions applied; the
    /// returned error names the failures so the caller can report the
    /// orphans.
    pub fn delete_many(&self, keys: &[String], abort: impl Fn() -> bool) -> anyhow::Result<()> {
        if abort() {
            bail!("aborted");
        }
        for chunk in keys.chunks(MAX_DELETE_BATCH) {
            if chunk.is_empty() {
                continue;
            }
            if abort() {
                bail!("aborted");
            }
            let objects: Vec<ObjectIdentifier> =
                chunk.iter().cloned().map(ObjectIdentifier::new).collect();
            let response = retrying(|| {
                if abort() {
                    return Err(ureq::Error::Io(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "aborted",
                    )));
                }
                let action = self
                    .bucket
                    .delete_objects(Some(&self.credentials), objects.iter());
                let url = action.sign(SIGN_EXPIRE);
                let (body, content_md5) = action.body_with_md5();
                self.agent
                    .post(url.as_str())
                    .header("Content-MD5", content_md5)
                    .header("Content-Type", "application/xml")
                    .send(body.as_bytes())
            })
            .map_err(|e| anyhow!("batch delete failed: {}", http_err(&e)))?;
            let response = checked("batch delete", "objects", response)?;
            let text = read_body_capped(response, DELETE_RESPONSE_CAP, &abort)
                .map_err(|e| anyhow!("batch delete response: {e}"))?;
            let parsed = DeleteObjectsResponse::parse(&text)
                .map_err(|e| anyhow!("batch delete response: {e}"))?;
            if !parsed.errors.is_empty() {
                let detail = parsed
                    .errors
                    .iter()
                    .map(|error| {
                        format!(
                            "{}: {} ({})",
                            crate::util::log::sanitize(&error.key),
                            error.code,
                            error.message
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                bail!(
                    "batch delete left {} object(s): {detail}",
                    parsed.errors.len()
                );
            }
        }
        Ok(())
    }

    pub fn delete(&self, key: &str, abort: impl Fn() -> bool) -> anyhow::Result<()> {
        if abort() {
            bail!("aborted");
        }
        let response = match retrying(|| {
            let url = self
                .bucket
                .delete_object(Some(&self.credentials), key)
                .sign(SIGN_EXPIRE);
            self.agent.delete(url.as_str()).call()
        }) {
            Ok(response) => response,
            Err(ureq::Error::StatusCode(404)) => return Ok(()),
            Err(e) => bail!("delete of {key} failed: {}", http_err(&e)),
        };
        checked("delete", key, response)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
