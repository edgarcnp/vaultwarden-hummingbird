//! S3 transport policy shared by every operation: presigning lifetime,
//! body budgets, retry classification, abort-aware upload readers, TLS
//! roots, endpoint normalization, and AWS region derivation. The client
//! in [`super::client`] owns the verbs; this module owns how a request is
//! made safe.

use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, bail};
use nix::fcntl::OFlag;
use url::Url;

use crate::util::fs::{STATE_ROOT, under_root};

/// Presigned-URL lifetime; must comfortably exceed the per-request
/// timeout (the request is issued immediately after signing).
pub(super) const SIGN_EXPIRE: Duration = Duration::from_secs(900);

/// Total body budget for one transfer (upload or download body). A single
/// end-to-end request timeout made large objects unsyncable whenever the
/// bucket was slow; per-phase budgets bound every hang while still giving
/// a body this whole window to make progress.
pub(super) const BODY_TIMEOUT: Duration = Duration::from_secs(600);

/// SigV4 signing region: derived from the endpoint for AWS S3 (its
/// signature is region-checked), `auto` for everything else — S3-
/// compatible providers (R2, B2, MinIO, ...) accept or ignore it.
pub(super) const AUTO_REGION: &str = "auto";

/// Whether a request failure is worth another attempt. Retrying a
/// definitive answer (bad credentials, missing object, TLS verification,
/// malformed URI) only delays the failure and multiplies load; retry
/// transient transport errors and the statuses providers use for overload.
pub(super) fn retryable(e: &ureq::Error) -> bool {
    match e {
        ureq::Error::StatusCode(code) => matches!(*code, 408 | 429 | 500 | 502 | 503 | 504),
        ureq::Error::Timeout(_) => true,
        ureq::Error::Io(io) => matches!(
            io.kind(),
            std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::WouldBlock
                | std::io::ErrorKind::UnexpectedEof
        ),
        // HostNotFound, BadUri, Http, Protocol, RedirectFailed: retrying
        // the same request cannot change the answer.
        _ => false,
    }
}

/// A reader that checks the stop flag before every chunk, so a large
/// upload body is cancelled promptly instead of running to BODY_TIMEOUT.
pub(super) struct AbortReader<'a, R> {
    pub(super) inner: R,
    pub(super) abort: &'a dyn Fn() -> bool,
}

impl<R: Read> Read for AbortReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if (self.abort)() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "aborted",
            ));
        }
        self.inner.read(buf)
    }
}

/// Bounded retries for idempotent requests (put/get/list/delete all are):
/// the caller rebuilds and re-signs the request per attempt, so a retry
/// can never reuse an expired presigned URL.
pub(super) const RETRY_ATTEMPTS: u32 = 3;
pub(super) const RETRY_BASE: Duration = Duration::from_millis(200);

/// Run one idempotent request with bounded, jittered retries. `request`
/// must build a fresh request each call.
pub(super) fn retrying<T>(
    mut request: impl FnMut() -> Result<T, ureq::Error>,
) -> Result<T, ureq::Error> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        match request() {
            Err(e) if attempt < RETRY_ATTEMPTS && retryable(&e) => {
                std::thread::sleep(backoff(attempt));
            }
            other => return other,
        }
    }
}

/// Read a PEM CA bundle. A file over the cap is refused before parsing, so
/// a mistaken path to a huge file cannot exhaust PID 1.
pub fn validate_ca_file(path: &str) -> anyhow::Result<()> {
    ca_certs(path).map(|_| ())
}

pub(super) fn ca_certs(path: &str) -> anyhow::Result<Vec<ureq::tls::Certificate<'static>>> {
    ca_certs_in(path, Path::new(STATE_ROOT))
}

fn ca_certs_in(path: &str, root: &Path) -> anyhow::Result<Vec<ureq::tls::Certificate<'static>>> {
    const MAX_CA_BYTES: u64 = 1024 * 1024;
    // The CA decides which server is trusted; it must live on the
    // supervisor-only state volume but outside the tailscaled-writable
    // subtree. Config resolution checks this first; repeating it here keeps
    // the transport safe for direct callers.
    let tailscale = root.join("tailscale");
    if !under_root(root, path) || under_root(&tailscale, path) {
        bail!(
            "SUPERVISOR_S3_CA_FILE {path} must live under {} and outside {}/tailscale",
            root.display(),
            root.display()
        );
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(OFlag::O_NOFOLLOW.bits() | OFlag::O_NONBLOCK.bits())
        .open(path)
        .map_err(|e| anyhow!("cannot read SUPERVISOR_S3_CA_FILE {path}: {e}"))?;
    let meta = file
        .metadata()
        .map_err(|e| anyhow!("cannot read SUPERVISOR_S3_CA_FILE {path}: {e}"))?;
    if !meta.is_file() {
        bail!("SUPERVISOR_S3_CA_FILE {path} is not a regular file");
    }
    if meta.len() > MAX_CA_BYTES {
        bail!("SUPERVISOR_S3_CA_FILE {path} exceeds the {MAX_CA_BYTES}-byte cap");
    }
    let mut bytes = Vec::new();
    file.take(MAX_CA_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| anyhow!("cannot read SUPERVISOR_S3_CA_FILE {path}: {e}"))?;
    if bytes.len() as u64 > MAX_CA_BYTES {
        bail!("SUPERVISOR_S3_CA_FILE {path} exceeds the {MAX_CA_BYTES}-byte cap");
    }
    let certs: Vec<_> = ureq::tls::parse_pem(&bytes)
        .filter_map(|item| match item {
            Ok(ureq::tls::PemItem::Certificate(cert)) => Some(cert),
            _ => None,
        })
        .collect();
    if certs.is_empty() {
        bail!("SUPERVISOR_S3_CA_FILE {path} holds no PEM certificate");
    }
    Ok(certs)
}

/// Read a capped response body, checking `abort` before every chunk. The
/// body limit is enforced by reading one byte past it; a truncated read is
/// an error, never a silently shortened manifest/list. Control-plane reads
/// that ignored `abort` could hold a shutdown for the whole body budget.
pub(super) fn read_body_capped(
    response: ureq::http::Response<ureq::Body>,
    max: u64,
    abort: &impl Fn() -> bool,
) -> anyhow::Result<String> {
    let reader = response.into_body().into_reader();
    let mut limited = reader.take(max.saturating_add(1));
    let mut body = AbortReader {
        inner: &mut limited,
        abort,
    };
    let mut out = Vec::new();
    body.read_to_end(&mut out)
        .map_err(|e| anyhow!("cannot read response body: {e}"))?;
    if out.len() as u64 > max {
        bail!("response body exceeds the {max}-byte cap");
    }
    String::from_utf8(out).map_err(|_| anyhow!("response body is not UTF-8"))
}

/// Whether an endpoint names the local machine (plaintext HTTP is
/// tolerable there; anywhere else it would expose SigV4 credentials).
pub(super) fn loopback(endpoint: &Url) -> bool {
    match endpoint.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

/// Exponential backoff with jitter derived from the wall clock (no RNG
/// dependency): 200ms, 400ms, ... plus up to 100ms.
pub(super) fn backoff(attempt: u32) -> Duration {
    let base = RETRY_BASE.saturating_mul(1 << (attempt - 1).min(3));
    let jitter = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.subsec_millis() as u64)
        .unwrap_or(0)
        % 100;
    base + Duration::from_millis(jitter)
}

/// The signing region for an endpoint: the region embedded in AWS S3's
/// hostnames, `auto` for every other S3-compatible provider. Handles the
/// regional, dualstack, FIPS, and China spellings AWS serves
/// (`s3.<region>.amazonaws.com`, `s3-<region>.amazonaws.com`,
/// `s3.dualstack.<region>.amazonaws.com`, `s3-fips.<region>.amazonaws.com`,
/// `s3-fips.dualstack.<region>.amazonaws.com`, and their
/// `.amazonaws.com.cn` variants); acceleration hosts always sign in
/// us-east-1.
pub(super) fn region_for(endpoint: &Url) -> String {
    let Some(raw_host) = endpoint.host_str() else {
        return AUTO_REGION.to_string();
    };
    // A virtual-hosted endpoint puts the bucket before the service host
    // (`bucket.s3.us-west-2.amazonaws.com`). Strip that label before
    // looking for the AWS service/region spelling.
    let host = if let Some((_, rest)) = raw_host.split_once(".s3.") {
        format!("s3.{rest}")
    } else if let Some((_, rest)) = raw_host.split_once(".s3-") {
        format!("s3-{rest}")
    } else {
        raw_host.to_string()
    };
    let Some(rest) = host
        .strip_suffix(".amazonaws.com")
        .or_else(|| host.strip_suffix(".amazonaws.com.cn"))
    else {
        return AUTO_REGION.to_string();
    };
    // S3 Transfer Acceleration signs in us-east-1 whatever the host
    // spelling says (`s3-accelerate[.dualstack].amazonaws.com`).
    if rest.starts_with("s3-accelerate") {
        return "us-east-1".to_string();
    }
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
pub(super) fn normalize_endpoint(mut endpoint: Url) -> Url {
    if !endpoint.path().ends_with('/') {
        let mut path = endpoint.path().to_string();
        path.push('/');
        endpoint.set_path(&path);
    }
    endpoint
}

/// Reject a non-2xx response that ureq did not already turn into an error.
/// With redirects disabled a 3xx arrives as a "successful" response;
/// treating it as one would make uploads silent no-ops and downloads
/// foreign bodies.
pub(super) fn checked(
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
pub(super) fn http_err(e: &ureq::Error) -> String {
    match e {
        ureq::Error::StatusCode(code) => format!("HTTP {code}"),
        ureq::Error::Timeout(_) => "timeout".into(),
        ureq::Error::Io(io) => format!("I/O error: {io}"),
        _ => "transport error".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ca_file_in_the_tailscaled_subtree_is_refused() {
        let dir = std::env::temp_dir().join(format!("vw-ca-ts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("tailscale")).unwrap();
        let path = dir.join("tailscale/ca.pem");
        std::fs::write(&path, b"not a certificate").unwrap();
        let err = ca_certs_in(path.to_str().unwrap(), &dir)
            .expect_err("the tailscaled-writable subtree is refused");
        assert!(err.to_string().contains("outside"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_symlinked_ca_file_is_refused() {
        let dir = std::env::temp_dir().join(format!("vw-ca-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let real = dir.join("real.pem");
        std::fs::write(&real, b"not a certificate").unwrap();
        let link = dir.join("link.pem");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = ca_certs_in(link.to_str().unwrap(), &dir).expect_err("a symlink is refused");
        assert!(err.to_string().contains("cannot read"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_non_pem_ca_file_is_refused() {
        let dir = std::env::temp_dir().join(format!("vw-ca-junk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for bytes in [&b""[..], &b"not a certificate"[..]] {
            let path = dir.join("junk.pem");
            std::fs::write(&path, bytes).unwrap();
            let err = ca_certs_in(path.to_str().unwrap(), &dir)
                .expect_err("a bundle with no certificate must be refused");
            assert!(
                err.to_string().contains("holds no PEM certificate"),
                "{err}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_fifo_ca_file_is_refused() {
        let dir = std::env::temp_dir().join(format!("vw-ca-fifo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("ca.pem");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o600)).unwrap();
        let start = std::time::Instant::now();
        let err = ca_certs_in(fifo.to_str().unwrap(), &dir).expect_err("a FIFO is refused");
        assert!(err.to_string().contains("not a regular file"), "{err}");
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
