//! S3 transport policy shared by every operation: presigning lifetime,
//! body budgets, retry classification, abort-aware upload readers, TLS
//! roots, endpoint normalization, and AWS region derivation. The client
//! in [`super::client`] owns the verbs; this module owns how a request is
//! made safe.

use std::io::Read;
use std::time::Duration;

use anyhow::{anyhow, bail};
use url::Url;

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
    const MAX_CA_BYTES: u64 = 1024 * 1024;
    // The CA decides which server is trusted; it must not live on a
    // vault-writable volume. Config resolution checks this too; keeping it
    // here covers direct callers.
    let isolated = crate::config::paths::under_root(
        std::path::Path::new(crate::config::SUPERVISOR_STATE),
        path,
    );
    if !isolated {
        bail!(
            "SUPERVISOR_S3_CA_FILE {path} must live under {}",
            crate::config::SUPERVISOR_STATE
        );
    }
    let meta = std::fs::metadata(path)
        .map_err(|e| anyhow!("cannot read SUPERVISOR_S3_CA_FILE {path}: {e}"))?;
    if !meta.is_file() {
        bail!("SUPERVISOR_S3_CA_FILE {path} is not a regular file");
    }
    if meta.len() > MAX_CA_BYTES {
        bail!("SUPERVISOR_S3_CA_FILE {path} exceeds the {MAX_CA_BYTES}-byte cap");
    }
    let bytes = std::fs::read(path)
        .map_err(|e| anyhow!("cannot read SUPERVISOR_S3_CA_FILE {path}: {e}"))?;
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
    let Some(host) = endpoint.host_str() else {
        return AUTO_REGION.to_string();
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
        ureq::Error::Io(io) => format!("I/O error: {io}"),
        _ => "transport error".into(),
    }
}
