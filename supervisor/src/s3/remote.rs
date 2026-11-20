//! A resolved S3 remote: the bucket, key prefix, and credentials the
//! client speaks to. Pure data, no behavior — every consumer (state sync,
//! DB backup) resolves its knobs into one of these; [`super::client::Client`]
//! is generic over any of them.

/// How the bucket name appears in request URLs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BucketStyle {
    /// `https://endpoint/bucket/key` (MinIO, most S3-compatible providers).
    Path,
    /// `https://bucket.endpoint/key` (AWS virtual-hosted style).
    VirtualHosted,
}

/// One S3 remote. Carries the access key secret, so it must never be
/// formatted, logged, or placed on a command line.
#[derive(Clone)]
pub struct RemoteSpec {
    /// Bucket name, with no path component.
    pub bucket: String,
    /// Bucket-relative key prefix: empty, or ending in `/`.
    pub prefix: String,
    /// SigV4 access key ID.
    pub key_id: String,
    /// SigV4 secret key; never log or render it.
    pub key_secret: String,
    /// S3-compatible endpoint; required, no provider is a default. Parsed
    /// once at config resolution and reused by every request.
    pub endpoint: url::Url,
    /// Permit plaintext HTTP to a non-loopback endpoint. Off by default:
    /// SigV4 credentials would otherwise cross the network in clear text.
    pub allow_http: bool,
    /// Optional PEM CA bundle replacing the built-in roots (private S3).
    /// Must sit under the supervisor-only state root; the transport refuses a
    /// symlink or non-regular file.
    pub ca_file: Option<String>,
    /// SigV4 region; `None` derives it from an AWS endpoint (`auto`
    /// elsewhere).
    pub region: Option<String>,
    /// Path-style (default) or virtual-hosted bucket addressing.
    pub style: BucketStyle,
}
