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

/// One S3 remote. Secrets ride in the struct only: never argv, never
/// logs.
#[derive(Clone)]
pub struct RemoteSpec {
    /// S3 bucket name
    pub bucket: String,
    /// bucket-relative key prefix: empty, or ending in `/`
    pub prefix: String,
    pub key_id: String,
    pub key_secret: String,
    /// S3-compatible endpoint; required, no provider is a default
    pub endpoint: String,
    /// Permit plaintext HTTP to a non-loopback endpoint. Off by default:
    /// SigV4 credentials would otherwise cross the network in clear text.
    pub allow_http: bool,
    /// Optional PEM CA bundle replacing the built-in roots (private S3).
    pub ca_file: Option<String>,
    /// SigV4 region; `None` derives it from an AWS endpoint (`auto`
    /// elsewhere).
    pub region: Option<String>,
    /// Path-style (default) or virtual-hosted bucket addressing.
    pub style: BucketStyle,
}
