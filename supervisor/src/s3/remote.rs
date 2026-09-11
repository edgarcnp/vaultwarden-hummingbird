//! A resolved S3 remote: the bucket, key prefix, and credentials the
//! client speaks to. Pure data, no behavior — every consumer (state sync,
//! DB backup) resolves its knobs into one of these; [`super::client::Client`]
//! is generic over any of them.

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
}
