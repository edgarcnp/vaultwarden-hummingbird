//! S3 connection settings shared by the state sync and the DB backup.
//! The `remote` knob keeps its `name:bucket[/prefix]` shape, but it is
//! parsed here into a [`RemoteSpec`] — the parts the in-crate S3 client
//! needs — no external tool consumes it anymore.

use std::time::Duration;

use crate::s3::RemoteSpec;

/// S3-backed persistence for /data identity files (opt-in): the same
/// tailnet node and vaultwarden RSA keys survive ephemeral redeploys.
#[derive(Clone)]
pub struct SyncConfig {
    /// the remote as configured (e.g. `r2:vw-state/sub`), for logs
    pub remote: String,
    /// the resolved bucket/prefix/credentials/endpoint
    pub target: RemoteSpec,
    /// periodic push cadence (0 disables periodic pushes)
    pub interval: Duration,
}

impl SyncConfig {
    /// Build from raw knob values. The endpoint is required: every
    /// provider — AWS included — is spelled out, none is a default.
    /// `Err` names the problem: callers degrade (state sync disabled /
    /// backup skipped) rather than guess.
    pub fn new(
        remote: String,
        key_id: String,
        key_secret: String,
        endpoint: String,
        interval: Duration,
    ) -> Result<Self, String> {
        if endpoint.is_empty() {
            return Err(
                "SUPERVISOR_S3_ENDPOINT is required; every S3-compatible provider \
                 (AWS included) is configured by its endpoint"
                    .into(),
            );
        }
        let target = parse_remote(&remote, key_id, key_secret, endpoint)?;
        Ok(Self {
            remote,
            target,
            interval,
        })
    }

    /// The sync's bucket-relative key prefix (empty, or ending in `/`).
    pub fn prefix(&self) -> &str {
        &self.target.prefix
    }
}

/// Parse `name:bucket[/prefix]` into a [`RemoteSpec`]. The name before
/// the colon is rclone legacy and is accepted but ignored. Bucket
/// sanity: non-empty, no `/`, `:`, or whitespace — provider-specific
/// rules are the operator's business, exactly as they were with rclone.
/// The prefix is normalized to end with `/` (or be empty).
fn parse_remote(
    remote: &str,
    key_id: String,
    key_secret: String,
    endpoint: String,
) -> Result<RemoteSpec, String> {
    let Some((_, path)) = remote.split_once(':') else {
        return Err("must be remote:bucket[/prefix]".into());
    };
    let path = path.trim();
    let (bucket, prefix) = match path.split_once('/') {
        Some((b, p)) => (b, p),
        None => (path, ""),
    };
    if bucket.is_empty()
        || bucket
            .chars()
            .any(|c| c.is_whitespace() || c == ':' || c == '/')
    {
        return Err("bucket must be non-empty and free of whitespace, ':' and '/'".into());
    }
    // Empty stays empty; anything else becomes a directory-style prefix.
    let prefix = prefix.trim_start_matches('/');
    let prefix = if prefix.is_empty() {
        String::new()
    } else {
        format!("{prefix}/")
    };
    Ok(RemoteSpec {
        bucket: bucket.to_string(),
        prefix,
        key_id,
        key_secret,
        endpoint,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn ok(remote: &str) -> (String, String) {
        let cfg = SyncConfig::new(
            remote.into(),
            "id".into(),
            "secret".into(),
            "https://s3.example.invalid".into(),
            Duration::from_secs(60),
        )
        .expect("valid remote");
        (cfg.target.bucket, cfg.target.prefix)
    }

    #[test]
    fn remotes_parse_into_bucket_and_prefix() {
        assert_eq!(ok("r2:vw-state"), ("vw-state".into(), String::new()));
        assert_eq!(ok("r2:vw-state/sub"), ("vw-state".into(), "sub/".into()));
        // trailing slash on the bucket alone stays root
        assert_eq!(ok("r2:vw-state/"), ("vw-state".into(), String::new()));
        // nested prefix keeps its structure
        assert_eq!(ok("s3:bucket/a/b"), ("bucket".into(), "a/b/".into()));
        // leading slash in the path is normalized away
        assert_eq!(ok("r2:vw-state//sub"), ("vw-state".into(), "sub/".into()));
        // the legacy name is accepted verbatim, whatever it holds
        assert_eq!(ok("my rem:vw-state"), ("vw-state".into(), String::new()));
    }

    #[test]
    fn invalid_remotes_are_rejected() {
        for remote in [
            "no-colon-here", // would once have meant a local path
            "r2:",           // empty bucket
            "r2:/sub",       // empty bucket before the slash
            "r2:my bucket",  // whitespace
            "r2:vw:state",   // colon in the bucket
        ] {
            assert!(
                SyncConfig::new(
                    remote.into(),
                    "id".into(),
                    "secret".into(),
                    "https://s3.example.invalid".into(),
                    Duration::from_secs(60)
                )
                .is_err(),
                "{remote} must be rejected"
            );
        }
    }

    /// No provider is a default: the endpoint is required, AWS included.
    #[test]
    fn empty_endpoint_is_rejected() {
        assert!(
            SyncConfig::new(
                "r2:vw-state".into(),
                "id".into(),
                "secret".into(),
                String::new(),
                Duration::from_secs(60)
            )
            .is_err()
        );
    }
}
