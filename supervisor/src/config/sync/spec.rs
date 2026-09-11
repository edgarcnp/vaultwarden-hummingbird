//! S3 connection settings shared by the state sync and the DB backup.
//! The `remote` knob keeps its `name:bucket[/prefix]` shape, but it is
//! parsed here into the parts the in-crate S3 client needs — no external
//! tool consumes it anymore.

use std::time::Duration;

/// S3-backed persistence for /data identity files (opt-in): the same
/// tailnet node and vaultwarden RSA keys survive ephemeral redeploys.
#[derive(Clone)]
pub struct SyncConfig {
    /// the remote as configured (e.g. `r2:vw-state/sub`), for logs
    pub remote: String,
    /// S3 bucket name (between `:` and the first `/`)
    pub bucket: String,
    /// bucket-relative key prefix: empty, or ending in `/`
    pub prefix: String,
    pub key_id: String,
    pub key_secret: String,
    /// custom S3 endpoint (empty = AWS default)
    pub endpoint: String,
    /// periodic push cadence (0 disables periodic pushes)
    pub interval: Duration,
}

impl SyncConfig {
    /// Build from raw knob values; empty `endpoint` = provider default.
    /// `Err` names the problem: callers degrade (state sync disabled /
    /// backup skipped) rather than guess.
    pub fn new(
        remote: String,
        key_id: String,
        key_secret: String,
        endpoint: String,
        interval: Duration,
    ) -> Result<Self, String> {
        let (bucket, prefix) = parse_remote(&remote)?;
        Ok(Self {
            remote,
            bucket,
            prefix,
            key_id,
            key_secret,
            endpoint,
            interval,
        })
    }
}

/// Parse `name:bucket[/prefix]`. The name before the colon is rclone
/// legacy and is accepted but ignored. Bucket sanity: non-empty, no
/// `/`, `:`, or whitespace — provider-specific rules are the operator's
/// business, exactly as they were with rclone. The prefix is normalized
/// to end with `/` (or be empty).
fn parse_remote(remote: &str) -> Result<(String, String), String> {
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
    Ok((bucket.to_string(), prefix))
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
            String::new(),
            Duration::from_secs(60),
        )
        .expect("valid remote");
        (cfg.bucket, cfg.prefix)
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
                    String::new(),
                    Duration::from_secs(60)
                )
                .is_err(),
                "{remote} must be rejected"
            );
        }
    }
}
