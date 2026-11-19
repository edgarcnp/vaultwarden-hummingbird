//! S3 connection settings shared by the state sync and the DB backup.
//! The `remote` knob keeps its `name:bucket[/prefix]` shape, but it is
//! parsed here into a [`RemoteSpec`] — the parts the in-crate S3 client
//! needs — no external tool consumes it anymore.

use std::time::Duration;

use anyhow::bail;

use crate::s3::RemoteSpec;

/// S3-backed persistence for the durable /data set (opt-in): the same
/// tailnet node, vaultwarden RSA keys, and user content survive ephemeral
/// redeploys.
#[derive(Clone)]
pub struct SyncConfig {
    /// the remote as configured (e.g. `r2:vw-state/sub`), for logs
    pub remote: String,
    /// the resolved bucket/prefix/credentials/endpoint
    pub target: RemoteSpec,
    /// periodic push cadence (0 disables periodic pushes)
    pub interval: Duration,
    /// The resolved tailscaled state file as a `/data`-relative name when it
    /// lives directly under `/data` (so it is inside the sync root).
    /// `None` = the identity file cannot be part of the durable set (a
    /// `mem:` state, or a path outside `/data`); the default
    /// `tailscaled.state` name is still accepted by the predicate.
    pub state_file: Option<String>,
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
    ) -> anyhow::Result<Self> {
        if endpoint.is_empty() {
            bail!(
                "SUPERVISOR_S3_ENDPOINT is required; every S3-compatible provider \
                 (AWS included) is configured by its endpoint"
            );
        }
        // Validate at config resolution, before a boot can depend on it.
        // The client repeats the parse (defense in depth).
        let parsed: url::Url = endpoint
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid SUPERVISOR_S3_ENDPOINT: {e}"))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            bail!("SUPERVISOR_S3_ENDPOINT must use http or https");
        }
        let target = parse_remote(&remote, key_id, key_secret, endpoint)?;
        Ok(Self {
            remote,
            target,
            interval,
            state_file: None,
        })
    }

    /// Point the sync at the configured state file, so a custom
    /// `TAILSCALE_STATE_FILE` under `/data` is still part of the durable
    /// set. A path outside `/data` (or `mem:`) stays unsynced — the caller
    /// logs that it cannot be covered.
    pub fn set_state_file(&mut self, state: &str) {
        // Only a normal, non-empty path under the state root is covered by
        // the sync root. A `/state/../etc` or control-character spelling is
        // not.
        self.state_file = state
            .strip_prefix("/state/")
            .filter(|rel| {
                // A leading slash here would make `root.join(rel)` absolute
                // and escape the state volume.
                !rel.is_empty()
                    && !rel.starts_with('/')
                    && !rel.contains("..")
                    && !rel.chars().any(char::is_control)
            })
            .map(str::to_string);
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
) -> anyhow::Result<RemoteSpec> {
    let Some((_, path)) = remote.split_once(':') else {
        bail!("must be remote:bucket[/prefix]");
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
        bail!("bucket must be non-empty and free of whitespace, ':' and '/'");
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

    /// A custom state file is stored under the state root; an extra leading
    /// slash after `/state/` must not turn it into an absolute path.
    #[test]
    fn state_file_mapping_never_escapes_the_state_root() {
        let mut cfg = SyncConfig::new(
            "r2:vw-state".into(),
            "id".into(),
            "secret".into(),
            "https://s3.example.invalid".into(),
            Duration::from_secs(60),
        )
        .expect("valid config");
        cfg.set_state_file("/state/tailscaled.state");
        assert_eq!(cfg.state_file.as_deref(), Some("tailscaled.state"));
        for state in [
            "/state//etc/passwd",
            "/state/../etc/passwd",
            "/state/sub/../x",
            "/state/a\nb",
        ] {
            cfg.set_state_file(state);
            assert_eq!(cfg.state_file, None, "{state} must not be mapped");
        }
    }

    /// The endpoint is parsed at resolution, not only at first request.
    #[test]
    fn malformed_endpoint_is_rejected() {
        assert!(
            SyncConfig::new(
                "r2:vw-state".into(),
                "id".into(),
                "secret".into(),
                "not a url".into(),
                Duration::from_secs(60)
            )
            .is_err()
        );
        assert!(
            SyncConfig::new(
                "r2:vw-state".into(),
                "id".into(),
                "secret".into(),
                "ftp://example.invalid".into(),
                Duration::from_secs(60)
            )
            .is_err()
        );
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
