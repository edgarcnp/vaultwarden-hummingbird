//! S3 state-sync settings (opt-in via SUPERVISOR_S3_*): the [`SyncConfig`]
//! carried by `Config` and consumed by `crate::proc::sync`, the runner.

use std::time::Duration;

/// Uppercased rclone remote name (the part before ':' in `remote:path`):
/// prefix of the RCLONE_CONFIG_* backend env vars.
pub(super) fn remote_env_name(remote: &str) -> String {
    remote.split(':').next().unwrap_or_default().to_uppercase()
}

/// S3-backed persistence for `/data` identity files (opt-in): tailscaled's
/// node state and vaultwarden's RSA keys are synced via rclone to an
/// S3-compatible bucket, restoring the same tailnet node and JWT-signing
/// keys across ephemeral redeploys. Single instance per bucket.
pub struct SyncConfig {
    /// rclone destination `remote:path` (e.g. `r2:vw-state`)
    pub remote: String,
    /// backend env for the rclone child (RCLONE_CONFIG_*; carries secrets)
    pub env: Vec<(String, String)>,
    /// periodic push cadence (0 disables periodic pushes)
    pub interval: Duration,
}

impl SyncConfig {
    /// Build from raw knob values; `endpoint` empty means the provider's
    /// default (e.g. AWS). The rclone child gets backend config via env
    /// vars — never argv, whose cmdline is world-readable in /proc.
    /// `RCLONE_CONFIG=/dev/null` disables the config file (env-only remotes).
    pub fn new(
        remote: String,
        key_id: String,
        key_secret: String,
        endpoint: String,
        interval: Duration,
    ) -> Self {
        let name = remote_env_name(&remote);
        let mut env = vec![
            ("RCLONE_CONFIG".to_string(), "/dev/null".to_string()),
            (format!("RCLONE_CONFIG_{name}_TYPE"), "s3".to_string()),
            (format!("RCLONE_CONFIG_{name}_ACCESS_KEY_ID"), key_id),
            (
                format!("RCLONE_CONFIG_{name}_SECRET_ACCESS_KEY"),
                key_secret,
            ),
        ];
        if !endpoint.is_empty() {
            env.push((format!("RCLONE_CONFIG_{name}_ENDPOINT"), endpoint));
            // A custom endpoint means a non-AWS S3 flavor; "Other" is
            // rclone's generic fallback (works for R2/Ceph/Minio) and
            // silences the per-run "provider not known" NOTICE.
            env.push((
                format!("RCLONE_CONFIG_{name}_PROVIDER"),
                "Other".to_string(),
            ));
        }
        Self {
            remote,
            env,
            interval,
        }
    }
}
