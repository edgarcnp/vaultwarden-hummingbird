//! S3 state-sync settings for rclone, reused by the DB backup.

use std::time::Duration;

/// Uppercased rclone remote name: prefix of the RCLONE_CONFIG_* env vars.
pub(super) fn remote_env_name(remote: &str) -> String {
    remote.split(':').next().unwrap_or_default().to_uppercase()
}

/// S3-backed persistence for /data identity files (opt-in): the same
/// tailnet node and vaultwarden RSA keys survive ephemeral redeploys.
#[derive(Clone)]
pub struct SyncConfig {
    /// rclone destination `remote:path` (e.g. `r2:vw-state`)
    pub remote: String,
    /// backend env for the rclone child (RCLONE_CONFIG_*; carries secrets)
    pub env: Vec<(String, String)>,
    /// periodic push cadence (0 disables periodic pushes)
    pub interval: Duration,
}

impl SyncConfig {
    /// Build from raw knob values; empty `endpoint` = provider default.
    /// Backend config rides env — never argv, which is world-readable
    /// in /proc.
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn endpoint_builds_provider_env() {
        let sync = SyncConfig::new(
            "r2:vw-state".to_string(),
            "id".to_string(),
            "secret".to_string(),
            "https://acct.r2.cloudflarestorage.com".to_string(),
            Duration::from_secs(90),
        );
        assert_eq!(sync.remote, "r2:vw-state");
        assert_eq!(sync.interval, Duration::from_secs(90));
        assert_eq!(
            sync.env,
            vec![
                ("RCLONE_CONFIG".to_string(), "/dev/null".to_string()),
                ("RCLONE_CONFIG_R2_TYPE".to_string(), "s3".to_string()),
                (
                    "RCLONE_CONFIG_R2_ACCESS_KEY_ID".to_string(),
                    "id".to_string()
                ),
                (
                    "RCLONE_CONFIG_R2_SECRET_ACCESS_KEY".to_string(),
                    "secret".to_string()
                ),
                (
                    "RCLONE_CONFIG_R2_ENDPOINT".to_string(),
                    "https://acct.r2.cloudflarestorage.com".to_string()
                ),
                ("RCLONE_CONFIG_R2_PROVIDER".to_string(), "Other".to_string()),
            ]
        );
    }

    #[test]
    fn no_endpoint_stays_aws_default() {
        let sync = SyncConfig::new(
            "r2:vw-state".to_string(),
            "id".to_string(),
            "secret".to_string(),
            String::new(),
            Duration::from_secs(60),
        );
        assert_eq!(
            sync.env,
            vec![
                ("RCLONE_CONFIG".to_string(), "/dev/null".to_string()),
                ("RCLONE_CONFIG_R2_TYPE".to_string(), "s3".to_string()),
                (
                    "RCLONE_CONFIG_R2_ACCESS_KEY_ID".to_string(),
                    "id".to_string()
                ),
                (
                    "RCLONE_CONFIG_R2_SECRET_ACCESS_KEY".to_string(),
                    "secret".to_string()
                ),
            ]
        );
    }
}
