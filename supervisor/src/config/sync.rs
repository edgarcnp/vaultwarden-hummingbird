//! S3 state-sync (opt-in via SUPERVISOR_S3_*): the [`SyncConfig`] carried
//! by `Config` and consumed by `crate::runtime::sync`, the runner — plus the
//! knob resolution that builds it from the env/file layer.

use std::time::Duration;

use super::consts::SYNC_INTERVAL_DEFAULT;
use crate::util::log;

/// Uppercased rclone remote name (the part before ':' in `remote:path`):
/// prefix of the RCLONE_CONFIG_* backend env vars.
pub(super) fn remote_env_name(remote: &str) -> String {
    remote.split(':').next().unwrap_or_default().to_uppercase()
}

/// Resolve the S3 state-sync knobs into a [`SyncConfig`]. Misconfigurations
/// degrade to sync disabled (never block the vault).
pub(super) fn resolve_sync(knob: &dyn Fn(&str, &str) -> String) -> Option<SyncConfig> {
    let remote = knob("SUPERVISOR_S3_REMOTE", "");
    let key_id = knob("SUPERVISOR_S3_ACCESS_KEY_ID", "");
    let key_secret = knob("SUPERVISOR_S3_SECRET_ACCESS_KEY", "");
    if remote.is_empty() {
        None
    } else if key_id.is_empty() || key_secret.is_empty() {
        log::err(
            "config: SUPERVISOR_S3_REMOTE set without SUPERVISOR_S3_ACCESS_KEY_ID/\
             SECRET_ACCESS_KEY; state sync disabled",
        );
        None
    } else if let Some((name_raw, _)) = remote.split_once(':') {
        let name = remote_env_name(name_raw);
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            log::err(&format!(
                "config: invalid SUPERVISOR_S3_REMOTE '{}' (remote name must be \
                 alphanumeric); state sync disabled",
                log::sanitize(&remote)
            ));
            None
        } else {
            let raw_interval = knob("SUPERVISOR_S3_SYNC_INTERVAL", "");
            let secs: u64 = match raw_interval.parse() {
                Ok(secs) => secs,
                Err(_) => {
                    log::err(&format!(
                        "config: invalid SUPERVISOR_S3_SYNC_INTERVAL '{}'; \
                         using default {SYNC_INTERVAL_DEFAULT}s",
                        log::sanitize(&raw_interval)
                    ));
                    SYNC_INTERVAL_DEFAULT
                }
            };
            Some(SyncConfig::new(
                remote,
                key_id,
                key_secret,
                knob("SUPERVISOR_S3_ENDPOINT", ""),
                Duration::from_secs(secs),
            ))
        }
    } else {
        log::err(&format!(
            "config: invalid SUPERVISOR_S3_REMOTE '{}' (must be remote:path); \
             state sync disabled",
            log::sanitize(&remote)
        ));
        None
    }
}

/// S3-backed persistence for /data identity files (opt-in): the same
/// tailnet node and vaultwarden RSA keys survive ephemeral redeploys.
/// Single instance per bucket. Cloned into [`super::backup::DbBackupConfig`],
/// which reuses the credentials and remote.
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
    /// in /proc. `RCLONE_CONFIG=/dev/null` disables the config file.
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
    use std::collections::BTreeMap;

    use super::*;

    /// resolve_sync over an explicit knob map (no process env touched).
    fn resolved(vars: &[(&str, &str)]) -> Option<SyncConfig> {
        let map: BTreeMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        resolve_sync(&|key, default| {
            map.get(key)
                .filter(|v| !v.is_empty())
                .cloned()
                .unwrap_or_else(|| default.to_string())
        })
    }

    const BASE: &[(&str, &str)] = &[
        ("SUPERVISOR_S3_REMOTE", "r2:vw-state"),
        ("SUPERVISOR_S3_ACCESS_KEY_ID", "id"),
        ("SUPERVISOR_S3_SECRET_ACCESS_KEY", "secret"),
    ];

    #[test]
    fn disabled_without_credentials_or_remote() {
        // remote without credentials: sync disabled
        assert!(resolved(&[("SUPERVISOR_S3_REMOTE", "r2:vw-state")]).is_none());
        // no remote at all: sync disabled
        assert!(resolved(&[]).is_none());
    }

    #[test]
    fn full_configuration_builds_rclone_env() {
        let sync = resolved(&[
            ("SUPERVISOR_S3_REMOTE", "r2:vw-state"),
            ("SUPERVISOR_S3_ACCESS_KEY_ID", "id"),
            ("SUPERVISOR_S3_SECRET_ACCESS_KEY", "secret"),
            (
                "SUPERVISOR_S3_ENDPOINT",
                "https://acct.r2.cloudflarestorage.com",
            ),
            ("SUPERVISOR_S3_SYNC_INTERVAL", "90"),
        ])
        .expect("sync enabled");
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
    fn invalid_interval_falls_back_to_default() {
        let mut vars: Vec<(&str, &str)> = BASE.to_vec();
        vars.push(("SUPERVISOR_S3_SYNC_INTERVAL", "not-a-number"));
        assert_eq!(
            resolved(&vars).expect("sync enabled").interval,
            Duration::from_secs(SYNC_INTERVAL_DEFAULT)
        );
    }

    /// A colon-less remote would make rclone write to a local path
    /// instead of the bucket.
    #[test]
    fn colon_less_remote_is_rejected() {
        let mut vars: Vec<(&str, &str)> = BASE.to_vec();
        *vars.first_mut().unwrap() = ("SUPERVISOR_S3_REMOTE", "mybucket");
        assert!(resolved(&vars).is_none());
        *vars.first_mut().unwrap() = ("SUPERVISOR_S3_REMOTE", "no-colon-here");
        assert!(resolved(&vars).is_none());
    }
}
