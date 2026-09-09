//! S3 state-sync knob resolution (SUPERVISOR_S3_*): builds a
//! [`SyncConfig`] from the env/file layer. Misconfigurations degrade to
//! sync disabled (never block the vault).

use std::time::Duration;

use super::super::consts::SYNC_INTERVAL_DEFAULT;
use super::spec::{SyncConfig, remote_env_name};
use crate::util::log;

/// Resolve the S3 state-sync knobs into a [`SyncConfig`].
pub(crate) fn resolve_sync(knob: &dyn Fn(&str, &str) -> String) -> Option<SyncConfig> {
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

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
    fn full_configuration_resolves() {
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
        // env construction is specced in super::spec's tests
        assert!(sync.env.contains(&(
            "RCLONE_CONFIG_R2_ENDPOINT".to_string(),
            "https://acct.r2.cloudflarestorage.com".to_string()
        )));
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

    /// A colon-less remote would make rclone write to a local path instead
    /// of the bucket.
    #[test]
    fn colon_less_remote_is_rejected() {
        let mut vars: Vec<(&str, &str)> = BASE.to_vec();
        *vars.first_mut().unwrap() = ("SUPERVISOR_S3_REMOTE", "mybucket");
        assert!(resolved(&vars).is_none());
        *vars.first_mut().unwrap() = ("SUPERVISOR_S3_REMOTE", "no-colon-here");
        assert!(resolved(&vars).is_none());
    }
}
