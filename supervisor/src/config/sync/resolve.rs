//! S3 state-sync knob resolution (SUPERVISOR_S3_*): builds a
//! [`SyncConfig`] from the env/file layer. Misconfigurations degrade to
//! sync disabled (never block the vault).

use std::time::Duration;

use super::super::consts::SYNC_INTERVAL_DEFAULT;
use super::super::env::parse_count;
use super::spec::SyncConfig;
use crate::util::log;

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
    } else {
        match SyncConfig::new(
            remote.clone(),
            key_id,
            key_secret,
            knob("SUPERVISOR_S3_ENDPOINT", ""),
            Duration::from_secs(parse_count(
                "SUPERVISOR_S3_SYNC_INTERVAL",
                &knob("SUPERVISOR_S3_SYNC_INTERVAL", ""),
                SYNC_INTERVAL_DEFAULT,
            )),
        ) {
            Ok(sync) => Some(sync),
            Err(e) => {
                log::err(&format!(
                    "config: invalid SUPERVISOR_S3_* configuration ({e}); state sync disabled"
                ));
                None
            }
        }
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
        ("SUPERVISOR_S3_ENDPOINT", "https://s3.example.invalid"),
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
        assert_eq!(sync.target.bucket, "vw-state");
        assert_eq!(sync.prefix(), "");
        assert_eq!(
            sync.target.endpoint,
            "https://acct.r2.cloudflarestorage.com"
        );
        assert_eq!(sync.interval, Duration::from_secs(90));
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

    /// A colon-less remote would once have made rclone write to a local
    /// path instead of the bucket; it is still rejected.
    #[test]
    fn malformed_remotes_are_rejected() {
        for remote in ["mybucket", "no-colon-here", "r2:"] {
            let mut vars: Vec<(&str, &str)> = BASE.to_vec();
            *vars.first_mut().unwrap() = ("SUPERVISOR_S3_REMOTE", remote);
            assert!(resolved(&vars).is_none(), "{remote} must be rejected");
        }
    }
}
