//! S3 state-sync knob resolution (SUPERVISOR_S3_*): builds a
//! [`SyncConfig`] from the env/file layer. Misconfigurations degrade to
//! sync disabled (never block the vault).

use std::time::Duration;

use super::super::consts::{MAX_INTERVAL_SECS, SYNC_INTERVAL_DEFAULT, SYNC_TIMEOUT};
use super::super::env::{parse_count, parse_flag};
use super::spec::SyncConfig;
use crate::config::consts::SUPERVISOR_STATE;
use crate::s3::{BucketStyle, Client, validate_ca_file};
use crate::util::log;

/// A CA bundle decides which server the supervisor trusts; the vault must
/// not be able to replace it. Require a normal path under `/state`.
fn ca_path_isolated(path: &str) -> bool {
    use std::path::Component;

    let path = std::path::Path::new(path);
    path.is_absolute()
        && path.starts_with(SUPERVISOR_STATE)
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

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
        let raw_interval = knob("SUPERVISOR_S3_SYNC_INTERVAL", "");
        let secs = match parse_count(
            "SUPERVISOR_S3_SYNC_INTERVAL",
            &raw_interval,
            SYNC_INTERVAL_DEFAULT,
        ) {
            s if s > MAX_INTERVAL_SECS => {
                log::err(&format!(
                    "config: SUPERVISOR_S3_SYNC_INTERVAL={s} exceeds the \
                     {MAX_INTERVAL_SECS}-second cap; using default"
                ));
                SYNC_INTERVAL_DEFAULT
            }
            s => s,
        };
        let mut sync = match SyncConfig::new(
            remote.clone(),
            key_id,
            key_secret,
            knob("SUPERVISOR_S3_ENDPOINT", ""),
            Duration::from_secs(secs),
        ) {
            Ok(sync) => sync,
            Err(e) => {
                log::err(&format!(
                    "config: invalid SUPERVISOR_S3_* configuration ({e}); state sync disabled"
                ));
                return None;
            }
        };
        sync.set_allow_http(parse_flag(
            "SUPERVISOR_S3_ALLOW_HTTP",
            &knob("SUPERVISOR_S3_ALLOW_HTTP", ""),
            false,
        ));
        let ca = knob("SUPERVISOR_S3_CA_FILE", "");
        if !ca.is_empty() {
            if !ca_path_isolated(&ca) {
                log::err(&format!(
                    "config: SUPERVISOR_S3_CA_FILE {} must live under /state (the \
                     vault can rewrite a CA on its own volume); state sync disabled",
                    log::sanitize(&ca)
                ));
                return None;
            }
            if let Err(e) = validate_ca_file(&ca) {
                log::err(&format!(
                    "config: unusable SUPERVISOR_S3_CA_FILE {} ({e}); state sync disabled",
                    log::sanitize(&ca)
                ));
                return None;
            }
            sync.set_ca_file(ca);
        }
        let region = knob("SUPERVISOR_S3_REGION", "");
        if !region.is_empty() {
            if !region
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
            {
                log::err(
                    "config: SUPERVISOR_S3_REGION must be letters, digits, and '-'; \
                     state sync disabled",
                );
                return None;
            }
            sync.set_region(region);
        }
        match knob("SUPERVISOR_S3_URL_STYLE", "path").as_str() {
            "path" => sync.set_style(BucketStyle::Path),
            "virtual" | "virtual-hosted" => sync.set_style(BucketStyle::VirtualHosted),
            other => {
                log::err(&format!(
                    "config: SUPERVISOR_S3_URL_STYLE '{}' is not 'path' or 'virtual'; \
                     state sync disabled",
                    log::sanitize(other)
                ));
                return None;
            }
        }
        // Build the transport once now: this validates the endpoint scheme
        // (plaintext HTTP policy), bucket shape, region/style, and CA bundle
        // before a boot depends on the feature. No network request is made.
        if let Err(e) = Client::connect(&sync.target, SYNC_TIMEOUT) {
            log::err(&format!(
                "config: unusable SUPERVISOR_S3_* transport ({e}); state sync disabled"
            ));
            return None;
        }
        Some(sync)
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
    fn transport_options_resolve() {
        let mut vars: Vec<(&str, &str)> = BASE.to_vec();
        vars.extend([
            ("SUPERVISOR_S3_ALLOW_HTTP", "true"),
            ("SUPERVISOR_S3_REGION", "eu-west-1"),
            ("SUPERVISOR_S3_URL_STYLE", "virtual"),
        ]);
        let sync = resolved(&vars).expect("options resolve");
        assert!(sync.target.allow_http);
        assert_eq!(sync.target.region.as_deref(), Some("eu-west-1"));
        assert_eq!(sync.target.style, BucketStyle::VirtualHosted);

        let mut vars: Vec<(&str, &str)> = BASE.to_vec();
        vars.push(("SUPERVISOR_S3_URL_STYLE", "bogus"));
        assert!(resolved(&vars).is_none(), "a typo'd style disables sync");

        let mut vars: Vec<(&str, &str)> = BASE.to_vec();
        vars.push(("SUPERVISOR_S3_CA_FILE", "/nonexistent/ca.pem"));
        assert!(resolved(&vars).is_none(), "an unreadable CA disables sync");

        // Plaintext HTTP to a remote host is refused by the transport.
        let mut vars: Vec<(&str, &str)> = BASE.to_vec();
        *vars.last_mut().unwrap() = ("SUPERVISOR_S3_ENDPOINT", "http://s3.example.invalid");
        assert!(
            resolved(&vars).is_none(),
            "remote plaintext HTTP disables sync"
        );
        let mut vars: Vec<(&str, &str)> = BASE.to_vec();
        *vars.last_mut().unwrap() = ("SUPERVISOR_S3_ENDPOINT", "http://s3.example.invalid");
        vars.push(("SUPERVISOR_S3_ALLOW_HTTP", "true"));
        assert!(
            resolved(&vars).is_some(),
            "the explicit opt-in allows plaintext HTTP"
        );
    }

    #[test]
    fn the_ca_bundle_must_live_on_the_supervisor_volume() {
        assert!(ca_path_isolated("/state/s3-ca.pem"));
        assert!(ca_path_isolated("/state/tls/ca.pem"));
        assert!(!ca_path_isolated("/data/s3-ca.pem"));
        assert!(!ca_path_isolated("/tmp/ca.pem"));
        assert!(!ca_path_isolated("/state/../data/ca.pem"));
        assert!(!ca_path_isolated("state/ca.pem"));
    }

    #[test]
    fn invalid_interval_falls_back_to_default() {
        let mut vars: Vec<(&str, &str)> = BASE.to_vec();
        vars.push(("SUPERVISOR_S3_SYNC_INTERVAL", "not-a-number"));
        assert_eq!(
            resolved(&vars).expect("sync enabled").interval,
            Duration::from_secs(SYNC_INTERVAL_DEFAULT)
        );
        // an absurd value (scheduler overflow territory) degrades too
        let mut vars: Vec<(&str, &str)> = BASE.to_vec();
        vars.push(("SUPERVISOR_S3_SYNC_INTERVAL", "18446744073709551615"));
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
