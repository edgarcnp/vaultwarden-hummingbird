//! DB backup knob resolution (SUPERVISOR_DB_BACKUP*): builds a
//! [`DbBackupConfig`] from the env/file layer. Periodic dumps and boot-time
//! restore arm independently; misconfigurations degrade to backup disabled
//! (never block the vault).

use std::time::Duration;

use super::super::consts::{BACKUP_INTERVAL_DEFAULT, BACKUP_KEEP_DEFAULT, BACKUP_STAGING};
use super::super::dburl::{self, DbSpec};
use super::super::env::parse_bool;
use super::super::sync::SyncConfig;
use super::spec::DbBackupConfig;
use crate::util::log;

/// Resolve the DB backup knobs into a [`DbBackupConfig`].
pub(crate) fn resolve_backup(
    knob: &dyn Fn(&str, &str) -> String,
    sync: Option<&SyncConfig>,
    db_url: Option<String>,
) -> Option<DbBackupConfig> {
    let periodic = match knob("SUPERVISOR_DB_BACKUP", "").as_str() {
        "" => false,
        v => match parse_bool(v) {
            Some(b) => b,
            None => {
                log::err(&format!(
                    "config: invalid SUPERVISOR_DB_BACKUP '{}' (want true/false); \
                     periodic backups disabled",
                    log::sanitize(v)
                ));
                false
            }
        },
    };
    let restore = match knob("SUPERVISOR_DB_BACKUP_RESTORE", "").as_str() {
        "" => false,
        v => match parse_bool(v) {
            Some(b) => b,
            None => {
                log::err(&format!(
                    "config: invalid SUPERVISOR_DB_BACKUP_RESTORE '{}' (want true/false); \
                     restore disabled",
                    log::sanitize(v)
                ));
                false
            }
        },
    };
    if !periodic && !restore {
        return None;
    }
    let Some(sync) = sync else {
        log::err(
            "config: SUPERVISOR_DB_BACKUP* set without SUPERVISOR_S3_REMOTE and \
             SUPERVISOR_S3_ACCESS_KEY_ID/SECRET_ACCESS_KEY; backup disabled",
        );
        return None;
    };

    // The vault's DB: explicit VAULTWARDEN_DATABASE_URL, else vaultwarden's
    // own default (sqlite under DATA_FOLDER, which the image pins to /data).
    let url = db_url
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .unwrap_or("/data/db.sqlite3")
        .to_string();
    let db = match db_url.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
        Some(url) => match dburl::parse(url) {
            Some(spec) => spec,
            None => {
                log::err(&format!(
                    "config: unsupported VAULTWARDEN_DATABASE_URL scheme '{}' (want postgres://, \
                     mysql:// or sqlite://); backup disabled",
                    log::sanitize(&dburl::scheme_for_log(url))
                ));
                return None;
            }
        },
        None => {
            log::info(
                "config: no VAULTWARDEN_DATABASE_URL; backup assumes the default sqlite DB at /data/db.sqlite3",
            );
            DbSpec::Sqlite {
                path: "/data/db.sqlite3".to_string(),
            }
        }
    };

    let raw_interval = knob("SUPERVISOR_DB_BACKUP_INTERVAL", "");
    let secs = match raw_interval.parse::<u64>() {
        Ok(s) if s > 0 => s,
        Ok(_) => {
            log::err("config: SUPERVISOR_DB_BACKUP_INTERVAL=0; using default");
            BACKUP_INTERVAL_DEFAULT
        }
        Err(_) => {
            if !raw_interval.is_empty() {
                log::err(&format!(
                    "config: invalid SUPERVISOR_DB_BACKUP_INTERVAL '{}'; \
                     using default {BACKUP_INTERVAL_DEFAULT}s",
                    log::sanitize(&raw_interval)
                ));
            }
            BACKUP_INTERVAL_DEFAULT
        }
    };

    let raw_keep = knob("SUPERVISOR_DB_BACKUP_KEEP", "");
    let keep = match raw_keep.parse::<u64>() {
        Ok(k) if k > 0 => k,
        Ok(_) => {
            log::err(
                "config: SUPERVISOR_DB_BACKUP_KEEP=0 would delete every backup; using default",
            );
            BACKUP_KEEP_DEFAULT
        }
        Err(_) => {
            if !raw_keep.is_empty() {
                log::err(&format!(
                    "config: invalid SUPERVISOR_DB_BACKUP_KEEP '{}'; \
                     using default {BACKUP_KEEP_DEFAULT}",
                    log::sanitize(&raw_keep)
                ));
            }
            BACKUP_KEEP_DEFAULT
        }
    };

    Some(DbBackupConfig {
        sync: sync.clone(),
        url,
        db,
        periodic,
        interval: Duration::from_secs(secs),
        keep: keep as usize,
        restore,
        staging: BACKUP_STAGING.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use super::super::spec::DbBackupConfig;
    use super::*;

    const S3_KNOBS: &[(&str, &str)] = &[
        ("SUPERVISOR_S3_REMOTE", "r2:vw-state"),
        ("SUPERVISOR_S3_ACCESS_KEY_ID", "id"),
        ("SUPERVISOR_S3_SECRET_ACCESS_KEY", "secret"),
    ];

    /// resolve_backup over an explicit knob map (no process env touched).
    fn resolved(vars: &[(&str, &str)]) -> Option<DbBackupConfig> {
        let map: BTreeMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let sync = crate::config::sync::resolve_sync(&|key, default| {
            map.get(key)
                .filter(|v| !v.is_empty())
                .cloned()
                .unwrap_or_else(|| default.to_string())
        });
        resolve_backup(
            &|key, default| {
                map.get(key)
                    .filter(|v| !v.is_empty())
                    .cloned()
                    .unwrap_or_else(|| default.to_string())
            },
            sync.as_ref(),
            None,
        )
    }

    /// resolve_backup with an explicit db_url (the VAULTWARDEN_DATABASE_URL
    /// path).
    fn resolved_with_url(vars: &[(&str, &str)], db_url: &str) -> Option<DbBackupConfig> {
        let map: BTreeMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let sync = crate::config::sync::resolve_sync(&|key, default| {
            map.get(key)
                .filter(|v| !v.is_empty())
                .cloned()
                .unwrap_or_else(|| default.to_string())
        });
        resolve_backup(
            &|key, default| {
                map.get(key)
                    .filter(|v| !v.is_empty())
                    .cloned()
                    .unwrap_or_else(|| default.to_string())
            },
            sync.as_ref(),
            Some(db_url.to_string()),
        )
    }

    #[test]
    fn disabled_by_default_and_by_bad_flags() {
        assert!(resolved(S3_KNOBS).is_none());
        assert!(resolved(&[("SUPERVISOR_DB_BACKUP", "true")]).is_none());
        // invalid flag values degrade to disabled (warn only)
        assert!(
            resolved(&[
                S3_KNOBS[0],
                S3_KNOBS[1],
                S3_KNOBS[2],
                ("SUPERVISOR_DB_BACKUP", "definitely")
            ])
            .is_none()
        );
    }

    #[test]
    fn requires_s3_state_sync() {
        assert!(resolved(&[("SUPERVISOR_DB_BACKUP", "true")]).is_none());
        assert!(resolved(&[("SUPERVISOR_DB_BACKUP_RESTORE", "true")]).is_none());
        // remote without credentials disables sync itself -> no backup
        assert!(
            resolved(&[
                ("SUPERVISOR_S3_REMOTE", "r2:vw-state"),
                ("SUPERVISOR_DB_BACKUP", "true"),
            ])
            .is_none()
        );
    }

    #[test]
    fn periodic_enables_with_defaults() {
        let mut vars: Vec<(&str, &str)> = S3_KNOBS.to_vec();
        vars.push(("SUPERVISOR_DB_BACKUP", "true"));
        let cfg = resolved(&vars).expect("backup enabled");
        assert!(cfg.periodic);
        assert!(!cfg.restore);
        assert_eq!(cfg.interval, Duration::from_secs(BACKUP_INTERVAL_DEFAULT));
        assert_eq!(cfg.keep, BACKUP_KEEP_DEFAULT as usize);
        // no VAULTWARDEN_DATABASE_URL -> default sqlite
        assert_eq!(
            cfg.db,
            DbSpec::Sqlite {
                path: "/data/db.sqlite3".into()
            }
        );
        assert_eq!(cfg.prefix(), "r2:vw-state/db");
    }

    #[test]
    fn restore_only_arms_restore() {
        let cfg = resolved_with_url(
            &[
                S3_KNOBS[0],
                S3_KNOBS[1],
                S3_KNOBS[2],
                ("SUPERVISOR_DB_BACKUP_RESTORE", "true"),
            ],
            "postgres://u:p@h/db",
        )
        .expect("restore enabled");
        assert!(!cfg.periodic);
        assert!(cfg.restore);
        assert_eq!(cfg.db.label(), "postgres");
    }

    #[test]
    fn knobs_parse_and_degrade_to_defaults() {
        let mut vars: Vec<(&str, &str)> = S3_KNOBS.to_vec();
        vars.push(("SUPERVISOR_DB_BACKUP", "true"));
        vars.push(("SUPERVISOR_DB_BACKUP_INTERVAL", "90"));
        vars.push(("SUPERVISOR_DB_BACKUP_KEEP", "5"));
        let cfg = resolved(&vars).expect("enabled");
        assert_eq!(cfg.interval, Duration::from_secs(90));
        assert_eq!(cfg.keep, 5);

        for (knob, value) in [
            ("SUPERVISOR_DB_BACKUP_INTERVAL", "not-a-number"),
            ("SUPERVISOR_DB_BACKUP_INTERVAL", "0"),
            ("SUPERVISOR_DB_BACKUP_KEEP", "not-a-number"),
            ("SUPERVISOR_DB_BACKUP_KEEP", "0"),
        ] {
            let mut vars: Vec<(&str, &str)> = S3_KNOBS.to_vec();
            vars.push(("SUPERVISOR_DB_BACKUP", "true"));
            vars.push((knob, value));
            let cfg = resolved(&vars).expect("still enabled");
            if knob.ends_with("INTERVAL") {
                assert_eq!(cfg.interval, Duration::from_secs(BACKUP_INTERVAL_DEFAULT));
            } else {
                assert_eq!(cfg.keep, BACKUP_KEEP_DEFAULT as usize);
            }
        }
    }

    #[test]
    fn unsupported_url_disables() {
        // VAULTWARDEN_DATABASE_URL is not a supervisor knob; it reaches the
        // resolver through the db_url argument, mirroring what env::build does.
        assert!(
            resolved_with_url(
                &[
                    S3_KNOBS[0],
                    S3_KNOBS[1],
                    S3_KNOBS[2],
                    ("SUPERVISOR_DB_BACKUP", "true"),
                ],
                "oracle://u:p@h/db",
            )
            .is_none()
        );
    }
}
