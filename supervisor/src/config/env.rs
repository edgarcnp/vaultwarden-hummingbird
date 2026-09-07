//! Supervisor config resolution: merge the process env, the optional
//! dotenv-file knobs, and code defaults into a validated [`Config`] (all
//! lookups done once at boot). The pieces live in sibling modules:
//! `consts` (static values), `sync` / `keepalive` (feature settings),
//! `dotenv` (the file layer).

use std::env;
use std::time::Duration;

use super::consts::SYNC_INTERVAL_DEFAULT;
use super::dotenv::FileConfig;
use super::keepalive::DbKeepalive;
use super::sync::{SyncConfig, remote_env_name};
use crate::util::log;

/// Keys owned by the supervisor (localized to PID 1): they configure the
/// supervisor/tailscale/S3-sync and are filtered out of the vaultwarden
/// child's env.
pub fn is_supervisor_key(key: &str) -> bool {
    key.starts_with("TS_") || key.starts_with("SUPERVISOR_")
}

/// `Some(v)` only for non-empty values: empty env/file entries are treated
/// as unset everywhere (an empty port or remote is never valid).
fn non_empty(v: Option<String>) -> Option<String> {
    v.filter(|v| !v.is_empty())
}

/// `Some(v)` only for a valid TCP port: 1-65535, digits only. A non-numeric
/// or out-of-range value logs a warning and falls back to the default
/// instead of breaking `tailscale serve` or the vaultwarden listener.
fn valid_port(v: Option<String>) -> Option<String> {
    let v = non_empty(v)?;
    match v.parse::<u16>() {
        Ok(p) if p != 0 => Some(v),
        _ => {
            log::err(&format!(
                "config: invalid port '{}' (want 1-65535); using default",
                log::sanitize(&v)
            ));
            None
        }
    }
}

/// Lenient boolean parse for the TS_* on/off knobs: the common spellings in
/// any casing. Anything else (including empty — handled as unset by the
/// caller) is `None`; callers warn and fall back to the default.
fn parse_bool(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Resolved supervisor configuration (all env/file lookups done once at boot).
pub struct Config {
    /// tailscaled state file (under the writable data volume)
    pub state: String,
    /// LocalAPI unix socket (must live on a writable, non-volume path)
    pub socket: String,
    /// exposed (gatekeeper) listen port: PORT wins, then ROCKET_PORT, else
    /// 8080 (non-root cannot bind 80)
    pub port: String,
    /// vaultwarden's own port, derived as `port + 1` and bound loopback-only
    /// (only `tailscale serve` and the gatekeeper's proxy-free design touch
    /// it). None = the exposed port leaves no room (65535): boot must fail
    /// closed — the caller refuses to run rather than co-binding or exposing
    /// vaultwarden directly.
    pub vault_port: Option<String>,
    /// node name announced to the tailnet (`TS_HOSTNAME`)
    pub hostname: String,
    /// Tailscale auth key or OAuth client secret (`TS_AUTHKEY`; empty = skip `up`)
    pub authkey: String,
    /// configure `tailscale serve` after a successful up (inbound tailnet path)
    pub serve: bool,
    /// userspace networking: no TUN device on PaaS platforms
    pub userspace: bool,
    /// S3 state sync (None = disabled)
    pub sync: Option<SyncConfig>,
    /// DB keepalive ping (None = disabled)
    pub db_keepalive: Option<DbKeepalive>,
    /// verbatim vaultwarden env names -> values (from the dotenv file, if any)
    pub vw_env: Vec<(String, String)>,
}

impl Config {
    /// Merge order:
    ///   supervisor knobs (TS_*/SUPERVISOR_*): process env > file > code defaults
    ///   port: PORT env > ROCKET_PORT env > file ROCKET_PORT > 8080
    ///   vault_port: port + 1 (internal, loopback-only)
    ///   vaultwarden keys: file > container env (applied in proc::run_vaultwarden)
    /// Empty values (env or file) are treated as unset. Boolean knobs
    /// (TS_SERVE/TS_USERSPACE) accept true/false/1/0/yes/no/on/off in any
    /// casing; other values warn and take the default.
    pub fn from_env() -> Self {
        Self::build(FileConfig::load(), |k| env::var(k).ok())
    }

    /// [`from_env`] with the env source injected. Tests pass a map instead
    /// of the process env: `std::env::set_var` is unsafe (and racy against
    /// any thread reading the env concurrently), so tests never mutate it.
    fn build(file: FileConfig, lookup: impl Fn(&str) -> Option<String>) -> Self {
        let port = valid_port(lookup("PORT"))
            .or_else(|| valid_port(lookup("ROCKET_PORT")))
            .or_else(|| valid_port(file.child.get("ROCKET_PORT").cloned()))
            .unwrap_or_else(|| "8080".into());
        let vault_port = port
            .parse::<u16>()
            .ok()
            .and_then(|p| p.checked_add(1))
            .map(|p| p.to_string());

        let knob = |key: &str, default: &str| -> String {
            non_empty(lookup(key))
                .or_else(|| non_empty(file.knobs.get(key).cloned()))
                .unwrap_or_else(|| default.to_string())
        };

        let sync = resolve_sync(&knob);

        // Lenient bool knobs: misspellings warn and take the default rather
        // than silently flipping the feature off.
        let flag = |key: &str, default: bool| -> bool {
            match knob(key, "") {
                v if v.is_empty() => default,
                v => match parse_bool(&v) {
                    Some(b) => b,
                    None => {
                        log::err(&format!(
                            "config: invalid {key} '{}' (want true/false); using default {default}",
                            log::sanitize(&v)
                        ));
                        default
                    }
                },
            }
        };

        Self {
            // Hard-pinned to the /data volume (the sync scope is /data too).
            state: knob("TS_STATE_FILE", "/data/tailscaled.state"),
            socket: knob("TS_SOCKET", "/tmp/tailscaled.sock"),
            port,
            vault_port,
            hostname: knob("TS_HOSTNAME", "vaultwarden"),
            authkey: knob("TS_AUTHKEY", ""),
            serve: flag("TS_SERVE", true),
            userspace: flag("TS_USERSPACE", true),
            sync,
            // DATABASE_URL is a vaultwarden (child) key: file wins over
            // process env, matching run_vaultwarden's child precedence —
            // the ping must reach the same DB the vault uses.
            db_keepalive: DbKeepalive::from_parts(
                &knob("SUPERVISOR_DB_KEEPALIVE", ""),
                file.child
                    .get("DATABASE_URL")
                    .cloned()
                    .or_else(|| non_empty(lookup("DATABASE_URL"))),
            ),
            vw_env: file.child.into_iter().collect(),
        }
    }
}

/// Resolve the S3 state-sync knobs into a [`SyncConfig`]. Misconfigurations
/// degrade to sync disabled (never block the vault).
fn resolve_sync(knob: &dyn Fn(&str, &str) -> String) -> Option<SyncConfig> {
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
    use std::fs;

    use super::*;

    /// Config from an explicit variable map + optional dotenv file layer.
    /// Tests never touch the process env: `std::env::set_var` is unsafe
    /// (and racy against any concurrent env reader), so merge-order
    /// coverage goes through [`Config::build`] with an injected lookup.
    fn mk(vars: &[(&str, &str)]) -> Config {
        mk_with_file(vars, FileConfig::default())
    }

    fn mk_with_file(vars: &[(&str, &str)], file: FileConfig) -> Config {
        let map: BTreeMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::build(file, move |k| map.get(k).cloned())
    }

    #[test]
    fn supervisor_keys_are_namespaced() {
        for key in [
            "TS_AUTHKEY",
            "TS_SERVE",
            "SUPERVISOR_ENV_FILE",
            "SUPERVISOR_X",
        ] {
            assert!(is_supervisor_key(key), "{key} should be supervisor-owned");
        }
        for key in ["TS", "SUPERVISOR", "ts_authkey", "PORT", "DATABASE_URL"] {
            assert!(!is_supervisor_key(key), "{key} should reach the child");
        }
    }

    #[test]
    fn port_validation() {
        assert_eq!(valid_port(Some("8080".into())).as_deref(), Some("8080"));
        assert_eq!(valid_port(Some("1".into())).as_deref(), Some("1"));
        assert_eq!(valid_port(Some("65535".into())).as_deref(), Some("65535"));
        assert_eq!(valid_port(Some("0".into())), None);
        assert_eq!(valid_port(Some("65536".into())), None);
        assert_eq!(valid_port(Some("-1".into())), None);
        assert_eq!(valid_port(Some("8080\n".into())), None);
        assert_eq!(valid_port(Some("".into())), None);
        assert_eq!(valid_port(None), None);
        assert_eq!(valid_port(Some("abc".into())), None);
    }

    #[test]
    fn defaults_and_merge_order() {
        let cfg = mk(&[]);
        assert_eq!(cfg.port, "8080");
        assert_eq!(cfg.vault_port.as_deref(), Some("8081"));
        assert_eq!(cfg.socket, "/tmp/tailscaled.sock");
        assert_eq!(cfg.state, "/data/tailscaled.state");
        assert_eq!(cfg.hostname, "vaultwarden");
        assert_eq!(cfg.authkey, "");
        assert!(cfg.serve && cfg.userspace);
        assert!(cfg.vw_env.is_empty());
        assert!(cfg.sync.is_none());

        let cfg = mk(&[("PORT", "3000"), ("ROCKET_PORT", "1111")]);
        assert_eq!(cfg.port, "3000");
        assert_eq!(cfg.vault_port.as_deref(), Some("3001"));
        let cfg = mk(&[("ROCKET_PORT", "1111")]);
        assert_eq!(cfg.port, "1111");
        let cfg = mk(&[("PORT", ""), ("ROCKET_PORT", "")]);
        assert_eq!(cfg.port, "8080");

        // 65535 leaves no room above the exposed port: the derivation yields
        // None, which the caller must treat as refuse-to-start (fail closed).
        let cfg = mk(&[("PORT", "65535")]);
        assert_eq!(cfg.port, "65535");
        assert_eq!(cfg.vault_port, None);
    }

    #[test]
    fn dotenv_file_merges_below_process_env() {
        let path = std::env::temp_dir().join(format!("vw-sup-cfg-{}.env", std::process::id()));
        fs::write(
            &path,
            "ROCKET_PORT=2222\nTS_HOSTNAME=file-host\nTS_AUTHKEY=file-key\nTS_SERVE=false\nDOMAIN=https://f.example\n",
        )
        .unwrap();
        let path_str = path.to_str().unwrap();

        let cfg = mk_with_file(&[], FileConfig::load_from(Some(path_str)));
        assert_eq!(cfg.port, "2222");
        assert_eq!(cfg.hostname, "file-host");
        assert_eq!(cfg.authkey, "file-key");
        assert!(!cfg.serve);
        assert!(cfg.userspace);
        assert_eq!(
            cfg.vw_env
                .iter()
                .find(|(k, _)| k == "DOMAIN")
                .map(|(_, v)| v.as_str()),
            Some("https://f.example")
        );
        assert!(cfg.vw_env.iter().any(|(k, _)| k == "ROCKET_PORT"));
        assert!(!cfg.vw_env.iter().any(|(k, _)| is_supervisor_key(k)));

        // process env wins over the file for supervisor knobs
        let cfg = mk_with_file(
            &[("TS_HOSTNAME", "env-host")],
            FileConfig::load_from(Some(path_str)),
        );
        assert_eq!(cfg.hostname, "env-host");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn s3_sync_knobs() {
        // remote without credentials: sync disabled
        let cfg = mk(&[("SUPERVISOR_S3_REMOTE", "r2:vw-state")]);
        assert!(cfg.sync.is_none());

        let mut vars: Vec<(&str, &str)> = vec![
            ("SUPERVISOR_S3_REMOTE", "r2:vw-state"),
            ("SUPERVISOR_S3_ACCESS_KEY_ID", "id"),
            ("SUPERVISOR_S3_SECRET_ACCESS_KEY", "secret"),
            (
                "SUPERVISOR_S3_ENDPOINT",
                "https://acct.r2.cloudflarestorage.com",
            ),
            ("SUPERVISOR_S3_SYNC_INTERVAL", "90"),
        ];
        let sync = mk(&vars).sync.expect("sync enabled");
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

        *vars.last_mut().unwrap() = ("SUPERVISOR_S3_SYNC_INTERVAL", "not-a-number");
        assert_eq!(
            mk(&vars).sync.expect("sync enabled").interval,
            Duration::from_secs(SYNC_INTERVAL_DEFAULT)
        );

        // A colon-less remote would make rclone write to a local path
        // instead of the bucket.
        *vars.first_mut().unwrap() = ("SUPERVISOR_S3_REMOTE", "mybucket");
        assert!(mk(&vars).sync.is_none());
        *vars.first_mut().unwrap() = ("SUPERVISOR_S3_REMOTE", "no-colon-here");
        assert!(mk(&vars).sync.is_none());
    }

    #[test]
    fn lenient_bool_knobs() {
        // Common spellings in any casing parse.
        let cfg = mk(&[("TS_SERVE", "YES"), ("TS_USERSPACE", "0")]);
        assert!(cfg.serve);
        assert!(!cfg.userspace);

        // A misspelling warns and takes the default instead of silently
        // disabling the feature.
        let cfg = mk(&[("TS_SERVE", "definitely")]);
        assert!(cfg.serve);
    }
}
