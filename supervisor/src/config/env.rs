//! Config resolution: process env + optional supervisor-owned dotenv file.

use std::env;
use std::time::Duration;

use super::dotenv::FileConfig;
use crate::util::log;

/// Hard-coded child binary paths (baked into the image, no PATH lookup).
pub const TAILSCALED: &str = "/usr/local/bin/tailscaled";
/// `tailscale` CLI (drives `up`/`serve` over the LocalAPI socket).
pub const TAILSCALE: &str = "/usr/local/bin/tailscale";
/// vaultwarden server binary (the payload this container exists to run).
pub const VAULTWARDEN: &str = "/vaultwarden";
/// rclone binary (S3 state sync; baked into the image by the fetch stage).
pub const RCLONE: &str = "/usr/local/bin/rclone";

/// Hard timeouts: never let a hung tailscaled block the vault.
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(90);
/// Hard timeout for `tailscale serve`.
pub const SERVE_TIMEOUT: Duration = Duration::from_secs(30);
/// Hard timeout waiting for tailscaled's LocalAPI socket.
pub const DAEMON_WAIT: Duration = Duration::from_secs(30);
/// Hard timeout for one rclone state-sync operation.
pub const SYNC_TIMEOUT: Duration = Duration::from_secs(60);
/// Default cadence (seconds) for periodic state pushes.
pub const SYNC_INTERVAL_DEFAULT: u64 = 3600;

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

/// Uppercased rclone remote name (the part before ':' in `remote:path`):
/// prefix of the RCLONE_CONFIG_* backend env vars.
fn remote_env_name(remote: &str) -> String {
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
        }
        Self {
            remote,
            env,
            interval,
        }
    }
}

/// Resolved supervisor configuration (all env/file lookups done once at boot).
pub struct Config {
    /// tailscaled state file (under the writable data volume)
    pub state: String,
    /// LocalAPI unix socket (must live on a writable, non-volume path)
    pub socket: String,
    /// vaultwarden listen port: PORT wins, then ROCKET_PORT, else 8080
    /// (non-root cannot bind 80)
    pub port: String,
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
    /// verbatim vaultwarden env names -> values (from the dotenv file, if any)
    pub vw_env: Vec<(String, String)>,
}

impl Config {
    /// Merge order:
    ///   supervisor knobs (TS_*/SUPERVISOR_*): process env > file > code defaults
    ///   port: PORT env > ROCKET_PORT env > file ROCKET_PORT > 8080
    ///   vaultwarden keys: file > container env (applied in proc::run_vaultwarden)
    /// Empty values (env or file) are treated as unset. Boolean knobs
    /// (TS_SERVE/TS_USERSPACE) accept true/false/1/0/yes/no/on/off in any
    /// casing; other values warn and take the default.
    pub fn from_env() -> Self {
        let file = FileConfig::load();

        let port = non_empty(env::var("PORT").ok())
            .or_else(|| non_empty(env::var("ROCKET_PORT").ok()))
            .or_else(|| non_empty(file.child.get("ROCKET_PORT").cloned()))
            .unwrap_or_else(|| "8080".into());

        let knob = |key: &str, default: &str| -> String {
            non_empty(env::var(key).ok())
                .or_else(|| non_empty(file.knobs.get(key).cloned()))
                .unwrap_or_else(|| default.to_string())
        };

        // Misconfigurations degrade to sync disabled (never block the vault).
        let sync = {
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
                        "config: invalid SUPERVISOR_S3_REMOTE '{remote}' (remote name must be \
                         alphanumeric); state sync disabled"
                    ));
                    None
                } else {
                    let raw_interval = knob("SUPERVISOR_S3_SYNC_INTERVAL", "");
                    let secs: u64 = match raw_interval.parse() {
                        Ok(secs) => secs,
                        Err(_) => {
                            log::err(&format!(
                                "config: invalid SUPERVISOR_S3_SYNC_INTERVAL '{raw_interval}'; \
                                 using default {SYNC_INTERVAL_DEFAULT}s"
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
                    "config: invalid SUPERVISOR_S3_REMOTE '{remote}' (must be remote:path); \
                     state sync disabled"
                ));
                None
            }
        };

        // Lenient bool knobs: misspellings warn and take the default rather
        // than silently flipping the feature off.
        let flag = |key: &str, default: bool| -> bool {
            match knob(key, "") {
                v if v.is_empty() => default,
                v => match parse_bool(&v) {
                    Some(b) => b,
                    None => {
                        log::err(&format!(
                            "config: invalid {key} '{v}' (want true/false); using default {default}"
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
            hostname: knob("TS_HOSTNAME", "vaultwarden"),
            authkey: knob("TS_AUTHKEY", ""),
            serve: flag("TS_SERVE", true),
            userspace: flag("TS_USERSPACE", true),
            sync,
            vw_env: file.child.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Every key `Config::from_env` / `FileConfig::load` may read.
    const ENV_KEYS: &[&str] = &[
        "PORT",
        "ROCKET_PORT",
        "TS_STATE_FILE",
        "TS_SOCKET",
        "TS_HOSTNAME",
        "TS_AUTHKEY",
        "TS_SERVE",
        "TS_USERSPACE",
        "SUPERVISOR_ENV_FILE",
        "SUPERVISOR_S3_REMOTE",
        "SUPERVISOR_S3_ACCESS_KEY_ID",
        "SUPERVISOR_S3_SECRET_ACCESS_KEY",
        "SUPERVISOR_S3_ENDPOINT",
        "SUPERVISOR_S3_SYNC_INTERVAL",
    ];

    fn set(key: &str, val: &str) {
        unsafe { env::set_var(key, val) };
    }

    fn clear() {
        for key in ENV_KEYS {
            unsafe { env::remove_var(key) };
        }
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

    /// All env mutation lives in this one test: `std::env` is process-global
    /// and libtest runs tests in parallel threads.
    #[test]
    fn from_env_merge_order() {
        clear();
        set("SUPERVISOR_ENV_FILE", "");
        let cfg = Config::from_env();
        assert_eq!(cfg.port, "8080");
        assert_eq!(cfg.socket, "/tmp/tailscaled.sock");
        assert_eq!(cfg.state, "/data/tailscaled.state");
        assert_eq!(cfg.hostname, "vaultwarden");
        assert_eq!(cfg.authkey, "");
        assert!(cfg.serve && cfg.userspace);
        assert!(cfg.vw_env.is_empty());

        set("PORT", "3000");
        set("ROCKET_PORT", "1111");
        assert_eq!(Config::from_env().port, "3000");
        unsafe { env::remove_var("PORT") };
        assert_eq!(Config::from_env().port, "1111");

        set("PORT", "");
        set("ROCKET_PORT", "");
        assert_eq!(Config::from_env().port, "8080");
        unsafe { env::remove_var("PORT") };
        unsafe { env::remove_var("ROCKET_PORT") };

        clear();
        let path = env::temp_dir().join(format!("vw-sup-cfg-{}.env", std::process::id()));
        fs::write(
            &path,
            "ROCKET_PORT=2222\nTS_HOSTNAME=file-host\nTS_AUTHKEY=file-key\nTS_SERVE=false\nDOMAIN=https://f.example\n",
        )
        .unwrap();
        set("SUPERVISOR_ENV_FILE", path.to_str().unwrap());
        let cfg = Config::from_env();
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
        set("TS_HOSTNAME", "env-host");
        assert_eq!(Config::from_env().hostname, "env-host");
        let _ = fs::remove_file(&path);

        clear();
        set("SUPERVISOR_ENV_FILE", "");
        assert!(Config::from_env().sync.is_none());

        set("SUPERVISOR_S3_REMOTE", "r2:vw-state");
        assert!(Config::from_env().sync.is_none());

        set("SUPERVISOR_S3_ACCESS_KEY_ID", "id");
        set("SUPERVISOR_S3_SECRET_ACCESS_KEY", "secret");
        set(
            "SUPERVISOR_S3_ENDPOINT",
            "https://acct.r2.cloudflarestorage.com",
        );
        set("SUPERVISOR_S3_SYNC_INTERVAL", "90");
        let sync = Config::from_env().sync.expect("sync enabled");
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
            ]
        );

        set("SUPERVISOR_S3_REMOTE", "no-colon-here");
        assert!(Config::from_env().sync.is_none());

        set("SUPERVISOR_S3_REMOTE", "r2:vw-state");
        set("SUPERVISOR_S3_SYNC_INTERVAL", "not-a-number");
        assert_eq!(
            Config::from_env().sync.expect("sync enabled").interval,
            Duration::from_secs(SYNC_INTERVAL_DEFAULT)
        );

        // A colon-less remote would make rclone write to a local path
        // instead of the bucket.
        set("SUPERVISOR_S3_REMOTE", "mybucket");
        assert!(Config::from_env().sync.is_none());

        // Lenient bool knobs: common spellings in any casing parse, and a
        // misspelling warns and takes the default instead of silently
        // disabling the feature.
        clear();
        set("SUPERVISOR_ENV_FILE", "");
        set("TS_SERVE", "YES");
        set("TS_USERSPACE", "0");
        let cfg = Config::from_env();
        assert!(cfg.serve);
        assert!(!cfg.userspace);
        set("TS_SERVE", "definitely");
        let cfg = Config::from_env();
        assert!(cfg.serve);
    }
}
