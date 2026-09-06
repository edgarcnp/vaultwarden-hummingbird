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
        // remote name prefixes the RCLONE_CONFIG_* env vars (uppercased)
        let name = remote.split(':').next().unwrap_or_default().to_uppercase();
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
    ///   supervisor knobs (TS_*/SUPERVISOR_*/PORT): process env > file > defaults
    ///   vaultwarden keys: file > container env (applied in proc::run_vaultwarden)
    pub fn from_env() -> Self {
        let file = FileConfig::load();

        // platform PORT always wins (Render injects it; non-root can't bind 80)
        let port = if let Ok(p) = env::var("PORT").or_else(|_| env::var("ROCKET_PORT")) {
            p
        } else if let Some(p) = file.child.get("ROCKET_PORT") {
            p.clone()
        } else {
            "8080".into()
        };

        let knob = |key: &str, default: &str| -> String {
            env::var(key)
                .ok()
                .or_else(|| file.knobs.get(key).cloned())
                .unwrap_or_else(|| default.to_string())
        };

        let data_folder = env::var("DATA_FOLDER").unwrap_or_else(|_| "/data".to_string());

        // S3 state sync: enabled by SUPERVISOR_S3_REMOTE; misconfigurations
        // degrade to sync disabled (never block the vault).
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
            } else {
                let name = remote.split(':').next().unwrap_or_default().to_uppercase();
                if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    log::err(&format!(
                        "config: invalid SUPERVISOR_S3_REMOTE '{remote}' (remote name must be \
                         alphanumeric); state sync disabled"
                    ));
                    None
                } else {
                    let secs: u64 = knob("SUPERVISOR_S3_SYNC_INTERVAL", "")
                        .parse()
                        .unwrap_or(SYNC_INTERVAL_DEFAULT);
                    Some(SyncConfig::new(
                        remote,
                        key_id,
                        key_secret,
                        knob("SUPERVISOR_S3_ENDPOINT", ""),
                        Duration::from_secs(secs),
                    ))
                }
            }
        };

        Self {
            state: knob("TS_STATE_FILE", &format!("{data_folder}/tailscaled.state")),
            socket: knob("TS_SOCKET", "/tmp/tailscaled.sock"),
            port,
            hostname: knob("TS_HOSTNAME", "vaultwarden"),
            authkey: knob("TS_AUTHKEY", ""),
            serve: knob("TS_SERVE", "true") == "true",
            userspace: knob("TS_USERSPACE", "true") == "true",
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
        "DATA_FOLDER",
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
        // --- defaults, env-only mode (no config file) ---
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

        // --- DATA_FOLDER relocates the state default ---
        set("DATA_FOLDER", "/d");
        assert_eq!(Config::from_env().state, "/d/tailscaled.state");

        // --- port precedence: PORT > ROCKET_PORT (process env) ---
        set("PORT", "3000");
        set("ROCKET_PORT", "1111");
        assert_eq!(Config::from_env().port, "3000");
        unsafe { env::remove_var("PORT") };
        assert_eq!(Config::from_env().port, "1111");

        // --- file layer: process env > file > defaults ---
        clear();
        let path = env::temp_dir().join(format!("vw-sup-cfg-{}.env", std::process::id()));
        fs::write(
            &path,
            "ROCKET_PORT=2222\nTS_HOSTNAME=file-host\nTS_AUTHKEY=file-key\nTS_SERVE=false\nDOMAIN=https://f.example\n",
        )
        .unwrap();
        set("SUPERVISOR_ENV_FILE", path.to_str().unwrap());
        let cfg = Config::from_env();
        assert_eq!(cfg.port, "2222"); // file ROCKET_PORT when env is silent
        assert_eq!(cfg.hostname, "file-host");
        assert_eq!(cfg.authkey, "file-key");
        assert!(!cfg.serve); // TS_SERVE=false in the file
        assert!(cfg.userspace); // file silent -> default true
        // child env gets verbatim file keys; TS_*/SUPERVISOR_* stay with PID 1
        assert_eq!(
            cfg.vw_env
                .iter()
                .find(|(k, _)| k == "DOMAIN")
                .map(|(_, v)| v.as_str()),
            Some("https://f.example")
        );
        assert!(cfg.vw_env.iter().any(|(k, _)| k == "ROCKET_PORT"));
        assert!(!cfg.vw_env.iter().any(|(k, _)| is_supervisor_key(k)));
        // a knob present in both: process env wins over the file
        set("TS_HOSTNAME", "env-host");
        assert_eq!(Config::from_env().hostname, "env-host");
        let _ = fs::remove_file(&path);

        // --- S3 sync: disabled without the remote knob ---
        clear();
        set("SUPERVISOR_ENV_FILE", "");
        assert!(Config::from_env().sync.is_none());

        // --- S3 sync: missing credentials degrade to disabled ---
        set("SUPERVISOR_S3_REMOTE", "r2:vw-state");
        assert!(Config::from_env().sync.is_none());

        // --- S3 sync: enabled; backend env derived from the remote name ---
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

        // --- S3 sync: invalid remote name degrades to disabled ---
        set("SUPERVISOR_S3_REMOTE", "no-colon-here");
        assert!(Config::from_env().sync.is_none());

        // --- S3 sync: unparsable interval falls back to the default ---
        set("SUPERVISOR_S3_REMOTE", "r2:vw-state");
        set("SUPERVISOR_S3_SYNC_INTERVAL", "not-a-number");
        assert_eq!(
            Config::from_env().sync.expect("sync enabled").interval,
            Duration::from_secs(SYNC_INTERVAL_DEFAULT)
        );
    }
}
