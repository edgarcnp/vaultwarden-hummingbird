//! Config resolution: process env + optional supervisor-owned dotenv file.

use std::env;
use std::time::Duration;

use super::dotenv::FileConfig;

/// Hard-coded child binary paths (baked into the image, no PATH lookup).
pub const TAILSCALED: &str = "/usr/local/bin/tailscaled";
/// `tailscale` CLI (drives `up`/`serve` over the LocalAPI socket).
pub const TAILSCALE: &str = "/usr/local/bin/tailscale";
/// vaultwarden server binary (the payload this container exists to run).
pub const VAULTWARDEN: &str = "/vaultwarden";

/// Hard timeouts: never let a hung tailscaled block the vault.
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(90);
/// Hard timeout for `tailscale serve`.
pub const SERVE_TIMEOUT: Duration = Duration::from_secs(30);
/// Hard timeout waiting for tailscaled's LocalAPI socket.
pub const DAEMON_WAIT: Duration = Duration::from_secs(30);

/// Keys owned by the supervisor (localized to PID 1): they configure the
/// supervisor/tailscale and are filtered out of the vaultwarden child's env.
pub fn is_supervisor_key(key: &str) -> bool {
    key.starts_with("TS_") || key.starts_with("SUPERVISOR_")
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
        Self {
            state: knob("TS_STATE_FILE", &format!("{data_folder}/tailscaled.state")),
            socket: knob("TS_SOCKET", "/tmp/tailscaled.sock"),
            port,
            hostname: knob("TS_HOSTNAME", "vaultwarden"),
            authkey: knob("TS_AUTHKEY", ""),
            serve: knob("TS_SERVE", "true") == "true",
            userspace: knob("TS_USERSPACE", "true") == "true",
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
    }
}
