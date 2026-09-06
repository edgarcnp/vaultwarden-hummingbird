//! Config resolution: process env + optional supervisor-owned dotenv file.

use std::env;
use std::time::Duration;

use super::dotenv::FileConfig;

pub const TAILSCALED: &str = "/usr/local/bin/tailscaled";
pub const TAILSCALE: &str = "/usr/local/bin/tailscale";
pub const VAULTWARDEN: &str = "/vaultwarden";

/// Hard timeouts: never let a hung tailscaled block the vault.
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(90);
pub const SERVE_TIMEOUT: Duration = Duration::from_secs(30);
pub const DAEMON_WAIT: Duration = Duration::from_secs(30);

/// Keys owned by the supervisor (localized to PID 1): they configure the
/// supervisor/tailscale and are filtered out of the vaultwarden child's env.
pub fn is_supervisor_key(key: &str) -> bool {
    key.starts_with("TS_") || key.starts_with("SUPERVISOR_")
}

pub struct Config {
    /// tailscaled state file (under the writable data volume)
    pub state: String,
    /// LocalAPI unix socket (must live on a writable, non-volume path)
    pub socket: String,
    /// vaultwarden listen port: PORT wins, then ROCKET_PORT, else 8080
    /// (non-root cannot bind 80)
    pub port: String,
    pub hostname: String,
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
