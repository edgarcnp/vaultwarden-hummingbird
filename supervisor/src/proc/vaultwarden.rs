//! vaultwarden child process control.

use std::process::Command;

use crate::config::{VAULTWARDEN, is_supervisor_key};
use crate::proc::process::{self, Pid};

/// vaultwarden in foreground with a *localized* environment. The child gets:
///   1. container env minus supervisor-owned keys (TS_*/SUPERVISOR_* —
///      Tailscale secrets stay with the supervisor)
///   2. dotenv-file vars (SUPERVISOR_ENV_FILE) — authoritative in file mode
///      (this is what makes image-baked posture defaults overridable)
///   3. hard invariants: ROCKET_PORT (from PORT), ROCKET_ADDRESS, DATA_FOLDER
///
/// Spawned as its own process-group leader (see `process::spawn`) so shutdown
/// signals reach the whole group. A spawn failure returns `None`; the caller
/// tears down what is already running and exits 1.
pub fn run_vaultwarden(port: &str, extra_env: &[(String, String)]) -> Option<Pid> {
    let mut cmd = Command::new(VAULTWARDEN);
    cmd.env_clear();
    for (k, v) in std::env::vars() {
        if is_supervisor_key(&k) {
            continue;
        }
        cmd.env(k, v);
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.env("ROCKET_PORT", port) // platform PORT always wins
        .env("ROCKET_ADDRESS", "0.0.0.0")
        .env("DATA_FOLDER", "/data");
    process::spawn(&mut cmd)
}
