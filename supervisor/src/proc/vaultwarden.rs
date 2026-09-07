//! vaultwarden child process control.

use std::env;
use std::ffi::OsStr;
use std::process::Command;

use crate::config::{VAULTWARDEN, is_supervisor_key};
use crate::proc::{Pid, spawn};

/// vaultwarden in the foreground with a *localized* environment: container
/// env minus supervisor-owned keys, then dotenv-file vars (authoritative —
/// this makes image-baked posture defaults overridable), then hard
/// invariants: ROCKET_PORT (internal vault port), ROCKET_ADDRESS
/// (loopback-only: the API is reachable solely via `tailscale serve`),
/// DATA_FOLDER. Spawn failure returns `None`; the caller tears down and
/// exits 1.
pub fn run_vaultwarden(vault_port: &str, extra_env: &[(String, String)]) -> Option<Pid> {
    let mut cmd = Command::new(VAULTWARDEN);
    cmd.env_clear();
    for (k, v) in env::vars_os() {
        if forwarded(&k) {
            cmd.env(k, v);
        }
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.env("ROCKET_PORT", vault_port)
        .env("ROCKET_ADDRESS", "127.0.0.1")
        .env("DATA_FOLDER", "/data");
    spawn(&mut cmd)
}

/// Forward everything except supervisor-owned keys. Non-UTF-8 keys are
/// dropped: a key the supervisor can't read must never reach the child
/// (a mangled `TS_*` secret would otherwise leak into its env).
fn forwarded(key: &OsStr) -> bool {
    key.to_str().is_some_and(|k| !is_supervisor_key(k))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    /// Supervisor-owned keys are filtered even when not valid UTF-8; the
    /// `vars_os` path must not panic on them (PID 1 has panic="abort").
    #[test]
    fn non_utf8_supervisor_keys_are_filtered() {
        let weird = OsString::from_vec(vec![0x54, 0x53, 0x5f, 0xff]); // "TS_\xff"
        assert!(!forwarded(OsStr::new("TS_AUTHKEY")));
        assert!(!forwarded(&weird));
        assert!(forwarded(OsStr::new("DATABASE_URL")));
        assert!(forwarded(OsStr::new("TS"))); // prefix only, not the whole ns
    }
}
