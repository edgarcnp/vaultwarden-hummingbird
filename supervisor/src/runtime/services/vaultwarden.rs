//! vaultwarden child process control.

use std::env;
use std::ffi::OsStr;
use std::process::Command;

use crate::config::{VAULTWARDEN, is_supervisor_key, vaultwarden_key};
use crate::runtime::{Pid, spawn};

/// vaultwarden in the foreground with a *localized* environment: container
/// env minus supervisor-owned keys (VAULTWARDEN_* stripped to the plain
/// upstream name), then dotenv-file vars (authoritative — this makes
/// image-baked posture defaults overridable), then hard invariants:
/// ROCKET_PORT (internal vault port), ROCKET_ADDRESS (loopback-only: the
/// API is reachable solely via `tailscale serve`), DATA_FOLDER. Spawn
/// failure returns `None`; the caller tears down and exits 1.
pub fn run_vaultwarden(vault_port: &str, extra_env: &[(String, String)]) -> Option<Pid> {
    let mut cmd = Command::new(VAULTWARDEN);
    cmd.env_clear();
    for (k, v) in env::vars_os() {
        if let Some(key) = child_key(&k) {
            cmd.env(key, v);
        }
    }
    for (k, v) in extra_env {
        if let Some(key) = child_key(OsStr::new(k)) {
            cmd.env(key, v);
        }
    }
    cmd.env("ROCKET_PORT", vault_port)
        .env("ROCKET_ADDRESS", "127.0.0.1")
        .env("DATA_FOLDER", "/data");
    spawn(&mut cmd)
}

/// Map a container-env key for the child: supervisor-owned keys are
/// dropped (including after `VAULTWARDEN_` stripping — a mangled
/// `VAULTWARDEN_TAILSCALE_*` key must not land in the child as
/// `TAILSCALE_*`), `VAULTWARDEN_*` keys are forwarded under the stripped
/// plain upstream name, everything else verbatim. Non-UTF-8 keys are
/// dropped: a key the supervisor can't read must never reach the child (a
/// mangled `TAILSCALE_*` secret would otherwise leak into its env).
fn child_key(key: &OsStr) -> Option<String> {
    let k = key.to_str()?;
    if is_supervisor_key(k) {
        return None;
    }
    let mapped = vaultwarden_key(k).map_or_else(|| k.to_string(), str::to_string);
    if is_supervisor_key(&mapped) {
        return None;
    }
    Some(mapped)
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
        let weird = OsString::from_vec(vec![0x54, 0x41, 0x49, 0x4c, 0xff]); // "TAIL\xff"
        assert_eq!(child_key(OsStr::new("TAILSCALE_AUTHKEY")), None);
        assert_eq!(child_key(OsStr::new("SUPERVISOR_S3_REMOTE")), None);
        assert_eq!(child_key(&weird), None);
        // VAULTWARDEN_ keys reach the child under the stripped upstream name
        assert_eq!(
            child_key(OsStr::new("VAULTWARDEN_DATABASE_URL")).as_deref(),
            Some("DATABASE_URL")
        );
        assert_eq!(child_key(OsStr::new("DOMAIN")).as_deref(), Some("DOMAIN"));
        // prefix only, not the whole namespace
        assert_eq!(
            child_key(OsStr::new("TAILSCALE")).as_deref(),
            Some("TAILSCALE")
        );
        assert_eq!(
            child_key(OsStr::new("VAULTWARDEN_")).as_deref(),
            Some("VAULTWARDEN_")
        );
    }

    /// A `VAULTWARDEN_`-prefixed key whose stripped name lands in the
    /// supervisor namespace must be dropped, not forwarded: the child
    /// receives no `TAILSCALE_*`/`SUPERVISOR_*` keys from any input.
    #[test]
    fn vaultwarden_prefixed_supervisor_names_are_dropped() {
        assert_eq!(child_key(OsStr::new("VAULTWARDEN_TAILSCALE_AUTHKEY")), None);
        assert_eq!(
            child_key(OsStr::new("VAULTWARDEN_SUPERVISOR_S3_REMOTE")),
            None
        );
        // stripped-to-empty and non-namespace remainders still pass through
        assert_eq!(
            child_key(OsStr::new("VAULTWARDEN_TAILSCALES")).as_deref(),
            Some("TAILSCALES")
        );
    }
}
