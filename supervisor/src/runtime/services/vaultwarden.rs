//! vaultwarden child process control.

use std::env;
use std::ffi::OsStr;
use std::process::Command;

use crate::config::{VAULTWARDEN, is_supervisor_key, vaultwarden_key};
use crate::runtime::{Pid, spawn};

/// vaultwarden in the foreground with a *granted* environment (default
/// deny): the ambient container env contributes ONLY `VAULTWARDEN_*`
/// keys (stripped to the plain upstream name — orchestrator/platform
/// settings must not shape the vault); the dotenv-file vars are the
/// explicit grant surface (this makes image-baked posture defaults
/// overridable, and bare upstream names in the file keep working); then
/// hard invariants: ROCKET_PORT (internal vault port), ROCKET_ADDRESS
/// (loopback-only: the API is reachable solely via `tailscale serve`),
/// DATA_FOLDER, and WEB_VAULT_ENABLED re-derived from what the image
/// actually baked (the image default never reaches this child, and an
/// API-only build must not boot with vaultwarden's compiled default).
/// Spawn failure returns `None`; the caller tears down and exits 1.
pub fn run_vaultwarden(vault_port: &str, extra_env: &[(String, String)]) -> Option<Pid> {
    let mut cmd = Command::new(VAULTWARDEN);
    cmd.env_clear();
    for (k, v) in env::vars_os() {
        if let Some(key) = ambient_key(&k) {
            cmd.env(key, v);
        }
    }
    for (k, v) in extra_env {
        if let Some(key) = file_key(OsStr::new(k)) {
            cmd.env(key, v);
        }
    }
    cmd.env("ROCKET_PORT", vault_port)
        .env("ROCKET_ADDRESS", "127.0.0.1")
        .env("DATA_FOLDER", "/data");
    // The image's WEB_VAULT_ENABLED default never reaches this child (the
    // ambient env is default-deny), so it is re-derived from what was
    // actually baked: an API-only build (empty /web-vault) must not boot
    // with vaultwarden's compiled default (enabled) — the vault exits 1
    // on the missing index.html. A populated folder leaves the knob unset.
    if let Some((key, value)) = web_vault_flag(WEB_VAULT_INDEX) {
        cmd.env(key, value);
    }
    spawn(&mut cmd)
}

/// Where the image bakes the web vault (WEB_VAULT_FOLDER in the
/// Containerfile).
const WEB_VAULT_INDEX: &str = "/web-vault/index.html";

/// `Some(("WEB_VAULT_ENABLED", "false"))` for an API-only image (no baked
/// index.html); `None` = leave the knob at vaultwarden's own default.
fn web_vault_flag(index: &str) -> Option<(&'static str, &'static str)> {
    if std::path::Path::new(index).exists() {
        None
    } else {
        Some(("WEB_VAULT_ENABLED", "false"))
    }
}

/// Map an *ambient* container-env key for the child (default deny): only
/// `VAULTWARDEN_*` keys are forwarded, under the stripped plain upstream
/// name. Supervisor-owned keys are dropped — including after stripping
/// (a mangled `VAULTWARDEN_TAILSCALE_*` key must not land in the child
/// as `TAILSCALE_*`) — and bare upstream keys are NOT forwarded: the
/// dotenv file is the explicit grant surface for those. Non-UTF-8 keys
/// are dropped: a key the supervisor can't read must never reach the
/// child (a mangled `TAILSCALE_*` secret would otherwise leak into its
/// env).
fn ambient_key(key: &OsStr) -> Option<String> {
    let stripped = vaultwarden_key(key.to_str()?)?;
    if is_supervisor_key(stripped) {
        return None;
    }
    Some(stripped.to_string())
}

/// Map a dotenv-file key for the child (the explicit grant surface):
/// supervisor-owned keys are dropped (they are routed to the supervisor's
/// own knobs before this point), `VAULTWARDEN_*` keys are forwarded under
/// the stripped plain upstream name, bare upstream names verbatim.
/// Non-UTF-8 keys are dropped, same rationale as [`ambient_key`].
fn file_key(key: &OsStr) -> Option<String> {
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

    /// Ambient env is default-deny: supervisor-owned keys are filtered
    /// even when not valid UTF-8, bare upstream keys do not pass, and
    /// `VAULTWARDEN_*` keys reach the child under the stripped upstream
    /// name. (PID 1 has panic="abort"; the `vars_os` path must not panic
    /// on weird keys.)
    #[test]
    fn ambient_env_is_default_deny() {
        let weird = OsString::from_vec(vec![0x54, 0x41, 0x49, 0x4c, 0xff]); // "TAIL\xff"
        assert_eq!(ambient_key(OsStr::new("TAILSCALE_AUTHKEY")), None);
        assert_eq!(ambient_key(OsStr::new("SUPERVISOR_S3_REMOTE")), None);
        assert_eq!(ambient_key(&weird), None);
        // VAULTWARDEN_ keys reach the child under the stripped upstream name
        assert_eq!(
            ambient_key(OsStr::new("VAULTWARDEN_DATABASE_URL")).as_deref(),
            Some("DATABASE_URL")
        );
        assert_eq!(
            ambient_key(OsStr::new("VAULTWARDEN_DOMAIN")).as_deref(),
            Some("DOMAIN")
        );
        // bare upstream keys: denied (the dotenv file is the grant surface)
        assert_eq!(ambient_key(OsStr::new("DOMAIN")), None);
        assert_eq!(ambient_key(OsStr::new("DATABASE_URL")), None);
        // prefix only, not the whole namespace
        assert_eq!(ambient_key(OsStr::new("TAILSCALE")), None);
        assert_eq!(ambient_key(OsStr::new("VAULTWARDEN_")), None);
    }

    /// A `VAULTWARDEN_`-prefixed key whose stripped name lands in the
    /// supervisor namespace must be dropped, not forwarded: the child
    /// receives no `TAILSCALE_*`/`SUPERVISOR_*` keys from any input.
    #[test]
    fn vaultwarden_prefixed_supervisor_names_are_dropped() {
        assert_eq!(
            ambient_key(OsStr::new("VAULTWARDEN_TAILSCALE_AUTHKEY")),
            None
        );
        assert_eq!(
            ambient_key(OsStr::new("VAULTWARDEN_SUPERVISOR_S3_REMOTE")),
            None
        );
        // stripped-to-supervisor names stay denied from the file path too
        assert_eq!(file_key(OsStr::new("VAULTWARDEN_TAILSCALE_AUTHKEY")), None);
        assert_eq!(
            file_key(OsStr::new("VAULTWARDEN_SUPERVISOR_S3_REMOTE")),
            None
        );
        // a stripped-to-empty remainder still passes through the file path
        assert_eq!(
            file_key(OsStr::new("VAULTWARDEN_")).as_deref(),
            Some("VAULTWARDEN_")
        );
    }

    /// The dotenv file is the explicit grant surface: bare upstream names
    /// forward verbatim, supervisor keys never pass.
    #[test]
    fn file_keys_forward_bare_upstream_names() {
        assert_eq!(file_key(OsStr::new("SUPERVISOR_S3_REMOTE")), None);
        assert_eq!(
            file_key(OsStr::new("VAULTWARDEN_DATABASE_URL")).as_deref(),
            Some("DATABASE_URL")
        );
        assert_eq!(file_key(OsStr::new("DOMAIN")).as_deref(), Some("DOMAIN"));
        assert_eq!(
            file_key(OsStr::new("TAILSCALE")).as_deref(),
            Some("TAILSCALE")
        );
    }

    /// An API-only image (no baked index.html) must disable the web vault
    /// for the child; a populated folder leaves the knob at its default.
    #[test]
    fn web_vault_flag_tracks_the_baked_index() {
        let dir = std::env::temp_dir().join(format!("vw-sup-wv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let index = dir.join("index.html");
        let path = index.to_str().unwrap();
        let _ = std::fs::remove_file(&index);
        assert_eq!(
            web_vault_flag(path),
            Some(("WEB_VAULT_ENABLED", "false")),
            "missing index.html = API-only build"
        );
        std::fs::write(&index, b"<html>").unwrap();
        assert_eq!(web_vault_flag(path), None, "baked vault = default");
        let _ = std::fs::remove_file(&index);
    }
}
