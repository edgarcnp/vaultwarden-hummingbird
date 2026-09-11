//! vaultwarden child process control.

use std::collections::BTreeMap;
use std::env;
use std::ffi::{OsStr, OsString};
use std::process::Command;

use crate::config::{VAULTWARDEN, is_supervisor_consumed, is_supervisor_key, vaultwarden_key};
use crate::runtime::{Handle, spawn};

/// vaultwarden in the foreground with a *granted* environment (see
/// [`granted_env`]). Spawn failure returns `None`; the caller tears down
/// and exits 1.
pub fn run_vaultwarden(vault_port: &str, extra_env: &[(String, String)]) -> Option<Handle> {
    let mut cmd = Command::new(VAULTWARDEN);
    cmd.env_clear();
    for (k, v) in granted_env(env::vars_os(), extra_env, vault_port) {
        cmd.env(k, v);
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

/// The vaultwarden child's granted environment, in precedence order: the
/// dotenv-file grant surface first, then the ambient container env
/// (default-deny: ONLY `VAULTWARDEN_*` keys, stripped to the plain upstream
/// name — orchestrator/platform settings must not shape the vault) — so a
/// direct container value wins over the file, matching the supervisor's own
/// env > file resolution (backup/restore must reach the same DB the vault
/// uses). Finally the hard invariants, which nothing may override:
/// ROCKET_PORT (internal vault port), ROCKET_ADDRESS (loopback-only: the
/// API is reachable solely via `tailscale serve`), DATA_FOLDER,
/// WEB_VAULT_FOLDER (where the image bakes the vault — the re-derived
/// WEB_VAULT_ENABLED checks this same path, so a child override would
/// desync the pair), and WEB_VAULT_ENABLED re-derived from what the image
/// actually baked (the
/// image default never reaches this child, and an API-only build must not
/// boot with vaultwarden's compiled default). Supervisor-consumed keys
/// ([`is_supervisor_consumed`]: supervisor namespaces + the port knobs)
/// never pass on either path; non-UTF-8 keys are dropped: a key the
/// supervisor can't read must never reach the child (a mangled
/// `TAILSCALE_*` secret would otherwise leak into its env).
fn granted_env(
    ambient: impl Iterator<Item = (OsString, OsString)>,
    file: &[(String, String)],
    vault_port: &str,
) -> Vec<(String, OsString)> {
    let mut env: BTreeMap<String, OsString> = BTreeMap::new();
    for (k, v) in file {
        if let Some(key) = file_key(OsStr::new(k)) {
            env.insert(key, v.clone().into());
        }
    }
    for (k, v) in ambient {
        if let Some(key) = ambient_key(&k) {
            env.insert(key, v);
        }
    }
    env.insert("ROCKET_PORT".into(), vault_port.into());
    env.insert("ROCKET_ADDRESS".into(), "127.0.0.1".into());
    env.insert("DATA_FOLDER".into(), "/data".into());
    env.insert("WEB_VAULT_FOLDER".into(), "/web-vault".into());
    // A populated folder leaves the knob unset; an API-only build (empty
    // /web-vault) must not boot with vaultwarden's compiled default
    // (enabled) — the vault exits 1 on the missing index.html.
    if let Some((key, value)) = web_vault_flag(WEB_VAULT_INDEX) {
        env.insert(key.into(), value.into());
    }
    env.into_iter().collect()
}

/// Map an *ambient* container-env key for the child (default deny): only
/// `VAULTWARDEN_*` keys are forwarded, under the stripped plain upstream
/// name. Supervisor-consumed keys are dropped — including after stripping
/// (a mangled `VAULTWARDEN_TAILSCALE_*` key must not land in the child
/// as `TAILSCALE_*`) — and bare upstream keys are NOT forwarded: the
/// dotenv file is the explicit grant surface for those.
fn ambient_key(key: &OsStr) -> Option<String> {
    let k = key.to_str()?;
    if is_supervisor_consumed(k) {
        return None;
    }
    let stripped = vaultwarden_key(k)?;
    if is_supervisor_key(stripped) {
        return None;
    }
    Some(stripped.to_string())
}

/// Map a dotenv-file key for the child (the explicit grant surface):
/// supervisor-consumed keys are dropped (they are routed to the
/// supervisor's own knobs before this point), `VAULTWARDEN_*` keys are
/// forwarded under the stripped plain upstream name, bare upstream names
/// verbatim. Non-UTF-8 keys are dropped, same rationale as [`ambient_key`].
fn file_key(key: &OsStr) -> Option<String> {
    let k = key.to_str()?;
    if is_supervisor_consumed(k) {
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
    /// receives no `TAILSCALE_*`/`SUPERVISOR_*` keys from any input. The
    /// supervisor-consumed port knobs never reach the child either (the
    /// supervisor binds the gate on them and pins the child's port).
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
        assert_eq!(ambient_key(OsStr::new("VAULTWARDEN_PORT")), None);
        assert_eq!(ambient_key(OsStr::new("VAULTWARDEN_ROCKET_PORT")), None);
        // stripped-to-supervisor names stay denied from the file path too
        assert_eq!(file_key(OsStr::new("VAULTWARDEN_TAILSCALE_AUTHKEY")), None);
        assert_eq!(
            file_key(OsStr::new("VAULTWARDEN_SUPERVISOR_S3_REMOTE")),
            None
        );
        assert_eq!(file_key(OsStr::new("VAULTWARDEN_PORT")), None);
        assert_eq!(file_key(OsStr::new("VAULTWARDEN_ROCKET_PORT")), None);
        // a stripped-to-empty remainder still passes through the file path
        assert_eq!(
            file_key(OsStr::new("VAULTWARDEN_")).as_deref(),
            Some("VAULTWARDEN_")
        );
    }

    /// The granted child env: file keys first, ambient keys override (the
    /// documented "direct value wins" — the supervisor's own resolution
    /// uses the same order), supervisor-consumed keys never pass, and the
    /// hard pins close it out. Only ROCKET_ADDRESS/ROCKET_PORT/DATA_FOLDER
    /// /WEB_VAULT_FOLDER and the re-derived web-vault flag may not be
    /// overridden.
    #[test]
    fn granted_env_file_first_ambient_wins_pins_last() {
        let ambient: Vec<(OsString, OsString)> = [
            ("VAULTWARDEN_DATABASE_URL", "sqlite:///data/env.sqlite3"),
            ("VAULTWARDEN_SIGNUPS_ALLOWED", "false"),
            ("VAULTWARDEN_PORT", "9999"),
            ("VAULTWARDEN_WEB_VAULT_FOLDER", "/leak/ambient"),
            ("WEB_VAULT_FOLDER", "/leak/ambient-bare"),
            ("TAILSCALE_AUTHKEY", "leak-me"),
        ]
        .iter()
        .map(|(k, v)| (OsString::from(k), OsString::from(v)))
        .collect();
        let file = [
            (
                "DATABASE_URL".to_string(),
                "sqlite:///data/file.sqlite3".to_string(),
            ),
            ("SIGNUPS_ALLOWED".to_string(), "true".to_string()),
            ("VAULTWARDEN_PORT".to_string(), "8888".to_string()),
            ("WEB_VAULT_FOLDER".to_string(), "/leak/file".to_string()),
            ("DOMAIN".to_string(), "https://f.example".to_string()),
        ];
        let env: std::collections::BTreeMap<String, String> =
            granted_env(ambient.into_iter(), &file, "8081")
                .into_iter()
                .map(|(k, v)| (k, v.to_string_lossy().into_owned()))
                .collect();
        assert_eq!(
            env.get("DATABASE_URL").map(String::as_str),
            Some("sqlite:///data/env.sqlite3"),
            "ambient env must override the file"
        );
        assert_eq!(
            env.get("SIGNUPS_ALLOWED").map(String::as_str),
            Some("false"),
            "ambient env must override the file"
        );
        assert_eq!(
            env.get("DOMAIN").map(String::as_str),
            Some("https://f.example"),
            "bare upstream names from the file pass"
        );
        assert!(
            !env.contains_key("PORT"),
            "port knob must not reach the child"
        );
        assert!(
            !env.contains_key("TAILSCALE_AUTHKEY"),
            "supervisor secrets must not reach the child"
        );
        // the hard pins win over everything
        assert_eq!(env.get("ROCKET_PORT").map(String::as_str), Some("8081"));
        assert_eq!(
            env.get("ROCKET_ADDRESS").map(String::as_str),
            Some("127.0.0.1")
        );
        assert_eq!(env.get("DATA_FOLDER").map(String::as_str), Some("/data"));
        assert_eq!(
            env.get("WEB_VAULT_FOLDER").map(String::as_str),
            Some("/web-vault"),
            "the baked folder is pinned: the re-derived WEB_VAULT_ENABLED \
             checks the same path"
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
