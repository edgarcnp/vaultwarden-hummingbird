//! vaultwarden child process control.

use std::env;
use std::ffi::{OsStr, OsString};
use std::process::Command;

use crate::config::{VAULTWARDEN, is_supervisor_consumed, is_supervisor_key, vaultwarden_key};
use crate::runtime::{EnvGrant, Handle, spawn};

/// vaultwarden in the foreground with a *granted* environment (see
/// [`granted_env`]). Spawn failure returns `None`; the caller tears down
/// and exits 1.
pub fn run_vaultwarden(vault_port: &str, extra_env: &[(String, String)]) -> Option<Handle> {
    let mut cmd = Command::new(VAULTWARDEN);
    granted_env(env::vars_os(), extra_env, vault_port).apply(&mut cmd);
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

/// Image defaults declared by the Containerfile's plain-name ENV block.
/// They are re-applied here as the grant's weakest layer: the child env
/// is cleared and default-deny, so without this the bare image values
/// would never reach vaultwarden. User config (dotenv file, then ambient
/// `VAULTWARDEN_*`) overrides every one of them. Keep in sync with the
/// Containerfile's RUNTIME DEFAULTS block.
const IMAGE_DEFAULTS: &[(&str, &str)] = &[
    // uploads off by default; 0 is vaultwarden's "disabled" spelling
    ("ORG_ATTACHMENT_LIMIT", "0"),
    ("USER_ATTACHMENT_LIMIT", "0"),
    // behaviorally the upstream default (blank == all), kept explicit
    ("ORG_CREATION_USERS", "all"),
    // upstream default true, kept explicit
    ("SIGNUPS_ALLOWED", "true"),
    // the base image has no localtime; pin the documented default
    ("TZ", "UTC"),
];

/// The vaultwarden child's granted environment, in precedence order: the
/// image defaults ([`IMAGE_DEFAULTS`]; the Containerfile's bare ENV names
/// cannot reach the default-deny child on their own), then the dotenv-file
/// child map (pre-routed at load: only stripped `VAULTWARDEN_*` keys are
/// in it — the file refused everything else), then the ambient container
/// env (default-deny: ONLY `VAULTWARDEN_*` keys, stripped to the plain
/// upstream name) — so a direct container value wins over the file,
/// matching the supervisor's own env > file resolution (backup/restore
/// must reach the same DB the vault uses). An empty value counts as unset
/// on every layer: it never shadows a lower layer. Finally the hard pins:
/// ROCKET_PORT (internal vault port), ROCKET_ADDRESS (loopback-only: the
/// API is reachable solely via `tailscale serve`), DATA_FOLDER,
/// WEB_VAULT_FOLDER (the re-derived WEB_VAULT_ENABLED checks this same
/// path, so a child override would desync the pair), and WEB_VAULT_ENABLED
/// re-derived from what the image actually baked (an API-only build must
/// not boot with vaultwarden's compiled default). Non-UTF-8 keys are
/// dropped.
fn granted_env(
    ambient: impl Iterator<Item = (OsString, OsString)>,
    file: &[(String, String)],
    vault_port: &str,
) -> EnvGrant {
    let grant = EnvGrant::new()
        .layer(
            IMAGE_DEFAULTS
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).into())),
        )
        .layer(
            file.iter()
                .filter(|(_, v)| !v.is_empty())
                .map(|(k, v)| (k.clone(), v.clone().into())),
        )
        .layer(ambient.filter_map(|(k, v)| {
            ambient_key(&k)
                .filter(|_| !v.is_empty())
                .map(|key| (key, v))
        }));
    // A populated folder leaves the knob unset; an API-only build (empty
    // /web-vault) must not boot with vaultwarden's compiled default
    // (enabled) — the vault exits 1 on the missing index.html.
    let grant = match web_vault_flag(WEB_VAULT_INDEX) {
        Some((key, value)) => grant.pin(key, value),
        None => grant,
    };
    grant
        .pin("ROCKET_PORT", vault_port)
        .pin("ROCKET_ADDRESS", "127.0.0.1")
        .pin("DATA_FOLDER", "/data")
        .pin("WEB_VAULT_FOLDER", "/web-vault")
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
    /// receives no `TAILSCALE_*`/`SUPERVISOR_*` keys from any input. (In
    /// the dotenv file such a key is outright invalid and refuses the
    /// boot; on the ambient env it can only be dropped, since platforms
    /// inject arbitrary keys.) The supervisor-consumed port knobs never
    /// reach the child either (the supervisor binds the gate on them and
    /// pins the child's port).
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
    }

    /// The granted child env, in precedence order: image defaults, then
    /// file keys (they arrive pre-routed: stripped `VAULTWARDEN_*` names
    /// only — the dotenv load refused everything else), then ambient keys
    /// (the documented "direct value wins" — the supervisor's own
    /// resolution uses the same order), and the hard pins close it out.
    /// Only ROCKET_ADDRESS/ROCKET_PORT/DATA_FOLDER/WEB_VAULT_FOLDER and
    /// the re-derived web-vault flag may not be overridden.
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
        // pre-routed child map: stripped names only
        let file = [
            (
                "DATABASE_URL".to_string(),
                "sqlite:///data/file.sqlite3".to_string(),
            ),
            ("SIGNUPS_ALLOWED".to_string(), "true".to_string()),
            ("DOMAIN".to_string(), "https://f.example".to_string()),
        ];
        let env: std::collections::BTreeMap<String, String> =
            granted_env(ambient.into_iter(), &file, "8081")
                .iter()
                .map(|(k, v)| (k.clone(), v.to_string_lossy().into_owned()))
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
            "pre-routed file names pass verbatim"
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

    /// Name -> value view of a grant, for assertions.
    fn child_env(grant: EnvGrant) -> std::collections::BTreeMap<String, String> {
        grant
            .iter()
            .map(|(k, v)| (k.clone(), v.to_string_lossy().into_owned()))
            .collect()
    }

    /// The image's declared defaults reach the child (the bare
    /// Containerfile ENV names never would through the default-deny
    /// routing) and stay overridable by both user layers.
    #[test]
    fn image_defaults_apply_and_user_config_wins() {
        let env = child_env(granted_env(std::iter::empty(), &[], "8081"));
        assert_eq!(
            env.get("ORG_ATTACHMENT_LIMIT").map(String::as_str),
            Some("0"),
            "image default: org uploads off"
        );
        assert_eq!(
            env.get("USER_ATTACHMENT_LIMIT").map(String::as_str),
            Some("0"),
            "image default: user uploads off"
        );
        assert_eq!(env.get("SIGNUPS_ALLOWED").map(String::as_str), Some("true"));

        let file = [("ORG_ATTACHMENT_LIMIT".to_string(), "1024".to_string())];
        let env = child_env(granted_env(std::iter::empty(), &file, "8081"));
        assert_eq!(
            env.get("ORG_ATTACHMENT_LIMIT").map(String::as_str),
            Some("1024"),
            "the dotenv file overrides an image default"
        );

        let ambient = [(
            OsString::from("VAULTWARDEN_ORG_ATTACHMENT_LIMIT"),
            OsString::from("2048"),
        )];
        let env = child_env(granted_env(ambient.into_iter(), &file, "8081"));
        assert_eq!(
            env.get("ORG_ATTACHMENT_LIMIT").map(String::as_str),
            Some("2048"),
            "ambient env overrides the file"
        );
    }

    /// Empty = unset on every layer (the documented contract): an empty
    /// ambient or file value must not shadow a lower layer, or the
    /// supervisor's own resolution (which applies the same rule) and the
    /// child env would disagree about what the vault actually uses.
    #[test]
    fn empty_values_never_shadow_a_lower_layer() {
        let file = [
            (
                "DATABASE_URL".to_string(),
                "sqlite:///data/file.sqlite3".to_string(),
            ),
            ("ORG_ATTACHMENT_LIMIT".to_string(), String::new()),
        ];
        let ambient = [
            (OsString::from("VAULTWARDEN_DATABASE_URL"), OsString::new()),
            (
                OsString::from("VAULTWARDEN_ORG_ATTACHMENT_LIMIT"),
                OsString::new(),
            ),
        ];
        let env = child_env(granted_env(ambient.into_iter(), &file, "8081"));
        assert_eq!(
            env.get("DATABASE_URL").map(String::as_str),
            Some("sqlite:///data/file.sqlite3"),
            "an empty ambient value must not shadow the file"
        );
        assert_eq!(
            env.get("ORG_ATTACHMENT_LIMIT").map(String::as_str),
            Some("0"),
            "an empty file value must not shadow the image default"
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
