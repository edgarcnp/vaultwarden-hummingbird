//! Config resolution: merge process env + optional dotenv file + code
//! defaults into a validated [`Config`] once at boot. Siblings: `consts`
//! (static values), `sync`/`keepalive` (feature settings), `dotenv` (file).

use std::env;

use super::backup::{DbBackupConfig, resolve_backup};
use super::dotenv::FileConfig;
use super::keepalive::DbKeepalive;
use super::sync::{SyncConfig, resolve_sync};
use crate::util::log;

/// Supervisor-owned keys (localized to PID 1): filtered out of the
/// vaultwarden child's env.
pub fn is_supervisor_key(key: &str) -> bool {
    key.starts_with("TS_") || key.starts_with("SUPERVISOR_")
}

/// `Some(v)` only for non-empty: empty entries are treated as unset.
fn non_empty(v: Option<String>) -> Option<String> {
    v.filter(|v| !v.is_empty())
}

/// `Some(v)` only for a valid 1-65535 port; invalid values warn and fall
/// back to the default instead of breaking listeners.
fn valid_port(v: Option<String>) -> Option<String> {
    let v = non_empty(v)?;
    match v.parse::<u16>() {
        Ok(p) if p != 0 => Some(v),
        _ => {
            log::err(&format!(
                "config: invalid port '{}' (want 1-65535); using default",
                log::sanitize(&v)
            ));
            None
        }
    }
}

/// Lenient on/off knob parse; `None` = callers warn and use their default.
fn parse_bool(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Some(true),
        "false" | "0" | "no" | "off" => Some(false),
        _ => None,
    }
}

/// Tailscale Service reference from `TS_SERVICE`: a bare name or an already
/// prefixed `svc:<name>` becomes `svc:<name>`; anything else (empty, bare
/// `svc:`) warns and disables the advertisement.
fn resolve_service(v: Option<String>) -> Option<String> {
    let v = non_empty(v)?;
    let name = v.strip_prefix("svc:").unwrap_or(&v);
    if name.is_empty() {
        log::err("config: invalid TS_SERVICE 'svc:' (want svc:<name>); not advertising a service");
        return None;
    }
    Some(format!("svc:{name}"))
}

/// Resolved supervisor configuration (all env/file lookups done once at boot).
pub struct Config {
    /// tailscaled state file (under the writable data volume)
    pub state: String,
    /// LocalAPI unix socket (writable, non-volume path)
    pub socket: String,
    /// exposed (gatekeeper) port: PORT > ROCKET_PORT > 8080
    pub port: String,
    /// vaultwarden's port (`port + 1`, loopback-only). None = exposed port
    /// is 65535: boot must fail closed.
    pub vault_port: Option<String>,
    /// node name announced to the tailnet (`TS_HOSTNAME`)
    pub hostname: String,
    /// Tailscale auth key or OAuth client secret (`TS_AUTHKEY`; empty = skip `up`)
    pub authkey: String,
    /// configure `tailscale serve` after a successful up
    pub serve: bool,
    /// advertise this node as a host of `svc:<name>` via `tailscale serve
    /// --service` (`TS_SERVICE`; None = classic device-level serve only)
    pub service: Option<String>,
    /// userspace networking: no TUN device on PaaS platforms
    pub userspace: bool,
    /// S3 state sync (None = disabled)
    pub sync: Option<SyncConfig>,
    /// DB backup/restore (None = disabled)
    pub backup: Option<DbBackupConfig>,
    /// DB keepalive ping (None = disabled)
    pub db_keepalive: Option<DbKeepalive>,
    /// verbatim vaultwarden env (from the dotenv file, if any)
    pub vw_env: Vec<(String, String)>,
}

impl Config {
    /// Merge order: knobs = env > file > default; port = PORT > ROCKET_PORT
    /// (env) > file ROCKET_PORT > 8080; vaultwarden keys = file > env.
    /// Empty = unset; bad booleans warn and take the default.
    pub fn from_env() -> Self {
        Self::build(FileConfig::load(), |k| env::var(k).ok())
    }

    /// [`Self::from_env`] with the env source injected: tests pass a map,
    /// never mutating the process env (unsafe and racy).
    fn build(file: FileConfig, lookup: impl Fn(&str) -> Option<String>) -> Self {
        let port = valid_port(lookup("PORT"))
            .or_else(|| valid_port(lookup("ROCKET_PORT")))
            .or_else(|| valid_port(file.child.get("ROCKET_PORT").cloned()))
            .unwrap_or_else(|| "8080".into());
        let vault_port = port
            .parse::<u16>()
            .ok()
            .and_then(|p| p.checked_add(1))
            .map(|p| p.to_string());

        let knob = |key: &str, default: &str| -> String {
            non_empty(lookup(key))
                .or_else(|| non_empty(file.knobs.get(key).cloned()))
                .unwrap_or_else(|| default.to_string())
        };

        let sync = resolve_sync(&knob);

        // The vault's DB URL: file wins over env — dumps and restores must
        // reach the same DB the vault uses.
        let db_url = file
            .child
            .get("DATABASE_URL")
            .cloned()
            .or_else(|| non_empty(lookup("DATABASE_URL")));
        let backup = resolve_backup(&knob, sync.as_ref(), db_url.clone());

        let flag = |key: &str, default: bool| -> bool {
            match knob(key, "") {
                v if v.is_empty() => default,
                v => match parse_bool(&v) {
                    Some(b) => b,
                    None => {
                        log::err(&format!(
                            "config: invalid {key} '{}' (want true/false); using default {default}",
                            log::sanitize(&v)
                        ));
                        default
                    }
                },
            }
        };

        Self {
            // hard-pinned to the volume; the sync scope is /data too
            state: knob("TS_STATE_FILE", "/data/tailscaled.state"),
            socket: knob("TS_SOCKET", "/tmp/tailscaled.sock"),
            port,
            vault_port,
            hostname: knob("TS_HOSTNAME", "vaultwarden-hummingbird"),
            authkey: knob("TS_AUTHKEY", ""),
            serve: flag("TS_SERVE", true),
            service: resolve_service(
                lookup("TS_SERVICE").or_else(|| file.knobs.get("TS_SERVICE").cloned()),
            ),
            userspace: flag("TS_USERSPACE", true),
            sync,
            backup,
            // child key: file wins over env — the ping must reach the same
            // DB the vault uses
            db_keepalive: DbKeepalive::from_parts(&knob("SUPERVISOR_DB_KEEPALIVE", ""), db_url),
            vw_env: file.child.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use super::*;

    /// Config from an explicit variable map + optional dotenv file layer
    /// (never the process env — see [`Config::build`]).
    fn mk(vars: &[(&str, &str)]) -> Config {
        mk_with_file(vars, FileConfig::default())
    }

    fn mk_with_file(vars: &[(&str, &str)], file: FileConfig) -> Config {
        let map: BTreeMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::build(file, move |k| map.get(k).cloned())
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

    #[test]
    fn port_validation() {
        assert_eq!(valid_port(Some("8080".into())).as_deref(), Some("8080"));
        assert_eq!(valid_port(Some("1".into())).as_deref(), Some("1"));
        assert_eq!(valid_port(Some("65535".into())).as_deref(), Some("65535"));
        assert_eq!(valid_port(Some("0".into())), None);
        assert_eq!(valid_port(Some("65536".into())), None);
        assert_eq!(valid_port(Some("-1".into())), None);
        assert_eq!(valid_port(Some("8080\n".into())), None);
        assert_eq!(valid_port(Some("".into())), None);
        assert_eq!(valid_port(None), None);
        assert_eq!(valid_port(Some("abc".into())), None);
    }

    #[test]
    fn defaults_and_merge_order() {
        let cfg = mk(&[]);
        assert_eq!(cfg.port, "8080");
        assert_eq!(cfg.vault_port.as_deref(), Some("8081"));
        assert_eq!(cfg.socket, "/tmp/tailscaled.sock");
        assert_eq!(cfg.state, "/data/tailscaled.state");
        assert_eq!(cfg.hostname, "vaultwarden-hummingbird");
        assert_eq!(cfg.authkey, "");
        assert!(cfg.serve && cfg.userspace);
        assert_eq!(cfg.service, None);
        assert!(cfg.vw_env.is_empty());
        assert!(cfg.sync.is_none());

        let cfg = mk(&[("PORT", "3000"), ("ROCKET_PORT", "1111")]);
        assert_eq!(cfg.port, "3000");
        assert_eq!(cfg.vault_port.as_deref(), Some("3001"));
        let cfg = mk(&[("ROCKET_PORT", "1111")]);
        assert_eq!(cfg.port, "1111");
        let cfg = mk(&[("PORT", ""), ("ROCKET_PORT", "")]);
        assert_eq!(cfg.port, "8080");

        // 65535 leaves no room above the exposed port: fail closed.
        let cfg = mk(&[("PORT", "65535")]);
        assert_eq!(cfg.port, "65535");
        assert_eq!(cfg.vault_port, None);
    }

    #[test]
    fn dotenv_file_merges_below_process_env() {
        let path = std::env::temp_dir().join(format!("vw-sup-cfg-{}.env", std::process::id()));
        fs::write(
            &path,
            "ROCKET_PORT=2222\nTS_HOSTNAME=file-host\nTS_AUTHKEY=file-key\nTS_SERVE=false\nDOMAIN=https://f.example\n",
        )
        .unwrap();
        let path_str = path.to_str().unwrap();

        let cfg = mk_with_file(&[], FileConfig::load_from(Some(path_str)));
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

        // process env wins over the file for supervisor knobs
        let cfg = mk_with_file(
            &[("TS_HOSTNAME", "env-host")],
            FileConfig::load_from(Some(path_str)),
        );
        assert_eq!(cfg.hostname, "env-host");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn lenient_bool_knobs() {
        let cfg = mk(&[("TS_SERVE", "YES"), ("TS_USERSPACE", "0")]);
        assert!(cfg.serve);
        assert!(!cfg.userspace);

        // misspelling warns and takes the default
        let cfg = mk(&[("TS_SERVE", "definitely")]);
        assert!(cfg.serve);
    }

    #[test]
    fn service_reference_resolution() {
        assert_eq!(
            resolve_service(Some("vaultwarden".into())),
            Some("svc:vaultwarden".into())
        );
        assert_eq!(
            resolve_service(Some("svc:vaultwarden".into())),
            Some("svc:vaultwarden".into())
        );
        // unset and empty mean the same: classic serve only
        assert_eq!(resolve_service(None), None);
        assert_eq!(resolve_service(Some(String::new())), None);
        // a bare prefix is a misconfiguration: warn, don't advertise
        assert_eq!(resolve_service(Some("svc:".into())), None);
    }

    #[test]
    fn service_knob_merges_over_the_file() {
        let cfg = mk_with_file(
            &[],
            FileConfig::load_from(Some(&env_dotenv("TS_SERVICE=file-svc\n"))),
        );
        assert_eq!(cfg.service.as_deref(), Some("svc:file-svc"));

        let cfg = mk_with_file(
            &[("TS_SERVICE", "env-svc")],
            FileConfig::load_from(Some(&env_dotenv("TS_SERVICE=file-svc\n"))),
        );
        assert_eq!(cfg.service.as_deref(), Some("svc:env-svc"));
    }

    /// One-key dotenv file for the merge tests above.
    fn env_dotenv(contents: &str) -> String {
        let path = std::env::temp_dir().join(format!("vw-sup-svc-{}.env", std::process::id()));
        fs::write(&path, contents).unwrap();
        path.to_str().unwrap().to_string()
    }
}
