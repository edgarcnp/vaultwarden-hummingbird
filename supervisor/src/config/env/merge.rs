//! Config merging: process env + optional dotenv file + code defaults
//! resolved into a validated [`Config`] once at boot.

use std::env;

use crate::config::backup::{DbBackupConfig, resolve_backup};
use crate::config::dotenv::FileConfig;
use crate::config::keepalive::DbKeepalive;
use crate::config::sync::{SyncConfig, resolve_sync};
use crate::util::log;

use super::knobs::{non_empty, parse_bool, resolve_service, valid_port};

/// Resolved supervisor configuration (all env/file lookups done once at boot).
pub struct Config {
    /// tailscaled state file (under the writable data volume)
    pub state: String,
    /// LocalAPI unix socket (writable, non-volume path)
    pub socket: String,
    /// exposed (gatekeeper) port: VAULTWARDEN_PORT > VAULTWARDEN_ROCKET_PORT > 8080
    pub port: String,
    /// vaultwarden's port (`port + 1`, loopback-only). None = exposed port
    /// is 65535: boot must fail closed.
    pub vault_port: Option<String>,
    /// node name announced to the tailnet (`TAILSCALE_HOSTNAME`)
    pub hostname: String,
    /// Tailscale auth key or OAuth client secret (`TAILSCALE_AUTHKEY`;
    /// empty = skip `up`)
    pub authkey: String,
    /// configure `tailscale serve` after a successful up
    pub serve: bool,
    /// advertise this node as a host of `svc:<name>` via `tailscale serve
    /// --service` (`TAILSCALE_SERVICE`; None = classic device-level serve
    /// only)
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
    /// Merge order: knobs = env > file > default; port = VAULTWARDEN_PORT >
    /// VAULTWARDEN_ROCKET_PORT (env) > file ROCKET_PORT > 8080; vaultwarden
    /// keys = file > env.
    /// Empty = unset; bad booleans warn and take the default.
    pub fn from_env() -> Self {
        Self::build(FileConfig::load(), |k| env::var(k).ok())
    }

    /// [`Self::from_env`] with the env source injected: tests pass a map,
    /// never mutating the process env (unsafe and racy).
    fn build(file: FileConfig, lookup: impl Fn(&str) -> Option<String>) -> Self {
        let port = valid_port(lookup("VAULTWARDEN_PORT"))
            .or_else(|| valid_port(lookup("VAULTWARDEN_ROCKET_PORT")))
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
            .or_else(|| non_empty(lookup("VAULTWARDEN_DATABASE_URL")));
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
            state: knob("TAILSCALE_STATE_FILE", "/data/tailscaled.state"),
            socket: knob("TAILSCALE_SOCKET", "/tmp/tailscaled.sock"),
            port,
            vault_port,
            hostname: knob("TAILSCALE_HOSTNAME", "vaultwarden-hummingbird"),
            authkey: knob("TAILSCALE_AUTHKEY", ""),
            serve: flag("TAILSCALE_SERVE", true),
            service: resolve_service(
                lookup("TAILSCALE_SERVICE")
                    .or_else(|| file.knobs.get("TAILSCALE_SERVICE").cloned()),
            ),
            userspace: flag("TAILSCALE_USERSPACE", true),
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
    use crate::config::env::knobs::is_supervisor_key;

    /// Config from an explicit variable map + optional dotenv file layer
    /// (never the process env — see [`Config::build`]). TAILSCALE_AUTHKEY
    /// is required, so tests inject a default.
    fn mk(vars: &[(&str, &str)]) -> Config {
        mk_with_file(vars, FileConfig::default())
    }

    fn mk_with_file(vars: &[(&str, &str)], file: FileConfig) -> Config {
        let map: BTreeMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let file_has_key = file.knobs.contains_key("TAILSCALE_AUTHKEY");
        Config::build(file, move |k| match map.get(k) {
            Some(v) => Some(v.clone()),
            // tests without an explicit authkey (env or file) get a
            // placeholder so unrelated knobs stay exercisable
            None if k == "TAILSCALE_AUTHKEY" && !file_has_key => Some("test-key".to_string()),
            None => None,
        })
    }

    #[test]
    fn defaults_and_merge_order() {
        let cfg = mk(&[]);
        assert_eq!(cfg.port, "8080");
        assert_eq!(cfg.vault_port.as_deref(), Some("8081"));
        assert_eq!(cfg.socket, "/tmp/tailscaled.sock");
        assert_eq!(cfg.state, "/data/tailscaled.state");
        assert_eq!(cfg.hostname, "vaultwarden-hummingbird");
        assert_eq!(cfg.authkey, "test-key");
        assert!(cfg.serve && cfg.userspace);
        assert_eq!(cfg.service, None);
        assert!(cfg.vw_env.is_empty());
        assert!(cfg.sync.is_none());

        let cfg = mk(&[
            ("VAULTWARDEN_PORT", "3000"),
            ("VAULTWARDEN_ROCKET_PORT", "1111"),
        ]);
        assert_eq!(cfg.port, "3000");
        assert_eq!(cfg.vault_port.as_deref(), Some("3001"));
        let cfg = mk(&[("VAULTWARDEN_ROCKET_PORT", "1111")]);
        assert_eq!(cfg.port, "1111");
        let cfg = mk(&[("VAULTWARDEN_PORT", ""), ("VAULTWARDEN_ROCKET_PORT", "")]);
        assert_eq!(cfg.port, "8080");

        // 65535 leaves no room above the exposed port: fail closed.
        let cfg = mk(&[("VAULTWARDEN_PORT", "65535")]);
        assert_eq!(cfg.port, "65535");
        assert_eq!(cfg.vault_port, None);
    }

    #[test]
    fn dotenv_file_merges_below_process_env() {
        let path = std::env::temp_dir().join(format!("vw-sup-cfg-{}.env", std::process::id()));
        fs::write(
            &path,
            "VAULTWARDEN_ROCKET_PORT=2222\nTAILSCALE_HOSTNAME=file-host\nTAILSCALE_AUTHKEY=file-key\nTAILSCALE_SERVE=false\nVAULTWARDEN_DOMAIN=https://f.example\n",
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
        assert!(cfg.vw_env.iter().any(|(k, _)| k == "DOMAIN"));
        assert!(!cfg.vw_env.iter().any(|(k, _)| is_supervisor_key(k)));

        // process env wins over the file for supervisor knobs
        let cfg = mk_with_file(
            &[("TAILSCALE_HOSTNAME", "env-host")],
            FileConfig::load_from(Some(path_str)),
        );
        assert_eq!(cfg.hostname, "env-host");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn lenient_bool_knobs() {
        let cfg = mk(&[("TAILSCALE_SERVE", "YES"), ("TAILSCALE_USERSPACE", "0")]);
        assert!(cfg.serve);
        assert!(!cfg.userspace);

        // misspelling warns and takes the default
        let cfg = mk(&[("TAILSCALE_SERVE", "definitely")]);
        assert!(cfg.serve);
    }

    #[test]
    fn service_knob_merges_over_the_file() {
        let cfg = mk_with_file(
            &[],
            FileConfig::load_from(Some(&env_dotenv("TAILSCALE_SERVICE=file-svc\n"))),
        );
        assert_eq!(cfg.service.as_deref(), Some("svc:file-svc"));

        let cfg = mk_with_file(
            &[("TAILSCALE_SERVICE", "env-svc")],
            FileConfig::load_from(Some(&env_dotenv("TAILSCALE_SERVICE=file-svc\n"))),
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
