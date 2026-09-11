//! Config merging: process env + optional dotenv file + code defaults
//! resolved into a validated [`Config`] once at boot.

use std::env;

use crate::config::backup::{DbBackupConfig, resolve_backup};
use crate::config::dotenv::FileConfig;
use crate::config::sync::{SyncConfig, resolve_sync};
use crate::util::log;

use super::knobs::{non_empty, parse_flag, resolve_service, valid_port};

/// Resolved supervisor configuration (all env/file lookups done once at boot).
pub struct Config {
    /// tailscaled state file (under the writable data volume)
    pub state: String,
    /// LocalAPI unix socket (writable, non-volume path)
    pub socket: String,
    /// exposed (gatekeeper) port: `VAULTWARDEN_PORT` (or its upstream-named
    /// alias `VAULTWARDEN_ROCKET_PORT`), process env before dotenv file,
    /// then the file's bare ROCKET_PORT, then 8080
    pub port: String,
    /// vaultwarden's port (`port + 1`, loopback-only). None = exposed port
    /// is 65535: boot must fail closed.
    pub vault_port: Option<String>,
    /// node name announced to the tailnet (`TAILSCALE_HOSTNAME`)
    pub hostname: String,
    /// Tailscale auth key or OAuth client secret (`TAILSCALE_AUTHKEY`;
    /// optional when S3 state sync is configured — the bucket then
    /// supplies the node identity — required otherwise: boot fails closed
    /// without one of the two)
    pub authkey: Option<String>,
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
    /// verbatim vaultwarden env (from the dotenv file, if any)
    pub vw_env: Vec<(String, String)>,
}

impl Config {
    /// Merge order, everywhere: env > file > default. The gatekeeper port
    /// accepts both knob spellings from either layer, then the file's bare
    /// ROCKET_PORT; vaultwarden keys (incl. the DB URL) likewise resolve
    /// env first, so the supervisor always sees the same values the child
    /// gets ([`crate::runtime::services::vaultwarden`] applies file, then
    /// ambient, then the pins). Empty = unset; bad booleans warn and take
    /// the default. Returns None when a required knob is missing
    /// (TAILSCALE_AUTHKEY): the vault is unreachable without Tailscale, so
    /// boot must fail closed.
    pub fn from_env() -> Option<Self> {
        Self::build(FileConfig::load(), |k| env::var(k).ok())
    }

    /// [`Self::from_env`] with the env source injected: tests pass a map,
    /// never mutating the process env (unsafe and racy).
    fn build(file: FileConfig, lookup: impl Fn(&str) -> Option<String>) -> Option<Self> {
        // The gatekeeper port: first valid candidate wins (invalid values
        // warn and fall through), process env before the dotenv file.
        let port = [
            lookup("VAULTWARDEN_PORT"),
            lookup("VAULTWARDEN_ROCKET_PORT"),
            file.knobs.get("VAULTWARDEN_PORT").cloned(),
            file.knobs.get("VAULTWARDEN_ROCKET_PORT").cloned(),
            file.child.get("ROCKET_PORT").cloned(),
        ]
        .into_iter()
        .find_map(valid_port)
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

        // The vault's DB URL: env wins over file — the same precedence the
        // child env applies, so dumps and restores always reach the same DB
        // the vault uses. (A bare DATABASE_URL on the container env is
        // default-deny for the child and is NOT consulted here: consuming
        // it would desync the backup target from the vault's actual DB.
        // The file's bare spelling is the explicit grant surface.)
        let db_url = non_empty(lookup("VAULTWARDEN_DATABASE_URL"))
            .or_else(|| file.child.get("DATABASE_URL").cloned());
        let backup = resolve_backup(&knob, sync.as_ref(), db_url.clone());

        let flag = |key: &str, default: bool| parse_flag(key, &knob(key, ""), default);

        // The node joins the tailnet with EITHER an authkey OR a restored
        // identity: with S3 state sync configured, the pulled
        // tailscaled.state is the machine and the key is never consumed —
        // so the key is only required when sync cannot supply the identity.
        let authkey = non_empty(Some(knob("TAILSCALE_AUTHKEY", "")));
        if authkey.is_none() && sync.is_none() {
            log::err(
                "config: TAILSCALE_AUTHKEY is required unless SUPERVISOR_S3_* state sync \
                 is configured to restore the node identity; refusing to start",
            );
            return None;
        }

        Some(Self {
            // hard-pinned to the volume; the sync scope is /data too
            state: knob("TAILSCALE_STATE_FILE", "/data/tailscaled.state"),
            socket: knob("TAILSCALE_SOCKET", "/tmp/tailscaled.sock"),
            port,
            vault_port,
            hostname: knob("TAILSCALE_HOSTNAME", "vaultwarden-hummingbird"),
            authkey,
            serve: flag("TAILSCALE_SERVE", true),
            service: resolve_service(
                lookup("TAILSCALE_SERVICE")
                    .or_else(|| file.knobs.get("TAILSCALE_SERVICE").cloned()),
            ),
            userspace: flag("TAILSCALE_USERSPACE", true),
            sync,
            backup,
            vw_env: file.child.into_iter().collect(),
        })
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
            // TAILSCALE_AUTHKEY is required; tests without one (in env or
            // file) get a placeholder so unrelated knobs stay exercisable
            None if k == "TAILSCALE_AUTHKEY" && !file_has_key => Some("test-key".to_string()),
            None => None,
        })
        .expect("test config always resolves")
    }

    #[test]
    fn authkey_required_unless_sync_can_restore_the_identity() {
        // no authkey from env or file, no state sync: fail closed
        let map: BTreeMap<String, String> = BTreeMap::new();
        assert!(
            Config::build(FileConfig::default(), move |k| map.get(k).cloned()).is_none(),
            "missing TAILSCALE_AUTHKEY without state sync must refuse to start"
        );
        // empty is as good as missing
        let map: BTreeMap<String, String> = [("TAILSCALE_AUTHKEY".to_string(), String::new())]
            .into_iter()
            .collect();
        assert!(Config::build(FileConfig::default(), move |k| map.get(k).cloned()).is_none());
        // file layer satisfies the requirement too
        let file = FileConfig::load_from(Some(&env_dotenv("TAILSCALE_AUTHKEY=file-key\n")));
        let cfg = Config::build(file, |_| None).expect("file key satisfies the gate");
        assert_eq!(cfg.authkey.as_deref(), Some("file-key"));
        // no authkey, but state sync configured: the bucket supplies the
        // node identity, so the key is optional
        let map: BTreeMap<String, String> = [
            ("SUPERVISOR_S3_REMOTE".to_string(), "r2:vw".to_string()),
            ("SUPERVISOR_S3_ACCESS_KEY_ID".to_string(), "id".to_string()),
            (
                "SUPERVISOR_S3_SECRET_ACCESS_KEY".to_string(),
                "sec".to_string(),
            ),
        ]
        .into_iter()
        .collect();
        let cfg = Config::build(FileConfig::default(), move |k| map.get(k).cloned())
            .expect("state sync replaces the authkey requirement");
        assert_eq!(cfg.authkey, None);
        assert!(cfg.sync.is_some());
        // an explicit empty key with sync configured passes the same way
        let map: BTreeMap<String, String> = [
            ("TAILSCALE_AUTHKEY".to_string(), String::new()),
            ("SUPERVISOR_S3_REMOTE".to_string(), "r2:vw".to_string()),
            ("SUPERVISOR_S3_ACCESS_KEY_ID".to_string(), "id".to_string()),
            (
                "SUPERVISOR_S3_SECRET_ACCESS_KEY".to_string(),
                "sec".to_string(),
            ),
        ]
        .into_iter()
        .collect();
        let cfg = Config::build(FileConfig::default(), move |k| map.get(k).cloned())
            .expect("empty key with sync configured is fine");
        assert_eq!(cfg.authkey, None);
        // sync knobs WITHOUT the credentials are not state sync: still
        // fail closed
        let map: BTreeMap<String, String> =
            [("SUPERVISOR_S3_REMOTE".to_string(), "r2:vw".to_string())]
                .into_iter()
                .collect();
        assert!(
            Config::build(FileConfig::default(), move |k| map.get(k).cloned()).is_none(),
            "a remote without credentials is not an identity source"
        );
    }

    #[test]
    fn defaults_and_merge_order() {
        let cfg = mk(&[]);
        assert_eq!(cfg.port, "8080");
        assert_eq!(cfg.vault_port.as_deref(), Some("8081"));
        assert_eq!(cfg.socket, "/tmp/tailscaled.sock");
        assert_eq!(cfg.state, "/data/tailscaled.state");
        assert_eq!(cfg.hostname, "vaultwarden-hummingbird");
        assert_eq!(cfg.authkey.as_deref(), Some("test-key"));
        assert!(cfg.serve && cfg.userspace);
        assert_eq!(cfg.service, None);
        assert!(cfg.vw_env.is_empty());
        assert!(cfg.sync.is_none());

        let cfg = mk(&[("VAULTWARDEN_PORT", "3000")]);
        assert_eq!(cfg.port, "3000");
        assert_eq!(cfg.vault_port.as_deref(), Some("3001"));
        let cfg = mk(&[("VAULTWARDEN_PORT", "")]);
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
        assert_eq!(cfg.authkey.as_deref(), Some("file-key"));
        assert!(!cfg.serve);
        assert!(cfg.userspace);
        assert_eq!(
            cfg.vw_env
                .iter()
                .find(|(k, _)| k == "DOMAIN")
                .map(|(_, v)| v.as_str()),
            Some("https://f.example")
        );
        assert!(cfg.vw_env.iter().any(|(k, _)| k == "DOMAIN"));
        assert!(!cfg.vw_env.iter().any(|(k, _)| is_supervisor_key(k)));
        // the port knob stays with the supervisor (the child's port is pinned)
        assert!(!cfg.vw_env.iter().any(|(k, _)| k == "ROCKET_PORT"));

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

    /// The gatekeeper port resolves from any layer and either spelling,
    /// process env before the dotenv file. The file's VAULTWARDEN_PORT
    /// previously leaked to the child as PORT instead of being consumed.
    #[test]
    fn port_resolves_from_any_source_env_first() {
        // file spelling VAULTWARDEN_PORT (documented in .env.example)
        let cfg = mk_with_file(
            &[],
            FileConfig::load_from(Some(&env_dotenv("VAULTWARDEN_PORT=8443\n"))),
        );
        assert_eq!(cfg.port, "8443");
        assert_eq!(cfg.vault_port.as_deref(), Some("8444"));
        // file alias spelling
        let cfg = mk_with_file(
            &[],
            FileConfig::load_from(Some(&env_dotenv("VAULTWARDEN_ROCKET_PORT=8445\n"))),
        );
        assert_eq!(cfg.port, "8445");
        // file's bare ROCKET_PORT keeps working as the last fallback
        let cfg = mk_with_file(
            &[],
            FileConfig::load_from(Some(&env_dotenv("ROCKET_PORT=8446\n"))),
        );
        assert_eq!(cfg.port, "8446");
        // env beats the file at every spelling
        let cfg = mk_with_file(
            &[("VAULTWARDEN_PORT", "3000")],
            FileConfig::load_from(Some(&env_dotenv("VAULTWARDEN_PORT=8443\n"))),
        );
        assert_eq!(cfg.port, "3000");
        // env alias beats file knob
        let cfg = mk_with_file(
            &[("VAULTWARDEN_ROCKET_PORT", "3001")],
            FileConfig::load_from(Some(&env_dotenv("VAULTWARDEN_PORT=8443\n"))),
        );
        assert_eq!(cfg.port, "3001");
        // an invalid env value warns and falls through to the file
        let cfg = mk_with_file(
            &[("VAULTWARDEN_PORT", "not-a-port")],
            FileConfig::load_from(Some(&env_dotenv("VAULTWARDEN_PORT=8443\n"))),
        );
        assert_eq!(cfg.port, "8443");
    }

    /// The vault's DB URL follows the same env > file precedence the child
    /// env applies, so the supervisor's backup target is always the DB the
    /// vault actually uses.
    #[test]
    fn db_url_env_wins_over_file() {
        let s3: &[(&str, &str)] = &[
            ("SUPERVISOR_S3_REMOTE", "r2:vw"),
            ("SUPERVISOR_S3_ACCESS_KEY_ID", "id"),
            ("SUPERVISOR_S3_SECRET_ACCESS_KEY", "secret"),
            ("SUPERVISOR_DB_BACKUP", "true"),
        ];
        let mut env: Vec<(&str, &str)> = s3.to_vec();
        env.push(("VAULTWARDEN_DATABASE_URL", "sqlite:///data/env.sqlite3"));
        let cfg = mk_with_file(
            &env,
            FileConfig::load_from(Some(&env_dotenv(
                "DATABASE_URL=sqlite:///data/file.sqlite3\n",
            ))),
        );
        assert_eq!(
            cfg.backup.as_ref().expect("backup enabled").db_path,
            "/data/env.sqlite3"
        );

        // file-only (either spelling) still resolves
        let cfg = mk_with_file(
            s3,
            FileConfig::load_from(Some(&env_dotenv(
                "VAULTWARDEN_DATABASE_URL=sqlite:///data/file.sqlite3\n",
            ))),
        );
        assert_eq!(
            cfg.backup.as_ref().expect("backup enabled").db_path,
            "/data/file.sqlite3"
        );
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

    /// One-key dotenv file for the merge tests above. Unique per call:
    /// tests run in parallel threads of one process, and a shared path
    /// would let one test's write race another test's read.
    fn env_dotenv(contents: &str) -> String {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("vw-sup-svc-{}-{n}.env", std::process::id()));
        fs::write(&path, contents).unwrap();
        path.to_str().unwrap().to_string()
    }
}
