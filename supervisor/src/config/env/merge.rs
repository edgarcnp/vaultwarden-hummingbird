//! Config merging: process env + optional dotenv file + code defaults
//! resolved into a validated [`Config`] once at boot.

use std::env;
use std::path::Path;

use crate::config::backup::{DbBackupConfig, resolve_backup};
use crate::config::consts::SUPERVISOR_STATE;
use crate::config::dotenv::FileConfig;
use crate::config::sync::{SyncConfig, resolve_sync};
use crate::util::log;

use super::super::paths;
use super::knobs::{non_empty, parse_flag, resolve_service, valid_port};
use super::schema;

/// Whether a dotenv path is inside the supervisor-only state volume. A
/// `..` component must be refused even when the textual prefix matches:
/// `/state/../data/.env` would otherwise read a vault-writable file.
fn env_file_isolated(path: &str) -> bool {
    crate::util::fs::under_root(Path::new(SUPERVISOR_STATE), path)
}

/// Resolved supervisor configuration (all env/file lookups done once at boot).
pub struct Config {
    /// tailscaled state file (a direct child of the supervisor-only state
    /// root; `mem:` is Tailscale's in-memory state for fully ephemeral
    /// deployments)
    pub state: String,
    /// LocalAPI unix socket (under the supervisor-only state root)
    pub socket: String,
    /// exposed (gatekeeper) port: `VAULTWARDEN_PORT`, process env before
    /// dotenv file, then 8080. The legacy `VAULTWARDEN_ROCKET_PORT` (env
    /// or file) and a bare `ROCKET_PORT` in the dotenv file refuse the
    /// boot — see [`Self::from_env`]; an ambient bare `ROCKET_PORT` is
    /// filtered, not fatal.
    pub port: u16,
    /// vaultwarden's port (`port + 1`, loopback-only). None = exposed port
    /// is 65535: boot must fail closed.
    pub vault_port: Option<u16>,
    /// node name announced to the tailnet (`TAILSCALE_HOSTNAME`)
    pub hostname: String,
    /// Tailscale auth key or OAuth client secret (`TAILSCALE_AUTHKEY`;
    /// optional when a valid local state file exists or S3 state sync can
    /// restore one; required otherwise: boot fails closed without an
    /// identity source)
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
    /// Merge order, everywhere: env > file > default. The dotenv file is
    /// strict (see [`FileConfig`]): only the three namespaces are
    /// accepted and any unrecognized key refuses the boot. The
    /// gatekeeper port has ONE spelling, `VAULTWARDEN_PORT` — the legacy
    /// `VAULTWARDEN_ROCKET_PORT` alias and a bare `ROCKET_PORT` in the
    /// dotenv file refuse the boot with a message naming the valid
    /// spelling (ambient values are filtered, not rejected). vaultwarden
    /// keys (incl. the DB URL) resolve env first, so the supervisor
    /// always sees the same values the child gets
    /// ([`crate::runtime::services::vaultwarden`] applies file, then
    /// ambient, then the pins). Empty = unset; bad booleans warn and
    /// take the default. Returns None when a required knob is missing
    /// (TAILSCALE_AUTHKEY) or anything refuses: the vault is unreachable
    /// without Tailscale, so boot must fail closed.
    pub fn from_env() -> Option<Self> {
        // The dotenv file holds the tailscale auth key and the S3
        // credentials. It must live on the supervisor-only /state volume: a file
        // mounted elsewhere (the old /config/.env) is readable by the vault
        // uid whenever the runtime's uid mapping allows it to be read at
        // all. `--env-file` users have no file in the container and are
        // unaffected (PID 1's environment is 0400 to the vault).
        if let Ok(path) = env::var("SUPERVISOR_ENV_FILE")
            && !path.is_empty()
            && !env_file_isolated(&path)
        {
            log::err(&format!(
                "config: SUPERVISOR_ENV_FILE {} must live under {SUPERVISOR_STATE} \
                 (the vault can read a file mounted on its volume); refusing to start",
                log::sanitize(&path)
            ));
            return None;
        }
        Self::build_at(Path::new(SUPERVISOR_STATE), FileConfig::load(), |k| {
            env::var(k).ok()
        })
    }

    /// [`Self::from_env`] with the env source injected: tests pass a map,
    /// never mutating the process env (unsafe and racy).
    #[cfg(test)]
    fn build(file: FileConfig, lookup: impl Fn(&str) -> Option<String>) -> Option<Self> {
        Self::build_at(Path::new(SUPERVISOR_STATE), file, lookup)
    }

    /// [`Self::build`] with an explicit state root. Production always uses
    /// `/state`; tests use a scratch root so they can create a real identity
    /// file without writing to the image's supervisor volume.
    fn build_at(
        root: &Path,
        file: FileConfig,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Option<Self> {
        // A configured-but-unreadable file refuses the boot: silently
        // running on env-only defaults is exactly the quiet
        // misconfiguration the strict file exists to prevent.
        if let Some(fatal) = &file.fatal {
            log::err(fatal);
            return None;
        }
        // Legacy port spellings refuse the boot, naming the one valid
        // spelling: they once changed behavior, so silently ignoring
        // them would silently change the deployment.
        if non_empty(lookup("VAULTWARDEN_ROCKET_PORT")).is_some() {
            log::err(
                "config: VAULTWARDEN_ROCKET_PORT (from the environment) is no longer accepted; \
                 use VAULTWARDEN_PORT; refusing to start",
            );
            return None;
        }
        if non_empty(file.knobs.get("VAULTWARDEN_ROCKET_PORT").cloned()).is_some() {
            log::err(
                "config: VAULTWARDEN_ROCKET_PORT (from the dotenv file) is no longer accepted; \
                 use VAULTWARDEN_PORT; refusing to start",
            );
            return None;
        }
        if file.invalid.iter().any(|k| k == "ROCKET_PORT") {
            log::err(
                "config: bare ROCKET_PORT (from the dotenv file) is no longer accepted; \
                 use VAULTWARDEN_PORT; refusing to start",
            );
            return None;
        }
        // Any other key outside the accepted namespaces is a typo or a
        // legacy spelling: name it and refuse — never ignore silently.
        if !file.invalid.is_empty() {
            let names = file
                .invalid
                .iter()
                .map(|k| log::sanitize(k))
                .collect::<Vec<_>>()
                .join(", ");
            log::err(&format!(
                "config: unrecognized dotenv file keys ({names}); only TAILSCALE_*/\
                 SUPERVISOR_*/VAULTWARDEN_* keys are accepted; refusing to start"
            ));
            return None;
        }

        // The gatekeeper port: first valid candidate wins (invalid values
        // warn and fall through), process env before the dotenv file.
        let port = [
            lookup("VAULTWARDEN_PORT"),
            file.knobs.get("VAULTWARDEN_PORT").cloned(),
        ]
        .into_iter()
        .find_map(valid_port)
        .unwrap_or_else(|| {
            schema::string_default("VAULTWARDEN_PORT")
                .parse()
                .expect("schema default is a valid port")
        });
        let vault_port = port.checked_add(1);

        let knob = |key: &str, default: &str| -> String {
            non_empty(lookup(key))
                .or_else(|| non_empty(file.knobs.get(key).cloned()))
                .unwrap_or_else(|| default.to_string())
        };
        // Scalar knobs assembled below take their default from the schema
        // table; the feature resolvers above keep their own `knob` calls.
        let value = |key: &str| -> String {
            non_empty(lookup(key))
                .or_else(|| non_empty(file.knobs.get(key).cloned()))
                .unwrap_or_else(|| schema::string_default(key).to_string())
        };
        // Flag knobs have typed defaults, so they take the raw value and
        // let `parse_flag` apply the schema default when it is empty.
        let raw = |key: &str| -> String {
            non_empty(lookup(key))
                .or_else(|| non_empty(file.knobs.get(key).cloned()))
                .unwrap_or_default()
        };

        // The state file anchors the node identity and the `--statedir`
        // derived from it. It must stay on the supervisor-only volume and
        // directly under its root so the derived cert cache is the synced
        // `/state/certs` tree. `mem:` is Tailscale's in-memory state.
        let state = value("TAILSCALE_STATE_FILE");
        if !paths::state_file(root, &state) {
            log::err(&format!(
                "config: TAILSCALE_STATE_FILE '{}' must be 'mem:' or a direct child of \
                 {}/tailscale; refusing to start",
                log::sanitize(&state),
                root.display()
            ));
            return None;
        }
        let state_rel = paths::state_rel(root, &state);
        let state_present = state != "mem:"
            && std::fs::metadata(&state).is_ok_and(|meta| meta.is_file() && meta.len() > 0);
        // The socket controls the LocalAPI: a socket on the vault volume
        // could be deleted or impersonated by the vault uid.
        let socket = value("TAILSCALE_SOCKET");
        if !paths::socket(root, &socket) {
            log::err(&format!(
                "config: TAILSCALE_SOCKET '{}' must be a path under {}/tailscale; \
                 refusing to start",
                log::sanitize(&socket),
                root.display()
            ));
            return None;
        }
        // A custom identity file must not shadow a supervisor sidecar or a
        // vault/bucket key. Check it even when sync is off: enabling sync
        // later must not turn a valid boot into a bucket collision.
        if let Some(rel) = state_rel
            && paths::reserved_state_name(rel)
        {
            log::err(&format!(
                "config: TAILSCALE_STATE_FILE '{}' collides with a supervisor or vault \
                 key; choose another name directly under {}/tailscale",
                log::sanitize(&state),
                root.display()
            ));
            return None;
        }

        let mut sync = resolve_sync(&knob);

        // The vault's DB URL: env wins over file — the same precedence the
        // child env applies, so dumps and restores always reach the same DB
        // the vault uses. The file's entry arrives only via the strict
        // routing (`VAULTWARDEN_DATABASE_URL` stripped); a bare
        // `DATABASE_URL` in the file already refused the boot above.
        let db_url = non_empty(lookup("VAULTWARDEN_DATABASE_URL"))
            .or_else(|| non_empty(file.child.get("DATABASE_URL").cloned()));
        let backup = resolve_backup(&knob, sync.as_ref(), db_url.clone());

        // A key is required only when no other source can supply identity:
        // a valid local state file, or a sync bucket that covers it.
        let authkey = non_empty(Some(knob("TAILSCALE_AUTHKEY", "")));
        let sync_can_supply = sync.is_some() && state_rel.is_some();
        if authkey.is_none() && !state_present && !sync_can_supply {
            log::err(
                "config: no identity source: set TAILSCALE_AUTHKEY, keep a valid local \
                 TAILSCALE_STATE_FILE, or configure SUPERVISOR_S3_* state sync covering \
                 that file; refusing to start",
            );
            return None;
        }
        if let Some(sync) = sync.as_mut()
            && let Some(rel) = state_rel
        {
            sync.set_state_file_rel(rel);
        }

        // Temporary-storage mode: an explicitly configured persistence
        // feature that cannot work is fatal (there is nowhere else for the
        // data to go); on a real volume it is an error message and a
        // degraded feature. `mem:`, a tmpfs /data, or vaultwarden's
        // volatile-storage acknowledgement declare the same mode.
        let volatile_storage = non_empty(lookup("VAULTWARDEN_I_REALLY_WANT_VOLATILE_STORAGE"))
            .or_else(|| non_empty(file.child.get("I_REALLY_WANT_VOLATILE_STORAGE").cloned()))
            .is_some();
        let ephemeral = parse_flag(
            "SUPERVISOR_EPHEMERAL",
            &raw("SUPERVISOR_EPHEMERAL"),
            schema::bool_default("SUPERVISOR_EPHEMERAL"),
        ) || state == "mem:"
            || volatile_storage
            || crate::util::fs::on_tmpfs("/data");
        if ephemeral {
            let s3_requested = [
                "SUPERVISOR_S3_REMOTE",
                "SUPERVISOR_S3_ACCESS_KEY_ID",
                "SUPERVISOR_S3_SECRET_ACCESS_KEY",
                "SUPERVISOR_S3_ENDPOINT",
                "SUPERVISOR_S3_SYNC_INTERVAL",
            ]
            .iter()
            .any(|key| !knob(key, "").is_empty());
            let backup_requested = [
                "SUPERVISOR_DB_BACKUP",
                "SUPERVISOR_DB_BACKUP_INTERVAL",
                "SUPERVISOR_DB_BACKUP_KEEP",
                "SUPERVISOR_DB_BACKUP_RESTORE",
            ]
            .iter()
            .any(|key| !knob(key, "").is_empty());
            if s3_requested && sync.is_none() {
                log::err(
                    "config: temporary-storage mode is declared but SUPERVISOR_S3_* is \
                     unusable; refusing to start with nowhere durable to put the data",
                );
                return None;
            }
            if backup_requested && backup.is_none() {
                log::err(
                    "config: temporary-storage mode is declared but SUPERVISOR_DB_BACKUP* \
                     is unusable; refusing to start with no DB backup",
                );
                return None;
            }
            if !s3_requested && !backup_requested {
                log::err(
                    "config: temporary-storage mode declared with no state sync or DB \
                     backup; data will not survive a redeploy",
                );
            }
        }

        Some(Self {
            state,
            socket,
            port,
            vault_port,
            hostname: value("TAILSCALE_HOSTNAME"),
            authkey,
            serve: parse_flag(
                "TAILSCALE_SERVE",
                &raw("TAILSCALE_SERVE"),
                schema::bool_default("TAILSCALE_SERVE"),
            ),
            service: resolve_service(
                non_empty(lookup("TAILSCALE_SERVICE"))
                    .or_else(|| non_empty(file.knobs.get("TAILSCALE_SERVICE").cloned())),
            ),
            userspace: parse_flag(
                "TAILSCALE_USERSPACE",
                &raw("TAILSCALE_USERSPACE"),
                schema::bool_default("TAILSCALE_USERSPACE"),
            ),
            sync,
            backup,
            vw_env: file.child.into_iter().collect(),
        })
    }
}

#[cfg(test)]
mod tests;
