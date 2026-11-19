//! Config merging: process env + optional dotenv file + code defaults
//! resolved into a validated [`Config`] once at boot.

use std::env;

use crate::config::backup::{DbBackupConfig, resolve_backup};
use crate::config::consts::SUPERVISOR_STATE;
use crate::config::dotenv::FileConfig;
use crate::config::sync::{SyncConfig, resolve_sync};
use crate::util::log;

use super::knobs::{non_empty, parse_flag, resolve_service, valid_port};
use super::schema;

/// Whether a dotenv path is inside the supervisor-only state volume. A
/// `..` component must be refused even when the textual prefix matches:
/// `/state/../data/.env` would otherwise read a vault-writable file.
fn env_file_isolated(path: &str) -> bool {
    use std::path::Component;

    let path = std::path::Path::new(path);
    path.is_absolute()
        && path.starts_with(SUPERVISOR_STATE)
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}

/// A custom state file is a bucket key too. These names already belong to
/// vault data (or the cert tree), so a state file using one would overwrite
/// or shadow that object in the bucket.
fn reserved_state_name(rel: &str) -> bool {
    rel == "config.json"
        || rel == "manifest"
        || rel == "tombstones"
        || rel == "certs"
        || rel == "attachments"
        || rel == "sends"
        || rel.starts_with("certs/")
        || rel.starts_with("attachments/")
        || rel.starts_with("sends/")
        || (rel.starts_with("rsa_key") && !rel.contains('/'))
}

/// Resolved supervisor configuration (all env/file lookups done once at boot).
pub struct Config {
    /// tailscaled state file (under the supervisor-only state volume;
    /// `mem:` is Tailscale's in-memory state for fully ephemeral
    /// deployments)
    pub state: String,
    /// LocalAPI unix socket (writable, non-volume path)
    pub socket: String,
    /// exposed (gatekeeper) port: `VAULTWARDEN_PORT`, process env before
    /// dotenv file, then 8080. The legacy `VAULTWARDEN_ROCKET_PORT` (env
    /// or file) and a bare `ROCKET_PORT` in the dotenv file refuse the
    /// boot — see [`Self::from_env`]; an ambient bare `ROCKET_PORT` is
    /// filtered, not fatal.
    pub port: String,
    /// vaultwarden's port (`port + 1`, loopback-only). None = exposed port
    /// is 65535: boot must fail closed.
    pub vault_port: Option<String>,
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
        // credentials. It must live on the 0700 supervisor volume: a file
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
        Self::build(FileConfig::load(), |k| env::var(k).ok())
    }

    /// [`Self::from_env`] with the env source injected: tests pass a map,
    /// never mutating the process env (unsafe and racy).
    fn build(file: FileConfig, lookup: impl Fn(&str) -> Option<String>) -> Option<Self> {
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
        .unwrap_or_else(|| schema::string_default("VAULTWARDEN_PORT").to_string());
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
        // derived from it; a relative path has no stable meaning for a
        // PID 1 (and would yield an empty statedir). `mem:` is Tailscale's
        // in-memory state, the documented fully-ephemeral mode.
        let state = value("TAILSCALE_STATE_FILE");
        if state != "mem:" && !state.starts_with('/') {
            log::err(&format!(
                "config: TAILSCALE_STATE_FILE '{}' must be an absolute path (or 'mem:'); \
                 refusing to start",
                log::sanitize(&state)
            ));
            return None;
        }
        // A state file is a third identity source, alongside an authkey and
        // a sync bucket that can restore one. Only a normal, non-empty path
        // under the supervisor-only state root is covered by state sync.
        let state_under_state = state.strip_prefix("/state/").filter(|rel| {
            !rel.is_empty()
                && !rel.starts_with('/')
                && !rel.contains("..")
                && !rel.chars().any(char::is_control)
        });
        let state_present = state != "mem:"
            && std::fs::metadata(&state).is_ok_and(|meta| meta.is_file() && meta.len() > 0);

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
        let sync_can_supply = sync.is_some() && state_under_state.is_some();
        if authkey.is_none() && !state_present && !sync_can_supply {
            log::err(
                "config: no identity source: set TAILSCALE_AUTHKEY, keep a valid local \
                 TAILSCALE_STATE_FILE, or configure SUPERVISOR_S3_* state sync covering \
                 that file; refusing to start",
            );
            return None;
        }
        // The identity file must ride inside the state root; anything else
        // cannot be covered by state sync, so say so rather than silently
        // losing the node on the next redeploy.
        if let Some(sync) = sync.as_mut() {
            sync.set_state_file(&state);
            if let Some(rel) = sync.state_file.as_deref()
                && reserved_state_name(rel)
            {
                log::err(&format!(
                    "config: TAILSCALE_STATE_FILE '{}' collides with a vault data key in \
                     the sync namespace; choose another name under /state",
                    log::sanitize(&state)
                ));
                return None;
            }
            if sync.state_file.is_none() && state != "mem:" {
                log::err(&format!(
                    "config: TAILSCALE_STATE_FILE '{}' is outside /state; SUPERVISOR_S3_* \
                     state sync cannot carry the node identity",
                    log::sanitize(&state)
                ));
            }
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
            // hard-pinned to the volume; the sync scope is /data too
            state,
            socket: value("TAILSCALE_SOCKET"),
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
