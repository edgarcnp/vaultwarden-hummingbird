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

/// Whether a dotenv path is inside the supervisor-only state volume and
/// outside the tailscaled-writable subtree. Textual prefixes are not enough:
/// `..` and the daemon's replaceable tree could expose a vault-writable file.
fn env_file_isolated(path: &str) -> bool {
    let root = Path::new(SUPERVISOR_STATE);
    let tailscale = Path::new(crate::config::TAILSCALE_DIR);
    let link = Path::new(crate::config::TAILSCALE_STATE_DIR);
    crate::util::fs::under_root(root, path)
        && !crate::util::fs::under_root(tailscale, path)
        && !crate::util::fs::under_root(link, path)
}

/// Whether the state file holds a real machine key: `tailscaled` writes `{}`
/// before login, so a placeholder must not satisfy the authkey gate. The read
/// is capped; the file may be 0600 (the supervisor holds CAP_DAC_READ_SEARCH).
fn state_has_identity(path: &str) -> bool {
    use base64::Engine as _;

    const MAX_STATE_BYTES: u64 = 16 * 1024 * 1024;
    let bytes = match crate::util::fs::read_capped_bytes(path, MAX_STATE_BYTES) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return false,
        Err(e) => {
            log::err(&format!(
                "config: cannot read the Tailscale state file {} ({e}); treating it as \
                 no identity — check the file mode and CAP_DAC_READ_SEARCH",
                log::sanitize(path)
            ));
            return false;
        }
    };
    // The FileStore JSON marshals `_machinekey` as a base64 string of the
    // 32-byte machine key. `{}` (written before login) and a corrupt key are
    // not identities; a local state that is not usable must not skip the
    // authkey gate.
    let Some(encoded) = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|value| value.get("_machinekey").cloned())
        .and_then(|value| value.as_str().map(str::to_string))
    else {
        return false;
    };
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .is_ok_and(|key| !key.is_empty())
}

/// Resolved supervisor configuration (all env/file lookups done once at boot).
pub struct Config {
    /// tailscaled state file (a direct child of the supervisor-only state
    /// root; `mem:` is Tailscale's in-memory state for fully ephemeral
    /// deployments)
    pub state: String,
    /// LocalAPI unix socket (under the supervisor-only state root)
    pub socket: String,
    /// Exposed (gatekeeper) port: `VAULTWARDEN_PORT`, env before dotenv file,
    /// then 8080. Legacy `VAULTWARDEN_ROCKET_PORT` and a bare `ROCKET_PORT` in
    /// the dotenv file refuse the boot; an ambient bare `ROCKET_PORT` is filtered.
    pub port: u16,
    /// vaultwarden's port (`port + 1`, loopback-only). None = exposed port
    /// is 65535: boot must fail closed.
    pub vault_port: Option<u16>,
    /// node name announced to the tailnet (`TAILSCALE_HOSTNAME`)
    pub hostname: String,
    /// Tailscale auth key or OAuth client secret (`TAILSCALE_AUTHKEY`). Optional
    /// when a valid local state file exists or S3 state sync can restore one;
    /// otherwise required, and boot fails closed without an identity source.
    pub authkey: Option<String>,
    /// configure `tailscale serve` after a successful up
    pub serve: bool,
    /// advertise this node as a host of `svc:<name>` via `tailscale serve
    /// --service` (`TAILSCALE_SERVICE`; None = classic device-level serve
    /// only)
    pub service: Option<String>,
    /// userspace networking: no TUN device on PaaS platforms
    pub userspace: bool,
    /// Run every child as PID 1's identity, without changing uid/gid or
    /// joining the tailscale group. Opt-in fallback for runtimes that
    /// cannot grant SETUID/SETGID/KILL/DAC_READ_SEARCH. It removes the
    /// vault/state isolation, so boot logs it as a security warning.
    pub single_uid: bool,
    /// S3 state sync (None = disabled)
    pub sync: Option<SyncConfig>,
    /// DB backup/restore (None = disabled)
    pub backup: Option<DbBackupConfig>,
    /// verbatim vaultwarden env (from the dotenv file, if any)
    pub vw_env: Vec<(String, String)>,
}

/// Boot-affecting flags resolved before the group join and layout
/// migration. Read from the process environment only: the dotenv file is
/// not parsed yet, so a file value could never take effect.
#[derive(Clone, Copy, Debug, Default)]
pub struct EarlyConfig {
    /// Run every child as the supervisor's uid/gid (no capability change).
    pub single_uid: bool,
}

impl EarlyConfig {
    /// Read the early flags from the process environment.
    pub fn from_env() -> Self {
        Self::from_lookup(&|k| env::var(k).ok())
    }

    /// [`Self::from_env`] with the source injected, for the config tests
    /// that never mutate the process environment.
    fn from_lookup(lookup: &impl Fn(&str) -> Option<String>) -> Self {
        let raw = lookup(schema::SINGLE_UID).unwrap_or_default();
        Self {
            single_uid: parse_flag(
                schema::SINGLE_UID,
                &raw,
                schema::bool_default(schema::SINGLE_UID),
            ),
        }
    }
}

impl Config {
    /// Resolve the full config with merge order env > dotenv file > schema
    /// default. Empty means unset, bad flags warn and take the default, and
    /// any refusal (strict file, legacy port spelling, no identity) is `None`.
    pub fn from_env() -> Option<Self> {
        Self::from_env_with(EarlyConfig::from_env())
    }

    /// [`Self::from_env`] with the pre-config flags passed explicitly, so
    /// the boot decision and the resolved config cannot diverge.
    pub fn from_env_with(early: EarlyConfig) -> Option<Self> {
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
                "config: SUPERVISOR_ENV_FILE {} must live under {SUPERVISOR_STATE} and \
                 outside {}/tailscale (the vault can read a file mounted on its volume, \
                 and tailscaled can replace a file in its subtree); refusing to start",
                log::sanitize(&path),
                SUPERVISOR_STATE
            ));
            return None;
        }
        Self::build_at(
            Path::new(SUPERVISOR_STATE),
            FileConfig::load(),
            |k| env::var(k).ok(),
            early,
        )
    }

    /// [`Self::from_env`] with the env source injected: tests pass a map,
    /// never mutating the process env (unsafe and racy).
    #[cfg(test)]
    fn build(file: FileConfig, lookup: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let early = EarlyConfig::from_lookup(&lookup);
        Self::build_at(Path::new(SUPERVISOR_STATE), file, lookup, early)
    }

    /// Resolve with an explicit state root and injected env source; production
    /// passes `/state`, tests a scratch root with a real identity file.
    fn build_at(
        root: &Path,
        file: FileConfig,
        lookup: impl Fn(&str) -> Option<String>,
        early: EarlyConfig,
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

        // The state file anchors the node identity and the state store's
        // parent. It must stay on the supervisor-only volume and directly
        // under the link directory (Tailscale chmods a directory named
        // exactly `tailscale`, which the daemon uid cannot do on the
        // supervisor-owned tree). A legacy direct child of the real tree is
        // mapped onto the link. `mem:` is Tailscale's in-memory state.
        let state = value("TAILSCALE_STATE_FILE");
        let state = paths::normalize_state_path(root, &state);
        if !paths::state_file(root, &state) {
            log::err(&format!(
                "config: TAILSCALE_STATE_FILE '{}' must be 'mem:' or a direct child of \
                 {}/tailscale-state (the real tree's legacy spelling is accepted); \
                 refusing to start",
                log::sanitize(&state),
                root.display()
            ));
            return None;
        }
        let state_rel = paths::state_rel(root, &state);
        let state_present = state != "mem:" && state_has_identity(&state);
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
                 key; choose another name directly under {}/tailscale-state",
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

        let userspace = parse_flag(
            "TAILSCALE_USERSPACE",
            &raw("TAILSCALE_USERSPACE"),
            schema::bool_default("TAILSCALE_USERSPACE"),
        );
        // Single-uid mode cannot change identity or receive capabilities,
        // so TUN mode's NET_ADMIN/NET_RAW are unreachable. Refuse here,
        // before a spawn that would fail with a confusing errno.
        if early.single_uid && !userspace {
            log::err(
                "config: SUPERVISOR_SINGLE_UID=true requires userspace networking; \
                 TUN mode needs NET_ADMIN/NET_RAW, which this mode cannot grant; \
                 set TAILSCALE_USERSPACE=true; refusing to start",
            );
            return None;
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
            userspace,
            single_uid: early.single_uid,
            sync,
            backup,
            vw_env: file.child.into_iter().collect(),
        })
    }
}

#[cfg(test)]
mod tests;
