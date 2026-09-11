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
    /// Merge order, everywhere: env > file > default. The dotenv file is
    /// strict (see [`FileConfig`]): only the three namespaces are
    /// accepted and any unrecognized key refuses the boot. The
    /// gatekeeper port has ONE spelling, `VAULTWARDEN_PORT` — the legacy
    /// `VAULTWARDEN_ROCKET_PORT` alias and a bare `ROCKET_PORT` refuse
    /// the boot with a message naming the valid spelling. vaultwarden
    /// keys (incl. the DB URL) resolve env first, so the supervisor
    /// always sees the same values the child gets
    /// ([`crate::runtime::services::vaultwarden`] applies file, then
    /// ambient, then the pins). Empty = unset; bad booleans warn and
    /// take the default. Returns None when a required knob is missing
    /// (TAILSCALE_AUTHKEY) or anything refuses: the vault is unreachable
    /// without Tailscale, so boot must fail closed.
    pub fn from_env() -> Option<Self> {
        Self::build(FileConfig::load(), |k| env::var(k).ok())
    }

    /// [`Self::from_env`] with the env source injected: tests pass a map,
    /// never mutating the process env (unsafe and racy).
    fn build(file: FileConfig, lookup: impl Fn(&str) -> Option<String>) -> Option<Self> {
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
        // the vault uses. The file's entry arrives only via the strict
        // routing (`VAULTWARDEN_DATABASE_URL` stripped); a bare
        // `DATABASE_URL` in the file already refused the boot above.
        let db_url = non_empty(lookup("VAULTWARDEN_DATABASE_URL"))
            .or_else(|| non_empty(file.child.get("DATABASE_URL").cloned()));
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
mod tests;
