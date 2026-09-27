//! PID 1 supervisor: tailscaled (userspace) + tailscale up/serve +
//! loopback-only vaultwarden. Tailscale is the sole inbound path, so it
//! is required: a missing TAILSCALE_AUTHKEY or any boot-time Tailscale
//! failure refuses to start (exit 1), and a mid-run tailscaled death
//! tears the vault down. Optional dotenv layer (SUPERVISOR_ENV_FILE), S3
//! state sync (SUPERVISOR_S3_*), and DB backup/restore (SUPERVISOR_DB_
//! BACKUP*). The authkey is staged to a 0600 file (never argv) and
//! removed after `up`.
//!
//! Boot runs through the explicit phase machine ([`boot`]); the shutdown
//! model is documented where it lives ([`runtime::process::watch`]):
//! children run in their own process groups; a stop request
//! (SIGTERM/SIGINT/SIGHUP/SIGQUIT) is observed by the main thread, which
//! drives TERM -> KILL escalation.

mod boot;
mod config;
mod runtime;
mod s3;
mod util;

use config::Config;
use runtime::gate_healthcheck;
use util::log;

/// One-shot `--healthcheck` mode: exit 0 iff the gate chain answers 2xx.
/// Runs before any boot side effect; config resolution is a pure read, so
/// the probe targets exactly the port the running supervisor binds. A
/// failed check logs one line, so a health-driven restart loop is
/// diagnosable from the container logs.
fn healthcheck() -> ! {
    let healthy = match Config::from_env() {
        Some(cfg) => {
            if gate_healthcheck(&cfg.port) {
                true
            } else {
                log::err(
                    "healthcheck: the gate did not answer healthy (gate not bound, or \
                     vaultwarden down)",
                );
                false
            }
        }
        None => {
            log::err("healthcheck: configuration could not be resolved");
            false
        }
    };
    std::process::exit(if healthy { 0 } else { 1 });
}

fn main() {
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg.as_os_str() == std::ffi::OsStr::new("--healthcheck"))
    {
        healthcheck();
    }

    boot::run()
}
