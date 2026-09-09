//! PID 1 supervisor: tailscaled (userspace) + tailscale up/serve +
//! loopback-only vaultwarden. Tailscale is the sole inbound path, so it is
//! required: a missing TAILSCALE_AUTHKEY or any boot-time Tailscale failure
//! refuses to start (exit 1), and a mid-run tailscaled death tears the
//! vault down. Optional dotenv layer (SUPERVISOR_ENV_FILE), S3 state sync
//! (SUPERVISOR_S3_*), and DB backup/restore (SUPERVISOR_DB_BACKUP*).
//! The authkey is staged to a 0600 file (never argv) and removed after
//! `up`.
//!
//! Shutdown model: children run in their own process groups; a stop request
//! (SIGTERM/SIGINT/SIGHUP/SIGQUIT) is observed by the main thread, which
//! drives TERM -> KILL escalation and namespace-wide reaping.

mod config;
mod runtime;
mod util;

use config::Config;
use runtime::{
    gate_healthcheck, install_signal_handlers, restore_if_empty, restore_state, shutdown,
    spawn_tailscaled, start_vw, stopping, sync_state, tailscale_serve, tailscale_up, take_stop,
};
use util::{log, net};

/// One-shot `--healthcheck` mode: exit 0 iff the gate chain answers 2xx.
/// Runs before any boot side effect; config resolution is a pure read, so
/// the probe targets exactly the port the running supervisor binds.
fn healthcheck() -> ! {
    match Config::from_env() {
        Some(cfg) => std::process::exit(if gate_healthcheck(&cfg.port) { 0 } else { 1 }),
        None => std::process::exit(1),
    }
}

/// Boot: arm signals, load config (Tailscale required — fail closed), then
/// restore S3 state, bring up Tailscale, and block in [`start_vw`] for the
/// container's lifetime.
fn main() {
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg.as_os_str() == std::ffi::OsStr::new("--healthcheck"))
    {
        healthcheck();
    }

    install_signal_handlers();
    let cfg = match Config::from_env() {
        Some(cfg) => cfg,
        None => std::process::exit(1),
    };

    // DB restore first: only an empty DB is touched, and vaultwarden must
    // not start on top of a half-done import — a failed restore refuses
    // to boot (exit 1) so the orchestrator retries with the DB still empty.
    if let Some(backup) = &cfg.backup
        && !restore_if_empty(backup, stopping)
    {
        std::process::exit(1);
    }

    if let Some(sync) = &cfg.sync {
        restore_state(sync, stopping);
    }

    let Some(tsd) = spawn_tailscaled(&cfg.state, &cfg.socket, cfg.userspace) else {
        log::err("tailscaled failed to start; refusing to run the vault without Tailscale");
        std::process::exit(1)
    };
    log::info("tailscaled started (userspace networking)");

    if !net::wait_daemon(&cfg.socket, config::DAEMON_WAIT, stopping) {
        if take_stop() {
            shutdown(Some(tsd), None, 0, None);
        }
        log::err("tailscaled socket never appeared; refusing to run the vault without Tailscale");
        shutdown(Some(tsd), None, 1, None)
    }

    log::info("authenticating tailscale node...");
    if tailscale_up(
        &cfg.authkey,
        &cfg.hostname,
        &cfg.socket,
        config::AUTH_TIMEOUT,
        stopping,
    ) {
        log::info("tailscale up: connected");
        if let Some(sync) = &cfg.sync {
            sync_state(sync, stopping);
        }
        if cfg.serve {
            let Some(vault_port) = &cfg.vault_port else {
                log::err("no room for the internal vault port; refusing to start");
                shutdown(Some(tsd), None, 1, None)
            };
            if !tailscale_serve(
                vault_port,
                cfg.service.as_deref(),
                &cfg.socket,
                config::SERVE_TIMEOUT,
                &stopping,
            ) {
                // Tailscale is the sole inbound path: serve failure means a
                // vault nobody can reach (typically MagicDNS/HTTPS certs
                // disabled). Same fail-closed contract as `up` above: exit
                // and let the orchestrator retry.
                shutdown(Some(tsd), None, 1, None)
            }
            let msg = match &cfg.service {
                Some(svc) => format!(
                    "tailscale serve: advertised {svc} (needs console definition + approval)"
                ),
                None => "tailscale serve: configured -> https://<hostname>.<tailnet>.ts.net".into(),
            };
            log::info(&msg);
        }
    } else {
        if take_stop() {
            shutdown(Some(tsd), None, 0, None);
        }
        log::err(
            "tailscale up failed or timed out - check TAILSCALE_AUTHKEY; refusing to run the vault without Tailscale",
        );
        shutdown(Some(tsd), None, 1, None)
    }

    start_vw(&cfg, tsd)
}
