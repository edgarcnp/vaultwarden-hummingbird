//! PID 1 supervisor: tailscaled (userspace) + tailscale up/serve +
//! loopback-only vaultwarden. Optional dotenv layer (SUPERVISOR_ENV_FILE)
//! and S3 state sync (SUPERVISOR_S3_*) so /data identity survives ephemeral
//! redeploys. The authkey is staged to a 0600 file (never argv) and removed
//! after `up`.
//!
//! Shutdown model: children run in their own process groups; a stop request
//! (SIGTERM/SIGINT/SIGHUP/SIGQUIT) is observed by the main thread, which
//! drives TERM -> KILL escalation and namespace-wide reaping.

mod config;
mod proc;
mod util;

use config::Config;
use proc::{
    gate_healthcheck, install_signal_handlers, restore_if_empty, restore_state, shutdown,
    spawn_tailscaled, start_vw, stopping, sync_state, tailscale_serve, tailscale_up, take_stop,
};
use util::{log, net};

/// One-shot `--healthcheck` mode: exit 0 iff the gate chain answers 2xx.
/// Runs before any boot side effect; config resolution is a pure read, so
/// the probe targets exactly the port the running supervisor binds.
fn healthcheck() -> ! {
    let cfg = Config::from_env();
    std::process::exit(if gate_healthcheck(&cfg.port) { 0 } else { 1 })
}

/// Boot: arm signals, load config, restore S3 state, bring up Tailscale
/// (best effort), then block in [`start_vw`] for the container's lifetime.
fn main() {
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg.as_os_str() == std::ffi::OsStr::new("--healthcheck"))
    {
        healthcheck();
    }

    install_signal_handlers();
    let cfg = Config::from_env();

    // DB restore first: only an empty DB is touched, and vaultwarden must
    // not start on top of a half-done import.
    if let Some(backup) = &cfg.backup {
        restore_if_empty(backup, stopping);
    }

    if let Some(sync) = &cfg.sync {
        restore_state(sync, stopping);
    }

    let Some(tsd) = spawn_tailscaled(&cfg.state, &cfg.socket, cfg.userspace) else {
        log::err("continuing without Tailscale");
        start_vw(&cfg, None)
    };
    log::info("tailscaled started (userspace networking)");

    if !net::wait_daemon(&cfg.socket, config::DAEMON_WAIT, stopping) {
        if take_stop() {
            shutdown(Some(tsd), 0, None);
        }
        log::err("tailscaled socket never appeared; continuing without Tailscale");
        start_vw(&cfg, Some(tsd))
    }

    if cfg.authkey.is_empty() {
        log::info("TS_AUTHKEY not set - starting without Tailscale");
    } else {
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
                    shutdown(Some(tsd), 1, None)
                };
                let ok = tailscale_serve(
                    vault_port,
                    cfg.service.as_deref(),
                    &cfg.socket,
                    config::SERVE_TIMEOUT,
                    &stopping,
                );
                let msg = if ok {
                    match &cfg.service {
                        Some(svc) => format!(
                            "tailscale serve: advertised {svc} (needs console definition + approval)"
                        ),
                        None => {
                            "tailscale serve: configured -> https://<hostname>.<tailnet>.ts.net"
                                .into()
                        }
                    }
                } else {
                    "tailscale serve failed (needs MagicDNS + HTTPS certs enabled); continuing"
                        .into()
                };
                log::info(&msg);
            }
        } else {
            if take_stop() {
                shutdown(Some(tsd), 0, None);
            }
            log::err(
                "tailscale up failed or timed out - check TS_AUTHKEY; continuing without Tailscale",
            );
        }
    }

    start_vw(&cfg, Some(tsd))
}
