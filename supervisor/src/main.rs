//! PID 1 supervisor: tailscaled (userspace) + tailscale up/serve + vaultwarden,
//! for shell-less, package-manager-less Red Hat bases (Hummingbird
//! core-runtime / UBI micro / distroless; glibc version-locked to the base).
//! Optional dotenv layer (SUPERVISOR_ENV_FILE): the supervisor owns the file
//! and distributes it localized to each child. Optional S3 state sync
//! (SUPERVISOR_S3_*): /data identity files survive ephemeral redeploys. The
//! Tailscale authkey is staged to a 0600 file (never argv) and removed after
//! `up`.
//!
//! Shutdown model (see `proc::process` / `proc::signals` / `proc::watch`):
//! children run in their own process groups; a stop request
//! (SIGTERM/SIGINT/SIGHUP/SIGQUIT) is observed on the main thread, which
//! drives a full teardown — TERM to every child group, escalation to KILL
//! after a grace period, and namespace-wide reaping so no orphan or zombie
//! outlives the container.

mod config;
mod proc;
mod util;

use config::Config;
use proc::{
    install_signal_handlers, restore_state, shutdown, spawn_tailscaled, start_vw, stopping,
    sync_state, tailscale_serve, tailscale_up, take_stop,
};
use util::{log, net};

/// Boot sequence: arm signals, load config, restore S3 state (opt-in), bring
/// up Tailscale (best effort — every failure path degrades to running
/// vaultwarden without it), then hand off to [`start_vw`], which blocks for
/// the container's lifetime.
fn main() {
    install_signal_handlers();
    let cfg = Config::from_env();

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
                let ok = tailscale_serve(vault_port, &cfg.socket, config::SERVE_TIMEOUT, stopping);
                log::info(if ok {
                    "tailscale serve: configured -> https://<hostname>.<tailnet>.ts.net"
                } else {
                    "tailscale serve failed (needs MagicDNS + HTTPS certs enabled); continuing"
                });
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
