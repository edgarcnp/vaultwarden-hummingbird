//! PID 1 supervisor: tailscaled (userspace) + tailscale up/serve + vaultwarden,
//! for shell-less, package-manager-less Red Hat bases (Hummingbird
//! core-runtime / UBI micro / distroless; glibc version-locked to the base).
//! Optional dotenv layer (SUPERVISOR_ENV_FILE): the supervisor owns the file
//! and distributes it localized to each child. Optional S3 state sync
//! (SUPERVISOR_S3_*): /data identity files survive ephemeral redeploys. The
//! Tailscale authkey is staged to a 0600 file (never argv) and removed after
//! `up`.
//!
//! Shutdown model (see `proc::process` / `proc::signals`): children run in
//! their own process groups; a stop request (SIGTERM/SIGINT/SIGHUP/SIGQUIT)
//! is observed on the main thread, which drives a full teardown — TERM to
//! every child group, escalation to KILL after a grace period, and
//! namespace-wide reaping so no orphan or zombie outlives the container.

mod config;
mod proc;
mod util;

use std::process::exit;
use std::time::Instant;

use config::{Config, SyncConfig};
use proc::{
    Gone, POLL, Pid, TERM_GRACE, alive, exit_code, exit_reason, install_signal_handlers, reap_any,
    reap_until_gone, restore_state, run_vaultwarden, signal_group, spawn_tailscaled, stopping,
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
                let ok = tailscale_serve(&cfg.port, &cfg.socket, config::SERVE_TIMEOUT, stopping);
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

/// Hand off to vaultwarden and supervise it: the watch loop is the single
/// reaper of the PID namespace (orphans re-parent to us as PID 1), observes
/// vaultwarden's exit or a stop request, drives periodic state sync, then
/// tears down tailscaled and exits with vaultwarden's code.
fn start_vw(cfg: &Config, tsd: Option<Pid>) -> ! {
    log::info("starting vaultwarden");
    let Some(vw) = run_vaultwarden(&cfg.port, &cfg.vw_env) else {
        shutdown(tsd, 1, None)
    };

    let mut last_sync = Instant::now();
    let code = 'watch: loop {
        if let Some((pid, raw)) = reap_any() {
            if pid == vw {
                break 'watch exit_code(raw);
            }
            if Some(pid) == tsd {
                log::err("tailscaled exited unexpectedly; the vault keeps running");
            } else {
                log::info(&format!("reaped stray pid {pid} ({})", exit_reason(raw)));
            }
            continue;
        }
        if take_stop() {
            log::info("stop requested; terminating children");
            if let Some(t) = tsd {
                signal_group(t, libc::SIGTERM);
            }
            signal_group(vw, libc::SIGTERM);
            break 'watch match reap_until_gone(vw, TERM_GRACE) {
                Gone::Reaped(raw) => exit_code(raw),
                _ => 1,
            };
        }
        if !alive(vw) {
            break 'watch 1;
        }
        if let Some(sync) = &cfg.sync
            && !sync.interval.is_zero()
            && last_sync.elapsed() >= sync.interval
        {
            sync_state(sync, stopping);
            last_sync = Instant::now();
        }
        std::thread::sleep(POLL);
    };

    shutdown(tsd, code, cfg.sync.as_ref())
}

/// Bring every child down and exit the container. TERM each child group,
/// escalate to KILL after `TERM_GRACE`, drain strays, make a final (best
/// effort) state push, then exit with `code`. Safe for children that are
/// already dead (group kill + reap are no-ops).
fn shutdown(tsd: Option<Pid>, code: i32, sync: Option<&SyncConfig>) -> ! {
    log::info("shutting down");
    if let Some(t) = tsd {
        signal_group(t, libc::SIGTERM);
        if matches!(reap_until_gone(t, TERM_GRACE), Gone::Stuck) {
            log::err(&format!("tailscaled (pid {t}) did not exit cleanly"));
        }
    }
    while reap_any().is_some() {}
    // Final push AFTER children are gone; must not abort on the stop flag.
    if let Some(sync) = sync {
        sync_state(sync, || false);
    }
    exit(code)
}
