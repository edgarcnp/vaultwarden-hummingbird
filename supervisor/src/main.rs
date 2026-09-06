//! PID 1 supervisor: tailscaled (userspace) + tailscale up/serve + vaultwarden.
//! Designed for shell-less, package-manager-less Red Hat bases
//! (Hummingbird core-runtime / UBI micro / distroless). glibc, version-locked
//! to the runtime base image. Optional dotenv config layer (SUPERVISOR_ENV_FILE):
//! the supervisor owns the file and distributes it localized to each child.
//!
//! Shutdown model (see `proc::process` / `proc::signals`): children run in
//! their own process groups; a stop request (SIGTERM/SIGINT/SIGHUP/SIGQUIT)
//! is observed on the main thread, which then drives a full teardown — TERM
//! to every child group, escalation to KILL after a grace period, and
//! namespace-wide reaping so no orphan or zombie outlives the container.

mod config;
mod proc;
mod util;

use std::process::exit;

use config::Config;
use proc::{
    Gone, POLL, Pid, TERM_GRACE, exit_code, exit_reason, install_signal_handlers, reap_any,
    reap_until_gone, run_vaultwarden, signal_group, spawn_tailscaled, stopping, tailscale_serve,
    tailscale_up, take_stop,
};
use util::{log, net};

fn main() {
    install_signal_handlers(); // first: no window of unhandled signals as PID 1
    let cfg = Config::from_env();

    // 1. tailscaled (userspace networking: no TUN device on PaaS)
    let Some(tsd) = spawn_tailscaled(&cfg.state, &cfg.socket, cfg.userspace) else {
        log::err("continuing without Tailscale");
        start_vw(&cfg, None)
    };
    log::info("tailscaled started (userspace networking)");

    // 2. wait for the LocalAPI socket
    if !net::wait_daemon(&cfg.socket, config::DAEMON_WAIT, stopping) {
        if take_stop() {
            shutdown(Some(tsd), 0);
        }
        log::err("tailscaled socket never appeared; continuing without Tailscale");
        start_vw(&cfg, Some(tsd))
    }

    // 3. authenticate (bounded) + serve (inbound tailnet path)
    if cfg.authkey.is_empty() {
        log::info("TS_AUTHKEY not set - starting without Tailscale");
    } else {
        log::info("authenticating tailscale node...");
        if tailscale_up(&cfg.authkey, &cfg.hostname, config::AUTH_TIMEOUT, stopping) {
            log::info("tailscale up: connected");
            if cfg.serve {
                let ok = tailscale_serve(&cfg.port, config::SERVE_TIMEOUT, stopping);
                log::info(if ok {
                    "tailscale serve: configured -> https://<hostname>.<tailnet>.ts.net"
                } else {
                    "tailscale serve failed (needs MagicDNS + HTTPS certs enabled); continuing"
                });
            }
        } else {
            if take_stop() {
                shutdown(Some(tsd), 0);
            }
            log::err(
                "tailscale up failed or timed out - check TS_AUTHKEY; continuing without Tailscale",
            );
        }
    }

    // 4. vaultwarden in foreground; supervisor blocks until it exits
    start_vw(&cfg, Some(tsd))
}

/// Hand off to vaultwarden and supervise it: the watch loop is the single
/// reaper of the PID namespace (orphans re-parent to us as PID 1), observes
/// vaultwarden's exit or a stop request, then tears down tailscaled and
/// exits with vaultwarden's code.
fn start_vw(cfg: &Config, tsd: Option<Pid>) -> ! {
    log::info("starting vaultwarden");
    let Some(vw) = run_vaultwarden(&cfg.port, &cfg.vw_env) else {
        shutdown(tsd, 1)
    };

    let code = 'watch: loop {
        if let Some((pid, raw)) = reap_any() {
            if pid == vw {
                break 'watch exit_code(raw);
            }
            if Some(pid) == tsd {
                log::err("tailscaled exited unexpectedly; the vault keeps running");
            } else {
                // Stray orphan (a helper some child left behind).
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
            // Defensive: exited without a reaped status reaching this loop
            // (should be impossible — we are the only reaper).
            break 'watch 1;
        }
        std::thread::sleep(POLL);
    };

    shutdown(tsd, code)
}

/// Bring every child down and exit the container. TERM each child group,
/// escalate to KILL after `TERM_GRACE`, drain strays, then exit with `code`.
/// Safe for children that are already dead (group kill + reap are no-ops).
fn shutdown(tsd: Option<Pid>, code: i32) -> ! {
    log::info("shutting down");
    if let Some(t) = tsd {
        signal_group(t, libc::SIGTERM);
        if matches!(reap_until_gone(t, TERM_GRACE), Gone::Stuck) {
            log::err(&format!("tailscaled (pid {t}) did not exit cleanly"));
        }
    }
    while reap_any().is_some() {} // drain any orphan that outlived its parent
    exit(code)
}

/// Liveness probe (not a reap): signal 0 checks existence only.
fn alive(pid: Pid) -> bool {
    unsafe { libc::kill(pid, 0) == 0 }
}
