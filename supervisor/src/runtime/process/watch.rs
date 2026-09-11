//! The vault watch loop and container teardown: the ordered shutdown that
//! brings every child down before exiting, and detached periodic-
//! maintenance threads (state sync, DB backup). Reaping itself lives in
//! the reaper hub ([`super::reaper`]); this loop only reads the
//! long-running children's delivered statuses.

use std::process::exit;
use std::time::{Duration, Instant};

use nix::sys::signal::Signal;

use crate::config::{BACKUP_FIRST_DELAY, Config, SyncConfig};
use crate::runtime::{
    Gone, Handle, POLL, TERM_GRACE, backup_tick, exit_code, gate_bind, gate_describe, gate_serve,
    reap_until_gone, run_vaultwarden, signal_group, stopping, sync_state, take_stop,
};
use crate::util::log;

/// Sleep slice for the maintenance threads' cadence: coarse enough not to
/// churn, fine enough that a stop request is honored promptly.
const SLEEP: Duration = Duration::from_secs(1);

/// Run `task` on its own detached thread: first after `first_delay`, then
/// once per `interval`, returning promptly on a stop request. Detached —
/// bounded phases self-abort on stop, and exit() reaps everything else.
/// The task must only ever wait on children it spawned itself (the
/// reaper hub stays the single owner of reaping).
fn spawn_periodic(first_delay: Duration, interval: Duration, task: impl Fn() + Send + 'static) {
    std::thread::spawn(move || {
        let mut due = Instant::now() + first_delay;
        loop {
            while Instant::now() < due {
                if stopping() {
                    return;
                }
                std::thread::sleep(SLEEP.min(due.saturating_duration_since(Instant::now())));
            }
            if stopping() {
                return;
            }
            task();
            due = Instant::now() + interval;
        }
    });
}

/// Hand off to vaultwarden and supervise it: bind the exposed-port
/// gatekeeper (the only `0.0.0.0` listener), start the loopback-only vault,
/// then watch — observing vaultwarden's exit or a stop request while
/// detached threads drive periodic state sync and DB backup — then tearing
/// down tailscaled and exiting with vaultwarden's code. Tailscale is the
/// sole inbound path: if tailscaled dies mid-run the vault is torn down
/// too (exit 1) so the orchestrator restarts the whole container — a vault
/// nobody can reach is worse than a short outage.
pub fn start_vw(cfg: &Config, tsd: Handle) -> ! {
    // fail closed on a missing internal port: co-binding would expose the vault
    let Some(vault_port) = &cfg.vault_port else {
        log::err("no room for the internal vault port above the exposed port; refusing to start");
        shutdown(Some(tsd), None, 1, None)
    };
    let gate = match gate_bind(&cfg.port) {
        Ok(g) => g,
        Err(e) => {
            log::err(&format!(
                "gatekeeper bind failed on 0.0.0.0:{}: {e}",
                log::sanitize(&cfg.port)
            ));
            shutdown(Some(tsd), None, 1, None)
        }
    };
    gate_describe(&cfg.port, vault_port);
    let Ok(vault_addr) = vault_port
        .parse::<u16>()
        .map(|p| std::net::SocketAddr::from(([127, 0, 0, 1], p)))
    else {
        log::err("internal vault port is not a valid port; refusing to start");
        shutdown(Some(tsd), None, 1, None)
    };
    drop(std::thread::spawn(move || {
        gate_serve(gate, Some(vault_addr))
    }));

    log::info("starting vaultwarden");
    let Some(vw) = run_vaultwarden(vault_port, &cfg.vw_env) else {
        shutdown(Some(tsd), None, 1, None)
    };
    // Periodic maintenance runs off the watch loop: a bounded sync push or
    // backup must never delay reaping or stop observation by up to its
    // timeout (60s).
    if let Some(backup) = cfg.backup.clone().filter(|b| b.periodic) {
        spawn_periodic(BACKUP_FIRST_DELAY, backup.interval, move || {
            backup_tick(&backup, stopping);
        });
    }
    if let Some(sync) = cfg.sync.clone().filter(|s| !s.interval.is_zero()) {
        spawn_periodic(sync.interval, sync.interval, move || {
            sync_state(&sync, stopping);
        });
    }

    let code = 'watch: loop {
        // Exits are delivered by the reaper hub into each child's slot;
        // the loop only reads. vw's exit is its own verdict; tsd's death
        // tears everything down.
        if let Some(raw) = vw.status() {
            break 'watch exit_code(raw);
        }
        if tsd.status().is_some() {
            // Tailscale is the only way in: no daemon, no reachable
            // vault. Tear everything down; the orchestrator restarts.
            log::err(
                "tailscaled exited unexpectedly; shutting down (restart to restore Tailscale)",
            );
            signal_group(vw.pid, Signal::SIGTERM);
            break 'watch 1;
        }
        if take_stop() {
            log::info("stop requested; terminating children");
            signal_group(tsd.pid, Signal::SIGTERM);
            signal_group(vw.pid, Signal::SIGTERM);
            break 'watch match reap_until_gone(&vw, TERM_GRACE) {
                Gone::Reaped(raw) => exit_code(raw),
                _ => 1,
            };
        }
        std::thread::sleep(POLL);
    };

    shutdown(Some(tsd), Some(vw), code, cfg.sync.as_ref())
}

/// Bring every child down and exit the container: TERM each child group,
/// escalate to KILL after `TERM_GRACE`, wait for one clean reaper pass,
/// make a final best-effort state push, then exit with `code`. Safe for
/// children that are already dead (group kill + wait are no-ops).
pub fn shutdown(
    tsd: Option<Handle>,
    vw: Option<Handle>,
    code: i32,
    sync: Option<&SyncConfig>,
) -> ! {
    log::info("shutting down");
    if let Some(t) = &tsd {
        signal_group(t.pid, Signal::SIGTERM);
        if matches!(reap_until_gone(t, TERM_GRACE), Gone::Stuck) {
            log::err(&format!("tailscaled (pid {}) did not exit cleanly", t.pid));
        }
    }
    if let Some(v) = &vw
        && matches!(reap_until_gone(v, TERM_GRACE), Gone::Stuck)
    {
        log::err(&format!("vaultwarden (pid {}) did not exit cleanly", v.pid));
    }
    // One clean reaper pass before the final push: strays reaped, nothing
    // pending. The hub is the only reaper, so teardown waits on it rather
    // than reaping anything itself.
    if !super::reaper::quiesce(Duration::from_secs(2)) {
        log::err("reaper did not quiesce; continuing shutdown");
    }
    // final push AFTER children are gone; must not abort on the stop flag
    if let Some(sync) = sync {
        sync_state(sync, || false);
    }
    exit(code)
}
