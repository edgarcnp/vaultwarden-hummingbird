//! The vault watch loop and container teardown: the ordered shutdown that
//! brings every child down before exiting, and the maintenance reactor that
//! drives periodic state sync and DB backup. Reaping itself lives in the
//! reaper hub ([`super::reaper`]); this loop only reads the long-running
//! children's delivered statuses.

use std::process::exit;
use std::time::Duration;

use nix::sys::signal::Signal;

use crate::config::{Config, PERSIST_BUDGET, PERSIST_FORCED_BUDGET};
use crate::runtime::{
    Gone, Handle, POLL, Reactor, TERM_GRACE, Task, exit_code, gate_bind, gate_describe, gate_serve,
    reap_until_gone, run_vaultwarden, signal_child, take_stop,
};
use crate::util::log;

/// Hand off to vaultwarden and supervise it: bind the exposed-port
/// gatekeeper (the only `0.0.0.0` listener), start the loopback-only vault,
/// then watch — observing vaultwarden's exit or a stop request while the
/// maintenance reactor drives periodic state sync and DB backup — then
/// tearing down tailscaled and exiting with vaultwarden's code. Tailscale
/// is the sole inbound path: if tailscaled dies mid-run the vault is torn
/// down too (exit 1) so the orchestrator restarts the whole container — a
/// vault nobody can reach is worse than a short outage.
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
    // One reactor thread owns every periodic task and the final flush:
    // exactly one writer per durability resource after boot (why: see
    // `runtime::maintenance`). Periodic maintenance runs off the watch
    // loop so a bounded sync push or backup never delays reaping or stop
    // observation by up to its timeout (60s).
    let mut tasks = Vec::new();
    if let Some(backup) = cfg.backup.clone().filter(|b| b.periodic) {
        tasks.push(Task::backup(backup));
    }
    if let Some(sync) = cfg.sync.clone() {
        // First push on a short delay, not a full interval: vaultwarden
        // only creates /data/rsa_key.pem once it has started, and the boot
        // push ran before it existed. This is the push that preserves the
        // vault's signing key across a redeploy. A zero interval disables
        // the cadence but still flushes at shutdown.
        tasks.push(Task::sync(sync));
    }
    let reactor = match Reactor::start(tasks) {
        Ok(reactor) => reactor,
        Err(e) => {
            // Maintenance silently ceasing to exist is worse than refusing
            // to run: a thread that cannot start fails the boot.
            log::err(&format!(
                "maintenance thread failed to start ({e}); refusing to run without it"
            ));
            shutdown(Some(tsd), Some(vw), 1, None)
        }
    };

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
            signal_child(&vw, Signal::SIGTERM);
            break 'watch 1;
        }
        if take_stop() {
            log::info("stop requested; terminating children");
            // Tell the reactor before teardown, not after: an in-flight
            // tick must observe the monotonic stop while children are
            // reaped, and the drain below then flushes on the same thread.
            if let Some(reactor) = &reactor {
                reactor.stop();
            }
            signal_child(&tsd, Signal::SIGTERM);
            signal_child(&vw, Signal::SIGTERM);
            break 'watch match reap_until_gone(&vw, TERM_GRACE) {
                Gone::Reaped(raw) => exit_code(raw),
                _ => 1,
            };
        }
        std::thread::sleep(POLL);
    };

    // No new periodic work from here on: an in-flight tick aborts on the
    // monotonic token while teardown runs, and the drain below then runs
    // the final flushes on the same thread.
    if let Some(reactor) = &reactor {
        reactor.stop();
    }
    shutdown(Some(tsd), Some(vw), code, reactor)
}

/// Bring every child down and exit the container: TERM each child group,
/// escalate to KILL after `TERM_GRACE`, wait for one clean reaper pass,
/// then let the reactor run the final DB dump and state push — children are
/// gone first, and the reactor is the only writer. The persist budget
/// bounds the finish; a stop request observed while draining shortens it.
/// Children that are already dead are fine: the escalation finds a
/// delivered status and the bounded wait returns immediately. This
/// function itself sends no TERM — callers do that before deciding to
/// shut down (the escalation here is the SIGKILL escalation only).
pub fn shutdown(tsd: Option<Handle>, vw: Option<Handle>, code: i32, reactor: Option<Reactor>) -> ! {
    log::info("shutting down");
    if let Some(t) = &tsd {
        signal_child(t, Signal::SIGTERM);
        if matches!(reap_until_gone(t, TERM_GRACE), Gone::Stuck) {
            log::err(&format!("tailscaled (pid {}) did not exit cleanly", t.pid));
        }
    }
    if let Some(v) = &vw
        && matches!(reap_until_gone(v, TERM_GRACE), Gone::Stuck)
    {
        log::err(&format!("vaultwarden (pid {}) did not exit cleanly", v.pid));
    }
    // One clean reaper pass before the final persists: strays reaped,
    // nothing pending. The hub is the only reaper, so teardown waits on it
    // rather than reaping anything itself.
    if !super::reaper::quiesce(Duration::from_secs(2)) {
        log::err("reaper did not quiesce; continuing shutdown");
    }
    // Final persists AFTER children are gone. The DB goes first — it
    // carries session and device state and is the smaller push, so it
    // should win any remaining drain budget over a potentially large
    // attachments upload; the reactor enforces the order.
    if let Some(reactor) = reactor {
        reactor.drain(PERSIST_BUDGET, PERSIST_FORCED_BUDGET);
    }
    exit(code)
}
