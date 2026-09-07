//! The vault watch loop and the container teardown: the single reaper of
//! the PID namespace, periodic state sync, DB keepalive ticks, and the
//! ordered shutdown that brings every child down before exiting.

use std::process::exit;
use std::time::Instant;

use nix::sys::signal::Signal;

use crate::config::{Config, SyncConfig};
use crate::proc::{
    Gone, POLL, Pid, TERM_GRACE, alive, db_keepalive_tick, exit_code, exit_reason, gate_bind,
    gate_describe, gate_serve, reap_any, reap_until_gone, run_vaultwarden, signal_group, stopping,
    sync_state, take_stop,
};
use crate::util::log;

/// Hand off to vaultwarden and supervise it: bind the exposed-port
/// gatekeeper (the only `0.0.0.0` listener), start the loopback-only vault,
/// then the watch loop — the single reaper of the PID namespace (orphans
/// re-parent to us as PID 1), observes vaultwarden's exit or a stop request,
/// drives periodic state sync, then tears down tailscaled and exits with
/// vaultwarden's code.
pub fn start_vw(cfg: &Config, tsd: Option<Pid>) -> ! {
    // Fail closed on a missing internal port: without it there is no secure
    // way to run the vault (co-binding would expose it, refusing is honest).
    let Some(vault_port) = &cfg.vault_port else {
        log::err("no room for the internal vault port above the exposed port; refusing to start");
        shutdown(tsd, 1, None)
    };
    let gate = match gate_bind(&cfg.port) {
        Ok(g) => g,
        Err(e) => {
            log::err(&format!(
                "gatekeeper bind failed on 0.0.0.0:{}: {e}",
                log::sanitize(&cfg.port)
            ));
            shutdown(tsd, 1, None)
        }
    };
    gate_describe(&cfg.port, vault_port);
    // The probe target: vaultwarden's loopback listener. A port that failed
    // to parse would mean a broken config — fail closed like every other
    // invalid-port path.
    let Ok(vault_addr) = vault_port
        .parse::<u16>()
        .map(|p| std::net::SocketAddr::from(([127, 0, 0, 1], p)))
    else {
        log::err("internal vault port is not a valid port; refusing to start");
        shutdown(tsd, 1, None)
    };
    drop(std::thread::spawn(move || {
        gate_serve(gate, Some(vault_addr))
    }));

    log::info("starting vaultwarden");
    let Some(vw) = run_vaultwarden(vault_port, &cfg.vw_env) else {
        shutdown(tsd, 1, None)
    };

    let mut last_sync = Instant::now();
    let mut last_sync_keepalive = Instant::now();
    let mut db_last_ok = None;
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
                signal_group(t, Signal::SIGTERM);
            }
            signal_group(vw, Signal::SIGTERM);
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
        if let Some(db) = &cfg.db_keepalive
            && last_sync_keepalive.elapsed() >= db.interval
        {
            db_keepalive_tick(db, &mut db_last_ok);
            last_sync_keepalive = Instant::now();
        }
        std::thread::sleep(POLL);
    };

    shutdown(tsd, code, cfg.sync.as_ref())
}

/// Bring every child down and exit the container. TERM each child group,
/// escalate to KILL after `TERM_GRACE`, drain strays, make a final (best
/// effort) state push, then exit with `code`. Safe for children that are
/// already dead (group kill + reap are no-ops).
pub fn shutdown(tsd: Option<Pid>, code: i32, sync: Option<&SyncConfig>) -> ! {
    log::info("shutting down");
    if let Some(t) = tsd {
        signal_group(t, Signal::SIGTERM);
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
