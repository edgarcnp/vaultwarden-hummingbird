//! The vault watch loop and container teardown: the single reaper of the
//! PID namespace, periodic state sync, DB keepalive ticks, and the ordered
//! shutdown that brings every child down before exiting.

use std::process::exit;
use std::time::{Duration, Instant};

use nix::sys::signal::Signal;

use crate::config::{BACKUP_FIRST_DELAY, Config, DbBackupConfig, SyncConfig};
use crate::runtime::{
    Gone, POLL, Pid, TERM_GRACE, alive, backup_tick, db_keepalive_tick, exit_code, exit_reason,
    gate_bind, gate_describe, gate_serve, reap_any, reap_until_gone, run_vaultwarden, signal_group,
    stopping, sync_state, take_stop,
};
use crate::util::log;

/// Sleep slice for the backup thread's cadence: coarse enough not to
/// churn, fine enough that a stop request is honored promptly.
const BACKUP_SLEEP: Duration = Duration::from_secs(1);

/// Periodic DB backups on their own thread: the first dump
/// [`BACKUP_FIRST_DELAY`] after the vault starts, then one per
/// `interval`. Detached — bounded phases self-abort on stop, and exit()
/// reaps everything else.
fn spawn_backup_thread(backup: DbBackupConfig) {
    std::thread::spawn(move || {
        let mut due = Instant::now() + BACKUP_FIRST_DELAY;
        loop {
            while Instant::now() < due {
                if stopping() {
                    return;
                }
                std::thread::sleep(BACKUP_SLEEP.min(due.saturating_duration_since(Instant::now())));
            }
            if stopping() {
                return;
            }
            backup_tick(&backup, stopping);
            due = Instant::now() + backup.interval;
        }
    });
}

/// Hand off to vaultwarden and supervise it: bind the exposed-port
/// gatekeeper (the only `0.0.0.0` listener), start the loopback-only vault,
/// then watch — observing vaultwarden's exit or a stop request, driving
/// periodic sync, then tearing down tailscaled and exiting with
/// vaultwarden's code.
pub fn start_vw(cfg: &Config, tsd: Option<Pid>) -> ! {
    // fail closed on a missing internal port: co-binding would expose the vault
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
    if let Some(backup) = cfg.backup.clone().filter(|b| b.periodic) {
        spawn_backup_thread(backup);
    }

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

/// Bring every child down and exit the container: TERM each child group,
/// escalate to KILL after `TERM_GRACE`, drain strays, make a final
/// best-effort state push, then exit with `code`. Safe for children that
/// are already dead (group kill + reap are no-ops).
pub fn shutdown(tsd: Option<Pid>, code: i32, sync: Option<&SyncConfig>) -> ! {
    log::info("shutting down");
    if let Some(t) = tsd {
        signal_group(t, Signal::SIGTERM);
        if matches!(reap_until_gone(t, TERM_GRACE), Gone::Stuck) {
            log::err(&format!("tailscaled (pid {t}) did not exit cleanly"));
        }
    }
    while reap_any().is_some() {}
    // final push AFTER children are gone; must not abort on the stop flag
    if let Some(sync) = sync {
        sync_state(sync, || false);
    }
    exit(code)
}
