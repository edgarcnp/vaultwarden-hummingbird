//! The boot sequence as an explicit phase machine. Every phase's policy
//! for a stop request and for failure lives in this one table, auditable
//! at a glance.
//!
//! | Phase        | Stop request                       | Failure                     |
//! |--------------|------------------------------------|-----------------------------|
//! | RestoreDb    | bounded ops abort; a failed        | exit 1: never start the     |
//! |              | import is still a failure          | vault on partial state      |
//! | AdoptLineage | non-fatal (skips)                  | never fails                 |
//! | RestoreState | non-fatal (skips)                  | logged; continue            |
//! |              |                                    | (fresh node / re-login)     |
//! | Tailscaled   | —                                  | exit 1: no Tailscale, no    |
//! |              |                                    | reachable vault             |
//! | DaemonWait   | exit 0 (clean boot abort)          | exit 1                      |
//! | TailscaleUp  | exit 0 (observed first)            | exit 1                      |
//! | Serve        | aborts the bounded ops → exit 1    | exit 1                      |
//! | Vault        | the watch loop owns the container  | exits with the vault's code |
//! |              | from here (see `process::watch`)   |                             |
//!
//! Any boot-phase exit tears down what exists (`tsd` once spawned) via
//! the ordered shutdown, WITHOUT a final state push: nothing durable has
//! changed before the vault runs (the post-`up` push already persisted
//! identity, and vault-phase exits — inside `start_vw` — push with
//! `cfg.sync` as before).

use crate::config::{AUTH_TIMEOUT, Config, DAEMON_WAIT, SERVE_TIMEOUT};
use crate::runtime::{
    Handle, adopt_lineage, install_signal_handlers, restore_if_empty, restore_state, shutdown,
    spawn_tailscaled, start_vw, stopping, sync_state, tailscale_serve, tailscale_up, take_stop,
};
use crate::util::{log, net};

/// What one boot phase decided: continue, or tear down and exit.
enum Outcome {
    Next,
    Exit(i32),
}

/// Boot phases, in execution order. `Vault` is not here: it is the
/// loop's tail and never returns.
#[derive(Clone, Copy)]
enum Phase {
    RestoreDb,
    AdoptLineage,
    RestoreState,
    Tailscaled,
    DaemonWait,
    TailscaleUp,
    Serve,
}

const PHASES: [Phase; 7] = [
    Phase::RestoreDb,
    Phase::AdoptLineage,
    Phase::RestoreState,
    Phase::Tailscaled,
    Phase::DaemonWait,
    Phase::TailscaleUp,
    Phase::Serve,
];

/// The boot context: resolved configuration plus the tailscaled handle
/// once the daemon phase has produced it.
struct Boot {
    cfg: Config,
    tsd: Option<Handle>,
}

impl Boot {
    /// Tear down what exists and exit. No final state push: nothing
    /// durable has changed during boot (see the module table).
    fn exit(&self, code: i32) -> ! {
        shutdown(self.tsd.clone(), None, code, None)
    }

    fn run(&mut self, phase: Phase) -> Outcome {
        match phase {
            Phase::RestoreDb => {
                // DB restore first: only an empty DB is touched, and
                // vaultwarden must not start on top of a half-done
                // import — a failed restore refuses to boot so the
                // orchestrator retries with the DB still empty.
                if let Some(backup) = &self.cfg.backup
                    && !restore_if_empty(backup, stopping)
                {
                    return Outcome::Exit(1);
                }
                Outcome::Next
            }
            Phase::AdoptLineage => {
                // restore=true declares the bucket authoritative, which
                // lets an upgraded (non-empty, unproven) DB continue
                // pushing instead of being refused at the first tick.
                if let Some(backup) = &self.cfg.backup {
                    adopt_lineage(backup, stopping);
                }
                Outcome::Next
            }
            Phase::RestoreState => {
                if let Some(sync) = &self.cfg.sync {
                    restore_state(sync, stopping);
                }
                Outcome::Next
            }
            Phase::Tailscaled => {
                match spawn_tailscaled(&self.cfg.state, &self.cfg.socket, self.cfg.userspace) {
                    Some(tsd) => {
                        self.tsd = Some(tsd);
                        log::info("tailscaled started (userspace networking)");
                        Outcome::Next
                    }
                    None => {
                        log::err(
                            "tailscaled failed to start; refusing to run the vault without Tailscale",
                        );
                        Outcome::Exit(1)
                    }
                }
            }
            Phase::DaemonWait => {
                if net::wait_daemon(&self.cfg.socket, DAEMON_WAIT, stopping) {
                    Outcome::Next
                } else if take_stop() {
                    Outcome::Exit(0)
                } else {
                    log::err(
                        "tailscaled socket never appeared; refusing to run the vault without Tailscale",
                    );
                    Outcome::Exit(1)
                }
            }
            Phase::TailscaleUp => {
                log::info("authenticating tailscale node...");
                if !tailscale_up(
                    self.cfg.authkey.as_deref(),
                    &self.cfg.hostname,
                    &self.cfg.socket,
                    AUTH_TIMEOUT,
                    stopping,
                ) {
                    if take_stop() {
                        return Outcome::Exit(0);
                    }
                    log::err(
                        "tailscale up failed or timed out - check TAILSCALE_AUTHKEY; \
                         refusing to run the vault without Tailscale",
                    );
                    return Outcome::Exit(1);
                }
                log::info("tailscale up: connected");
                if let Some(sync) = &self.cfg.sync {
                    sync_state(sync, stopping);
                }
                Outcome::Next
            }
            Phase::Serve => {
                if !self.cfg.serve {
                    return Outcome::Next;
                }
                let Some(vault_port) = &self.cfg.vault_port else {
                    log::err("no room for the internal vault port; refusing to start");
                    return Outcome::Exit(1);
                };
                // Tailscale is the sole inbound path: serve failure means
                // a vault nobody can reach (typically MagicDNS/HTTPS
                // certs disabled). Same fail-closed contract as `up`.
                if !tailscale_serve(
                    vault_port,
                    self.cfg.service.as_deref(),
                    &self.cfg.socket,
                    SERVE_TIMEOUT,
                    &stopping,
                ) {
                    return Outcome::Exit(1);
                }
                let msg = match &self.cfg.service {
                    Some(svc) => {
                        format!(
                            "tailscale serve: advertised {svc} (needs console definition + approval)"
                        )
                    }
                    None => {
                        "tailscale serve: configured -> https://<hostname>.<tailnet>.ts.net".into()
                    }
                };
                log::info(&msg);
                Outcome::Next
            }
        }
    }
}

/// Boot: arm signals, load config (Tailscale required — fail closed),
/// then run the phase table and hand the container to the vault watch
/// loop for the lifetime of the process.
pub fn run() -> ! {
    if !install_signal_handlers() {
        log::err("cannot register stop signals; refusing to run without graceful shutdown");
        std::process::exit(1);
    }
    let Some(cfg) = Config::from_env() else {
        std::process::exit(1);
    };

    let mut boot = Boot { cfg, tsd: None };
    for phase in PHASES {
        match boot.run(phase) {
            Outcome::Next => {}
            Outcome::Exit(code) => boot.exit(code),
        }
    }

    // The Tailscale phase always ran: the daemon phase produced the
    // handle, and every failure path after it exits through Boot::exit.
    let tsd = boot.tsd.expect("tailscaled phase ran");
    start_vw(&boot.cfg, tsd)
}
