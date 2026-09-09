//! Signal wiring for PID 1, registered through `signal-hook`'s flag API:
//! its handler does exactly one async-signal-safe thing — set the flag —
//! which is precisely the contract this module needs.
//!
//! All signal *delivery* (forwarding to children, escalation,
//! reaping) happens on the main thread, which owns the child pids as plain
//! locals and polls [`take_stop`]. No shared pid tables, no arming gates,
//! no registration windows: a signal arriving in ANY phase is observed at
//! the next tick and acted on with full context; forwarding latency is
//! bounded by one poll tick (~100 ms) — irrelevant next to container stop
//! timeouts.
//!
//! SIGTERM/SIGINT/SIGHUP/SIGQUIT are all stop requests (from a container
//! orchestrator's perspective that is what they are); SIGCHLD and SIGPIPE
//! are left alone (reaping is a poll; std write errors are handled
//! in-process).

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
use signal_hook::flag;

use crate::util::log;

static STOP: OnceLock<Arc<AtomicBool>> = OnceLock::new();

/// The process-global stop flag, created on first use.
fn flag() -> &'static Arc<AtomicBool> {
    STOP.get_or_init(|| Arc::new(AtomicBool::new(false)))
}

/// Arm the stop handlers. Call once, first thing in `main`. Returns false
/// if any required signal could not be registered: as PID 1 the container
/// orchestrator's stop signals ARE the shutdown mechanism — a supervisor
/// that cannot catch them degrades to SIGKILL-only teardown (no graceful
/// child termination, no final state sync), so the boot must fail instead.
pub fn install_signal_handlers() -> bool {
    let mut ok = true;
    for sig in [SIGTERM, SIGINT, SIGHUP, SIGQUIT] {
        match flag::register(sig, Arc::clone(flag())) {
            // SigId is Copy (no Drop): the registration lives for the whole
            // process, which is what a PID 1 wants.
            Ok(_) => {}
            Err(e) => {
                log::err(&format!("signal {sig} registration failed: {e}"));
                ok = false;
            }
        }
    }
    ok
}

/// Consume the stop request: true at most once. The main loop's only
/// signal interface.
pub fn take_stop() -> bool {
    flag().swap(false, Ordering::SeqCst)
}

/// Peek without consuming — used by bounded phases that must abort early
/// but leave acting on the request to the main loop.
pub fn stopping() -> bool {
    flag().load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_stop_consumes_once() {
        assert!(!stopping());
        assert!(!take_stop());
        flag().store(true, Ordering::SeqCst);
        assert!(stopping());
        assert!(take_stop());
        assert!(!stopping());
        assert!(!take_stop());
    }
}
