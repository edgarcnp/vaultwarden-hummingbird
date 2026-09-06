//! Signal wiring for PID 1, armed with `sigaction` (not `signal`, whose
//! semantics vary by libc).
//!
//! Design: the handler does exactly one async-signal-safe thing — raise the
//! stop flag. All signal *delivery* (forwarding to children, escalation,
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

use std::sync::atomic::{AtomicBool, Ordering};

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn handle(_: libc::c_int) {
    // Async-signal-safe: a single relaxed-ish store is all we need; SeqCst
    // keeps it simple and is uncontended.
    STOP_REQUESTED.store(true, Ordering::SeqCst);
}

/// Arm the stop handlers. Call once, first thing in `main` — as PID 1 an
/// unhandled signal is ignored by the kernel, so there is no crash risk
/// before this, only a dropped request.
pub fn install_signal_handlers() {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = handle as extern "C" fn(libc::c_int) as usize;
    action.sa_flags = libc::SA_RESTART;
    unsafe { libc::sigemptyset(&mut action.sa_mask) };
    for &sig in &[libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGQUIT] {
        unsafe { libc::sigaction(sig, &action, std::ptr::null_mut()) };
    }
}

/// Consume the stop request: true at most once. The main loop's only
/// signal interface.
pub fn take_stop() -> bool {
    STOP_REQUESTED.swap(false, Ordering::SeqCst)
}

/// Peek without consuming — used by bounded phases that must abort early
/// but leave acting on the request to the main loop.
pub fn stopping() -> bool {
    STOP_REQUESTED.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_stop_consumes_once() {
        assert!(!stopping());
        assert!(!take_stop());
        STOP_REQUESTED.store(true, Ordering::SeqCst);
        assert!(stopping());
        assert!(take_stop());
        assert!(!stopping());
        assert!(!take_stop());
    }
}
