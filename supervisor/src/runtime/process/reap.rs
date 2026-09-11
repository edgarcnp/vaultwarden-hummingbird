//! Wait-status decoding and the escalation wait for teardown. Reaping
//! itself lives in the reaper hub ([`super::reaper`]) — the only waitpid
//! caller in the process; this module just reads delivered statuses.

use std::time::Duration;

use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;

use super::child::{KILL_GRACE, POLL, signal_group};
use super::reaper::Handle;
use crate::util::log;
use crate::util::wait_until;

/// Container exit code: the child's own code, or 128+signal (a SIGTERM'd
/// service reports 143 — same as tini / plain Docker).
pub fn exit_code(status: WaitStatus) -> i32 {
    match status {
        WaitStatus::Exited(_, code) => code,
        WaitStatus::Signaled(_, sig, _) => 128 + sig as i32,
        _ => 1,
    }
}

/// Human-readable wait status for logs.
pub fn exit_reason(status: WaitStatus) -> String {
    match status {
        WaitStatus::Exited(_, code) => format!("exit status {code}"),
        WaitStatus::Signaled(_, sig, _) => format!("terminated by signal {}", sig as i32),
        other => format!("wait status {other:?}"),
    }
}

/// Outcome of waiting for a child to be reaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gone {
    /// Delivered by the reaper hub; wait status. (A second call finds the
    /// same status: slots are not consumed.)
    Reaped(WaitStatus),
    /// Still unreapable after SIGKILL + grace (uninterruptible D-state);
    /// gave up rather than hanging the container's exit.
    Stuck,
}

/// Wait until `pid`'s exit status is delivered by the reaper hub.
/// Escalates SIGTERM→SIGKILL once `grace` passes, then gives up after
/// [`KILL_GRACE`] more seconds rather than hanging the container's exit.
pub fn reap_until_gone(child: &Handle, grace: Duration) -> Gone {
    let reaped = || child.status();
    if let Some(status) = wait_until(reaped, grace, || false, POLL) {
        return Gone::Reaped(status);
    }
    signal_group(child.pid, Signal::SIGKILL);
    match wait_until(reaped, KILL_GRACE, || false, POLL) {
        Some(status) => Gone::Reaped(status),
        None => {
            log::err(&format!(
                "pid {} unreapable; continuing shutdown",
                child.pid
            ));
            Gone::Stuck
        }
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::time::Duration;

    use nix::sys::signal::Signal;
    use nix::sys::wait::WaitStatus;
    use nix::unistd::Pid as NixPid;

    use super::super::child::spawn;
    use super::*;

    #[test]
    fn exit_code_decodes_exit_and_signal_statuses() {
        let p = NixPid::from_raw(1);
        assert_eq!(exit_code(WaitStatus::Exited(p, 0)), 0);
        assert_eq!(exit_code(WaitStatus::Exited(p, 3)), 3);
        assert_eq!(
            exit_code(WaitStatus::Signaled(p, Signal::SIGTERM, false)),
            143
        );
        assert_eq!(exit_code(WaitStatus::Stopped(p, Signal::SIGSTOP)), 1);
    }

    #[test]
    fn exit_reason_is_human_readable() {
        let p = NixPid::from_raw(1);
        assert_eq!(exit_reason(WaitStatus::Exited(p, 0)), "exit status 0");
        assert_eq!(exit_reason(WaitStatus::Exited(p, 3)), "exit status 3");
        assert_eq!(
            exit_reason(WaitStatus::Signaled(p, Signal::SIGTERM, false)),
            "terminated by signal 15"
        );
    }

    #[test]
    fn signal_group_refuses_own_namespace() {
        assert!(!signal_group(0, Signal::SIGTERM));
        assert!(!signal_group(1, Signal::SIGTERM));
        assert!(!signal_group(-5, Signal::SIGTERM));
    }

    #[test]
    fn reap_until_gone_terminates_and_escalates() {
        // SIGTERM lands, the hub delivers 143, and a second call finds
        // the same status (slots are read, not consumed).
        let child = spawn(Command::new("/bin/sh").args(["-c", "sleep 30"])).expect("spawn child");
        assert!(signal_group(child.pid, Signal::SIGTERM));
        match reap_until_gone(&child, Duration::from_secs(5)) {
            Gone::Reaped(status) => assert_eq!(exit_code(status), 143),
            gone => panic!("expected reap after SIGTERM, got {gone:?}"),
        }
        match reap_until_gone(&child, Duration::from_millis(50)) {
            Gone::Reaped(status) => assert_eq!(exit_code(status), 143),
            gone => panic!("expected the delivered status again, got {gone:?}"),
        }

        // No clean exit: escalation to SIGKILL produces 137.
        let child = spawn(Command::new("/bin/sh").args(["-c", "sleep 30"])).expect("spawn child");
        match reap_until_gone(&child, Duration::from_millis(200)) {
            Gone::Reaped(status) => assert_eq!(exit_code(status), 137),
            gone => panic!("expected SIGKILL escalation, got {gone:?}"),
        }
    }
}
