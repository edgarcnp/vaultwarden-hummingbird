//! Namespace-wide reaping and wait-status decoding: as PID 1 every orphan
//! re-parents to us, so the reaper drains strays as well as our own
//! children.

use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::sys::signal::Signal;
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
// nix's typed pid wrapper; the crate's public `Pid` is a plain i32 alias,
// so nix calls convert at the boundary.
use nix::unistd::Pid as NixPid;

use super::child::{POLL, Pid, signal_group};
use crate::util::log;

/// After SIGKILL (uncatchable), wait this long for the reap before giving
/// up; an uninterruptible (D-state) process is the container runtime's
/// problem, and must not hang our own exit.
const KILL_GRACE: Duration = Duration::from_secs(5);

/// Reap one pending zombie from anywhere in the namespace. `None` means
/// nothing reapable right now (`StillAlive` = children alive but no zombie
/// yet, `ECHILD` = no children, `EINTR` = retry on the next tick).
///
/// Never call this from tests: the namespace-wide `waitpid` would also reap
/// the test harness's own children.
pub fn reap_any() -> Option<(Pid, WaitStatus)> {
    match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
        Ok(status) => status.pid().map(|p| (p.as_raw(), status)),
        Err(_) => None,
    }
}

/// Container exit code for a wait status: the child's own code, or the
/// shell convention 128+signal when it died to a signal (a SIGTERM'd
/// service reports 143 — same as tini / plain Docker behavior).
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
    /// Reaped here; wait status.
    Reaped(WaitStatus),
    /// Already gone (e.g. reaped elsewhere as a stray).
    Vanished,
    /// Still unreapable after SIGKILL + grace (uninterruptible D-state);
    /// gave up rather than hanging the container's exit.
    Stuck,
}

/// Wait until `pid` is reaped, draining stray zombies along the way.
/// Escalates SIGTERM→SIGKILL once `grace` passes, then gives up after
/// [`KILL_GRACE`] more seconds rather than hanging the container's exit.
pub fn reap_until_gone(pid: Pid, grace: Duration) -> Gone {
    let mut deadline = Instant::now() + grace;
    let mut killed = false;
    loop {
        match waitpid(Some(NixPid::from_raw(pid)), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => {}
            Ok(status) => return Gone::Reaped(status),
            Err(Errno::ECHILD) => return Gone::Vanished,
            Err(_) => {}
        }
        while let Some((p, status)) = reap_any() {
            if p == pid {
                return Gone::Reaped(status);
            }
        }
        let now = Instant::now();
        if now >= deadline {
            if killed {
                log::err(&format!("pid {pid} unreapable; continuing shutdown"));
                return Gone::Stuck;
            }
            signal_group(pid, Signal::SIGKILL);
            killed = true;
            deadline = now + KILL_GRACE;
        }
        std::thread::sleep(POLL);
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;

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
    fn child_lifecycle_spawn_signal_reap_escalate() {
        let pid = spawn(Command::new("/bin/sh").args(["-c", "sleep 30"])).expect("spawn child");
        assert!(signal_group(pid, Signal::SIGTERM));
        match reap_until_gone(pid, Duration::from_secs(5)) {
            Gone::Reaped(status) => assert_eq!(exit_code(status), 143),
            gone => panic!("expected reap after SIGTERM, got {gone:?}"),
        }
        assert_eq!(
            reap_until_gone(pid, Duration::from_millis(50)),
            Gone::Vanished
        );

        let pid = spawn(Command::new("/bin/sh").args(["-c", "sleep 30"])).expect("spawn child");
        match reap_until_gone(pid, Duration::from_millis(200)) {
            Gone::Reaped(status) => assert_eq!(exit_code(status), 137),
            gone => panic!("expected SIGKILL escalation, got {gone:?}"),
        }
    }
}
