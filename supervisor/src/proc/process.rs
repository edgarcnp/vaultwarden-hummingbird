//! Process primitives for a PID 1 supervisor: spawning, reaping, group
//! signaling, liveness, and bounded child runs.
//!
//! Reaping is race-free by ownership:
//! - Long-running children ([`spawn`]) are process-group leaders; their
//!   `std::process::Child` handle is dropped on purpose — statuses come only
//!   from the namespace-wide reaper ([`reap_any`]), never std's targeted
//!   `try_wait`/`wait`, which would race it over the same zombie.
//! - Bounded CLI children ([`run_bounded_env`]) are reaped via std inside
//!   the helper; the main thread is single-threaded, so the two never
//!   overlap. They are also group leaders, so a timeout kill reaches
//!   anything they spawned.
//! - As PID 1, any orphan re-parents to us; only the namespace-wide
//!   `waitpid` here (not std) reaps those, and skipping them would leak
//!   zombies.
//!
//! All syscalls go through `nix`, a safe typed wrapper — no `unsafe` in
//! this crate.

use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::sys::signal::{Signal, kill, killpg};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
// nix's typed pid wrapper; the crate's public `Pid` is a plain i32 alias,
// so nix calls convert at the boundary.
use nix::unistd::Pid as NixPid;

use crate::util::log;

/// Poll cadence of the reap/watch loops: `waitpid(WNOHANG)` is cheap, this
/// only bounds signal-observation and shutdown latency.
pub const POLL: Duration = Duration::from_millis(100);

/// Grace before SIGTERM escalates to SIGKILL on teardown (matches Docker's
/// default 10s stop timeout; only pathological children ever reach it).
pub const TERM_GRACE: Duration = Duration::from_secs(10);

/// After SIGKILL (uncatchable), wait this long for the reap before giving
/// up; an uninterruptible (D-state) process is the container runtime's
/// problem, and must not hang our own exit.
pub const KILL_GRACE: Duration = Duration::from_secs(5);

/// Child process id (also its process-group id, see [`spawn`]).
pub type Pid = i32;

/// Spawn `cmd` as the leader of its own process group and return its pid.
/// Doing it in the child (`process_group(0)`) closes the classic race where
/// the child execs before the parent could `setpgid` it.
pub fn spawn(cmd: &mut Command) -> Option<Pid> {
    cmd.process_group(0);
    match cmd.spawn() {
        Ok(child) => Some(child.id() as Pid),
        Err(e) => {
            log::err(&format!(
                "{} spawn failed: {e}",
                cmd.get_program().to_string_lossy()
            ));
            None
        }
    }
}

/// Liveness probe (not a reap): `None` sends signal 0, which checks
/// existence only. `Err` covers both nonexistence and EPERM — as PID 1 the
/// latter cannot happen for our own children.
pub fn alive(pid: Pid) -> bool {
    kill(NixPid::from_raw(pid), None).is_ok()
}

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

/// Signal the whole process group of a child spawned via [`spawn`] (its pgid
/// equals its pid), falling back to the bare pid if the group vanished.
/// Refuses pid <= 1: `killpg(1, …)` semantics are platform-specific and
/// `kill(-1, …)` would signal every process in the namespace.
pub fn signal_group(pid: Pid, sig: Signal) -> bool {
    if pid <= 1 {
        return false;
    }
    killpg(NixPid::from_raw(pid), sig).is_ok() || kill(NixPid::from_raw(pid), sig).is_ok()
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

/// Run a child to completion with a hard timeout; kill on expiry. Aborts
/// early when `abort` fires, so a stop request never waits out a bounded
/// phase. stdio is inherited so failures stay visible in container logs.
pub fn run_bounded(timeout: Duration, prog: &str, args: &[&str], abort: impl Fn() -> bool) -> bool {
    run_bounded_env(timeout, prog, args, &[], abort)
}

/// [`run_bounded`] with extra child env vars (e.g. rclone backend config).
/// The child runs as its own process-group leader, so the expiry/abort kill
/// reaches anything it spawned, not just the direct child.
pub fn run_bounded_env(
    timeout: Duration,
    prog: &str,
    args: &[&str],
    extra_env: &[(String, String)],
    abort: impl Fn() -> bool,
) -> bool {
    let mut cmd = Command::new(prog);
    cmd.args(args).process_group(0);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            log::err(&format!("{prog} spawn failed: {e}"));
            return false;
        }
    };
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return st.success(),
            Ok(None) => {}
            Err(_) => return false,
        }
        if abort() {
            log::info(&format!("stop requested; aborting {prog}"));
            break;
        }
        if start.elapsed() > timeout {
            log::err(&format!("{prog} timed out after {timeout:?}"));
            break;
        }
        std::thread::sleep(POLL);
    }
    // Whole-group kill first, then the direct child, then reap.
    let pid = child.id() as i32;
    let _ = killpg(NixPid::from_raw(pid), Signal::SIGKILL);
    let _ = child.kill();
    let _ = child.wait();
    false
}

#[cfg(test)]
mod tests {
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
