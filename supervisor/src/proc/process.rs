//! Process primitives for a PID 1 supervisor: spawning, reaping, group
//! signaling, and shutdown escalation.
//!
//! Ownership model (this is what makes the reaping race-free):
//! - Long-running children (tailscaled, vaultwarden) are spawned as their own
//!   process-group leaders (`process_group(0)`), so one `kill(-pgid)` reaches
//!   the child *and* everything it spawned. Their `std::process::Child`
//!   handle is dropped on purpose: statuses are collected only via the
//!   namespace-wide reaper (`reap_any`), never through std's targeted
//!   `try_wait`/`wait`, which would race it over the same zombie.
//! - Short-lived CLI children (`run_bounded`) keep std's Child instead: they
//!   live and die strictly inside that helper, before the watch loop starts,
//!   so there is no overlap in time or target with the namespace reaper.
//! - As PID 1, any orphan in the container re-parents to us; only `waitpid`
//!   here (not std) can reap those, and skipping them would leak zombies.

use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};

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

/// Reap one pending zombie from anywhere in the namespace. `None` means
/// nothing reapable right now (0 = children alive but no zombie yet,
/// -1 = ECHILD/EINTR).
///
/// Never call this from tests: `waitpid(-1, …)` would also reap the test
/// harness's own children.
pub fn reap_any() -> Option<(Pid, i32)> {
    let mut status = 0;
    let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
    (pid > 0).then_some((pid, status))
}

/// Container exit code for a raw wait status: the child's own code, or the
/// shell convention 128+signal when it died to a signal (a SIGTERM'd
/// service reports 143 — same as tini / plain Docker behavior).
pub fn exit_code(raw: i32) -> i32 {
    if libc::WIFEXITED(raw) {
        libc::WEXITSTATUS(raw)
    } else if libc::WIFSIGNALED(raw) {
        128 + libc::WTERMSIG(raw)
    } else {
        1
    }
}

/// Human-readable wait status for logs.
pub fn exit_reason(raw: i32) -> String {
    if libc::WIFEXITED(raw) {
        format!("exit status {}", libc::WEXITSTATUS(raw))
    } else if libc::WIFSIGNALED(raw) {
        format!("terminated by signal {}", libc::WTERMSIG(raw))
    } else {
        format!("wait status {raw:#x}")
    }
}

/// Signal the whole process group of a child spawned via [`spawn`] (its pgid
/// equals its pid), falling back to the bare pid if the group vanished.
/// Refuses pid <= 1: `kill(-1, …)` would signal every process in the namespace.
pub fn signal_group(pid: Pid, sig: libc::c_int) -> bool {
    if pid <= 1 {
        return false;
    }
    unsafe { libc::kill(-pid, sig) == 0 || libc::kill(pid, sig) == 0 }
}

/// Outcome of waiting for a child to be reaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gone {
    /// Reaped here; raw wait status.
    Reaped(i32),
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
        // Targeted fast path; also covers "already reaped as a stray" via ECHILD.
        let mut status = 0;
        match unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } {
            p if p == pid => return Gone::Reaped(status),
            -1 if std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) => {
                return Gone::Vanished;
            }
            _ => {}
        }
        while let Some((p, raw)) = reap_any() {
            if p == pid {
                return Gone::Reaped(raw);
            }
        }
        let now = Instant::now();
        if now >= deadline {
            if killed {
                log::err(&format!("pid {pid} unreapable; continuing shutdown"));
                return Gone::Stuck;
            }
            signal_group(pid, libc::SIGKILL);
            killed = true;
            deadline = now + KILL_GRACE;
        }
        std::thread::sleep(POLL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_decodes_exit_and_signal_statuses() {
        assert_eq!(exit_code(0), 0);
        assert_eq!(exit_code(3 << 8), 3); // WIFEXITED, code 3
        assert_eq!(exit_code(15), 143); // WIFSIGNALED, SIGTERM -> 128+15
        assert_eq!(exit_code((19 << 8) | 0x7f), 1); // WIFSTOPPED: defensive
    }

    #[test]
    fn exit_reason_is_human_readable() {
        assert_eq!(exit_reason(0), "exit status 0");
        assert_eq!(exit_reason(3 << 8), "exit status 3");
        assert_eq!(exit_reason(15), "terminated by signal 15");
    }

    #[test]
    fn signal_group_refuses_own_namespace() {
        // pid <= 1 must never reach kill(-1, …) — that would signal every
        // process in the PID namespace, including us.
        assert!(!signal_group(0, libc::SIGTERM));
        assert!(!signal_group(1, libc::SIGTERM));
        assert!(!signal_group(-5, libc::SIGTERM));
    }
}
