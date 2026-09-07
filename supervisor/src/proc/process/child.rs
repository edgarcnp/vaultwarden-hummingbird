//! Child primitives: spawning, liveness, and group signaling, plus the
//! shared timing constants of the reap/watch loops and the [`Pid`] alias.
//!
//! Reaping is race-free by ownership (see `reap` / `run`):
//! - Long-running children ([`spawn`]) are process-group leaders; their
//!   `std::process::Child` handle is dropped on purpose — statuses come only
//!   from the namespace-wide reaper ([`reap_any`]), never std's targeted
//!   `try_wait`/`wait`, which would race it over the same zombie.
//! - Bounded CLI children ([`run_bounded_env`]) are reaped via std inside
//!   the helper; the main thread is single-threaded, so the two never
//!   overlap. They are also group leaders, so a timeout kill reaches
//!   anything they spawned.
//! - As PID 1, any orphan re-parents to us; only the namespace-wide
//!   `waitpid` there (not std) reaps those, and skipping them would leak
//!   zombies.
//!
//! All syscalls go through `nix`, a safe typed wrapper — no `unsafe` in
//! this crate.

use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::Duration;

use nix::sys::signal::{Signal, kill, killpg};
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
