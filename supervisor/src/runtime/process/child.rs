//! Child primitives: spawning, liveness, and group signaling, plus the
//! shared timing constants of the reap/watch loops and the [`Pid`] alias.
//!
//! Reaping is race-free by ownership (see `reap` / `run`):
//! - Long-running children ([`spawn`]) are process-group leaders; their
//!   `std::process::Child` handle is dropped on purpose — statuses come only
//!   from the namespace-wide reaper ([`super::reap::reap_any`]), never std's
//!   targeted `try_wait`/`wait`, which would race it over the same zombie.
//! - Bounded CLI children ([`super::run::run_bounded_env`]) are reaped via
//!   std, but the main thread's namespace-wide reaper may steal the zombie
//!   first when the run happens off the main thread (the backup thread);
//!   the stolen-exit registry ([`super::stolen`]) preserves the verdict.
//!   They are also group leaders, so a timeout kill reaches
//!   anything they spawned.
//! - As PID 1, any orphan re-parents to us; only the namespace-wide
//!   `waitpid` there (not std) reaps those, and skipping them would leak
//!   zombies.

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

/// Grace before SIGTERM escalates to SIGKILL on teardown (Docker's default
/// stop timeout; only pathological children ever reach it).
pub const TERM_GRACE: Duration = Duration::from_secs(10);

/// Child process id (also its process-group id, see [`spawn`]).
pub type Pid = i32;

/// Spawn `cmd` as the leader of its own process group. Doing it in the
/// child (`process_group(0)`) closes the race where the child execs before
/// the parent could `setpgid` it.
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

/// Liveness probe: `None` sends signal 0, checking existence only.
pub fn alive(pid: Pid) -> bool {
    kill(NixPid::from_raw(pid), None).is_ok()
}

/// Signal the whole process group of a child spawned via [`spawn`] (pgid ==
/// pid), falling back to the bare pid if the group vanished. Refuses
/// pid <= 1: `kill(-1, …)` would signal every process in the namespace.
pub fn signal_group(pid: Pid, sig: Signal) -> bool {
    if pid <= 1 {
        return false;
    }
    killpg(NixPid::from_raw(pid), sig).is_ok() || kill(NixPid::from_raw(pid), sig).is_ok()
}
