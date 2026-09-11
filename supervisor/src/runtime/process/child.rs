//! Child primitives: spawning and group signaling, plus the shared
//! timing constants of the reap/watch/run loops and the [`Pid`] alias.
//! Spawning registers the child with the reaper hub ([`super::reaper`]),
//! which owns every `waitpid` in the process; waiters only read the
//! delivered status.

use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use nix::sys::signal::{kill, killpg, Signal};
// nix's typed pid wrapper; the crate's public `Pid` is a plain i32 alias,
// so nix calls convert at the boundary.
use nix::unistd::Pid as NixPid;

use super::pidfd::PidFd;
use super::reaper::{self, Handle};
use crate::util::log;

/// Poll cadence of the reap/watch/run loops; bounds signal-observation
/// and shutdown latency.
pub const POLL: Duration = Duration::from_millis(100);

/// Grace before SIGTERM escalates to SIGKILL on teardown (Docker's default
/// stop timeout; only pathological children ever reach it).
pub const TERM_GRACE: Duration = Duration::from_secs(10);

/// After SIGKILL (uncatchable), wait this long for the reap before giving
/// up; a D-state process is the container runtime's problem, not ours.
pub(crate) const KILL_GRACE: Duration = Duration::from_secs(5);

/// Child process id (also its process-group id, see [`spawn`]).
pub type Pid = i32;

/// Spawn `cmd` as the leader of its own process group, registered with
/// the reaper hub. Doing the grouping in the child (`process_group(0)`)
/// closes the race where the child execs before the parent could
/// `setpgid` it.
///
/// The registry lock is held across `spawn(2)` + registration: a child
/// that exits instantly cannot be reaped-and-unmatched by the reaper
/// thread, because every delivery takes the same lock after the insert.
///
/// The std `Child` handle is dropped on purpose: nobody but the reaper
/// hub ever reaps. Failure (spawn error, or `pidfd_open` refusing on a
/// pre-5.3 kernel) returns `None` — a child nobody can supervise is a
/// child nobody may run.
pub fn spawn(cmd: &mut Command) -> Option<Handle> {
    cmd.process_group(0);
    reaper::start();
    let mut reg = reaper::registry_lock();
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            log::err(&format!(
                "{} spawn failed: {e}",
                cmd.get_program().to_string_lossy()
            ));
            return None;
        }
    };
    let pid = child.id() as Pid;
    let pidfd = match PidFd::open(pid) {
        Ok(fd) => Arc::new(fd),
        Err(e) => {
            log::err(&format!(
                "pidfd_open failed for pid {pid}: {e} (Linux 5.3+ required); \
                 refusing to run an unsupervisable child"
            ));
            let _ = kill(NixPid::from_raw(pid), Signal::SIGKILL);
            return None; // reaper thread reaps the killed child
        }
    };
    let handle = reaper::insert_locked(&mut reg, pid, pidfd);
    drop(reg);
    drop(child);
    Some(handle)
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
