//! Child primitives: spawning and group signaling, plus the shared
//! timing constants of the reap/watch/run loops and the [`Pid`] alias.
//! Spawning registers the child with the reaper hub ([`super::reaper`]),
//! which owns every `waitpid` in the process; waiters only read the
//! delivered status.

use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use nix::sys::prctl;
use nix::sys::signal::{Signal, kill, killpg};
use nix::sys::stat::{Mode, umask};
// nix's typed pid wrapper; the crate's public `Pid` is a plain i32 alias,
// so nix calls convert at the boundary.
use nix::unistd::{Gid, Pid as NixPid, Uid, getegid, geteuid, setgroups, setresgid, setresuid};

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

/// The identity and file-creation mask a child runs with.
#[derive(Clone, Copy, Debug)]
pub struct Credentials {
    pub uid: u32,
    pub gid: u32,
    /// 0o007 = owner+group read/write, no access for others. The data
    /// group is how the vault's files stay readable by the supervisor.
    pub umask: u32,
}

/// Run a child a different UID. The supervisor holds CAP_SETUID/CAP_SETGID
/// and the vault is the only child that needs this: it must not share an
/// identity with the process holding the tailscale state, LocalAPI socket,
/// and secrets.
///
/// The credential change happens in the forked child before `exec`, after
/// `setgroups([])` (a leftover supplementary group would survive the UID
/// change). `setresgid`/`setresuid` set all three ids; with the supervisor
/// as the caller, no saved uid remains to regain the old identity. The
/// final `PR_SET_NO_NEW_PRIVS` makes the restriction irreversible across
/// `exec`. The closure only makes async-signal-safe syscalls.
pub fn spawn_as(cmd: &mut Command, creds: Credentials) -> Option<Handle> {
    let same_identity = geteuid().as_raw() == creds.uid && getegid().as_raw() == creds.gid;
    // SAFETY: pre_exec runs between fork and exec; the closure allocates
    // nothing and only calls the syscalls above.
    unsafe {
        cmd.pre_exec(move || {
            let fail = |e: nix::errno::Errno| std::io::Error::from_raw_os_error(e as i32);
            // No identity transition means no group list to clear; this
            // also keeps the path testable without CAP_SETGID.
            if !same_identity {
                setgroups(&[]).map_err(fail)?;
            }
            setresgid(
                Gid::from_raw(creds.gid),
                Gid::from_raw(creds.gid),
                Gid::from_raw(creds.gid),
            )
            .map_err(fail)?;
            setresuid(
                Uid::from_raw(creds.uid),
                Uid::from_raw(creds.uid),
                Uid::from_raw(creds.uid),
            )
            .map_err(fail)?;
            prctl::set_no_new_privs().map_err(fail)?;
            umask(Mode::from_bits_truncate(creds.umask));
            Ok(())
        });
    }
    spawn(cmd)
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

/// Signal a still-running child through its handle. Registration in the
/// reaper's registry is the liveness proof: the targeted `waitpid` and
/// the entry's removal happen under the registry lock, so while the entry
/// is present the child has not been reaped and its pid cannot have been
/// recycled. The signal goes out under that same lock, closing the window
/// between the reaper's waitpid and its status delivery. Returns false
/// for a reaped child (and for the [`signal_group`] refusals), true when
/// a signal was delivered.
pub fn signal_child(child: &Handle, sig: Signal) -> bool {
    let reg = reaper::registry_lock();
    if !reg.contains_key(&child.pid) {
        return false;
    }
    let delivered = signal_group(child.pid, sig);
    drop(reg);
    delivered
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::super::reap::{Gone, exit_code, reap_until_gone};
    use super::*;

    /// The forked child applies the credential closure (umask here) and
    /// still spawns/reaps normally. The cross-uid transition needs the
    /// supervisor's capabilities; the image smoke covers that identity.
    #[test]
    fn spawn_as_applies_the_child_settings() {
        let dir = std::env::temp_dir().join(format!(
            "vw-sup-cred-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("umask");
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(format!("umask > '{}'", out.display()));
        let handle = spawn_as(
            &mut cmd,
            Credentials {
                uid: geteuid().as_raw(),
                gid: getegid().as_raw(),
                umask: 0o007,
            },
        )
        .expect("a child with the current identity must spawn");
        match reap_until_gone(&handle, Duration::from_secs(5)) {
            Gone::Reaped(status) => assert_eq!(exit_code(status), 0),
            Gone::Stuck => panic!("the child did not exit"),
        }
        assert_eq!(std::fs::read_to_string(&out).unwrap().trim(), "0007");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
