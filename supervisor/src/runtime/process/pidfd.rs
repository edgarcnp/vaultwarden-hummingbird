//! pidfd: a stable, race-free handle to a child process (Linux 5.3+).
//! The reaper hub ([`super::reaper`]) polls these fds to notice exits
//! promptly; readiness (POLLIN) means the child is waitable. Correctness
//! never depends on the poll — the reaper's waitpid sweep catches every
//! exit — so a missed or partial poll can only cost latency, never a
//! lost status.

use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd};
use std::time::Duration;

use nix::libc;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

use super::child::Pid;

/// An owned pidfd. Closed on drop; never duplicated, so exactly one
/// component polls it (the reaper).
pub struct PidFd(OwnedFd);

impl AsFd for PidFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl PidFd {
    /// `pidfd_open(2)`. Fails on kernels < 5.3 (ENOSYS) or an unknown
    /// pid; callers treat failure as a failed spawn (fail-closed boot).
    pub fn open(pid: Pid) -> std::io::Result<Self> {
        let fd = open_syscall(pid);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: the syscall returned a fresh, solely-owned descriptor;
        // OwnedFd takes exclusive ownership and closes it on drop.
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd as i32) }))
    }

    /// Indices into `fds` with a pending event within `timeout`. Any
    /// event (not just POLLIN) counts as ready: the caller's targeted
    /// waitpid is the authority, and ECHILD there simply means the sweep
    /// already reaped and delivered this child.
    pub fn ready_indices(fds: &[&PidFd], timeout: Duration) -> Vec<usize> {
        let mut pollfds: Vec<PollFd> = fds
            .iter()
            .map(|fd| PollFd::new(fd.as_fd(), PollFlags::POLLIN))
            .collect();
        if pollfds.is_empty() {
            return Vec::new();
        }
        let timeout = PollTimeout::try_from(timeout).unwrap_or(PollTimeout::NONE);
        if poll(pollfds.as_mut_slice(), timeout).unwrap_or(0) <= 0 {
            // Timeout, EINTR, or error: the reaper's sweep covers
            // correctness, so treat as "nothing ready".
            return Vec::new();
        }
        pollfds
            .iter()
            .enumerate()
            .filter(|(_, p)| p.revents().is_some_and(|flags| !flags.is_empty()))
            .map(|(i, _)| i)
            .collect()
    }
}

#[cfg(target_os = "linux")]
fn open_syscall(pid: Pid) -> libc::c_long {
    // SAFETY: pidfd_open takes a pid and flags; it allocates a descriptor
    // or fails, touching nothing else.
    unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::c_int, 0 as libc::c_uint) }
}

#[cfg(not(target_os = "linux"))]
fn open_syscall(_pid: Pid) -> libc::c_long {
    // Non-Linux builds compile but can never supervise: fail closed with
    // ENOSYS at runtime (the supervisor is only ever run as a Linux
    // container's PID 1).
    *nix::libc::__errno_location() = libc::ENOSYS;
    -1
}

#[cfg(test)]
mod tests {
    use std::process::Command;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::runtime::process::child::POLL;

    #[test]
    fn own_pidfd_is_open_and_not_ready() {
        let fd = PidFd::open(std::process::id() as Pid).expect("self pidfd");
        assert!(
            PidFd::ready_indices(&[&fd], Duration::ZERO).is_empty(),
            "a live process is never waitable"
        );
    }

    /// Exit flips the pidfd to ready, and it stays ready even after the
    /// reaper hub reaps the zombie. The test never calls waitpid itself:
    /// with the hub running in this process, that would race it.
    #[test]
    #[allow(clippy::zombie_processes)]
    fn exit_flips_the_pidfd_to_ready() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 30"])
            .spawn()
            .expect("spawn");
        let fd = PidFd::open(child.id() as Pid).expect("pidfd");
        assert!(
            PidFd::ready_indices(&[&fd], Duration::ZERO).is_empty(),
            "live child must not poll ready"
        );
        child.kill().expect("SIGKILL delivered");
        let deadline = Instant::now() + Duration::from_secs(5);
        while PidFd::ready_indices(&[&fd], POLL).is_empty() {
            assert!(Instant::now() < deadline, "pidfd never turned ready");
            std::thread::sleep(POLL);
        }
    }
}
