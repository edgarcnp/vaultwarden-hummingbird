//! pidfd: a stable, race-free handle to a child process (Linux 5.3+).
//! The reaper hub ([`super::reaper`]) polls these fds to notice exits
//! promptly; readiness (POLLIN) means the child is waitable. Correctness
//! never depends on the poll — the reaper's waitpid sweep catches every
//! exit — so a missed or partial poll can only cost latency, never a
//! lost status.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

use nix::libc;

use super::child::Pid;

/// An owned pidfd. Closed on drop; never duplicated, so exactly one
/// component polls it (the reaper).
pub struct PidFd(OwnedFd);

impl AsRawFd for PidFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
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
    pub fn ready_indices(fds: &[RawFd], timeout: Duration) -> Vec<usize> {
        let mut pollfds: Vec<libc::pollfd> = fds
            .iter()
            .map(|&fd| libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        if pollfds.is_empty() {
            return Vec::new();
        }
        let ms = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
        // SAFETY: pollfds is a valid, non-empty array of pollfd for the
        // duration of the call; poll(2) does not retain it.
        let n = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, ms) };
        if n <= 0 {
            // Timeout, EINTR, or error: the reaper's sweep covers
            // correctness, so treat as "nothing ready".
            return Vec::new();
        }
        pollfds
            .iter()
            .enumerate()
            .filter(|(_, p)| p.revents != 0)
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
            PidFd::ready_indices(&[fd.as_raw_fd()], Duration::ZERO).is_empty(),
            "a live process is never waitable"
        );
    }

    /// Exit flips the pidfd to ready, and it stays ready even after the
    /// reaper hub reaps the zombie. The test never calls waitpid itself:
    /// with the hub running in this process, that would race it.
    // The child is deliberately never waited on here (see above); the
    // reaper hub reaps it, or the test process's exit does.
    #[test]
    #[allow(clippy::zombie_processes)]
    fn exit_flips_the_pidfd_to_ready() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 30"])
            .spawn()
            .expect("spawn");
        let fd = PidFd::open(child.id() as Pid).expect("pidfd");
        assert!(
            PidFd::ready_indices(&[fd.as_raw_fd()], Duration::ZERO).is_empty(),
            "live child must not poll ready"
        );
        child.kill().expect("SIGKILL delivered");
        let deadline = Instant::now() + Duration::from_secs(5);
        while PidFd::ready_indices(&[fd.as_raw_fd()], POLL).is_empty() {
            assert!(Instant::now() < deadline, "pidfd never turned ready");
            std::thread::sleep(POLL);
        }
    }
}
