//! The reaper hub: the single owner of every `waitpid` in the process.
//!
//! Children are spawned through [`super::child::spawn`], which registers
//! them here under the registry lock held across spawn + insert. The
//! reaper thread (started lazily at the first spawn) reaps and *delivers*
//! each status into the child's registered slot; waiters — bounded runs
//! on any thread, the vault watch loop, teardown — only ever read slots.
//! Because exactly one component ever reaps, a reaped-out-from-under
//! race cannot exist, and a delivered status is always the true one
//! (no fail-closed guessing, no lost-exit registry).
//!
//! Every child is also a pidfd ([`super::pidfd`]); the reaper polls the
//! registry's pidfds for prompt exit detection and then reaps each ready
//! child with a targeted waitpid. A `waitpid(-1, WNOHANG)` sweep follows
//! every tick to reap strays (orphaned namespace children re-parented to
//! PID 1, no pidfd) — and as a correctness backstop for anything the poll
//! path missed. Deliveries take the registry lock, so a child that exits
//! between spawn and registration is delivered, never mistaken for a
//! stray.

use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, Weak};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid as NixPid;

use super::child::{POLL, Pid};
use super::pidfd::PidFd;
use super::reap::exit_reason;
use crate::util::log;

/// Delivered wait status of one registered child. Written once (by the
/// reaper), read by any holder of the [`Handle`].
pub(crate) struct Waiter {
    slot: Mutex<Option<WaitStatus>>,
    cv: Condvar,
}

/// Registered handle to a spawned child: its pid (for group signaling)
/// and the slot its exit status is delivered into. Cloneable; the slot
/// survives reaping, so late readers (teardown after the watch loop saw
/// the exit) still find the status.
#[derive(Clone)]
pub struct Handle {
    pub pid: Pid,
    waiter: Arc<Waiter>,
}

/// Registered child entry: its pidfd (for the poll) and the waiter slot
/// its status is delivered into.
pub(crate) struct Entry {
    pub(crate) pidfd: Arc<PidFd>,
    pub(crate) waiter: Weak<Waiter>,
}

fn registry() -> &'static Mutex<HashMap<Pid, Entry>> {
    static REG: OnceLock<Mutex<HashMap<Pid, Entry>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Registry lock for [`insert_locked`]: held by [`super::child::spawn`]
/// across `spawn(2)` + registration, closing the spawn-vs-reap window.
pub(crate) fn registry_lock() -> MutexGuard<'static, HashMap<Pid, Entry>> {
    registry().lock().unwrap_or_else(|e| e.into_inner())
}

/// Register a freshly spawned child. Caller holds [`registry_lock`] and
/// passes its map — this must never re-lock (child::spawn holds the
/// guard across spawn + registration).
pub(crate) fn insert_locked(reg: &mut HashMap<Pid, Entry>, pid: Pid, pidfd: Arc<PidFd>) -> Handle {
    let waiter = Arc::new(Waiter {
        slot: Mutex::new(None),
        cv: Condvar::new(),
    });
    reg.insert(
        pid,
        Entry {
            pidfd,
            waiter: Arc::downgrade(&waiter),
        },
    );
    Handle { pid, waiter }
}

impl Waiter {
    fn deliver(&self, status: WaitStatus) {
        *self.slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(status);
        self.cv.notify_all();
    }
}

impl Handle {
    /// The delivered exit status, once the reaper has reaped the child;
    /// `None` while it is still running (or before delivery). Reads do
    /// not consume: teardown may check a status the watch loop saw first.
    pub fn status(&self) -> Option<WaitStatus> {
        *self.waiter.slot.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Block until the status is delivered or `timeout` passes. The
    /// poll-slice shape keeps stop requests and deadlines observable.
    pub fn wait(&self, timeout: Duration) -> Option<WaitStatus> {
        let deadline = Instant::now() + timeout;
        let mut slot = self.waiter.slot.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(status) = *slot {
                return Some(status);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let slice = POLL.min(deadline - now);
            let (guard, _) = self
                .waiter
                .cv
                .wait_timeout(slot, slice)
                .unwrap_or_else(|e| e.into_inner());
            slot = guard;
        }
    }
}

/// Idempotently start the reaper thread. Called before the first spawn.
pub(crate) fn start() {
    static START: OnceLock<()> = OnceLock::new();
    START.get_or_init(|| {
        std::thread::Builder::new()
            .name("reaper".into())
            .spawn(run)
            .expect("reaper thread");
    });
}

/// One reaper pass: reap pidfd-ready children, then sweep strays.
/// The only `waitpid` call sites in the process live here.
fn tick() {
    let entries: Vec<(Pid, Arc<PidFd>)> = registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .map(|(pid, e)| (*pid, Arc::clone(&e.pidfd)))
        .collect();
    let fds: Vec<_> = entries.iter().map(|(_, fd)| fd.as_raw_fd()).collect();
    for i in PidFd::ready_indices(&fds, POLL) {
        let (pid, _) = &entries[i];
        // Targeted wait, WNOHANG: every waitpid call site is
        // non-blocking, so a spurious poll event can never stall the
        // reaper. ECHILD = already reaped by an earlier pass here
        // (defensive only; delivery always consumes the registry entry).
        match waitpid(NixPid::from_raw(*pid), Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => {}
            Ok(status) => deliver_reaped(*pid, status),
            Err(Errno::ECHILD) => {}
            Err(e) => log::err(&format!("reaper: waitpid({pid}) failed: {e}")),
        }
    }
    // Strays (orphans with no pidfd) and the poll backstop. The registry
    // lookup happens after the reap; child::spawn holds the lock across
    // spawn+insert, so a delivery can never miss its registration.
    loop {
        match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
            // Nothing reapable right now (children exist, none exited).
            Ok(WaitStatus::StillAlive) => break,
            Ok(status) => {
                let pid = status.pid().map(NixPid::as_raw).unwrap_or(0);
                deliver_reaped(pid, status);
            }
            Err(Errno::ECHILD) | Err(Errno::EINTR) => break,
            Err(e) => {
                log::err(&format!("reaper: unexpected waitpid failure: {e}"));
                break;
            }
        }
    }
}

/// A child was just reaped: route its status to the registered waiter —
/// consuming the registry entry, so both reaping paths (poll, sweep)
/// leak nothing and cannot double-deliver — or log it as a stray.
fn deliver_reaped(pid: Pid, status: WaitStatus) {
    let waiter = registry()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&pid)
        .map(|e| e.waiter);
    match waiter.as_ref().and_then(Weak::upgrade) {
        Some(w) => w.deliver(status),
        None => log::info(&format!(
            "reaper: stray pid {pid} ({})",
            exit_reason(status)
        )),
    }
}

fn run() {
    loop {
        set_idle(false);
        tick();
        set_idle(true);
    }
}

/// Idle flag: false for the duration of a reaper pass, true after a full
/// clean pass. [`quiesce`] waits on it.
fn set_idle(idle: bool) {
    *IDLE.lock().unwrap_or_else(|e| e.into_inner()) = idle;
    if idle {
        IDLE_CV.notify_all();
    }
}

static IDLE: Mutex<bool> = Mutex::new(true);
static IDLE_CV: Condvar = Condvar::new();

/// Wait for one full clean reaper pass (nothing ready, no strays) —
/// shutdown uses this so the single-waitpid-owner rule survives teardown
/// too. Bounded by `timeout`.
pub(crate) fn quiesce(timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    let mut idle = IDLE.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        if *idle {
            return true;
        }
        let now = Instant::now();
        if now >= deadline {
            return false;
        }
        let (guard, _) = IDLE_CV
            .wait_timeout(idle, POLL.min(deadline - now))
            .unwrap_or_else(|e| e.into_inner());
        idle = guard;
    }
}
