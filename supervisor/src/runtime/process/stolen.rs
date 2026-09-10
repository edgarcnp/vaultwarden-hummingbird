//! Stolen-exit-status registry: the main thread's namespace-wide reaper
//! (`reap_any` = `waitpid(-1, WNOHANG)`) can reap a bounded-run child
//! owned by another thread (e.g. a periodic-maintenance thread) before
//! that thread's own `try_wait` sees it; std then reports `ECHILD` and
//! the run's true exit status is lost. When `reap_any` reaps a registered
//! pid it records the wait status here; the bounded run consults the
//! registry before giving up. `take` distinguishes "status recorded" from
//! "reaped unknown" — the latter must still be treated as failure (safe
//! direction).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use nix::sys::wait::WaitStatus;

static STOLEN: OnceLock<Mutex<HashMap<i32, Option<WaitStatus>>>> = OnceLock::new();

fn stolen() -> &'static Mutex<HashMap<i32, Option<WaitStatus>>> {
    STOLEN.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Register a bounded-run child so a reaper that steals its zombie can
/// preserve the wait status for the owner's `try_wait`.
pub(crate) fn register(pid: i32) {
    if let Ok(mut map) = stolen().lock() {
        map.insert(pid, None);
    }
}

/// Unregister; `Some(status)` = a reaper stole the run and recorded its
/// status; `Some(None)` = stolen with an unknown status; `None` = the
/// owner's own `waitpid` should have the status.
pub(crate) fn take(pid: i32) -> Option<Option<WaitStatus>> {
    let mut map = stolen().lock().ok()?;
    map.remove(&pid)
}

/// Record a status observed by the namespace-wide reaper for a registered
/// pid (no-op when the pid is not registered).
pub(crate) fn record(pid: i32, status: WaitStatus) {
    if let Ok(mut map) = stolen().lock()
        && map.contains_key(&pid)
    {
        map.insert(pid, Some(status));
    }
}
