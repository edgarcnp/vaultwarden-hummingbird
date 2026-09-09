//! Single-flight liveness verdict for the gate: concurrent `/alive`
//! requests share one vaultwarden probe. The public port must not fan a
//! probe flood out into thousands of backend connections; at most one
//! probe runs per TTL window, and waiters join its verdict. Staleness is
//! bounded by the same budget an unshared probe already had.

use std::net::SocketAddr;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use super::probe::{PROBE_TIMEOUT, get_alive};

/// Cache window for a completed probe. The probe itself is bounded by
/// [`PROBE_TIMEOUT`], so worst-case verdict age stays at
/// TTL + PROBE_TIMEOUT — the same order a fresh probe on every request
/// already had.
const PROBE_TTL: Duration = PROBE_TIMEOUT;

/// Slack on top of the probe budget for joining an in-flight probe.
const WAIT_SLACK: Duration = Duration::from_millis(500);

pub(super) struct Liveness {
    vault: Option<SocketAddr>,
    ttl: Duration,
    flight: Mutex<Flight>,
    settled: Condvar,
}

/// One probe window: the last verdict and whether one is in flight.
#[derive(Default)]
struct Flight {
    verdict: Option<(Instant, bool)>,
    probing: bool,
}

impl Liveness {
    pub(super) fn new(vault: Option<SocketAddr>) -> Self {
        Self {
            vault,
            ttl: PROBE_TTL,
            flight: Mutex::new(Flight::default()),
            settled: Condvar::new(),
        }
    }

    /// Shared verdict: fresh cache hit, join the in-flight probe, or
    /// probe. At most one backend probe per TTL window.
    pub(super) fn alive(&self) -> bool {
        let mut f = self.flight.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((at, ok)) = f.verdict {
            if at.elapsed() < self.ttl {
                return ok;
            }
            f.verdict = None;
        }
        if f.probing {
            // Join the in-flight probe. Bounded: a wedged prober must not
            // hold the gate — fail to the last verdict (or down).
            let deadline = Instant::now() + PROBE_TIMEOUT + WAIT_SLACK;
            loop {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                let (guard, _) = self
                    .settled
                    .wait_timeout(f, deadline - now)
                    .unwrap_or_else(|e| e.into_inner());
                f = guard;
                if !f.probing {
                    break;
                }
            }
            return f.verdict.map(|(_, ok)| ok).unwrap_or(false);
        }
        f.probing = true;
        drop(f);
        let ok = self
            .vault
            .is_some_and(|addr| get_alive(addr, PROBE_TIMEOUT));
        let mut f = self.flight.lock().unwrap_or_else(|e| e.into_inner());
        f.probing = false;
        f.verdict = Some((Instant::now(), ok));
        self.settled.notify_all();
        ok
    }

    #[cfg(test)]
    pub(super) fn with_ttl(vault: Option<SocketAddr>, ttl: Duration) -> Self {
        Self {
            vault,
            ttl,
            flight: Mutex::new(Flight::default()),
            settled: Condvar::new(),
        }
    }
}
