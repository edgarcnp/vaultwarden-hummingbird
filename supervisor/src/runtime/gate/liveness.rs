//! TTL-cached liveness verdict for the gate: `/alive` requests within the
//! cache window share the last probe's verdict, so a public probe flood
//! cannot fan out into a backend flood — the backend sees at most
//! `MAX_CONNS` (the admission cap in `server`) bounded probes per window,
//! and a steady flood amortizes to one probe per window. Staleness is
//! bounded by the same budget an uncached probe already had.

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::probe::{PROBE_TIMEOUT, get_alive};

/// Cache window for a completed probe (= the probe budget, so worst-case
/// verdict age stays in the same order as an uncached probe).
const PROBE_TTL: Duration = PROBE_TIMEOUT;

/// TTL-cached `/alive` verdict shared by every gate handler.
pub(super) struct Liveness {
    /// Loopback vault address to probe, or `None` to report down unprobed.
    vault: Option<SocketAddr>,
    /// How long a completed probe's verdict may be reused.
    ttl: Duration,
    /// Last verdict and when it was taken; `None` until the first probe.
    verdict: Mutex<Option<(Instant, bool)>>,
}

impl Liveness {
    /// A cache with the production TTL ([`PROBE_TTL`]).
    pub(super) fn new(vault: Option<SocketAddr>) -> Self {
        Self {
            vault,
            ttl: PROBE_TTL,
            verdict: Mutex::new(None),
        }
    }

    /// Shared verdict: a fresh cache hit, else one bounded probe (its
    /// result becomes the new window). Both directions are cheap: the
    /// probe is a loopback roundtrip under [`PROBE_TIMEOUT`].
    pub(super) fn alive(&self) -> bool {
        let mut cached = crate::util::lock_ignoring_poison(&self.verdict);
        if let Some((at, ok)) = *cached
            && at.elapsed() < self.ttl
        {
            return ok;
        }
        let ok = self
            .vault
            .is_some_and(|addr| get_alive(addr, PROBE_TIMEOUT));
        *cached = Some((Instant::now(), ok));
        ok
    }

    /// A cache with an explicit window (tests shrink it).
    #[cfg(test)]
    pub(super) fn with_ttl(vault: Option<SocketAddr>, ttl: Duration) -> Self {
        Self {
            vault,
            ttl,
            verdict: Mutex::new(None),
        }
    }
}
