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

pub(super) struct Liveness {
    vault: Option<SocketAddr>,
    ttl: Duration,
    verdict: Mutex<Option<(Instant, bool)>>,
}

impl Liveness {
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
        let mut cached = self.verdict.lock().unwrap_or_else(|e| e.into_inner());
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

    #[cfg(test)]
    pub(super) fn with_ttl(vault: Option<SocketAddr>, ttl: Duration) -> Self {
        Self {
            vault,
            ttl,
            verdict: Mutex::new(None),
        }
    }
}
