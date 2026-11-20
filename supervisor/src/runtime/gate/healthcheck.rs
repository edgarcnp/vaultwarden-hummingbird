//! One-shot `--healthcheck` mode (the image's HEALTHCHECK exec-form):
//! probe the full chain end-to-end — this binary's gatekeeper on `exposed`
//! (loopback), which itself probes vaultwarden's loopback `/alive` — and
//! report the verdict a platform health probe would get.

use std::net::SocketAddr;
use std::time::Duration;

use super::probe::{PROBE_TIMEOUT, get_alive};

use crate::runtime::POLL;
use crate::util::log;
use crate::util::wait_until;

/// Hard overall deadline for retrying an unbound boot-time gate. Worst case
/// is budget + probe (6 + 2 = 8s), under the image's 10s health-check timeout.
const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(6);

/// Must be called before any boot side effect: spawns no children, touches
/// no Tailscale state. A zero port is a failed check, never a panic.
pub fn healthcheck(port: u16) -> bool {
    // 0 is never a real listener (config never resolves to it).
    if port == 0 {
        log::err("healthcheck: invalid exposed port 0");
        return false;
    }
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    healthcheck_until(addr, HEALTHCHECK_TIMEOUT)
}

/// The retry loop with an explicit budget (tests shrink it to keep the
/// suite fast). Termination is by construction: each iteration checks the
/// deadline, and the probe itself is bounded by [`PROBE_TIMEOUT`].
fn healthcheck_until(addr: SocketAddr, budget: Duration) -> bool {
    wait_until(
        || get_alive(addr, PROBE_TIMEOUT).then_some(()),
        budget,
        || false,
        POLL,
    )
    .is_some()
}

#[cfg(test)]
mod tests {
    //! Healthcheck retry tests against a stand-in gate and vault.
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use super::super::liveness::Liveness;
    use super::super::probe::fake_vault;
    use super::super::server::{bind, handle};
    use super::{healthcheck, healthcheck_until};

    /// Stand-in gatekeeper: serves the real `handle` on an ephemeral listener
    /// for every connection (healthcheck retries), probing `vault` exactly
    /// like the real gate. Returns the exposed port.
    fn fake_gate(vault: Option<SocketAddr>) -> u16 {
        let listener = bind(0).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(std::thread::spawn(move || {
            let live = Arc::new(Liveness::new(vault));
            for stream in listener.incoming().flatten() {
                let live = Arc::clone(&live);
                drop(std::thread::spawn(move || handle(stream, &live)));
            }
        }));
        port
    }

    #[test]
    fn healthcheck_answers_true_when_the_chain_is_healthy() {
        let port = fake_gate(Some(fake_vault("200 OK")));
        assert!(healthcheck_until(
            format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_secs(2)
        ));
    }

    /// The gate answers 503 while the vault is down or starting: the
    /// verdict is `false`, but only after the full budget — a probe that
    /// fires during the boot window gets the chance to see the vault come
    /// up instead of failing a healthy boot.
    #[test]
    fn healthcheck_answers_false_when_the_vault_is_down() {
        for vault in [None, Some(fake_vault("500 Internal Server Error"))] {
            let port = fake_gate(vault);
            assert!(
                !healthcheck_until(
                    format!("127.0.0.1:{port}").parse().unwrap(),
                    Duration::from_millis(300)
                ),
                "{vault:?}"
            );
        }
    }

    /// A gate that is not yet bound (early boot) must be retried until the
    /// budget runs out — and the probe must never hang past it.
    #[test]
    fn healthcheck_is_bounded_when_the_gate_is_not_bound() {
        // Claim an ephemeral port, then release it: nothing listens there.
        let free = bind(0).unwrap();
        let addr = format!("127.0.0.1:{}", free.local_addr().unwrap().port());
        drop(free);
        let budget = Duration::from_millis(300);
        let start = Instant::now();
        assert!(!healthcheck_until(addr.parse().unwrap(), budget));
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "healthcheck did not return within 30s"
        );
    }

    #[test]
    fn healthcheck_rejects_port_zero() {
        assert!(!healthcheck(0));
    }
}
