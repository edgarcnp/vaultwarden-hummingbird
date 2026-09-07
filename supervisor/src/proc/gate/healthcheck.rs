//! One-shot `--healthcheck` mode (the image's HEALTHCHECK exec-form): probe
//! the full chain end-to-end — the gatekeeper on `exposed` (loopback), which
//! itself probes vaultwarden's loopback `/alive` — and report the verdict a
//! platform health probe would get.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::probe::{PROBE_TIMEOUT, get_alive};

use crate::proc::POLL;
use crate::util::log;

/// Hard overall deadline for the one-shot `--healthcheck` probe: a boot-time
/// gate that is not yet bound is retried until this expires. A probe can
/// start just before the deadline and still run [`PROBE_TIMEOUT`], so the
/// worst case is budget + probe; 6 + 2 = 8s stays well under the image's
/// HEALTHCHECK timeout (10s) — the probe can never be the reason a health
/// check times out.
const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(6);

/// One-shot `--healthcheck` mode: probe the full chain end-to-end and
/// report the verdict a platform health probe would get. While the gate is
/// not yet bound (early boot) or reports the vault still starting, retry
/// until [`HEALTHCHECK_TIMEOUT`]; a timeout is `false`, never a hang, and
/// the runtime stays well under the image's 10s HEALTHCHECK timeout. Must
/// be called before any boot side effect: spawns no children, touches no
/// Tailscale state. An unparseable port is a failed check, never a panic.
pub fn healthcheck(exposed: &str) -> bool {
    let port = match exposed.parse::<u16>() {
        // 0 is never a real listener (boot-time `valid_port` rejects it too).
        Ok(p @ 1..) => p,
        _ => {
            log::err(&format!(
                "healthcheck: invalid exposed port '{}'",
                log::sanitize(exposed)
            ));
            return false;
        }
    };
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    healthcheck_until(addr, HEALTHCHECK_TIMEOUT)
}

/// The healthcheck retry loop with an explicit budget (tests shrink it to
/// keep the suite fast). Termination is by construction: each iteration
/// checks the deadline, and the probe itself is bounded by
/// [`PROBE_TIMEOUT`].
fn healthcheck_until(addr: SocketAddr, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    loop {
        if get_alive(addr, PROBE_TIMEOUT) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(POLL);
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    use super::super::probe::fake_vault;
    use super::super::{bind, handle};
    use super::{healthcheck, healthcheck_until};

    /// A stand-in gatekeeper: serves the real `handle` on an ephemeral
    /// listener for every connection (the healthcheck retries, so one-shot
    /// serving would not do), probing `vault` exactly like the real gate.
    /// Returns the exposed port.
    fn fake_gate(vault: Option<SocketAddr>) -> u16 {
        let listener = bind("0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                drop(std::thread::spawn(move || handle(stream, vault)));
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
        let free = bind("0").unwrap();
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
    fn healthcheck_rejects_an_invalid_exposed_port() {
        for port in ["", "not-a-port", "0", "65536", "-1"] {
            assert!(!healthcheck(port), "{port}");
        }
    }
}
