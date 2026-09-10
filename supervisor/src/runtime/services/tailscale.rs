//! tailscaled / tailscale CLI control.

use std::process::Command;
use std::time::Duration;

use crate::config::{TAILSCALE, TAILSCALED};
use crate::runtime::{Pid, apply_env, run_bounded, run_bounded_capture, spawn};
use crate::util::{StagedFile, log};

/// tailscaled, with no TUN device when `userspace` (PaaS sandboxes deny
/// /dev/net/tun). `--statedir` (derived from the state file's dir, on the
/// persistent volume) is required for `tailscale serve` HTTPS cert caching.
/// Environment is allow-listed ([`apply_env`]) — no supervisor secrets.
pub fn spawn_tailscaled(state: &str, socket: &str, userspace: bool) -> Option<Pid> {
    let mut cmd = Command::new(TAILSCALED);
    cmd.arg("--state").arg(state).arg("--socket").arg(socket);
    if let Some(dir) = std::path::Path::new(state)
        .parent()
        .and_then(|d| d.to_str())
    {
        cmd.arg("--statedir").arg(dir);
    }
    if userspace {
        cmd.arg("--tun=userspace-networking");
    }
    apply_env(&mut cmd, &[]);
    spawn(&mut cmd)
}

/// `tailscale up` with hard timeout; a failure makes the caller refuse to
/// boot the vault (Tailscale is the sole inbound path).
/// The authkey is staged to a 0600 file and passed as `--auth-key=file:`
/// (never argv — /proc cmdline is world-readable) and removed afterwards.
/// `socket` is the CLI's `--socket`: tailscaled runs on a non-default
/// LocalAPI path.
pub fn tailscale_up(
    authkey: &str,
    hostname: &str,
    socket: &str,
    timeout: Duration,
    abort: impl Fn() -> bool,
) -> bool {
    let mut key_file = match StagedFile::create("ts-authkey") {
        Ok(f) => f,
        Err(_) => {
            log::err("tailscale up: cannot stage authkey file; skipping authentication");
            return false;
        }
    };
    if key_file.write_all(authkey.as_bytes()).is_err() {
        log::err("tailscale up: cannot write authkey file; skipping authentication");
        return false;
    }
    let ok = run_bounded(
        timeout,
        TAILSCALE,
        &[
            "--socket",
            socket,
            "up",
            &format!("--auth-key=file:{}", key_file.path()),
            "--hostname",
            hostname,
            "--accept-dns=false",
        ],
        abort,
    );
    drop(key_file); // unlink the authkey (0600 staging contract)
    ok
}

/// `tailscale serve`: inbound tailnet path for the loopback vault
/// (userspace mode has none without it). With `service` set
/// (`TAILSCALE_SERVICE`), the node advertises itself as a host of `svc:<name>` — the Service-host
/// form. An advertisement registered before the service existed in the
/// admin console can wedge the host registration console-side ("no Service
/// hosts" forever), so any stale `svc:<name>` config is cleared first; a
/// fresh advertise then re-registers cleanly. The CLI implies `--bg`,
/// requires a tagged node and admin-console Service definition (plus
/// approval, or an `autoApprovers.services` policy).
///
/// A zero exit alone proves nothing (the CLI can exit 0 with the serve
/// config not yet active), so the live `serve status` output is checked
/// for the configured target before success is reported — the boot gate
/// that treats serve failure as fatal is only as good as this check.
pub fn tailscale_serve(
    port: &str,
    service: Option<&str>,
    socket: &str,
    timeout: Duration,
    abort: &impl Fn() -> bool,
) -> bool {
    if let Some(svc) = service {
        let _ = run_bounded(
            timeout,
            TAILSCALE,
            &["--socket", socket, "serve", "clear", svc],
            abort,
        );
    }
    let target = format!("http://127.0.0.1:{port}");
    let svc_arg = service.map(|svc| format!("--service={svc}"));
    let mut args: Vec<&str> = vec!["--socket", socket, "serve"];
    match &svc_arg {
        Some(flag) => args.push(flag),
        None => args.push("--bg"),
    }
    args.push("--https=443");
    args.push(&target);
    if !run_bounded(timeout, TAILSCALE, &args, abort) {
        return false;
    }
    // Readiness: `serve status` must show the configured target. One
    // bounded retry covers the config-propagation gap between `serve`
    // returning and the status reflecting it.
    for _ in 0..3 {
        if abort() {
            return false;
        }
        let status = run_bounded_capture(
            timeout,
            TAILSCALE,
            &["--socket", socket, "serve", "status", "--json"],
            &[],
            abort,
        );
        if status.is_some_and(|s| serve_status_has(&s, &target)) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    log::err("tailscale serve: config not visible in serve status");
    false
}

/// True iff the `serve status --json` payload advertises `target` over
/// HTTPS (pure, unit-tested — never parsed from argv or logs).
fn serve_status_has(status: &str, target: &str) -> bool {
    status.contains(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The readiness check matches the configured target anywhere in the
    /// status payload, and rejects a payload without it.
    #[test]
    fn serve_status_check_matches_target() {
        let target = "http://127.0.0.1:8081";
        let payload = r#"{"Web":{"https://node.tailnet.ts.net:443":{"Handlers":[{"Proxy":"http://127.0.0.1:8081"}]}}}"#;
        assert!(serve_status_has(payload, target));
        assert!(!serve_status_has(r#"{"Web":{}}"#, target));
        assert!(!serve_status_has("", target));
        // wrong port: not our serve
        assert!(!serve_status_has(
            r#"{"Web":{"https://n.ts.net:443":{"Handlers":[{"Proxy":"http://127.0.0.1:9999"}]}}}"#,
            target
        ));
    }
}
