//! tailscaled / tailscale CLI control.

use std::process::Command;
use std::time::{Duration, Instant};

use crate::config::{TAILSCALE, TAILSCALED};
use crate::proc::process::{self, Pid};
use crate::util::log;

/// tailscaled with no TUN device (PaaS sandboxes deny /dev/net/tun).
/// Spawned as its own process-group leader (see `process::spawn`).
pub fn spawn_tailscaled(state: &str, socket: &str, userspace: bool) -> Option<Pid> {
    let mut cmd = Command::new(TAILSCALED);
    cmd.arg("--state").arg(state).arg("--socket").arg(socket);
    if userspace {
        cmd.arg("--tun=userspace-networking");
    }
    process::spawn(&mut cmd)
}

/// tailscale up with hard timeout; auth failures are non-fatal for the vault.
pub fn tailscale_up(
    authkey: &str,
    hostname: &str,
    timeout: Duration,
    abort: impl Fn() -> bool,
) -> bool {
    run_bounded(
        timeout,
        TAILSCALE,
        &[
            "up",
            "--authkey",
            authkey,
            "--hostname",
            hostname,
            "--accept-dns=false",
        ],
        abort,
    )
}

/// userspace mode has no inbound tailnet path without serve.
pub fn tailscale_serve(port: &str, timeout: Duration, abort: impl Fn() -> bool) -> bool {
    run_bounded(
        timeout,
        TAILSCALE,
        &[
            "serve",
            "--bg",
            "--https=443",
            &format!("http://127.0.0.1:{port}"),
        ],
        abort,
    )
}

/// Run a child to completion with a hard timeout; kill on expiry. Aborts
/// early when `abort` fires, so a stop request never waits out a bounded
/// phase. stdio is inherited so failures stay visible in container logs.
///
/// This child is reaped HERE via std (`try_wait`/`wait`); the namespace-wide
/// reaper (`process::reap_any`) only runs in the watch/teardown phases,
/// which strictly follow this one — no status-stealing races.
pub fn run_bounded(timeout: Duration, prog: &str, args: &[&str], abort: impl Fn() -> bool) -> bool {
    let mut child = match Command::new(prog).args(args).spawn() {
        Ok(c) => c,
        Err(e) => {
            log::err(&format!("{prog} spawn failed: {e}"));
            return false;
        }
    };
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return st.success(),
            Ok(None) => {}
            Err(_) => return false,
        }
        if abort() {
            log::info(&format!("stop requested; aborting {prog}"));
            break;
        }
        if start.elapsed() > timeout {
            log::err(&format!("{prog} timed out after {timeout:?}"));
            break;
        }
        std::thread::sleep(process::POLL);
    }
    let _ = child.kill();
    let _ = child.wait(); // reap: no zombie
    false
}
