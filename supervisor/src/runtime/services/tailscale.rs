//! tailscaled and the `tailscale` CLI: the daemon runs under its own UID
//! in its own process group with an allow-listed env, dropped capabilities,
//! and `no_new_privs`; every CLI call is bounded. `tailscale up` joins the
//! tailnet (or rejoins from restored state); `tailscale serve` exposes the
//! loopback vault and is verified against `serve status` before boot proceeds.

use std::process::Command;
use std::time::{Duration, Instant};

use crate::config::{
    TAILSCALE, TAILSCALE_DIR, TAILSCALE_GID, TAILSCALED, TAILSCALED_GROUPS, TAILSCALED_UID,
};
use crate::runtime::{
    Credentials, Handle, TUN_CAPS, apply_env, run_bounded, run_bounded_capture, spawn_as,
    spawn_as_with_caps,
};
use crate::util::{StagedFile, log};

/// tailscaled's dedicated identity: it owns the state tree and the LocalAPI
/// socket, and is a member of the `tailscale` group (which the supervisor
/// joins for its own access).
const TAILSCALED_CREDS: Credentials = Credentials {
    uid: TAILSCALED_UID,
    gid: TAILSCALE_GID,
    groups: &TAILSCALED_GROUPS,
    umask: 0o007,
};

/// Spawn tailscaled under its dedicated UID in its own process group, with
/// an allow-listed env and (TUN mode only) NET_ADMIN/NET_RAW; userspace mode
/// needs none. `--statedir` keeps the serve cert cache; `None` on failure.
pub fn spawn_tailscaled(state: &str, socket: &str, userspace: bool) -> Option<Handle> {
    let mut cmd = Command::new(TAILSCALED);
    cmd.arg("--state").arg(state).arg("--socket").arg(socket);
    // Cert cache, Taildrop staging, and log policy live on the real
    // group-writable tree. The state file itself goes through the
    // differently named link: Tailscale chmods a parent basename of
    // `tailscale` to 0700, which the daemon uid cannot do on the
    // supervisor-owned tree (and would silently fall back to `mem:`).
    cmd.arg("--statedir").arg(TAILSCALE_DIR);
    if userspace {
        cmd.arg("--tun=userspace-networking");
    }
    apply_env(&mut cmd, &[]);
    if userspace {
        spawn_as(&mut cmd, TAILSCALED_CREDS)
    } else {
        spawn_as_with_caps(&mut cmd, TAILSCALED_CREDS, TUN_CAPS)
    }
}

/// Run `tailscale up` under a hard timeout; failure means the caller must
/// refuse to boot the vault. An authkey is staged to a 0600 file and passed
/// as `--auth-key=file:` so the key never reaches argv; restored state needs none.
pub fn tailscale_up(
    authkey: Option<&str>,
    hostname: &str,
    socket: &str,
    timeout: Duration,
    abort: impl Fn() -> bool,
) -> bool {
    let key_file = match authkey {
        Some(key) => {
            let mut file =
                match StagedFile::create_in(crate::config::SUPERVISOR_STATE, "ts-authkey") {
                    Ok(f) => f,
                    Err(_) => {
                        log::err(
                            "tailscale up: cannot stage authkey file; skipping authentication",
                        );
                        return false;
                    }
                };
            if file.write_all(key.as_bytes()).is_err() {
                log::err("tailscale up: cannot write authkey file; skipping authentication");
                return false;
            }
            Some(file)
        }
        None => None,
    };
    let mut args: Vec<&str> = vec!["--socket", socket, "up"];
    let auth_flag;
    if let Some(file) = &key_file {
        auth_flag = format!("--auth-key=file:{}", file.path());
        args.push(&auth_flag);
    }
    args.extend(["--hostname", hostname, "--accept-dns=false"]);
    let ok = run_bounded(timeout, TAILSCALE, &args, abort);
    drop(key_file); // unlink the authkey (0600 staging contract)
    ok
}

/// Run `tailscale serve` for the loopback vault (userspace mode's only
/// inbound path) and verify the target appears in `serve status --json`;
/// one `timeout` bounds the sequence. With `service`, stale `svc:` is cleared.
pub fn tailscale_serve(
    port: u16,
    service: Option<&str>,
    socket: &str,
    timeout: Duration,
    abort: &impl Fn() -> bool,
) -> bool {
    let deadline = Instant::now() + timeout;
    let remaining = || deadline.saturating_duration_since(Instant::now());
    if let Some(svc) = service
        && !remaining().is_zero()
    {
        let _ = run_bounded(
            remaining(),
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
    if remaining().is_zero() || !run_bounded(remaining(), TAILSCALE, &args, abort) {
        return false;
    }
    // Readiness: `serve status` must show the configured target. One
    // bounded retry covers the config-propagation gap between `serve`
    // returning and the status reflecting it.
    for _ in 0..3 {
        if abort() || remaining().is_zero() {
            return false;
        }
        let status = run_bounded_capture(
            remaining(),
            TAILSCALE,
            &["--socket", socket, "serve", "status", "--json"],
            &[],
            abort,
        );
        if status.is_some_and(|s| serve_status_has(&s, &target)) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500).min(remaining()));
    }
    log::err("tailscale serve: config not visible in serve status");
    false
}

/// True iff the `serve status --json` payload contains `target` (a substring
/// check; the payload is never parsed from argv or logs).
fn serve_status_has(status: &str, target: &str) -> bool {
    status.contains(target)
}

#[cfg(test)]
mod tests {
    //! Serve-status readiness parsing tests.
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
