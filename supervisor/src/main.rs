//! PID 1 supervisor: tailscaled (userspace) + tailscale up/serve +
//! loopback-only vaultwarden. Tailscale is the sole inbound path, so it
//! is required: a missing TAILSCALE_AUTHKEY or any boot-time Tailscale
//! failure refuses to start (exit 1), and a mid-run tailscaled death
//! tears the vault down. Optional dotenv layer (SUPERVISOR_ENV_FILE), S3
//! state sync (SUPERVISOR_S3_*), and DB backup/restore (SUPERVISOR_DB_
//! BACKUP*). The authkey is staged to a 0600 file (never argv) and
//! removed after `up`.
//!
//! Boot runs through the explicit phase machine ([`boot`]); the shutdown
//! model is documented where it lives ([`runtime::process::watch`]):
//! children run in their own process groups; a stop request
//! (SIGTERM/SIGINT/SIGHUP/SIGQUIT) is observed by the main thread, which
//! drives TERM -> KILL escalation.

mod boot;
mod config;
mod runtime;
mod s3;
mod util;

use config::{Config, SUPERVISOR_UID, VAULT_GID, VAULT_UID};
use nix::sys::stat::{Mode, umask};
use runtime::gate_healthcheck;
use util::log;

/// One-shot `--security-probe` mode: prove that a supervisor-spawned child
/// cannot change identity. This is the regression test for the capability
/// drop; the image smoke runs it with the same caps the deployment grants.
fn security_probe() -> ! {
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    let run = |handle: Option<runtime::Handle>| -> bool {
        let Some(handle) = handle else {
            return false;
        };
        match runtime::reap_until_gone(&handle, TIMEOUT) {
            runtime::Gone::Reaped(status) => runtime::exit_code(status) == 0,
            runtime::Gone::Stuck => false,
        }
    };

    // 1. The vault child (different uid) must not be able to setuid back.
    let mut vault = std::process::Command::new("/proc/self/exe");
    vault
        .args(["--security-probe-child"])
        .arg(VAULT_UID.to_string())
        .arg(SUPERVISOR_UID.to_string());
    let vault_ok = run(runtime::spawn_as(
        &mut vault,
        runtime::Credentials {
            uid: VAULT_UID,
            gid: VAULT_GID,
            umask: 0o007,
        },
    ));

    // 2. A same-uid child (tailscaled/tailscale CLI) must not be able to
    //    change uid either; it inherits the supervisor's capabilities if
    //    they are not dropped.
    let mut helper = std::process::Command::new("/proc/self/exe");
    helper
        .args(["--security-probe-child"])
        .arg(SUPERVISOR_UID.to_string())
        .arg(VAULT_UID.to_string());
    let helper_ok = run(runtime::spawn(&mut helper));

    if vault_ok && helper_ok {
        log::info("isolation probe: ok");
        std::process::exit(0);
    }
    log::err("isolation probe: FAILED: a child retained the ability to change uid");
    std::process::exit(1);
}

/// One-shot child side of [`security_probe`]: report whether a setuid to
/// the parent's identity is still possible.
fn security_probe_child(current: u32, target: u32) -> ! {
    if nix::unistd::geteuid().as_raw() != current {
        log::err("isolation probe: child has an unexpected uid");
        std::process::exit(2);
    }
    let target = nix::unistd::Uid::from_raw(target);
    match nix::unistd::setresuid(target, target, target) {
        Ok(()) => {
            log::err("isolation probe: child changed uid");
            std::process::exit(1);
        }
        Err(_) => std::process::exit(0),
    }
}

/// One-shot `--healthcheck` mode: exit 0 iff the gate chain answers 2xx.
/// Runs before any boot side effect; config resolution is a pure read, so
/// the probe targets exactly the port the running supervisor binds. A
/// failed check logs one line, so a health-driven restart loop is
/// diagnosable from the container logs.
fn healthcheck() -> ! {
    let healthy = match Config::from_env() {
        Some(cfg) => {
            if gate_healthcheck(&cfg.port) {
                true
            } else {
                log::err(
                    "healthcheck: the gate did not answer healthy (gate not bound, or \
                     vaultwarden down)",
                );
                false
            }
        }
        None => {
            log::err("healthcheck: configuration could not be resolved");
            false
        }
    };
    std::process::exit(if healthy { 0 } else { 1 });
}

fn main() {
    // Everything the supervisor creates under /data is shared with the
    // vault through the data group (the vault runs a different UID). 0o007
    // makes new files 0660 and directories 0770; explicit modes still
    // override this (state sidecars are 0600, staging is 0700).
    umask(Mode::from_bits_truncate(0o007));

    let mut args = std::env::args_os();
    let _program = args.next();
    let mode = args.next();
    let mode = mode.as_deref();
    if mode == Some(std::ffi::OsStr::new("--security-probe")) {
        security_probe();
    }
    if mode == Some(std::ffi::OsStr::new("--security-probe-child")) {
        let parse = |value: Option<std::ffi::OsString>| {
            value.and_then(|value| value.to_str().and_then(|value| value.parse::<u32>().ok()))
        };
        let current = parse(args.next());
        let target = parse(args.next());
        let (Some(current), Some(target)) = (current, target) else {
            log::err("isolation probe: child wants <current-uid> <target-uid>");
            std::process::exit(2);
        };
        security_probe_child(current, target);
    }
    if mode == Some(std::ffi::OsStr::new("--healthcheck")) {
        healthcheck();
    }

    boot::run()
}
