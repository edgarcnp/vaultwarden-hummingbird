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

use config::{
    Config, SUPERVISOR_UID, TAILSCALE_GID, TAILSCALED_GROUPS, TAILSCALED_UID, VAULT_GID, VAULT_UID,
};
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
            groups: &[],
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

    // 3. tailscaled's uid must be unable to read supervisor secrets or the
    //    vault's data, while still writing its own state tree.
    let state_secret = "/state/.probe-secret";
    let data_secret = "/data/.probe-data";
    let write_path = "/state/tailscale/.probe-write";
    // Atomic replace, never a write through a pre-planted symlink: /data is
    // vault-writable, so a link at the probe path must not redirect the
    // supervisor onto a supervisor-only file.
    let planted = crate::util::fs::write_atomic(state_secret, b"secret", 0o600)
        .and_then(|()| crate::util::fs::write_atomic(data_secret, b"data", 0o600))
        .is_ok();
    let tailscaled_ok = planted && {
        let mut probe = std::process::Command::new("/proc/self/exe");
        probe.args([
            "--tailscaled-probe-child",
            state_secret,
            data_secret,
            write_path,
        ]);
        run(runtime::spawn_as(
            &mut probe,
            runtime::Credentials {
                uid: TAILSCALED_UID,
                gid: TAILSCALE_GID,
                groups: &TAILSCALED_GROUPS,
                umask: 0o007,
            },
        ))
    };
    let _ = std::fs::remove_file(state_secret);
    let _ = std::fs::remove_file(data_secret);
    let _ = std::fs::remove_file(write_path);

    if vault_ok && helper_ok && tailscaled_ok {
        log::info("isolation probe: ok");
        std::process::exit(0);
    }
    log::err(
        "isolation probe: FAILED: a child retained privileges or crossed a \
         supervisor/vault boundary",
    );
    std::process::exit(1);
}

/// Child side of the tailscaled boundary probe: run as the tailscaled uid
/// and prove it cannot read a supervisor secret or `/data`, but can write
/// its own state tree.
fn tailscaled_probe_child(state_secret: &str, data_secret: &str, write_path: &str) -> ! {
    if nix::unistd::geteuid().as_raw() != TAILSCALED_UID {
        log::err("tailscaled probe: child has an unexpected uid");
        std::process::exit(2);
    }
    if std::fs::read(state_secret).is_ok() {
        log::err("tailscaled probe: read a supervisor secret");
        std::process::exit(1);
    }
    if std::fs::read(data_secret).is_ok() {
        log::err("tailscaled probe: read the vault data volume");
        std::process::exit(1);
    }
    if crate::util::fs::write_atomic(write_path, b"probe", 0o600).is_err()
        || std::fs::remove_file(write_path).is_err()
    {
        log::err("tailscaled probe: cannot write its own state tree");
        std::process::exit(1);
    }
    #[cfg(target_os = "linux")]
    if !nix::sys::prctl::get_no_new_privs().unwrap_or(false) {
        log::err("tailscaled probe: no_new_privs is unset");
        std::process::exit(1);
    }
    match runtime::caps_are_empty() {
        Ok(true) => std::process::exit(0),
        Ok(false) => {
            log::err("tailscaled probe: retained capabilities");
            std::process::exit(1);
        }
        Err(e) => {
            log::err(&format!("tailscaled probe: cannot read capabilities: {e}"));
            std::process::exit(1);
        }
    }
}

/// One-shot child side of [`security_probe`]: report whether a setuid to
/// the parent's identity is still possible.
fn security_probe_child(current: u32, target: u32) -> ! {
    if nix::unistd::geteuid().as_raw() != current {
        log::err("isolation probe: child has an unexpected uid");
        std::process::exit(2);
    }
    // setresuid failing is necessary but not sufficient: a retained
    // capability (same-uid spawn) or a missing no_new_privs (a setuid/file-
    // cap exec could re-grant the bounding set) must also fail the probe.
    #[cfg(target_os = "linux")]
    if !nix::sys::prctl::get_no_new_privs().unwrap_or(false) {
        log::err("isolation probe: child has no_new_privs unset");
        std::process::exit(1);
    }
    match runtime::caps_are_empty() {
        Ok(true) => {}
        Ok(false) => {
            log::err("isolation probe: child retained capabilities");
            std::process::exit(1);
        }
        Err(e) => {
            log::err(&format!("isolation probe: cannot read capabilities: {e}"));
            std::process::exit(1);
        }
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
            if gate_healthcheck(cfg.port) {
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
    if mode == Some(std::ffi::OsStr::new("--tailscaled-probe-child")) {
        let next = |value: Option<std::ffi::OsString>| {
            value.and_then(|value| value.to_str().map(str::to_string))
        };
        let state = next(args.next());
        let data = next(args.next());
        let write = next(args.next());
        let (Some(state), Some(data), Some(write)) = (state, data, write) else {
            log::err("tailscaled probe: child wants <state-secret> <data-secret> <write-path>");
            std::process::exit(2);
        };
        tailscaled_probe_child(&state, &data, &write);
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
