//! tailscaled / tailscale CLI control.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::process::Command;
use std::time::Duration;

use crate::config::{TAILSCALE, TAILSCALED};
use crate::proc::{Pid, run_bounded, spawn};
use crate::util::log;

/// tailscaled, with no TUN device when `userspace` (PaaS sandboxes deny
/// /dev/net/tun). `--statedir` (derived from the state file's dir, on the
/// persistent volume) is required for `tailscale serve` HTTPS cert caching.
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
    spawn(&mut cmd)
}

/// `tailscale up` with hard timeout; failures are non-fatal for the vault.
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
    let Some(key_file) = stage_authkey(authkey) else {
        log::err("tailscale up: cannot stage authkey file; skipping authentication");
        return false;
    };
    let ok = run_bounded(
        timeout,
        TAILSCALE,
        &[
            "--socket",
            socket,
            "up",
            &format!("--auth-key=file:{key_file}"),
            "--hostname",
            hostname,
            "--accept-dns=false",
        ],
        abort,
    );
    let _ = std::fs::remove_file(&key_file);
    ok
}

/// Stage the authkey under a unique 0600 file in /tmp; the sequence number
/// keeps paths collision-proof for tests and retries.
fn stage_authkey(authkey: &str) -> Option<String> {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let path = format!(
        "/tmp/ts-authkey-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    write_authkey_file(&path, authkey).ok().map(|_| path)
}

/// Create `path` (0600, must not pre-exist) holding `authkey`; a partial
/// write removes the file (we only ever clean up files we created).
fn write_authkey_file(path: &str, authkey: &str) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    if let Err(e) = file
        .write_all(authkey.as_bytes())
        .and_then(|_| file.sync_all())
    {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(())
}

/// `tailscale serve`: inbound tailnet path for the loopback vault
/// (userspace mode has none without it).
pub fn tailscale_serve(
    port: &str,
    socket: &str,
    timeout: Duration,
    abort: impl Fn() -> bool,
) -> bool {
    run_bounded(
        timeout,
        TAILSCALE,
        &[
            "--socket",
            socket,
            "serve",
            "--bg",
            "--https=443",
            &format!("http://127.0.0.1:{port}"),
        ],
        abort,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The staged authkey: 0600 perms, verbatim content, and it is the file
    /// `--auth-key=file:` will read back. (Removal after `up` is covered by
    /// the caller's cleanup line; here we just don't leave it behind.)
    #[test]
    fn authkey_is_staged_0600_with_verbatim_content() {
        use std::os::unix::fs::PermissionsExt;
        let path = stage_authkey("tskey-auth-test").expect("staged");
        let meta = std::fs::metadata(&path).expect("exists");
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "tskey-auth-test");
        assert!(std::fs::remove_file(&path).is_ok());
    }

    /// A path that cannot be created must fail cleanly: no file, no partial
    /// write (the cleanup-after-open path removes the created file).
    #[test]
    fn authkey_write_failure_creates_nothing() {
        let bad = std::env::temp_dir()
            .join(format!("vw-sup-missing-{}", std::process::id()))
            .join("nested")
            .join("authkey");
        assert!(write_authkey_file(bad.to_str().unwrap(), "secret").is_err());
        assert!(!bad.exists());
    }
}
