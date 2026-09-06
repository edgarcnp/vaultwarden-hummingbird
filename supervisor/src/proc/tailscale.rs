//! tailscaled / tailscale CLI control.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
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

/// `tailscale up` with hard timeout; auth failures are non-fatal for the
/// vault. The authkey is staged into a 0600 file under `/tmp` and passed as
/// `--auth-key=file:...` — never argv, whose cmdline is world-readable in
/// /proc.
pub fn tailscale_up(
    authkey: &str,
    hostname: &str,
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

/// Stage the authkey under a unique 0600 file in /tmp. `up` runs once, but
/// the sequence number keeps paths collision-proof for tests and retries.
fn stage_authkey(authkey: &str) -> Option<String> {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let path = format!(
        "/tmp/ts-authkey-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    write_authkey_file(&path, authkey).ok().map(|_| path)
}

/// Create `path` (0600, must not pre-exist) holding `authkey`. If creation
/// succeeded but the write did not, the partial secret is removed.
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
        // We created this file; a partial secret must not remain on disk.
        // (create_new means we never touch a file we didn't create.)
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(())
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
/// This child is reaped HERE via std (`try_wait`/`wait`); it never overlaps
/// with the namespace-wide reaper (`process::reap_any`): both run on the
/// single main thread, and while this helper polls, nothing else reaps —
/// no status-stealing races. (rclone syncs DO run inside the watch loop,
/// but only between `reap_any` polls, never concurrently.)
pub fn run_bounded(timeout: Duration, prog: &str, args: &[&str], abort: impl Fn() -> bool) -> bool {
    run_bounded_env(timeout, prog, args, &[], abort)
}

/// [`run_bounded`] with extra child env vars (e.g. rclone backend config).
/// The child runs as its own process-group leader, so the expiry/abort kill
/// reaches anything it spawned, not just the direct child.
pub fn run_bounded_env(
    timeout: Duration,
    prog: &str,
    args: &[&str],
    extra_env: &[(String, String)],
    abort: impl Fn() -> bool,
) -> bool {
    let mut cmd = Command::new(prog);
    cmd.args(args).process_group(0);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = match cmd.spawn() {
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
    // Whole-group kill first (the child may have exited; helpers may live on),
    // then the direct child, then reap.
    let pid = child.id() as i32;
    unsafe { libc::kill(-pid, libc::SIGKILL) };
    let _ = child.kill();
    let _ = child.wait(); // reap: no zombie
    false
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
