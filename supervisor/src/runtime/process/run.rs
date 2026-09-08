//! Bounded child runs: run a CLI child to completion with a hard timeout,
//! killing its whole process group on expiry so nothing it spawned
//! outlives the budget.

use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid as NixPid;

use super::child::POLL;
use crate::util::log;

/// Run a child to completion with a hard timeout; kill on expiry. Aborts
/// early when `abort` fires, so a stop request never waits out a bounded
/// phase. stdio is inherited so failures stay visible in container logs.
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
        std::thread::sleep(POLL);
    }
    // Whole-group kill first, then the direct child, then reap.
    let pid = child.id() as i32;
    let _ = killpg(NixPid::from_raw(pid), Signal::SIGKILL);
    let _ = child.kill();
    let _ = child.wait();
    false
}

/// [`run_bounded_env`] capturing the child's stdout; stderr stays
/// inherited so failures remain visible in container logs. `None` = spawn
/// failure, stop request, timeout, or non-zero exit. Output is drained on
/// a helper thread so a chatty child cannot fill the pipe and deadlock
/// the bounded loop.
pub fn run_bounded_capture(
    timeout: Duration,
    prog: &str,
    args: &[&str],
    extra_env: &[(String, String)],
    abort: impl Fn() -> bool,
) -> Option<String> {
    use std::io::Read;
    use std::process::Stdio;

    let mut cmd = Command::new(prog);
    cmd.args(args).process_group(0).stdout(Stdio::piped());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            log::err(&format!("{prog} spawn failed: {e}"));
            return None;
        }
    };
    let mut pipe = child.stdout.take();
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(p) = pipe.as_mut() {
            let _ = p.read_to_end(&mut buf);
        }
        buf
    });
    let start = Instant::now();
    let success = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st.success(),
            Ok(None) => {}
            Err(_) => break false,
        }
        if abort() {
            log::info(&format!("stop requested; aborting {prog}"));
            break false;
        }
        if start.elapsed() > timeout {
            log::err(&format!("{prog} timed out after {timeout:?}"));
            break false;
        }
        std::thread::sleep(POLL);
    };
    if !success {
        let pid = child.id() as i32;
        let _ = killpg(NixPid::from_raw(pid), Signal::SIGKILL);
        let _ = child.kill();
    }
    let _ = child.wait();
    let out = reader.join().unwrap_or_default();
    success.then(|| String::from_utf8_lossy(&out).into_owned())
}
