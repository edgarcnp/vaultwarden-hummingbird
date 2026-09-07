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
