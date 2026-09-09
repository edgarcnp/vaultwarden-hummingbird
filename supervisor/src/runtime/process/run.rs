//! Bounded child runs: run a CLI child to completion with a hard timeout,
//! killing its whole process group on expiry so nothing it spawned
//! outlives the budget. Each child registers with the stolen-exit
//! registry ([`super::stolen`]): a bounded run may own its child from a
//! non-main thread (the backup thread), where the main thread's
//! namespace-wide reaper can reap the zombie first — the registry
//! preserves the verdict that std's `ECHILD` would otherwise destroy.

use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, killpg};
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid as NixPid;

use super::child::POLL;
use super::stolen;
use crate::util::log;

/// Verdict from a reaper-stolen run: a recorded status, or `None`
/// (stolen with the status lost — the safe direction is failure).
/// Exit code 0 = success, decoded like the reaper does ([`exit_code`]).
fn stolen_verdict(pid: i32) -> Option<bool> {
    stolen::take(pid)
        .flatten()
        .map(|st: WaitStatus| super::reap::exit_code(st) == 0)
}

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
    let pid = child.id() as i32;
    stolen::register(pid);
    let start = Instant::now();
    let success = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st.success(),
            Ok(None) => {}
            // ECHILD (or another wait error): the main reaper may have
            // stolen the zombie; consult the registry before failing.
            Err(_) => {
                if let Some(v) = stolen_verdict(pid) {
                    break v;
                }
            }
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
        // Whole-group kill first, then the direct child, then reap.
        let _ = killpg(NixPid::from_raw(pid), Signal::SIGKILL);
        let _ = child.kill();
    }
    let _ = child.wait();
    let _ = stolen::take(pid); // drop the entry if it was never consulted
    success
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
    let pid = child.id() as i32;
    stolen::register(pid);
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
            // ECHILD (or another wait error): the main reaper may have
            // stolen the zombie; consult the registry before failing.
            Err(_) => {
                if let Some(v) = stolen_verdict(pid) {
                    break v;
                }
            }
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
        let _ = killpg(NixPid::from_raw(pid), Signal::SIGKILL);
        let _ = child.kill();
    }
    let _ = child.wait();
    let _ = stolen::take(pid); // drop the entry if it was never consulted
    let out = reader.join().unwrap_or_default();
    success.then(|| String::from_utf8_lossy(&out).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A zombie reaped out from under a bounded run (the main reaper's
    /// `waitpid(-1)`) must not flip the verdict: the stolen-exit registry
    /// hands the true status back. This is the regression for the
    /// backup-thread race: std reports `ECHILD`, the registry reports
    /// success. The child sleeps past registration, so whoever reaps the
    /// zombie — this test or another test's namespace-wide reaper — finds
    /// it registered and records the status.
    #[test]
    fn stolen_zombie_does_not_flip_the_verdict() {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "sleep 0.5; exit 0"]).process_group(0);
        let mut child = cmd.spawn().expect("spawn");
        let pid = child.id() as i32;
        stolen::register(pid);
        // wait out the child's exit (registration is long done)
        std::thread::sleep(Duration::from_millis(1000));
        // try to reap it ourselves; ECHILD = another reaper got there
        // first and recorded the status (registration predates the exit)
        if let Ok(status) = nix::sys::wait::waitpid(Some(NixPid::from_raw(pid)), None) {
            stolen::record(pid, status);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        let verdict = loop {
            if let Some(v) = stolen_verdict(pid) {
                break v;
            }
            assert!(Instant::now() < deadline, "stolen status never recorded");
            std::thread::sleep(POLL);
        };
        assert!(verdict, "a reaped-successful run must report success");
        let _ = child.kill();
        let _ = child.wait();
    }

    /// A registry entry without a recorded status must fail closed, never
    /// invent success. Uses a never-spawned pid: no process, no reaper.
    #[test]
    fn stolen_without_a_recorded_status_fails_closed() {
        let pid = std::process::id()
            .checked_add(100_000)
            .expect("no overflow") as i32;
        stolen::register(pid);
        assert_eq!(stolen::take(pid), Some(None));
        assert_eq!(stolen_verdict(pid), None, "no invented success");
        // a double take is empty: the entry was consumed
        assert_eq!(stolen::take(pid), None);
    }
}
