//! Bounded child runs: run a CLI child to completion with a hard timeout,
//! killing its whole process group on expiry so nothing it spawned
//! outlives the budget. Each child registers with the stolen-exit
//! registry ([`super::stolen`]): a bounded run may own its child from a
//! non-main thread (the backup thread), where the main thread's
//! namespace-wide reaper can reap the zombie first — the registry
//! preserves the verdict that std's `ECHILD` would otherwise destroy.

use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, killpg};
use nix::sys::wait::WaitStatus;
use nix::unistd::Pid as NixPid;

use super::child::POLL;
use super::stolen;
use crate::util::log;

/// Cap on stdout captured by [`run_bounded_capture`]: a listing far beyond
/// any real bucket is treated as a failed run. Only listings flow through
/// this path (object names), so megabytes are already extraordinary.
const CAPTURE_MAX: u64 = 16 * 1024 * 1024;

/// Temp file for captured stdout: unique per call (pid + seq), 0600,
/// container-private /tmp, unlinked when the guard drops — every exit
/// path, including panics, cleans it up.
struct TempOut {
    file: std::fs::File,
    path: String,
}

impl TempOut {
    fn new() -> std::io::Result<Self> {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = format!(
            "/tmp/vw-cap-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        Ok(Self { file, path })
    }
}

impl Drop for TempOut {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

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
/// failure, stop request, timeout, non-zero exit, or oversized output.
/// Stdout lands in a temp file, not a pipe: the poll loop stays in charge
/// (no reader thread waiting on an EOF a group-escaped descendant could
/// hold open) and output is capped — a bucket list too big for
/// [`CAPTURE_MAX`] fails the run instead of exhausting supervisor memory.
pub fn run_bounded_capture(
    timeout: Duration,
    prog: &str,
    args: &[&str],
    extra_env: &[(String, String)],
    abort: impl Fn() -> bool,
) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    use std::process::Stdio;

    let mut cap = TempOut::new().ok()?;
    let mut cmd = Command::new(prog);
    cmd.args(args)
        .process_group(0)
        .stdout(Stdio::from(cap.file.try_clone().ok()?));
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
        // Output cap: checked while the child still runs, so an oversized
        // listing is killed at the cap, never read in full afterwards.
        if cap.file.metadata().is_ok_and(|m| m.len() > CAPTURE_MAX) {
            log::err(&format!(
                "{prog} output exceeded {CAPTURE_MAX} bytes; killing"
            ));
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
    if !success {
        return None;
    }
    let mut out = String::new();
    cap.file.seek(SeekFrom::Start(0)).ok()?;
    cap.file.read_to_string(&mut out).ok()?;
    Some(out)
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

    /// Captured stdout comes back verbatim on success; stderr stays out.
    #[test]
    fn capture_returns_stdout_verbatim() {
        let out = run_bounded_capture(
            Duration::from_secs(10),
            "/bin/sh",
            &["-c", "echo captured-line; echo stray >&2"],
            &[],
            || false,
        );
        assert_eq!(out.as_deref(), Some("captured-line\n"));
    }

    /// The temp file is 0600 and unlinked on drop (RAII covers every exit
    /// path; counting files would race with parallel capture tests).
    #[test]
    fn capture_temp_file_is_0600_and_removed_on_drop() {
        use std::os::unix::fs::PermissionsExt;
        let out = TempOut::new().expect("temp file created");
        let meta = std::fs::metadata(&out.path).expect("exists");
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let path = out.path.clone();
        drop(out);
        assert!(
            !std::path::Path::new(&path).exists(),
            "temp file must be removed on drop"
        );
    }

    /// A timeout must not depend on EOF: a descendant that inherited the
    /// (file-backed) stdout and stays alive cannot hold the run open.
    /// The child execs a sleeper with a backgrounded sibling sharing its
    /// stdout; the run must fail at the timeout and return, not block
    /// waiting for the sibling. With the old pipe+join design this hung
    /// until the sibling exited.
    #[test]
    fn capture_timeout_survives_a_stdout_holding_descendant() {
        let start = Instant::now();
        let out = run_bounded_capture(
            Duration::from_secs(2),
            "/bin/sh",
            &["-c", "sleep 30 & exec sleep 30"],
            &[],
            || false,
        );
        assert!(out.is_none(), "timeout must fail the run");
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "the run must not wait out a descendant holding stdout"
        );
    }

    /// Oversized output fails the run instead of exhausting memory: the
    /// writer is killed once past the cap (checked during the run), and
    /// nothing comes back.
    #[test]
    fn capture_fails_closed_on_oversized_output() {
        let out = run_bounded_capture(
            Duration::from_secs(30),
            "/bin/sh",
            &["-c", "while true; do echo 0123456789abcdef; done"],
            &[],
            || false,
        );
        assert!(out.is_none(), "oversized output must fail the run");
    }
}
