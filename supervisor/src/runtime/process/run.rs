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

/// Env keys external children may inherit: secret-free plumbing only.
/// Everything else (auth keys, S3 credentials, database URLs, SMTP/admin
/// secrets) stays inside the supervisor — a helper binary that is
/// compromised or merely chatty must not become a secrets broadcast.
/// The set is deliberately tiny:
/// - `HTTP(S)_PROXY`/`ALL_PROXY`/`NO_PROXY`: egress-controlled deployments
///   route rclone and Tailscale traffic through a proxy;
/// - `SSL_CERT_FILE`/`SSL_CERT_DIR`: Go (rclone, tailscaled) and libpq
///   trust custom roots this way;
/// - `TZ`: cosmetic timestamps in child logs.
const BASELINE_ENV: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "TZ",
];

/// The allow-listed subset of `vars` that children may inherit (pure, so
/// the policy is unit-testable). Non-UTF-8 keys are dropped, like the
/// vaultwarden child env: a mangled key must not reach a child.
pub(crate) fn allowlisted(vars: impl Iterator<Item = (String, String)>) -> Vec<(String, String)> {
    vars.filter(|(k, _)| BASELINE_ENV.contains(&k.as_str()))
        .collect()
}

/// Clear the child's environment and set only the allow-listed subset of
/// `source` plus the explicit `extra_env` (connection config rides there —
/// e.g. pg_env, RCLONE_CONFIG_*). Never place secrets here.
fn apply_env_from(
    cmd: &mut Command,
    extra_env: &[(String, String)],
    source: impl Iterator<Item = (String, String)>,
) {
    cmd.env_clear();
    for (k, v) in allowlisted(source) {
        cmd.env(k, v);
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
}

/// [`apply_env_from`] over the supervisor's own environment. Shared by the
/// bounded runs and the long-running tailscaled spawn.
pub fn apply_env(cmd: &mut Command, extra_env: &[(String, String)]) {
    apply_env_from(
        cmd,
        extra_env,
        std::env::vars_os().filter_map(|(k, v)| {
            let k = k.to_str()?;
            Some((k.to_string(), v.to_string_lossy().into_owned()))
        }),
    );
}

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

/// Core of both bounded runs: spawn, register, poll (verdict / abort /
/// timeout / capture cap), then group-kill on failure and settle the
/// stolen-exit entry. `capture` redirects stdout to a temp file and
/// enforces the capture cap while the child runs; the file comes back so
/// the capture wrapper can do its own capped final read. Returns
/// `(success, captured stdout file)`; the file is `None` when not
/// capturing or when the run never got far enough to matter.
fn run_bounded_core(
    timeout: Duration,
    prog: &str,
    args: &[&str],
    extra_env: &[(String, String)],
    abort: impl Fn() -> bool,
    capture: bool,
) -> (bool, Option<TempOut>) {
    let cap = if capture {
        match TempOut::new() {
            Ok(c) => Some(c),
            Err(_) => return (false, None),
        }
    } else {
        None
    };
    let mut cmd = Command::new(prog);
    cmd.args(args).process_group(0);
    if let Some(cap) = &cap {
        use std::process::Stdio;
        match cap.file.try_clone() {
            // the temp file exists but stdout cannot ride it: fail the run
            Ok(file) => cmd.stdout(Stdio::from(file)),
            Err(_) => return (false, None),
        };
    }
    apply_env(&mut cmd, extra_env);
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            log::err(&format!("{prog} spawn failed: {e}"));
            return (false, None);
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
        if capture
            && cap
                .as_ref()
                .is_some_and(|c| c.file.metadata().is_ok_and(|m| m.len() > CAPTURE_MAX))
        {
            log::err(&format!(
                "{prog} output exceeded {CAPTURE_MAX} bytes; killing"
            ));
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
    (success, cap)
}

/// Run a child to completion with a hard timeout; kill on expiry. Aborts
/// early when `abort` fires, so a stop request never waits out a bounded
/// phase. stdio is inherited so failures stay visible in container logs.
pub fn run_bounded(timeout: Duration, prog: &str, args: &[&str], abort: impl Fn() -> bool) -> bool {
    run_bounded_env(timeout, prog, args, &[], abort)
}

/// [`run_bounded`] with extra child env vars (e.g. rclone backend config).
/// The child runs as its own process-group leader, so the expiry/abort kill
/// reaches anything it spawned, not just the direct child. Its environment
/// is allow-listed ([`apply_env`]) — the supervisor's env never leaks.
pub fn run_bounded_env(
    timeout: Duration,
    prog: &str,
    args: &[&str],
    extra_env: &[(String, String)],
    abort: impl Fn() -> bool,
) -> bool {
    run_bounded_core(timeout, prog, args, extra_env, abort, false).0
}

/// [`run_bounded_env`] capturing the child's stdout; stderr stays
/// inherited so failures remain visible in container logs. `None` = spawn
/// failure, stop request, timeout, non-zero exit, or oversized output.
/// Stdout lands in a temp file, not a pipe: the poll loop stays in charge
/// (no reader thread waiting on an EOF a group-escaped descendant could
/// hold open) and output is capped twice — killed at [`CAPTURE_MAX`] while
/// running, and the final read is itself capped, so a burst written between
/// cap checks (or by an outliving descendant) fails the run instead of
/// exhausting supervisor memory.
pub fn run_bounded_capture(
    timeout: Duration,
    prog: &str,
    args: &[&str],
    extra_env: &[(String, String)],
    abort: impl Fn() -> bool,
) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};

    let (success, cap) = run_bounded_core(timeout, prog, args, extra_env, abort, true);
    if !success {
        return None;
    }
    let mut cap = cap?;
    let mut out = Vec::new();
    cap.file.seek(SeekFrom::Start(0)).ok()?;
    // Read at most one byte past the cap: the in-loop metadata check can
    // miss a final burst written between the last check and a fast
    // successful exit, and a group-escaped descendant may keep appending
    // to the file-backed stdout afterwards — so the cap is enforced at
    // read time, not trusted from the loop's last check.
    cap.file
        .by_ref()
        .take(CAPTURE_MAX + 1)
        .read_to_end(&mut out)
        .ok()?;
    if out.len() as u64 > CAPTURE_MAX {
        log::err(&format!("{prog} output exceeded {CAPTURE_MAX} bytes"));
        return None;
    }
    Some(String::from_utf8_lossy(&out).into_owned())
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

    /// The cap must hold even when the writer exits between the loop's
    /// metadata checks: a burst dumped in one shot (well under one poll
    /// tick) and a successful exit must still fail the run, because the
    /// final read itself is capped.
    #[test]
    fn capture_fails_closed_on_a_burst_exited_between_cap_checks() {
        let out = run_bounded_capture(
            Duration::from_secs(30),
            "/bin/sh",
            &["-c", "dd if=/dev/zero bs=1M count=20 2>/dev/null"],
            &[],
            || false,
        );
        assert!(
            out.is_none(),
            "a 20MB burst past the 16MB cap must fail the run"
        );
    }

    /// The allow-list policy: baseline plumbing keys pass, secrets and
    /// everything else do not, and the child env is exactly
    /// baseline + extra_env (apply_env_from clears the rest).
    #[test]
    fn env_allowlist_passes_plumbing_and_blocks_secrets() {
        let vars = [
            ("TAILSCALE_AUTHKEY".to_string(), "leak-me".to_string()),
            (
                "SUPERVISOR_S3_SECRET_ACCESS_KEY".to_string(),
                "x".to_string(),
            ),
            (
                "VAULTWARDEN_DATABASE_URL".to_string(),
                "postgres://x".to_string(),
            ),
            ("SMTP_PASSWORD".to_string(), "x".to_string()),
            ("HTTPS_PROXY".to_string(), "http://proxy:3128".to_string()),
            ("NO_PROXY".to_string(), "localhost".to_string()),
            ("TZ".to_string(), "UTC".to_string()),
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("HOME".to_string(), "/root".to_string()),
        ];
        let mut cmd = Command::new("unused");
        apply_env_from(
            &mut cmd,
            &[("MARKER".to_string(), "yes".to_string())],
            vars.into_iter(),
        );
        let envs: std::collections::BTreeMap<String, String> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.expect("set, not removed").to_string_lossy().into_owned(),
                )
            })
            .collect();
        assert_eq!(
            envs,
            std::collections::BTreeMap::from([
                ("HTTPS_PROXY".to_string(), "http://proxy:3128".to_string()),
                ("NO_PROXY".to_string(), "localhost".to_string()),
                ("TZ".to_string(), "UTC".to_string()),
                ("MARKER".to_string(), "yes".to_string()),
            ])
        );
    }

    /// Behavioral: a child run's environment is exactly baseline plumbing
    /// plus extras — no supervisor vars (test env included) leak through,
    /// and extras land. Needs no env mutation: the clear-then-allowlist
    /// policy makes CARGO_/PATH absence hold in any environment.
    #[test]
    fn bounded_run_env_is_baseline_plus_extras() {
        let env = run_bounded_capture(
            Duration::from_secs(10),
            "/bin/sh",
            &["-c", "env"],
            &[("MARKER_VAR".to_string(), "yes".to_string())],
            || false,
        )
        .unwrap_or_default();
        assert!(
            env.contains("MARKER_VAR=yes"),
            "extras must reach the child"
        );
        assert!(
            !env.contains("CARGO_"),
            "supervisor env leaked into a bounded child"
        );
        assert!(
            !env.lines().any(|l| l.starts_with("PATH=")),
            "only the allow-list may pass, and PATH is not on it"
        );
    }
}
