//! Bounded child runs: run a CLI child to completion with a hard timeout,
//! killing its whole process group on expiry so nothing it spawned
//! outlives the budget. Children are registered with the reaper hub
//! ([`super::reaper`]) at spawn; verdicts come from the delivered status,
//! never from a local wait.

use std::process::Command;
use std::time::{Duration, Instant};

use nix::sys::signal::Signal;

use super::child::{KILL_GRACE, POLL, signal_group, spawn};
use super::env::EnvGrant;
use super::reap::exit_code;
use crate::util::{StagedFile, log};

/// Env keys external children may inherit: secret-free plumbing only.
/// Everything else (auth keys, S3 credentials, database URLs, SMTP/admin
/// secrets) stays inside the supervisor — a helper binary that is
/// compromised or merely chatty must not become a secrets broadcast.
/// The set is deliberately tiny:
/// - `HTTP(S)_PROXY`/`ALL_PROXY`/`NO_PROXY`: egress-controlled deployments
///   route Tailscale traffic through a proxy;
/// - `SSL_CERT_FILE`/`SSL_CERT_DIR`: Go (tailscaled) trusts custom roots
///   this way;
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

/// [`allowlisted`] over the supervisor's own environment, applied as an
/// [`EnvGrant`]: clear, allow-listed plumbing, then `extra_env`
/// (connection config rides there — e.g. pg_env). Never place secrets
/// here. Shared by the bounded runs and the long-running tailscaled
/// spawn.
pub fn apply_env(cmd: &mut Command, extra_env: &[(String, String)]) {
    EnvGrant::new()
        .layer(
            allowlisted(std::env::vars_os().filter_map(|(k, v)| {
                let k = k.to_str()?;
                Some((k.to_string(), v.to_string_lossy().into_owned()))
            }))
            .into_iter()
            .map(|(k, v)| (k, v.into())),
        )
        .layer(extra_env.iter().cloned().map(|(k, v)| (k, v.into())))
        .apply(cmd);
}

/// Cap on stdout captured by [`run_bounded_capture`]: a listing far beyond
/// any real bucket is treated as a failed run. Only listings flow through
/// this path (object names), so megabytes are already extraordinary.
const CAPTURE_MAX: u64 = 16 * 1024 * 1024;

/// Core of both bounded runs: spawn (registered with the reaper hub),
/// poll (verdict / abort / timeout / capture cap), then group-kill on
/// failure and consume the reaped status. `capture` redirects stdout to a
/// temp file and enforces the capture cap while the child runs; the file
/// comes back so the capture wrapper can do its own capped final read.
/// Returns `(success, captured stdout file)`; the file is `None` when not
/// capturing or when the run never got far enough to matter.
fn run_bounded_core(
    timeout: Duration,
    prog: &str,
    args: &[&str],
    extra_env: &[(String, String)],
    abort: impl Fn() -> bool,
    capture: bool,
) -> (bool, Option<StagedFile>) {
    let cap = if capture {
        match StagedFile::create("vw-cap") {
            Ok(c) => Some(c),
            Err(_) => return (false, None),
        }
    } else {
        None
    };
    let mut cmd = Command::new(prog);
    cmd.args(args);
    if let Some(cap) = &cap {
        use std::process::Stdio;
        match cap.file().try_clone() {
            // the temp file exists but stdout cannot ride it: fail the run
            Ok(file) => cmd.stdout(Stdio::from(file)),
            Err(_) => return (false, None),
        };
    }
    apply_env(&mut cmd, extra_env);
    let Some(child) = spawn(&mut cmd) else {
        return (false, None);
    };
    let start = Instant::now();
    let success = loop {
        // Exit first: a delivered status beats abort/timeout — the real
        // verdict of a child that finished in the same tick it was
        // stopped for. The bounded wait doubles as the loop's sleep.
        if let Some(st) = child.wait(POLL) {
            break exit_code(st) == 0;
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
                .is_some_and(|c| c.file().metadata().is_ok_and(|m| m.len() > CAPTURE_MAX))
        {
            log::err(&format!(
                "{prog} output exceeded {CAPTURE_MAX} bytes; killing"
            ));
            break false;
        }
    };
    if !success {
        // Whole-group kill: the leader and anything it spawned. The hub
        // reaps and delivers; consumed below so the kill has landed
        // before callers proceed.
        signal_group(child.pid, Signal::SIGKILL);
    }
    // Consume the reap on every path (bounded): a D-state child gives up
    // here — the verdict is already decided, the zombie is the runtime's.
    let _ = child.wait(KILL_GRACE);
    (success, cap)
}

/// Run a child to completion with a hard timeout; kill on expiry. Aborts
/// early when `abort` fires, so a stop request never waits out a bounded
/// phase. stdio is inherited so failures stay visible in container logs.
pub fn run_bounded(timeout: Duration, prog: &str, args: &[&str], abort: impl Fn() -> bool) -> bool {
    run_bounded_env(timeout, prog, args, &[], abort)
}

/// [`run_bounded`] with extra child env vars (e.g. connection plumbing).
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
/// Stdout lands in a temp file, not a pipe, so the poll loop stays in
/// charge (why: the stdout-holding-descendant test below); output is
/// capped twice — in-loop and at the final read.
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
    let cap = cap?;
    let mut out = Vec::new();
    cap.file().seek(SeekFrom::Start(0)).ok()?;
    // Read at most one byte past the cap: the in-loop metadata check can
    // miss a final burst written between the last check and a fast
    // successful exit, and a group-escaped descendant may keep appending
    // to the file-backed stdout afterwards — so the cap is enforced at
    // read time, not trusted from the loop's last check.
    cap.file()
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

    /// A child that exits almost instantly still yields its true verdict:
    /// spawn + registration are atomic against the reaper (registry lock
    /// held across both), so the status is delivered, never lost to the
    /// stray sweep. Repeated to shake the race window.
    #[test]
    fn instant_exits_deliver_their_true_verdict() {
        for _ in 0..10 {
            assert!(run_bounded(
                Duration::from_secs(5),
                "/bin/sh",
                &["-c", "exit 0"],
                || false
            ));
            assert!(!run_bounded(
                Duration::from_secs(5),
                "/bin/sh",
                &["-c", "exit 7"],
                || false
            ));
        }
    }

    /// Captured stdout comes back verbatim on success; stderr stays out.
    /// (The 0600 + unlink-on-drop contract lives in
    /// [`crate::util::StagedFile`]'s own tests.)
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
    /// baseline + extra_env (EnvGrant clears the rest).
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
        EnvGrant::new()
            .layer(
                allowlisted(vars.into_iter())
                    .into_iter()
                    .map(|(k, v)| (k, v.into())),
            )
            .layer([("MARKER".to_string(), "yes".into())])
            .apply(&mut cmd);
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
