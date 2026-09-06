//! rclone-backed S3 state sync (opt-in via SUPERVISOR_S3_*).
//!
//! On hosts without persistent volumes this restores the *same* tailscale
//! node and vaultwarden RSA signing keys across redeploys:
//!   - pull:  bucket -> /data, once at boot before any daemon starts
//!   - push:  /data -> bucket, after `up`, on a cadence, and at shutdown
//!
//! Scope is limited to identity files (tailscaled.state, rsa_key*) — the
//! database is external and everything else in /data is regenerable. The
//! bucket therefore holds secrets (node key, JWT signing key): keep it
//! private, and run ONE container per bucket/path (a state file restored in
//! two containers simultaneously means one node identity twice).
//!
//! Every sync failure is non-fatal: the vault runs regardless; worst case is
//! a fresh node registration (re-auth) or one client re-login.

use crate::config::{RCLONE, SYNC_TIMEOUT, SyncConfig};
use crate::proc::run_bounded_env;
use crate::util::log;

/// /data files worth persisting (identity only; the DB lives elsewhere).
const INCLUDES: [&str; 4] = ["--include", "tailscaled.state", "--include", "rsa_key*"];

/// rclone argument vector for one copy operation. The backend config comes
/// from env (RCLONE_CONFIG*), never argv, whose cmdline is world-readable.
fn copy_args(src: &str, dst: &str) -> Vec<String> {
    let mut args: Vec<String> = ["copy", src, dst].iter().map(|s| s.to_string()).collect();
    args.extend(INCLUDES.iter().map(|s| s.to_string()));
    args
}

/// Pull identity files from the bucket into /data. Called at boot, before
/// tailscaled is spawned, so a restored state file wins over nothing.
pub fn restore_state(cfg: &SyncConfig, abort: impl Fn() -> bool) -> bool {
    run(cfg, "pull", &copy_args(&cfg.remote, "/data"), abort)
}

/// Push identity files from /data to the bucket. Called after `up` (fresh
/// state), on the periodic cadence, and at shutdown.
pub fn sync_state(cfg: &SyncConfig, abort: impl Fn() -> bool) -> bool {
    run(cfg, "push", &copy_args("/data", &cfg.remote), abort)
}

fn run(cfg: &SyncConfig, what: &str, args: &[String], abort: impl Fn() -> bool) -> bool {
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let ok = run_bounded_env(SYNC_TIMEOUT, RCLONE, &args, &cfg.env, abort);
    if ok {
        log::info(&format!("state sync: {what} ok ({})", cfg.remote));
    } else {
        log::err(&format!(
            "state sync: {what} failed; continuing (fresh node/re-login possible)"
        ));
    }
    ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn copy_args_covers_scope_and_direction() {
        let a = copy_args("/data", "r2:vw-state");
        assert_eq!(&a[..3], &["copy", "/data", "r2:vw-state"]);
        assert_eq!(&a[3..], &INCLUDES);
        let b = copy_args("r2:vw-state", "/data");
        assert_eq!(&b[1..3], &["r2:vw-state", "/data"]);
    }

    /// run() with a bogus binary must fail cleanly (bounded, non-fatal).
    #[test]
    fn sync_failure_is_bounded_and_reported() {
        let cfg = SyncConfig::new(
            "r2:vw".into(),
            "id".into(),
            "secret".into(),
            String::new(),
            Duration::from_secs(60),
        );
        assert!(!run(&cfg, "push", &copy_args("/data", &cfg.remote), || {
            false
        }));
    }
}
