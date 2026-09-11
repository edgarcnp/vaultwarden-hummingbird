//! rclone-backed S3 state sync (opt-in via SUPERVISOR_S3_*): pulls /data
//! identity files at boot, pushes after `up`, on a cadence, and at shutdown
//! — so node identity and vaultwarden signing keys survive ephemeral
//! redeploys (also keeps distance from Let's Encrypt's 5-certs-per-week
//! limit). The bucket holds secrets: keep it private, one container per
//! bucket/path. Every failure is non-fatal; worst case is a fresh node
//! registration, one client re-login, or one cert re-issuance.

use crate::config::{RCLONE, RCLONE_NO_CHECK_BUCKET, SYNC_TIMEOUT, SyncConfig};
use crate::runtime::run_bounded_env;
use crate::util::log;

/// /data files worth persisting (identity only; the DB lives elsewhere).
/// `certs/**` covers the ACME account key and the issued ts.net cert+key.
const INCLUDES: [&str; 6] = [
    "--include",
    "tailscaled.state",
    "--include",
    "rsa_key*",
    "--include",
    "certs/**",
];

/// rclone argv for one copy operation; backend config rides env (never
/// argv — /proc cmdline is world-readable). `--no-traverse` swaps the
/// destination listing (Class A) for per-file HEADs (Class B, 12.5×
/// cheaper on R2): six files compare cheaper as HEADs than as a bucket
/// list. Uploads skip the bucket pre-check (see [`RCLONE_NO_CHECK_BUCKET`]);
/// harmless on the pull path.
fn copy_args(src: &str, dst: &str) -> Vec<String> {
    ["copy", RCLONE_NO_CHECK_BUCKET, "--no-traverse", src, dst]
        .into_iter()
        .chain(INCLUDES)
        .map(String::from)
        .collect()
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
        assert_eq!(
            &a[..5],
            &[
                "copy",
                RCLONE_NO_CHECK_BUCKET,
                "--no-traverse",
                "/data",
                "r2:vw-state"
            ]
        );
        assert_eq!(&a[5..], &INCLUDES);
        let b = copy_args("r2:vw-state", "/data");
        assert_eq!(&b[3..5], &["r2:vw-state", "/data"]);
    }

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
