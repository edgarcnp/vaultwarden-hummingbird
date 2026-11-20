//! Static configuration baked into the image: child binary paths and hard
//! timeouts. No lookups, no env — pure constants.

use std::time::Duration;

/// Absolute path of the tailscaled daemon binary in the image.
pub const TAILSCALED: &str = "/usr/local/bin/tailscaled";
/// Absolute path of the tailscale CLI in the image.
pub const TAILSCALE: &str = "/usr/local/bin/tailscale";
/// Absolute path of the vaultwarden binary in the image.
pub const VAULTWARDEN: &str = "/vaultwarden";

/// Root of the supervisor-only state volume; shared with the transport and
/// the path checks.
pub use crate::util::fs::STATE_ROOT as SUPERVISOR_STATE;

// Process identities. tailscaled has a dedicated uid and the tailscale
// group; the supervisor joins that group so it can reach the LocalAPI
// socket and read the daemon's files. The vault runs as a different uid in
// the shared data group, so it cannot traverse the supervisor's state
// volume, read the LocalAPI socket, or see PID 1's environment.
/// UID the supervisor (PID 1) runs as.
pub const SUPERVISOR_UID: u32 = 65532;
/// GID the supervisor runs as; the vault's shared data group.
pub const SUPERVISOR_GID: u32 = 65532;
/// UID the tailscaled daemon runs as.
pub const TAILSCALED_UID: u32 = 65531;
/// GID of the tailscale group; it owns the LocalAPI socket and state tree.
pub const TAILSCALE_GID: u32 = 65531;
/// UID the vaultwarden child runs as, outside the tailscale group.
pub const VAULT_UID: u32 = 65533;
/// GID the vaultwarden child runs as, in the shared data group.
pub const VAULT_GID: u32 = 65532;

/// The supplementary groups every tailscaled spawn (and the isolation
/// probe) receives: the shared `tailscale` group. One definition so the
/// probe and the real spawn cannot diverge.
pub const TAILSCALED_GROUPS: [nix::unistd::Gid; 1] = [nix::unistd::Gid::from_raw(TAILSCALE_GID)];

/// The current tailscaled data tree: certs, the LocalAPI socket, and the
/// actual state file. It is group-writable for tailscaled.
pub const TAILSCALE_DIR: &str = "/state/tailscale";

/// The path handed to `tailscaled --state`: a supervisor-created symlink to
/// [`TAILSCALE_DIR`]. Tailscale chmods a state directory whose basename is
/// exactly `tailscale` to 0700; the daemon uid cannot chmod the
/// supervisor-owned group tree, so it would fall back to an in-memory store.
/// The differently named link keeps the real tree supervisor-owned and
/// group-writable while Tailscale sees a directory it will not chmod.
pub const TAILSCALE_STATE_DIR: &str = "/state/tailscale-state";

// Hard timeouts: a hung child must never block the vault.
/// Bound on one `tailscale up` login attempt.
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(90);
/// Bound on one `tailscale serve` configuration run.
pub const SERVE_TIMEOUT: Duration = Duration::from_secs(30);
/// Bound on the wait for the tailscaled LocalAPI socket to appear.
pub const DAEMON_WAIT: Duration = Duration::from_secs(30);
/// Per-phase timeout for each S3 control request.
pub const SYNC_TIMEOUT: Duration = Duration::from_secs(60);
/// Overall budget for the final shutdown persists (DB dump, then state
/// push). Child teardown ahead of it is bounded by the grace constants, so
/// the normal path fits inside the shipped compose `stop_grace_period`
/// (180s: reaping ≤ 32s plus this budget). A thread stuck past the budget
/// is abandoned at budget + `SYNC_TIMEOUT`, which can exceed that grace —
/// the process exits anyway; only that transfer is lost.
pub const PERSIST_BUDGET: Duration = Duration::from_secs(120);
/// A stop request observed while draining shortens the persist budget to
/// this, so a hurry-up SIGTERM gets a fast exit.
pub const PERSIST_FORCED_BUDGET: Duration = Duration::from_secs(15);
/// Delay before the first periodic backup after the vault starts. Short so
/// an ephemeral container that is redeployed early still has a recent dump
/// to restore.
pub const BACKUP_FIRST_DELAY: Duration = Duration::from_secs(60);
/// Delay before the first periodic state push, also measured from the vault
/// starting: vaultwarden creates `/data/rsa_key.pem` during startup, so a
/// push a little later is the first that can carry it. It runs before the
/// first DB backup (30s vs 60s), so a large dump cannot starve the signing
/// key; without this the next push would wait a full sync interval, and a
/// redeploy inside that window loses the signing key (every session revoked).
pub const SYNC_FIRST_DELAY: Duration = Duration::from_secs(30);

/// Extra wait for the vault's signing key on the first push: a slow vault
/// must not make the first backup keyless. Bounded so a failed vault cannot
/// hold the maintenance thread indefinitely.
pub const SYNC_RSA_WAIT: Duration = Duration::from_secs(120);

/// Overall budget for one boot state pull. Per-request timeouts still leave
/// a slow bucket able to delay boot for a long time; a partial pull is
/// better than an unbounded boot, and the next boot retries.
pub const BOOT_RESTORE_BUDGET: Duration = Duration::from_secs(30 * 60);

/// Overall budget for the DB-restore candidate fallback. A bucket can list
/// thousands of full-size invalid candidates; each is bounded, but the
/// fallback as a whole must not hold boot indefinitely.
pub const DB_RESTORE_BUDGET: Duration = Duration::from_secs(30 * 60);

/// Overall budget for one periodic state push, independent of the number
/// of objects and attempts.
pub const SYNC_RUN_BUDGET: Duration = Duration::from_secs(60 * 60);

/// Overall budget for one periodic backup cycle (dump, upload, manifest,
/// prune). The drain has its own, shorter deadline.
pub const BACKUP_RUN_BUDGET: Duration = Duration::from_secs(60 * 60);

// Default cadences/counts; seconds where applicable.
/// Default state-sync cadence when `SUPERVISOR_S3_SYNC_INTERVAL` is unset.
pub(crate) const SYNC_INTERVAL_DEFAULT: u64 = 3600;
/// Default DB-backup cadence when `SUPERVISOR_DB_BACKUP_INTERVAL` is unset.
pub(crate) const BACKUP_INTERVAL_DEFAULT: u64 = 21600;
/// Default dump count when `SUPERVISOR_DB_BACKUP_KEEP` is unset.
pub(crate) const BACKUP_KEEP_DEFAULT: u64 = 3;

/// Upper bound for every interval knob: `Instant + Duration` panics on
/// overflow (and aborts the container under `panic = "abort"`), and no
/// legitimate cadence is longer than a week. Larger values degrade to the
/// knob's default, loudly.
pub(crate) const MAX_INTERVAL_SECS: u64 = 7 * 24 * 3600;

/// Upper bound for `SUPERVISOR_DB_BACKUP_KEEP`: the manifest has a 256 KiB
/// read cap, so an unbounded keep could write a manifest this process
/// could never read back (~75 bytes per entry).
pub(crate) const MAX_BACKUP_KEEP: u64 = 1000;

/// Local staging directory on the supervisor-only state volume for
/// in-flight dumps and restore pulls; swept before each run and after each
/// restore.
pub(crate) const BACKUP_STAGING: &str = "/state/db-backups";
