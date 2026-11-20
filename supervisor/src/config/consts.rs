//! Static configuration baked into the image: child binary paths and hard
//! timeouts. No lookups, no env — pure constants.

use std::time::Duration;

pub const TAILSCALED: &str = "/usr/local/bin/tailscaled";
pub const TAILSCALE: &str = "/usr/local/bin/tailscale";
pub const VAULTWARDEN: &str = "/vaultwarden";

// Path policy: the supervisor-only state volume root (shared with the
// transport and path checks).
pub use crate::util::fs::STATE_ROOT as SUPERVISOR_STATE;

// Process identities. The supervisor and tailscaled share the image UID;
// the vault runs as a different UID in the shared data group so it cannot
// read the supervisor's state volume, LocalAPI socket, or environment.
pub const SUPERVISOR_UID: u32 = 65532;
pub const SUPERVISOR_GID: u32 = 65532;
pub const TAILSCALED_UID: u32 = 65531;
pub const TAILSCALE_GID: u32 = 65531;
pub const VAULT_UID: u32 = 65533;
pub const VAULT_GID: u32 = 65532;

/// The group-writable subtree for tailscaled's state, certs, and LocalAPI
/// socket: the supervisor and tailscaled share the `tailscale` group; the
/// vault is not a member.
pub const TAILSCALE_DIR: &str = "/state/tailscale";

// Hard timeouts: a hung child must never block the vault.
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(90);
pub const SERVE_TIMEOUT: Duration = Duration::from_secs(30);
pub const DAEMON_WAIT: Duration = Duration::from_secs(30);
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
pub(crate) const SYNC_INTERVAL_DEFAULT: u64 = 3600;
pub(crate) const BACKUP_INTERVAL_DEFAULT: u64 = 21600;
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
