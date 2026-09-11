//! Static configuration baked into the image: child binary paths and hard
//! timeouts. No lookups, no env — pure constants.

use std::time::Duration;

pub const TAILSCALED: &str = "/usr/local/bin/tailscaled";
pub const TAILSCALE: &str = "/usr/local/bin/tailscale";
pub const VAULTWARDEN: &str = "/vaultwarden";
pub const RCLONE: &str = "/usr/local/bin/rclone";

/// rclone's `--s3-no-check-bucket`, passed on every S3 upload: the bucket
/// existence pre-check is a bucket-level op that least-privilege tokens
/// (e.g. R2 object-scoped keys) deny with 403, and rclone then falls back
/// to CreateBucket — denied for the same reason. The bucket must exist
/// (SUPERVISOR_S3_REMOTE points at it); a missing bucket fails loudly.
pub const RCLONE_NO_CHECK_BUCKET: &str = "--s3-no-check-bucket";

// Hard timeouts: a hung child must never block the vault.
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(90);
pub const SERVE_TIMEOUT: Duration = Duration::from_secs(30);
pub const DAEMON_WAIT: Duration = Duration::from_secs(30);
pub const SYNC_TIMEOUT: Duration = Duration::from_secs(60);
/// Delay before the first periodic backup after the vault starts.
pub const BACKUP_FIRST_DELAY: Duration = Duration::from_secs(300);

// Default cadences/counts; seconds where applicable.
pub const SYNC_INTERVAL_DEFAULT: u64 = 3600;
pub const BACKUP_INTERVAL_DEFAULT: u64 = 21600;
pub const BACKUP_KEEP_DEFAULT: u64 = 3;

/// Local staging directory (on the data volume) for in-flight dumps and
/// restore pulls; swept before each run and after each restore.
pub const BACKUP_STAGING: &str = "/data/db-backups";
