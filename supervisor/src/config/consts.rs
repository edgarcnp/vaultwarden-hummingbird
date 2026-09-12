//! Static configuration baked into the image: child binary paths and hard
//! timeouts. No lookups, no env — pure constants.

use std::time::Duration;

pub const TAILSCALED: &str = "/usr/local/bin/tailscaled";
pub const TAILSCALE: &str = "/usr/local/bin/tailscale";
pub const VAULTWARDEN: &str = "/vaultwarden";

// Hard timeouts: a hung child must never block the vault.
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(90);
pub const SERVE_TIMEOUT: Duration = Duration::from_secs(30);
pub const DAEMON_WAIT: Duration = Duration::from_secs(30);
pub const SYNC_TIMEOUT: Duration = Duration::from_secs(60);
/// Delay before the first periodic backup after the vault starts.
pub const BACKUP_FIRST_DELAY: Duration = Duration::from_secs(300);
/// Delay before the first periodic state push, also measured from the vault
/// starting: vaultwarden creates `/data/rsa_key.pem` during startup, so a
/// push a little later is the first that can carry it. Without this the next
/// push would wait a full sync interval, and a redeploy inside that window
/// loses the signing key (every session revoked).
pub const SYNC_FIRST_DELAY: Duration = Duration::from_secs(60);

// Default cadences/counts; seconds where applicable.
pub const SYNC_INTERVAL_DEFAULT: u64 = 3600;
pub const BACKUP_INTERVAL_DEFAULT: u64 = 21600;
pub const BACKUP_KEEP_DEFAULT: u64 = 3;

/// Local staging directory (on the data volume) for in-flight dumps and
/// restore pulls; swept before each run and after each restore.
pub const BACKUP_STAGING: &str = "/data/db-backups";
