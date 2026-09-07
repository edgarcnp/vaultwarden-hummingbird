//! Static configuration baked into the image: child binary paths and hard
//! timeouts. No lookups, no env — pure constants.

use std::time::Duration;

/// Hard-coded child binary paths (baked into the image, no PATH lookup).
pub const TAILSCALED: &str = "/usr/local/bin/tailscaled";
/// `tailscale` CLI (drives `up`/`serve` over the LocalAPI socket).
pub const TAILSCALE: &str = "/usr/local/bin/tailscale";
/// vaultwarden server binary (the payload this container exists to run).
pub const VAULTWARDEN: &str = "/vaultwarden";
/// rclone binary (S3 state sync; baked into the image by the fetch stage).
pub const RCLONE: &str = "/usr/local/bin/rclone";

/// Hard timeouts: never let a hung tailscaled block the vault.
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(90);
/// Hard timeout for `tailscale serve`.
pub const SERVE_TIMEOUT: Duration = Duration::from_secs(30);
/// Hard timeout waiting for tailscaled's LocalAPI socket.
pub const DAEMON_WAIT: Duration = Duration::from_secs(30);
/// Hard timeout for one rclone state-sync operation.
pub const SYNC_TIMEOUT: Duration = Duration::from_secs(60);
/// Default cadence (seconds) for periodic state pushes.
pub const SYNC_INTERVAL_DEFAULT: u64 = 3600;
/// Hard timeout for one DB keepalive ping (bounded like every other phase;
/// a hung DB must never stall the watch loop).
pub const DB_PING_TIMEOUT: Duration = Duration::from_secs(15);
