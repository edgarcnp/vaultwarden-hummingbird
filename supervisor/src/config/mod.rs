//! Config resolution: process env + optional supervisor-owned dotenv file.
//! Feature modules follow a `spec`/`resolve` folder split, re-exported here.

mod backup;
mod consts;
mod dburl;
mod dotenv;
mod env;
mod sync;

pub use backup::DbBackupConfig;
pub use consts::{
    AUTH_TIMEOUT, BACKUP_FIRST_DELAY, DAEMON_WAIT, RCLONE, RCLONE_NO_CHECK_BUCKET, SERVE_TIMEOUT,
    SYNC_TIMEOUT, TAILSCALE, TAILSCALED, VAULTWARDEN,
};
pub use env::{Config, is_supervisor_consumed, is_supervisor_key, vaultwarden_key};
pub use sync::SyncConfig;
