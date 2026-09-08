//! Config resolution: process env + optional supervisor-owned dotenv file.
//!
//! mod.rs is declarations only; the public surface is re-exports.

mod backup;
mod consts;
mod dburl;
mod dotenv;
mod env;
mod keepalive;
mod sync;

pub use backup::DbBackupConfig;
pub use consts::{
    AUTH_TIMEOUT, BACKUP_FIRST_DELAY, BACKUP_TIMEOUT, DAEMON_WAIT, DB_PING_TIMEOUT, DB_TOOL_LIB,
    MARIADB, MARIADB_DUMP, PG_DUMP, PG_RESTORE, RCLONE, SERVE_TIMEOUT, SYNC_TIMEOUT, TAILSCALE,
    TAILSCALED, VAULTWARDEN,
};
pub use dburl::DbSpec;
pub use env::{Config, is_supervisor_key};
pub use keepalive::DbKeepalive;
pub use sync::SyncConfig;
