//! Config resolution: process env + optional supervisor-owned dotenv file.
//! Feature modules follow a `spec`/`resolve` folder split, re-exported here.

mod backup;
mod consts;
mod dburl;
mod dotenv;
mod env;
mod keepalive;
mod sync;

pub use backup::DbBackupConfig;
pub use consts::{
    AUTH_TIMEOUT, BACKUP_FIRST_DELAY, BACKUP_TIMEOUT, DAEMON_WAIT, DB_PING_TIMEOUT, MARIADB,
    MARIADB_DUMP, MARIADB_TOOL_LIB, PG_DUMP, PG_RESTORE, PG_TOOL_LIB, RCLONE, SERVE_TIMEOUT,
    SYNC_TIMEOUT, TAILSCALE, TAILSCALED, VAULTWARDEN,
};
pub use dburl::DbSpec;
pub use env::{Config, is_supervisor_key, vaultwarden_key};
pub use keepalive::DbKeepalive;
pub use sync::SyncConfig;
