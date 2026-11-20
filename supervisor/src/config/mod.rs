//! Boot-time configuration: process env plus an optional supervisor-owned
//! dotenv file, resolved once and re-exported here. Every feature follows a
//! `spec`/`resolve` split; anything unresolved or conflicting refuses the boot.

mod backup;
mod consts;
mod dburl;
mod dotenv;
mod env;
pub(crate) mod paths;
mod sync;

pub use backup::DbBackupConfig;
pub use consts::{
    AUTH_TIMEOUT, BACKUP_FIRST_DELAY, BACKUP_RUN_BUDGET, BOOT_RESTORE_BUDGET, DAEMON_WAIT,
    DB_RESTORE_BUDGET, PERSIST_BUDGET, PERSIST_FORCED_BUDGET, SERVE_TIMEOUT, SUPERVISOR_GID,
    SUPERVISOR_STATE, SUPERVISOR_UID, SYNC_FIRST_DELAY, SYNC_RSA_WAIT, SYNC_RUN_BUDGET,
    SYNC_TIMEOUT, TAILSCALE, TAILSCALE_DIR, TAILSCALE_GID, TAILSCALE_STATE_DIR, TAILSCALED,
    TAILSCALED_GROUPS, TAILSCALED_UID, VAULT_GID, VAULT_UID, VAULTWARDEN,
};
pub use env::{Config, is_supervisor_consumed, is_supervisor_key, vaultwarden_key};
pub use sync::SyncConfig;
