//! Config resolution: process env + optional supervisor-owned dotenv file.
//!
//! mod.rs is declarations only; the public surface is re-exports.

mod dotenv;
mod env;

pub use env::{
    is_supervisor_key, Config, DbKeepalive, SyncConfig, AUTH_TIMEOUT, DAEMON_WAIT, DB_PING_TIMEOUT,
    RCLONE, SERVE_TIMEOUT, SYNC_TIMEOUT, TAILSCALE, TAILSCALED, VAULTWARDEN,
};
