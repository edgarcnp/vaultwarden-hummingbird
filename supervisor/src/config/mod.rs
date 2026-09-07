//! Config resolution: process env + optional supervisor-owned dotenv file.
//!
//! mod.rs is declarations only; the public surface is re-exports.

mod consts;
mod dotenv;
mod env;
mod keepalive;
mod sync;

pub use consts::{
    AUTH_TIMEOUT, DAEMON_WAIT, DB_PING_TIMEOUT, RCLONE, SERVE_TIMEOUT, SYNC_TIMEOUT, TAILSCALE,
    TAILSCALED, VAULTWARDEN,
};
pub use env::{Config, is_supervisor_key};
pub use keepalive::DbKeepalive;
pub use sync::SyncConfig;
