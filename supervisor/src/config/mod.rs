//! Config resolution: process env + optional supervisor-owned dotenv file.
//!
//! mod.rs is declarations only — the public surface is re-exports so callers
//! never change on internal moves.

mod dotenv;
mod env;

pub use env::{
    AUTH_TIMEOUT, Config, DAEMON_WAIT, RCLONE, SERVE_TIMEOUT, SYNC_TIMEOUT, SyncConfig, TAILSCALE,
    TAILSCALED, VAULTWARDEN, is_supervisor_key,
};
