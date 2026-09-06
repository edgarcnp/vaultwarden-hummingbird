//! Config resolution: process env + optional supervisor-owned dotenv file.
//!
//! mod.rs is declarations only — the public surface is re-exports so callers
//! never change on internal moves.

mod dotenv;
mod env;

pub use env::{
    is_supervisor_key, Config, AUTH_TIMEOUT, DAEMON_WAIT, SERVE_TIMEOUT, TAILSCALE, TAILSCALED,
    VAULTWARDEN,
};
