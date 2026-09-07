//! Child process management: tailscaled/tailscale, vaultwarden, signals,
//! S3 state sync.
//!
//! mod.rs is declarations only; the public surface is re-exports.

mod gate;
mod keepalive;
mod process;
mod signals;
mod sync;
mod tailscale;
mod vaultwarden;

pub use gate::{bind as gate_bind, describe as gate_describe, serve as gate_serve};

pub use keepalive::tick as db_keepalive_tick;
pub use process::{
    alive, exit_code, exit_reason, reap_any, reap_until_gone, run_bounded, run_bounded_env,
    signal_group, spawn, Gone, Pid, POLL, TERM_GRACE,
};
pub use signals::{install_signal_handlers, stopping, take_stop};
pub use sync::{restore_state, sync_state};
pub use tailscale::{spawn_tailscaled, tailscale_serve, tailscale_up};
pub use vaultwarden::run_vaultwarden;
