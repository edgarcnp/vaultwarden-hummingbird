//! Child process management: tailscaled/tailscale, vaultwarden, signals,
//! S3 state sync.
//!
//! mod.rs is declarations only — each child lives in its own module; the
//! public surface is re-exports so callers never change on internal moves.

mod process;
mod signals;
mod sync;
mod tailscale;
mod vaultwarden;

pub use process::{
    Gone, POLL, Pid, TERM_GRACE, exit_code, exit_reason, reap_any, reap_until_gone, signal_group,
};
pub use signals::{install_signal_handlers, stopping, take_stop};
pub use sync::{restore_state, sync_state};
pub use tailscale::{run_bounded_env, spawn_tailscaled, tailscale_serve, tailscale_up};
pub use vaultwarden::run_vaultwarden;
