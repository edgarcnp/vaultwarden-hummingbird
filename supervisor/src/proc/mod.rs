//! Child process management: tailscaled/tailscale, vaultwarden, signals.
//!
//! mod.rs is declarations only — each child lives in its own module; the
//! public surface is re-exports so callers never change on internal moves.

mod process;
mod signals;
mod tailscale;
mod vaultwarden;

pub use process::{
    exit_code, exit_reason, reap_any, reap_until_gone, signal_group, Gone, Pid, POLL, TERM_GRACE,
};
pub use signals::{install_signal_handlers, stopping, take_stop};
pub use tailscale::{spawn_tailscaled, tailscale_serve, tailscale_up};
pub use vaultwarden::run_vaultwarden;
