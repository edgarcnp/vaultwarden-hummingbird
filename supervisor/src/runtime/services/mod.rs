//! The supervised payload children: tailscaled + the tailscale CLI
//! ([`tailscale`]) and the vaultwarden server ([`vaultwarden`]).

mod tailscale;
mod vaultwarden;

pub use tailscale::{spawn_tailscaled, tailscale_serve, tailscale_up};
pub use vaultwarden::run_vaultwarden;
