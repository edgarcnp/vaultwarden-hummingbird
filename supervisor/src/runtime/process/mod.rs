//! Process supervision for a PID 1 supervisor: spawning and group
//! signaling ([`child`]), pidfd handles ([`pidfd`]), the single-reaper
//! hub ([`reaper`]), wait-status decoding and the escalation wait
//! ([`reap`]), bounded child runs ([`run`]), child-environment grants
//! ([`mod@env`]), stop-signal wiring ([`signals`]), and the vault watch loop
//! / container teardown ([`watch`]).

mod child;
mod env;
mod pidfd;
mod reap;
mod reaper;
mod run;
mod signals;
mod watch;

pub use child::{
    Credentials, POLL, TERM_GRACE, TUN_CAPS, caps_are_empty, child_credentials,
    join_tailscale_group, signal_child, spawn, spawn_as, spawn_as_with_caps,
};
pub use env::EnvGrant;
pub use reap::{Gone, exit_code, reap_until_gone};
pub use reaper::Handle;
pub use run::{apply_env, run_bounded, run_bounded_capture};
pub use signals::{install_signal_handlers, stopping, take_stop};
pub use watch::{shutdown, start_vw};
