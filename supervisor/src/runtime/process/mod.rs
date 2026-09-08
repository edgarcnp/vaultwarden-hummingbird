//! Process supervision for a PID 1 supervisor: spawning, liveness, and
//! group signaling ([`child`]), namespace-wide reaping and wait-status
//! decoding ([`reap`]), bounded child runs ([`run`]), stop-signal wiring
//! ([`signals`]), and the vault watch loop / container teardown
//! ([`watch`]).
//!
//! mod.rs is declarations only; the public surface is re-exports.

mod child;
mod reap;
mod run;
mod signals;
mod watch;

pub use child::{POLL, Pid, TERM_GRACE, alive, signal_group, spawn};
pub use reap::{Gone, exit_code, exit_reason, reap_any, reap_until_gone};
pub use run::{run_bounded, run_bounded_capture, run_bounded_env};
pub use signals::{install_signal_handlers, stopping, take_stop};
pub use watch::{shutdown, start_vw};
