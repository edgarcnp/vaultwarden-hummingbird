//! Child primitives for a PID 1 supervisor: spawning, liveness, and group
//! signaling ([`child`]), namespace-wide reaping and wait-status decoding
//! ([`reap`]), and bounded child runs ([`run`]).
//!
//! mod.rs is declarations only; the public surface is re-exports.

mod child;
mod reap;
mod run;

pub use child::{POLL, Pid, TERM_GRACE, alive, signal_group, spawn};
pub use reap::{Gone, exit_code, exit_reason, reap_any, reap_until_gone};
pub use run::{run_bounded, run_bounded_env};
