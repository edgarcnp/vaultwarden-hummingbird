//! Child primitives for a PID 1 supervisor: spawning, liveness, and group
//! signaling ([`child`]), namespace-wide reaping and wait-status decoding
//! ([`reap`]), and bounded child runs ([`run`]).
//!
//! mod.rs is declarations only; the public surface is re-exports.

mod child;
mod reap;
mod run;

pub use child::{alive, signal_group, spawn, Pid, POLL, TERM_GRACE};
pub use reap::{exit_code, exit_reason, reap_any, reap_until_gone, Gone};
pub use run::{run_bounded, run_bounded_capture, run_bounded_env};
