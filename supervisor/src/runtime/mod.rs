//! The container runtime: everything the supervisor *does*, as opposed to
//! what it is configured with (`crate::config`). Grouped by responsibility:
//! `backup` (S3 DB dump/restore), `db` (postgres plumbing + keepalive),
//! `gate` (exposed-port health gate), `process` (supervision core: spawn,
//! reap, bounded runs, signals, watch loop), `services` (the supervised
//! children: tailscaled/tailscale, vaultwarden), `sync` (S3 /data state
//! persistence).
//!
//! mod.rs is declarations only; the public surface is re-exports.

mod backup;
mod db;
mod gate;
mod process;
mod services;
mod sync;

pub use backup::{restore_if_empty, tick as backup_tick};
pub use db::db_keepalive_tick;
pub use gate::{
    bind as gate_bind, describe as gate_describe, healthcheck as gate_healthcheck,
    serve as gate_serve,
};
pub use process::{
    Gone, POLL, Pid, TERM_GRACE, alive, exit_code, exit_reason, install_signal_handlers, reap_any,
    reap_until_gone, run_bounded, run_bounded_capture, run_bounded_env, shutdown, signal_group,
    spawn, start_vw, stopping, take_stop,
};
pub use services::{run_vaultwarden, spawn_tailscaled, tailscale_serve, tailscale_up};
pub use sync::{restore_state, sync_state};
