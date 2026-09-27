//! The container runtime: everything the supervisor *does*, as opposed to
//! what it is configured with (`crate::config`). Grouped by responsibility:
//! `backup` (S3 DB dump/restore), `gate` (exposed-port health gate),
//! `maintenance` (the single scheduler for periodic sync/backup and the
//! shutdown flush), `process` (supervision core: spawn, reaper hub, bounded
//! runs, signals, watch loop), `services` (the supervised children:
//! tailscaled/tailscale, vaultwarden), `sync` (S3 /data state persistence).

mod backup;
mod gate;
mod maintenance;
mod process;
mod services;
mod sync;

pub use backup::{RestoreOutcome, adopt_lineage, restore_if_empty};
pub use gate::{
    bind as gate_bind, describe as gate_describe, healthcheck as gate_healthcheck,
    serve as gate_serve,
};
pub use maintenance::Reactor;
pub(crate) use maintenance::Task;
pub use process::{
    EnvGrant, Gone, Handle, POLL, TERM_GRACE, apply_env, exit_code, install_signal_handlers,
    reap_until_gone, run_bounded, run_bounded_capture, shutdown, signal_child, spawn, start_vw,
    stopping, take_stop,
};
pub use services::{run_vaultwarden, spawn_tailscaled, tailscale_serve, tailscale_up};
pub use sync::{restore_state, sync_state};
