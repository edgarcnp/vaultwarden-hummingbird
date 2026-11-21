//! The container runtime: everything the supervisor *does*, as opposed to
//! what it is configured with (`crate::config`). Grouped by responsibility:
//! `backup` (S3 DB dump/restore), `gate` (exposed-port health gate),
//! `maintenance` (the single scheduler for periodic sync/backup and the
//! shutdown flush), `migrate` (one-time old-layout move), `process`
//! (supervision core: spawn, reaper hub, bounded runs, signals, watch
//! loop), `services` (the supervised children: tailscaled/tailscale,
//! vaultwarden), `sync` (S3 persistence of the durable set).

mod backup;
mod gate;
mod maintenance;
mod migrate;
mod process;
mod services;
mod sync;

#[cfg(test)]
pub(crate) mod test_support;

pub use backup::{RestoreOutcome, adopt_lineage, restore_if_empty};
pub use gate::{
    bind as gate_bind, describe as gate_describe, healthcheck as gate_healthcheck,
    serve as gate_serve,
};
pub use maintenance::Reactor;
pub(crate) use maintenance::Task;
pub use migrate::migrate_layout;
pub use process::{
    Credentials, EnvGrant, Gone, Handle, POLL, TERM_GRACE, TUN_CAPS, apply_env, caps_are_empty,
    child_credentials, exit_code, install_signal_handlers, join_tailscale_group, reap_until_gone,
    run_bounded, run_bounded_capture, shutdown, signal_child, spawn, spawn_as, spawn_as_with_caps,
    start_vw, stopping, take_stop,
};
pub use services::{run_vaultwarden, spawn_tailscaled, tailscale_serve, tailscale_up};
pub use sync::{restore_state, sync_state};
