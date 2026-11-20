//! S3 state-sync configuration (opt-in via SUPERVISOR_S3_*).
//! Misconfiguration resolves to `None` (sync disabled), never a failed boot.

mod resolve;
mod spec;

pub(crate) use resolve::resolve_sync;
pub use spec::SyncConfig;
