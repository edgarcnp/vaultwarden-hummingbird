//! S3 state-sync configuration (opt-in via SUPERVISOR_S3_*).
//!
//! mod.rs is declarations only; the public surface is re-exports.

mod resolve;
mod spec;

pub(crate) use resolve::resolve_sync;
pub use spec::SyncConfig;
