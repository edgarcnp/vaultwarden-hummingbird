//! DB backup/restore configuration (opt-in via SUPERVISOR_DB_BACKUP*).
//!
//! mod.rs is declarations only; the public surface is re-exports.

mod resolve;
mod spec;

pub(crate) use resolve::resolve_backup;
pub use spec::DbBackupConfig;
