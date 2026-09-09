//! DB backup/restore configuration (opt-in via SUPERVISOR_DB_BACKUP*).

mod resolve;
mod spec;

pub(crate) use resolve::resolve_backup;
pub use spec::DbBackupConfig;
