//! DB backup/restore settings consumed by `crate::runtime::backup`.

use std::time::Duration;

use super::super::sync::SyncConfig;

/// S3-backed sqlite dumps (opt-in): periodic snapshots pushed to
/// `<state remote>/db`, pruned to keep-N, plus an opt-in boot-time restore
/// into an empty DB. Cloned onto the maintenance thread that runs the
/// periodic dumps.
#[derive(Clone)]
pub struct DbBackupConfig {
    /// S3 credentials + backend env, shared with the state sync (cloned)
    pub sync: SyncConfig,
    /// the vault's sqlite database file (dump/restore target)
    pub db_path: String,
    /// periodic dumps enabled (SUPERVISOR_DB_BACKUP)
    pub periodic: bool,
    /// periodic dump cadence
    pub interval: Duration,
    /// dumps kept in the bucket (oldest pruned after each push)
    pub keep: usize,
    /// boot-time restore into an empty DB (SUPERVISOR_DB_BACKUP_RESTORE)
    pub restore: bool,
    /// local staging dir on the data volume for in-flight dumps/pulls
    pub staging: String,
}

impl DbBackupConfig {
    /// Bucket-relative prefix holding the dumps; ends with `/`.
    pub fn prefix(&self) -> String {
        format!("{}db/", self.sync.prefix())
    }

    /// Object-name prefix for the dumps (`<remote>/db/sqlite-…`).
    pub fn db_label(&self) -> &'static str {
        "sqlite"
    }

    /// Backup file extension of the dump format.
    pub fn db_ext(&self) -> &'static str {
        "sqlite3"
    }
}
