//! The [`DbBackupConfig`] carried by `Config`: DB backup/restore settings
//! consumed by `crate::runtime::backup`, the runner. Credentials and the
//! bucket path are reused from the S3 state sync: dumps live under
//! `<state remote>/db`.

use std::time::Duration;

use super::super::dburl::DbSpec;
use super::super::sync::SyncConfig;

/// S3-backed DB dumps (opt-in): periodic snapshots pushed to
/// `<state remote>/db`, pruned to keep-N per backend, plus an opt-in
/// boot-time restore into an empty DB. Single instance per bucket/path.
/// Cloned onto the backup thread.
#[derive(Clone)]
pub struct DbBackupConfig {
    /// S3 credentials + backend env, shared with the state sync (cloned)
    pub sync: SyncConfig,
    /// vaultwarden's database URL verbatim (`VAULTWARDEN_DATABASE_URL`;
    /// postgres client use; never logged — carries credentials)
    pub url: String,
    /// parsed vaultwarden database URL (dump/restore target)
    pub db: DbSpec,
    /// periodic dumps enabled (SUPERVISOR_DB_BACKUP)
    pub periodic: bool,
    /// periodic dump cadence
    pub interval: Duration,
    /// per-backend dumps kept in the bucket (oldest pruned after each push)
    pub keep: usize,
    /// boot-time restore into an empty DB (SUPERVISOR_DB_BACKUP_RESTORE)
    pub restore: bool,
    /// local staging dir on the data volume for in-flight dumps/pulls
    pub staging: String,
}

impl DbBackupConfig {
    /// Bucket prefix holding the dumps: `<state remote>/db`.
    pub fn prefix(&self) -> String {
        format!("{}/db", self.sync.remote)
    }
}
