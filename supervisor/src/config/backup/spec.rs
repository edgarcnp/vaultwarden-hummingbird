//! DB backup/restore settings consumed by `crate::runtime::backup`.

use std::time::Duration;

use super::super::sync::SyncConfig;

/// S3-backed sqlite dumps (opt-in): periodic snapshots under `<remote>/db`,
/// pruned to keep-N, plus an optional boot-time restore into an empty DB.
/// Cloned onto the maintenance thread that runs the periodic dumps.
#[derive(Clone)]
pub struct DbBackupConfig {
    /// S3 credentials and backend settings, shared with state sync.
    pub sync: SyncConfig,
    /// Path of the vault's sqlite database file (dump/restore target).
    pub db_path: String,
    /// Run periodic dumps (`SUPERVISOR_DB_BACKUP`).
    pub periodic: bool,
    /// Periodic dump cadence.
    pub interval: Duration,
    /// Dumps kept in the bucket; older ones are pruned after each push.
    pub keep: usize,
    /// Restore the newest dump into an empty DB at boot
    /// (`SUPERVISOR_DB_BACKUP_RESTORE`).
    pub restore: bool,
    /// Local staging directory for in-flight dumps and pulls.
    pub staging: String,
    /// Supervisor-only directory for the lineage and hash sidecars; never
    /// on the vault-writable data volume.
    pub state_dir: String,
}

impl DbBackupConfig {
    /// Bucket-relative prefix holding the dumps; ends with `/`.
    pub fn prefix(&self) -> String {
        format!("{}db/", self.sync.prefix())
    }

    /// A short stable key for this (database, remote, endpoint) identity.
    /// Sidecars are per identity, so switching any of them cannot inherit
    /// a stale lineage or unchanged-dump record.
    pub fn sidecar_key(&self) -> String {
        let identity = format!(
            "{}\0{}\0{}",
            self.db_path, self.sync.remote, self.sync.target.endpoint
        );
        crate::util::hash::sha256_bytes(identity.as_bytes())[..16].to_string()
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

#[cfg(test)]
mod tests {
    //! Sidecar identity isolation across database, remote, and endpoint.

    use super::*;

    /// Build a valid config for one database, remote, and endpoint triplet.
    fn cfg(db: &str, remote: &str, endpoint: &str) -> DbBackupConfig {
        DbBackupConfig {
            sync: SyncConfig::new(
                remote.into(),
                "id".into(),
                "secret".into(),
                endpoint.into(),
                Duration::from_secs(60),
            )
            .expect("valid test sync"),
            db_path: db.into(),
            periodic: true,
            interval: Duration::from_secs(60),
            keep: 3,
            restore: false,
            staging: "/state/db-backups".into(),
            state_dir: "/state".into(),
        }
    }

    /// Sidecars are per (database, remote, endpoint): switching any of
    /// them must not inherit a stale lineage or unchanged-dump record.
    #[test]
    fn sidecar_identity_separates_database_remote_and_endpoint() {
        let base = cfg("/data/db.sqlite3", "r2:vw", "https://s3.example.invalid");
        assert_ne!(
            base.sidecar_key(),
            cfg("/data/other.sqlite3", "r2:vw", "https://s3.example.invalid").sidecar_key()
        );
        assert_ne!(
            base.sidecar_key(),
            cfg("/data/db.sqlite3", "r2:other", "https://s3.example.invalid").sidecar_key()
        );
        assert_ne!(
            base.sidecar_key(),
            cfg("/data/db.sqlite3", "r2:vw", "https://other.example.invalid").sidecar_key()
        );
        assert_eq!(base.sidecar_key(), base.sidecar_key());
    }
}
