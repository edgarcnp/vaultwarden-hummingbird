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
    /// local staging dir on the supervisor state volume for in-flight
    /// dumps/pulls
    pub staging: String,
    /// supervisor-only directory for the lineage and hash sidecars; never
    /// on the vault-writable data volume
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
    use super::*;

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
