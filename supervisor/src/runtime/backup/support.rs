//! Shared test fixtures for the backup modules (config builders and
//! unique staging dirs; tests run concurrently on one process).

#![cfg(test)]

use std::time::Duration;

use crate::config::{DbBackupConfig, DbSpec, SyncConfig};

/// Unique-ish staging dir per test invocation.
pub(super) fn next_staging() -> String {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("vw-sup-stage-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir.to_string_lossy().into_owned()
}

/// A sqlite DbBackupConfig pointed at `url` with a unique staging dir.
pub(super) fn cfg(url: &str) -> DbBackupConfig {
    DbBackupConfig {
        sync: SyncConfig::new(
            "r2:vw".into(),
            "id".into(),
            "secret".into(),
            String::new(),
            Duration::from_secs(60),
        ),
        url: url.to_string(),
        db: DbSpec::Sqlite {
            path: "/nonexistent/db.sqlite3".into(),
        },
        periodic: true,
        interval: Duration::from_secs(43_200),
        keep: 3,
        restore: false,
        staging: next_staging(),
    }
}
