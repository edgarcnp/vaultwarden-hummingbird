//! Shared test fixtures for the backup modules (config builders and
//! unique staging dirs; tests run concurrently on one process).

#![cfg(test)]

use std::time::Duration;

use crate::config::{DbBackupConfig, SyncConfig};

/// Unique-ish scratch base per test invocation; the sidecars live directly
/// in it and the staging dir below it.
fn next_base() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("vw-sup-stage-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Unique-ish staging dir per test invocation.
pub(super) fn next_staging() -> String {
    next_base().join("staging").to_string_lossy().into_owned()
}

/// A DbBackupConfig with a custom sync config and unique scratch paths.
pub(super) fn cfg_with_sync(sync: SyncConfig) -> DbBackupConfig {
    let base = next_base();
    DbBackupConfig {
        sync,
        db_path: "/nonexistent/db.sqlite3".into(),
        periodic: true,
        interval: Duration::from_secs(43_200),
        keep: 3,
        restore: false,
        staging: base.join("staging").to_string_lossy().into_owned(),
        state_dir: base.to_string_lossy().into_owned(),
    }
}

/// A DbBackupConfig over a nonexistent sqlite source with a unique
/// staging dir.
pub(super) fn cfg() -> DbBackupConfig {
    cfg_with_sync(
        SyncConfig::new(
            "r2:vw".into(),
            "id".into(),
            "secret".into(),
            // dead local port: connect must succeed, no request is valid
            "http://127.0.0.1:1".into(),
            Duration::from_secs(60),
        )
        .expect("valid test remote"),
    )
}
