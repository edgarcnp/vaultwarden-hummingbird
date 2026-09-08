//! SQLite restore: emptiness gate (file absent) and import (integrity
//! check on the staged copy, then atomic rename into place). In-process
//! via bundled rusqlite — no external tool. Same filesystem (data
//! volume), so the rename has no torn-copy window.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::util::log;

/// Emptiness per the never-overwrite invariant: the live file is absent.
pub(crate) fn is_empty(path: &str) -> Result<bool, String> {
    Ok(!Path::new(path).exists())
}

/// Integrity pre-check (`PRAGMA integrity_check` on the staged copy),
/// then import (atomic rename). The live path was verified absent
/// immediately before; a re-check here keeps the invariant absolute.
pub(crate) fn import(staged: &str, path: &str) -> bool {
    let check = match rusqlite::Connection::open_with_flags(
        staged,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    ) {
        Ok(c) => c
            .query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))
            .unwrap_or_else(|e| format!("check failed: {e}")),
        Err(e) => format!("cannot open: {e}"),
    };
    if check != "ok" {
        log::err(&format!(
            "db restore: staged dump failed integrity check ({check})"
        ));
        return false;
    }
    if Path::new(path).exists() {
        log::err("db restore: live DB appeared mid-restore; not overwriting");
        return false;
    }
    match std::fs::rename(staged, path) {
        Ok(()) => {
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            true
        }
        Err(e) => {
            log::err(&format!("db restore: cannot move dump into place: {e}"));
            false
        }
    }
}
