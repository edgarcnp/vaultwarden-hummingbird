//! Emptiness verification for the boot-time restore: the gate that makes
//! restore miss-never-corrupt. Anything uncertain is Err (ambiguous),
//! never "empty" — callers fail closed.

use crate::config::DbBackupConfig;

/// Emptiness per [`super::sqlite::is_empty`]'s never-overwrite contract.
pub(super) fn is_empty(cfg: &DbBackupConfig) -> Result<bool, String> {
    super::sqlite::is_empty(&cfg.db_path)
}

#[cfg(test)]
mod tests {
    use super::super::support;
    use super::*;

    #[test]
    fn missing_file_is_empty() {
        let cfg = support::cfg();
        assert!(is_empty(&cfg).unwrap());
    }
}
